package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
)

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	kek := make([]byte, kms.KEKSize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	provider, err := kms.NewMockProvider(kek, 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	enc, err := New(provider)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return enc
}

func TestNewNilProvider(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want error")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)

	cases := map[string][]byte{
		"phone":        []byte("+989121234567"),
		"backup-email": []byte("user@example.com"),
		"totp-secret":  []byte("JBSWY3DPEHPK3PXP"),
		"empty":        {},
		"binary":       {0x00, 0xFF, 0x10, 0x42, 0x00},
		"long":         bytes.Repeat([]byte("A"), 4096),
		"unicode":      []byte("داده حساس"),
	}
	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			blob, err := enc.Encrypt(ctx, plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := enc.Decrypt(ctx, blob)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
			}
		})
	}
}

// TestEncryptUniqueCiphertext ensures a fresh DEK and nonces are used per call,
// so identical plaintext produces distinct blobs (no deterministic leakage).
func TestEncryptUniqueCiphertext(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)
	plaintext := []byte("+989121234567")

	blob1, err := enc.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	blob2, err := enc.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if bytes.Equal(blob1, blob2) {
		t.Error("two encryptions of same plaintext produced identical blobs")
	}
}

// TestBlobLayout checks the serialized header structure matches the spec in
// docs/data-architecture.md §2.1.
func TestBlobLayout(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)
	plaintext := []byte("hello")

	blob, err := enc.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wantMin := headerSize + wrappedDEKSize + len(plaintext)
	if len(blob) != wantMin {
		t.Errorf("blob len = %d, want %d (header %d + wrappedDEK %d + pii %d)",
			len(blob), wantMin, headerSize, wrappedDEKSize, len(plaintext))
	}
	if blob[0] != 1 {
		t.Errorf("version byte = %d, want 1", blob[0])
	}
}

func TestDecryptMalformed(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)

	cases := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"header-only":      make([]byte, headerSize),
		"one-short":        make([]byte, headerSize+wrappedDEKSize-1),
		"truncated-header": make([]byte, 10),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := enc.Decrypt(ctx, blob); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decrypt error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestDecryptTampered(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)
	plaintext := []byte("sensitive-value")

	blob, err := enc.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip a byte in the trailing PII ciphertext region: authentication fails.
	t.Run("pii-ciphertext", func(t *testing.T) {
		bad := bytes.Clone(blob)
		bad[len(bad)-1] ^= 0xFF
		if _, err := enc.Decrypt(ctx, bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Decrypt error = %v, want ErrDecrypt", err)
		}
	})

	// Flip a byte in the PII tag field.
	t.Run("pii-tag", func(t *testing.T) {
		bad := bytes.Clone(blob)
		piiTagStart := versionSize + kms.NonceSize + kms.TagSize + kms.NonceSize
		bad[piiTagStart] ^= 0xFF
		if _, err := enc.Decrypt(ctx, bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Decrypt error = %v, want ErrDecrypt", err)
		}
	})

	// Flip a byte in the wrapped DEK region: unwrap (KMS) fails.
	t.Run("wrapped-dek", func(t *testing.T) {
		bad := bytes.Clone(blob)
		bad[headerSize] ^= 0xFF
		if _, err := enc.Decrypt(ctx, bad); err == nil {
			t.Fatal("Decrypt of tampered wrapped DEK = nil error, want error")
		}
	})
}

// TestDecryptUnknownVersion ensures a blob stamped with a KEK version the
// provider does not know is rejected.
func TestDecryptUnknownVersion(t *testing.T) {
	ctx := context.Background()
	enc := newTestEncryptor(t)
	plaintext := []byte("value")

	blob, err := enc.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob[0] = 99 // unknown version
	if _, err := enc.Decrypt(ctx, blob); err == nil {
		t.Fatal("Decrypt with unknown version = nil error, want error")
	}
}

// TestCrossKEKDecryptFails ensures a blob produced under one KEK cannot be
// decrypted by an Encryptor backed by a different KEK at the same version.
func TestCrossKEKDecryptFails(t *testing.T) {
	ctx := context.Background()
	enc1 := newTestEncryptor(t)
	enc2 := newTestEncryptor(t)

	blob, err := enc1.Encrypt(ctx, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := enc2.Decrypt(ctx, blob); err == nil {
		t.Fatal("Decrypt with foreign KEK = nil error, want error")
	}
}
