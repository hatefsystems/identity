package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
)

// newTestKEK returns a random 32-byte KEK for tests.
func newTestKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, KEKSize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return kek
}

func newTestDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return dek
}

func TestNewMockProviderInvalidKEK(t *testing.T) {
	cases := map[string]int{
		"too-short": 16,
		"too-long":  48,
		"empty":     0,
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewMockProvider(make([]byte, size), 1)
			if !errors.Is(err, ErrInvalidKEK) {
				t.Fatalf("NewMockProvider(len=%d) error = %v, want ErrInvalidKEK", size, err)
			}
		})
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)

	wrapped, nonce, tag, version, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if len(nonce) != NonceSize {
		t.Errorf("nonce len = %d, want %d", len(nonce), NonceSize)
	}
	if len(tag) != TagSize {
		t.Errorf("tag len = %d, want %d", len(tag), TagSize)
	}
	if len(wrapped) != DEKSize {
		t.Errorf("wrapped len = %d, want %d", len(wrapped), DEKSize)
	}
	if bytes.Equal(wrapped, dek) {
		t.Error("wrapped DEK equals plaintext DEK; not encrypted")
	}

	got, err := p.UnwrapDEK(ctx, wrapped, nonce, tag, version)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Error("unwrapped DEK does not match original")
	}
}

func TestWrapDEKUniqueNonce(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)

	_, nonce1, _, _, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK #1: %v", err)
	}
	_, nonce2, _, _, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK #2: %v", err)
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Error("two WrapDEK calls produced identical nonces")
	}
}

func TestWrapDEKInvalidDEK(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	if _, _, _, _, err := p.WrapDEK(ctx, make([]byte, 16)); !errors.Is(err, ErrInvalidDEK) {
		t.Fatalf("WrapDEK(short) error = %v, want ErrInvalidDEK", err)
	}
}

func TestUnwrapDEKUnknownVersion(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)
	wrapped, nonce, tag, _, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if _, err := p.UnwrapDEK(ctx, wrapped, nonce, tag, 9); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("UnwrapDEK(version=9) error = %v, want ErrUnknownKeyVersion", err)
	}
}

func TestUnwrapDEKInvalidNonce(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)
	wrapped, _, tag, version, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if _, err := p.UnwrapDEK(ctx, wrapped, make([]byte, 8), tag, version); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("UnwrapDEK(bad nonce) error = %v, want ErrInvalidNonce", err)
	}
}

func TestUnwrapDEKTampered(t *testing.T) {
	ctx := context.Background()
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)
	wrapped, nonce, tag, version, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	t.Run("tampered-ciphertext", func(t *testing.T) {
		bad := bytes.Clone(wrapped)
		bad[0] ^= 0xFF
		if _, err := p.UnwrapDEK(ctx, bad, nonce, tag, version); !errors.Is(err, ErrUnwrap) {
			t.Fatalf("error = %v, want ErrUnwrap", err)
		}
	})
	t.Run("tampered-tag", func(t *testing.T) {
		bad := bytes.Clone(tag)
		bad[0] ^= 0xFF
		if _, err := p.UnwrapDEK(ctx, wrapped, nonce, bad, version); !errors.Is(err, ErrUnwrap) {
			t.Fatalf("error = %v, want ErrUnwrap", err)
		}
	})
	t.Run("wrong-nonce", func(t *testing.T) {
		bad := bytes.Clone(nonce)
		bad[0] ^= 0xFF
		if _, err := p.UnwrapDEK(ctx, wrapped, bad, tag, version); !errors.Is(err, ErrUnwrap) {
			t.Fatalf("error = %v, want ErrUnwrap", err)
		}
	})
}

// TestKEKRotation verifies that a DEK wrapped under a retired KEK version can
// still be unwrapped after the active KEK has rotated, and that a new wrap uses
// the new active version (docs/disaster-recovery.md §2.2).
func TestKEKRotation(t *testing.T) {
	ctx := context.Background()
	oldKEK := newTestKEK(t)
	newKEK := newTestKEK(t)

	// Provider initially active at version 1.
	p, err := NewMockProvider(oldKEK, 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	dek := newTestDEK(t)
	wrappedOld, nonceOld, tagOld, versionOld, err := p.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK old: %v", err)
	}

	// Rotate: register version 2 and make a fresh provider active at 2 while
	// retaining version 1 for backward-compatible decryption.
	rotated, err := NewMockProvider(newKEK, 2)
	if err != nil {
		t.Fatalf("NewMockProvider rotated: %v", err)
	}
	if err := rotated.AddKEK(1, oldKEK); err != nil {
		t.Fatalf("AddKEK: %v", err)
	}

	// Old record still decrypts using its stored version byte.
	got, err := rotated.UnwrapDEK(ctx, wrappedOld, nonceOld, tagOld, versionOld)
	if err != nil {
		t.Fatalf("UnwrapDEK old after rotation: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Error("rotated provider failed to recover DEK wrapped under retired KEK")
	}

	// New writes use the new active version.
	_, _, _, versionNew, err := rotated.WrapDEK(ctx, dek)
	if err != nil {
		t.Fatalf("WrapDEK new: %v", err)
	}
	if versionNew != 2 {
		t.Errorf("new wrap version = %d, want 2", versionNew)
	}
}

func TestAddKEKInvalid(t *testing.T) {
	p, err := NewMockProvider(newTestKEK(t), 1)
	if err != nil {
		t.Fatalf("NewMockProvider: %v", err)
	}
	if err := p.AddKEK(2, make([]byte, 10)); !errors.Is(err, ErrInvalidKEK) {
		t.Fatalf("AddKEK(short) error = %v, want ErrInvalidKEK", err)
	}
}

// Ensure MockProvider satisfies the Provider interface.
var _ Provider = (*MockProvider)(nil)
