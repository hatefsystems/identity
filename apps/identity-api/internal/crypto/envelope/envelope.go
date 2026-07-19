// Package envelope implements AES-GCM-256 application-layer envelope encryption
// for Personally Identifiable Information (PII) such as phone numbers, backup
// emails, and MFA secrets, per docs/data-architecture.md §2.
//
// Each record is protected with a freshly generated 256-bit Data Encryption
// Key (DEK). The PII is encrypted with the DEK; the DEK itself is wrapped by a
// master Key Encryption Key (KEK) held in the KMS (Infisical). The wrapped DEK
// and ciphertext are serialized together into a single self-describing binary
// blob stored in a PostgreSQL BYTEA column.
//
// Serialized layout (docs/data-architecture.md §2.1):
//
//	+---------+----------------+--------------+----------------+--------------+
//	| Version | DEK-Wrap Nonce | DEK-Wrap Tag | PII-Enc Nonce  | PII-Enc Tag  |
//	| 1 byte  | 12 bytes       | 16 bytes     | 12 bytes       | 16 bytes     |
//	+---------+----------------+--------------+----------------+--------------+
//	| Encrypted DEK (variable) | Encrypted PII ciphertext (variable)          |
//	+--------------------------+----------------------------------------------+
//
// The DEK is always exactly 32 bytes, so once the header is parsed the wrapped
// DEK length is fixed (32 bytes, since AES-GCM ciphertext length equals the
// plaintext length) and the remainder is the PII ciphertext.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
)

const (
	// versionOffset and the following offsets describe the fixed-size header
	// that precedes the variable-length wrapped DEK and PII ciphertext.
	versionSize = 1

	// headerSize is the total fixed-size prefix:
	// Version(1) + DEKWrapNonce(12) + DEKWrapTag(16) + PIINonce(12) + PIITag(16).
	headerSize = versionSize + kms.NonceSize + kms.TagSize + kms.NonceSize + kms.TagSize

	// wrappedDEKSize is the length of the wrapped DEK ciphertext. AES-GCM
	// ciphertext length equals plaintext length, and the DEK is 32 bytes, so
	// the wrapped DEK (excluding its separately-stored tag) is also 32 bytes.
	wrappedDEKSize = kms.DEKSize
)

// Sentinel errors for callers and metrics classification (see
// idp_envelope_encryption_errors_total in docs/devops-operations.md §3.1).
var (
	// ErrMalformed indicates the serialized blob is too short or structurally
	// invalid and cannot be parsed.
	ErrMalformed = errors.New("envelope: malformed ciphertext blob")
	// ErrDecrypt indicates the PII ciphertext failed authentication/decryption.
	ErrDecrypt = errors.New("envelope: failed to decrypt PII")
)

// Encryptor performs envelope encryption and decryption of PII using a KMS
// Provider to wrap and unwrap the per-record DEK. It is safe for concurrent
// use provided the underlying Provider is.
type Encryptor struct {
	kms kms.Provider
}

// New constructs an Encryptor backed by the given KMS Provider.
func New(provider kms.Provider) (*Encryptor, error) {
	if provider == nil {
		return nil, errors.New("envelope: kms provider must not be nil")
	}
	return &Encryptor{kms: provider}, nil
}

// Encrypt encrypts plaintext PII and returns the serialized envelope blob
// suitable for storage in a BYTEA column. A unique DEK and unique nonces are
// generated for every call, so encrypting the same plaintext twice yields
// distinct ciphertexts.
func (e *Encryptor) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	// 1. Generate a fresh 256-bit DEK.
	dek := make([]byte, kms.DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}

	// 2. Encrypt the PII with the DEK (AES-GCM-256).
	piiAEAD, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	piiNonce := make([]byte, kms.NonceSize)
	if _, err := rand.Read(piiNonce); err != nil {
		return nil, fmt.Errorf("envelope: generate PII nonce: %w", err)
	}
	// Seal appends the 16-byte tag to the ciphertext; split it into its own
	// field to match the serialized layout.
	piiSealed := piiAEAD.Seal(nil, piiNonce, plaintext, nil)
	piiCiphertext := piiSealed[:len(piiSealed)-kms.TagSize]
	piiTag := piiSealed[len(piiSealed)-kms.TagSize:]

	// 3. Wrap the DEK with the master KEK via the KMS.
	wrappedDEK, wrapNonce, wrapTag, keyVersion, err := e.kms.WrapDEK(ctx, dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: wrap DEK: %w", err)
	}
	if len(wrappedDEK) != wrappedDEKSize {
		return nil, fmt.Errorf("envelope: unexpected wrapped DEK size %d", len(wrappedDEK))
	}

	// 4. Serialize: header || wrapped DEK || PII ciphertext.
	blob := make([]byte, 0, headerSize+len(wrappedDEK)+len(piiCiphertext))
	blob = append(blob, keyVersion)
	blob = append(blob, wrapNonce...)
	blob = append(blob, wrapTag...)
	blob = append(blob, piiNonce...)
	blob = append(blob, piiTag...)
	blob = append(blob, wrappedDEK...)
	blob = append(blob, piiCiphertext...)
	return blob, nil
}

// Decrypt parses a serialized envelope blob, unwraps the DEK via the KMS using
// the embedded version byte, and returns the decrypted PII plaintext.
func (e *Encryptor) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	if len(blob) < headerSize+wrappedDEKSize {
		return nil, ErrMalformed
	}

	// Parse the fixed-size header.
	off := 0
	version := blob[off]
	off += versionSize

	wrapNonce := blob[off : off+kms.NonceSize]
	off += kms.NonceSize
	wrapTag := blob[off : off+kms.TagSize]
	off += kms.TagSize

	piiNonce := blob[off : off+kms.NonceSize]
	off += kms.NonceSize
	piiTag := blob[off : off+kms.TagSize]
	off += kms.TagSize

	// Fixed-size wrapped DEK, then the remainder is the PII ciphertext.
	wrappedDEK := blob[off : off+wrappedDEKSize]
	off += wrappedDEKSize
	piiCiphertext := blob[off:]

	// Unwrap the DEK with the KEK version recorded in the blob.
	dek, err := e.kms.UnwrapDEK(ctx, wrappedDEK, wrapNonce, wrapTag, version)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap DEK: %w", err)
	}

	// Decrypt the PII with the recovered DEK.
	piiAEAD, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(piiCiphertext)+len(piiTag))
	sealed = append(sealed, piiCiphertext...)
	sealed = append(sealed, piiTag...)

	plaintext, err := piiAEAD.Open(nil, piiNonce, sealed, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// newGCM constructs an AES-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: new AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: new GCM: %w", err)
	}
	return aead, nil
}
