// Package kms defines the Key Management Service (KMS) abstraction used by the
// application-layer envelope encryption module (see docs/data-architecture.md
// §2). The master Key Encryption Key (KEK) is conceptually owned by an external
// KMS (Infisical in production); this package wraps and unwraps the per-record
// Data Encryption Keys (DEKs) under that KEK using AES-GCM-256.
//
// A Provider interface decouples callers from the concrete KMS backend so that
// a real Infisical client can be substituted for the MockProvider used in
// development and tests without touching the envelope logic.
package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// KEKSize is the required master Key Encryption Key length in bytes
	// (AES-256 => 32 bytes).
	KEKSize = 32
	// DEKSize is the Data Encryption Key length in bytes (AES-256 => 32 bytes).
	DEKSize = 32
	// NonceSize is the AES-GCM nonce length in bytes (the standard 96-bit
	// nonce recommended by NIST SP 800-38D and matching the 12-byte
	// DEK-Wrap Nonce field in docs/data-architecture.md §2.1).
	NonceSize = 12
	// TagSize is the AES-GCM authentication tag length in bytes (128-bit).
	TagSize = 16
)

// Sentinel errors allow callers (and the envelope module) to distinguish
// configuration mistakes from cryptographic failures for metrics/alerting
// (see the idp_envelope_encryption_errors_total taxonomy in
// docs/devops-operations.md §3.1).
var (
	// ErrInvalidKEK indicates a KEK of the wrong length was supplied.
	ErrInvalidKEK = errors.New("kms: KEK must be exactly 32 bytes (AES-256)")
	// ErrInvalidDEK indicates a DEK of the wrong length was supplied.
	ErrInvalidDEK = errors.New("kms: DEK must be exactly 32 bytes (AES-256)")
	// ErrUnknownKeyVersion indicates no KEK is registered for the requested
	// version byte. During key rotation, older records carry the version of
	// the (possibly retired) KEK that must be used to unwrap their DEK
	// (docs/disaster-recovery.md §2.2 "Backward Compatibility").
	ErrUnknownKeyVersion = errors.New("kms: no KEK registered for key version")
	// ErrInvalidNonce indicates a nonce of the wrong length was supplied.
	ErrInvalidNonce = errors.New("kms: nonce must be exactly 12 bytes")
	// ErrUnwrap indicates the wrapped DEK failed authentication/decryption
	// (corruption, tampering, or a KEK mismatch).
	ErrUnwrap = errors.New("kms: failed to unwrap DEK")
)

// Provider wraps and unwraps Data Encryption Keys (DEKs) under a master Key
// Encryption Key (KEK). Implementations must be safe for concurrent use.
type Provider interface {
	// WrapDEK encrypts (wraps) a 256-bit DEK under the active master KEK.
	// It returns the wrapped DEK ciphertext, the GCM nonce used, the GCM
	// authentication tag, and the version byte identifying which KEK
	// performed the wrap (so the correct KEK can later be selected for
	// unwrapping across rotations).
	WrapDEK(ctx context.Context, dek []byte) (wrapped, nonce, tag []byte, keyVersion byte, err error)

	// UnwrapDEK decrypts a previously wrapped DEK using the KEK identified by
	// keyVersion. The nonce and tag must be those produced by WrapDEK.
	UnwrapDEK(ctx context.Context, wrapped, nonce, tag []byte, keyVersion byte) (dek []byte, err error)
}

// MockProvider is an in-memory Provider used for local development and tests.
// It holds one or more AES-GCM-256 KEKs keyed by version byte, mirroring the
// production model where Infisical retains rotated KEK versions so that older
// database rows remain decryptable (docs/disaster-recovery.md §2.2).
//
// It performs real AES-GCM cryptography; only the key storage/retrieval is
// mocked. It is safe for concurrent use because the KEK set is fixed at
// construction time and the underlying cipher.AEAD is stateless per call.
type MockProvider struct {
	keks          map[byte]cipher.AEAD
	activeVersion byte
}

// NewMockProvider constructs a MockProvider with a single active KEK at the
// given version. Additional (e.g. rotated/retired) KEK versions can be
// registered with AddKEK to support backward-compatible decryption.
func NewMockProvider(kek []byte, activeVersion byte) (*MockProvider, error) {
	if len(kek) != KEKSize {
		return nil, ErrInvalidKEK
	}
	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	return &MockProvider{
		keks:          map[byte]cipher.AEAD{activeVersion: aead},
		activeVersion: activeVersion,
	}, nil
}

// AddKEK registers an additional KEK under the given version byte. This models
// KMS key rotation: newly written records use the active KEK, while previously
// written records continue to be unwrapped with the retired KEK that matches
// their stored version byte.
func (m *MockProvider) AddKEK(version byte, kek []byte) error {
	if len(kek) != KEKSize {
		return ErrInvalidKEK
	}
	aead, err := newGCM(kek)
	if err != nil {
		return err
	}
	m.keks[version] = aead
	return nil
}

// WrapDEK implements Provider using the active KEK.
func (m *MockProvider) WrapDEK(_ context.Context, dek []byte) (wrapped, nonce, tag []byte, keyVersion byte, err error) {
	if len(dek) != DEKSize {
		return nil, nil, nil, 0, ErrInvalidDEK
	}
	aead, ok := m.keks[m.activeVersion]
	if !ok {
		return nil, nil, nil, 0, ErrUnknownKeyVersion
	}

	nonce = make([]byte, NonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, nil, 0, fmt.Errorf("kms: generate nonce: %w", err)
	}

	// Seal appends the 16-byte GCM tag to the ciphertext. The envelope format
	// stores the tag as a distinct field, so split it out here.
	sealed := aead.Seal(nil, nonce, dek, nil)
	wrapped = sealed[:len(sealed)-TagSize]
	tag = sealed[len(sealed)-TagSize:]
	return wrapped, nonce, tag, m.activeVersion, nil
}

// UnwrapDEK implements Provider, selecting the KEK by version byte.
func (m *MockProvider) UnwrapDEK(_ context.Context, wrapped, nonce, tag []byte, keyVersion byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonce
	}
	aead, ok := m.keks[keyVersion]
	if !ok {
		return nil, ErrUnknownKeyVersion
	}

	// Reassemble the ciphertext||tag layout expected by Open.
	sealed := make([]byte, 0, len(wrapped)+len(tag))
	sealed = append(sealed, wrapped...)
	sealed = append(sealed, tag...)

	dek, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrUnwrap
	}
	return dek, nil
}

// newGCM constructs an AES-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: new AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: new GCM: %w", err)
	}
	return aead, nil
}
