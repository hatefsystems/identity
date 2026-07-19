// Package blindindex implements deterministic SHA-256 cryptographic blind
// indexing for exact-match lookups over encrypted PII, per
// docs/data-architecture.md §2.2.
//
// PII columns (phone, backup email, MFA secret) are stored as AES-GCM-256
// envelope-encrypted blobs, which are opaque and non-searchable. To locate a
// user by phone number or backup email without an O(N) full-table decryption,
// the database also stores a blind index:
//
//	blind_index = SHA-256(PII + secret_pepper)
//
// The digest is stored in a dedicated, B-tree-indexed VARCHAR(64) column
// (phone_blind_index / backup_email_blind_index), enabling O(1) exact-match
// lookups without revealing plaintext. The secret pepper is retrieved from the
// KMS (Infisical) at bootstrap and kept only in memory; it is never logged.
//
// Only exact-match queries are supported by design. Wildcard, prefix, or
// substring searches over PII are prohibited to preserve data minimization.
package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// PepperSize is the minimum required pepper length in bytes. A 256-bit pepper
// matches the SHA-256 security level and resists offline brute-force of the
// index even if the database is exfiltrated.
const PepperSize = 32

// DigestHexLen is the length of a hex-encoded SHA-256 digest (32 bytes => 64
// hex characters), matching the VARCHAR(64) blind index columns.
const DigestHexLen = 64

// ErrInvalidPepper indicates the configured pepper is too short.
var ErrInvalidPepper = errors.New("blindindex: pepper must be at least 32 bytes")

// Indexer computes blind indexes over PII using a secret pepper. It is safe for
// concurrent use; the pepper is fixed at construction and never mutated.
type Indexer struct {
	pepper []byte
}

// New constructs an Indexer with the given secret pepper. The pepper must be at
// least PepperSize bytes.
func New(pepper []byte) (*Indexer, error) {
	if len(pepper) < PepperSize {
		return nil, ErrInvalidPepper
	}
	// Defensive copy so callers cannot mutate the pepper after construction.
	p := make([]byte, len(pepper))
	copy(p, pepper)
	return &Indexer{pepper: p}, nil
}

// Compute returns the hex-encoded SHA-256 blind index for the given PII value.
//
// The pepper is combined with the PII via HMAC-SHA-256 rather than plain
// concatenation. HMAC realizes the keyed SHA-256(PII + pepper) construction the
// docs describe while structurally avoiding length-extension and
// concatenation-ambiguity pitfalls, and keeps the pepper in the key position.
// The input is normalized (trimmed of surrounding whitespace and lowercased) so
// that trivially different representations of the same identifier map to the
// same index. Callers remain responsible for domain-specific canonicalization
// (e.g. E.164 phone formatting) before calling Compute.
func (i *Indexer) Compute(pii string) string {
	normalized := normalize(pii)
	mac := hmac.New(sha256.New, i.pepper)
	// Write never returns an error for hash.Hash implementations.
	_, _ = mac.Write([]byte(normalized))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum)
}

// Equal reports whether two blind index digests are equal using a constant-time
// comparison to avoid leaking information through timing side-channels
// (docs/architecture.md "Timing Attack Resistance").
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// normalize applies consistent canonicalization to index inputs.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
