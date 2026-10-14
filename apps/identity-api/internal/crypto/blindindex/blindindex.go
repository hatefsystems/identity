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

	"golang.org/x/text/unicode/norm"
)

// PepperSize is the minimum required pepper length in bytes. A 256-bit pepper
// matches the SHA-256 security level and resists offline brute-force of the
// index even if the database is exfiltrated.
//
// It does not make the index safe against *pepper* compromise: the input space
// for an email address or an E.164 phone number is enumerable, so a leaked
// pepper re-identifies every indexed row. Version is what makes a compromised
// pepper retirable; see Indexer.Version.
const PepperSize = 32

// DigestHexLen is the length of a hex-encoded SHA-256 digest (32 bytes => 64
// hex characters), matching the VARCHAR(64) blind index columns.
const DigestHexLen = 64

// ErrInvalidPepper indicates the configured pepper is too short.
var ErrInvalidPepper = errors.New("blindindex: pepper must be at least 32 bytes")

// ErrInvalidVersion indicates a negative pepper generation.
var ErrInvalidVersion = errors.New("blindindex: pepper version must not be negative")

// Indexer computes blind indexes over PII using a secret pepper. It is safe for
// concurrent use; the pepper is fixed at construction and never mutated.
type Indexer struct {
	pepper  []byte
	version int16
}

// New constructs an Indexer with the given secret pepper and its generation
// number. The pepper must be at least PepperSize bytes.
//
// The version is recorded alongside every digest it produces and is hashed into
// the security ledger's signed body. Without it the pepper could never be
// rotated: the index lives inside a signed, UPDATE-forbidden row, so a rotation
// would orphan the lookup path for all history with no way to tell which
// generation any given row used.
func New(pepper []byte, version int16) (*Indexer, error) {
	if len(pepper) < PepperSize {
		return nil, ErrInvalidPepper
	}
	if version < 0 {
		return nil, ErrInvalidVersion
	}
	// Defensive copy so callers cannot mutate the pepper after construction.
	p := make([]byte, len(pepper))
	copy(p, pepper)
	return &Indexer{pepper: p, version: version}, nil
}

// Version reports the pepper generation this Indexer represents.
func (i *Indexer) Version() int16 { return i.version }

// Compute returns the hex-encoded SHA-256 blind index for the given PII value.
//
// The pepper is combined with the PII via HMAC-SHA-256 rather than plain
// concatenation. HMAC realizes the keyed SHA-256(PII + pepper) construction the
// docs describe while structurally avoiding length-extension and
// concatenation-ambiguity pitfalls, and keeps the pepper in the key position.
// Callers remain responsible for domain-specific canonicalization
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
//
// NFKC runs before case folding, not after, and is not optional: an identifier
// typed as a decomposed sequence (e.g. "é" as e + U+0301) and the same
// identifier in composed form are the same address to a human and to a mail
// server, but different byte strings to HMAC. Without normalization the two
// produce different indexes, so a lawful-inquiry lookup silently misses rows
// whose attribution material was captured in the other form — a false negative
// that looks exactly like "no such subject".
func normalize(s string) string {
	return strings.ToLower(norm.NFKC.String(strings.TrimSpace(s)))
}
