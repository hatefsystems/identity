// Package recovery implements the one-time recovery (backup) codes that let a
// user regain access when every registered passkey and the TOTP authenticator
// are unavailable (Task 4.6).
//
// The security properties it is required to hold (docs/data-architecture.md
// §1.2, docs/api-design.md §1.3, docs/threat-modeling.md T1/D1):
//
//   - High entropy: each code is generated from crypto/rand with at least
//     128 bits of entropy (default 160), so guessing is infeasible and the
//     stored hash cannot be brute-forced offline from a database dump.
//   - SHA-256, not Argon2id: because the codes are already high-entropy, a
//     single fast hash is sufficient. Using a memory-hard KDF here would hand
//     an attacker a CPU-exhaustion DoS vector on an unauthenticated-adjacent
//     endpoint (threat-modeling.md D1) and would break the O(1) indexed
//     lookup, since a per-row salt cannot be searched by hash.
//   - Deterministic lookup: the hash is the search key, matched through the
//     partial unique index idx_recovery_codes_hash, so verification is a single
//     indexed read rather than a scan-and-compare over the user's whole batch.
//   - Atomic single use: verification and physical deletion of the row happen
//     inside one ACID transaction with the row held under FOR UPDATE, so two
//     concurrent submissions of the same code can never both succeed
//     (see Service.Verify).
package recovery

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// codeAlphabet is Crockford base32: the digits and upper-case letters with
// I, L, O, and U removed. Dropping the visually ambiguous glyphs (and U, to
// avoid accidental profanity) means a code read off paper or a screenshot
// transcribes unambiguously, and the confusable characters that remain can be
// folded deterministically in Normalize.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// bitsPerChar is the entropy contributed by one alphabet character:
// log2(32) = 5 bits exactly, which is what makes the entropy accounting in
// charsForBits exact rather than an approximation.
const bitsPerChar = 5

// MinEntropyBits is the floor mandated by Task 4.6 and
// docs/data-architecture.md §1.2. Configuration below this value is rejected
// rather than silently raised, so a weakened policy cannot ship unnoticed.
const MinEntropyBits = 128

// DefaultEntropyBits is the default per-code entropy: 160 bits, comfortably
// above the 128-bit floor and an exact multiple of bitsPerChar (32 characters).
const DefaultEntropyBits = 160

// groupSize is the number of characters between separators in the display form
// ("XXXXX-XXXXX-..."), which makes a long code readable and transcribable.
const groupSize = 5

// charsForBits converts an entropy budget in bits into the number of alphabet
// characters needed to carry it, rounding up so the generated code always meets
// or exceeds the requested entropy.
func charsForBits(bits int) int {
	return (bits + bitsPerChar - 1) / bitsPerChar
}

// EntropyBits reports the actual entropy of a code of the given character
// length, which is what a caller should log or document rather than the
// requested budget (the rounding in charsForBits can only round up).
func EntropyBits(chars int) int {
	return chars * bitsPerChar
}

// generateCode returns a single recovery code of length chars, drawn uniformly
// from codeAlphabet using crypto/rand.
//
// Uniformity matters: the naive "random byte modulo 32" would be unbiased only
// because 256 is a multiple of 32, and that coincidence would silently
// disappear if the alphabet ever changed. rand.Int over the alphabet length is
// unbiased for any alphabet, so the entropy accounting above stays honest.
func generateCode(chars int) (string, error) {
	if chars <= 0 {
		return "", fmt.Errorf("recovery: code length must be positive, got %d", chars)
	}

	limit := big.NewInt(int64(len(codeAlphabet)))
	out := make([]byte, 0, chars)
	for i := 0; i < chars; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("recovery: generate code: %w", err)
		}
		out = append(out, codeAlphabet[n.Int64()])
	}
	return string(out), nil
}

// format inserts a dash every groupSize characters, producing the form the user
// is shown and expected to copy down. Normalize strips the separators again, so
// a user may type the code with or without them.
func format(code string) string {
	if len(code) <= groupSize {
		return code
	}

	var b strings.Builder
	// Worst case one separator per group.
	b.Grow(len(code) + len(code)/groupSize)
	for i, ch := range code {
		if i > 0 && i%groupSize == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// Normalize canonicalizes a user-submitted code so cosmetic transcription
// differences do not cause a false rejection: case is folded up, separators and
// whitespace are dropped, and the characters excluded from the alphabet are
// folded onto the glyph they are confused with (O to 0, I and L to 1). Any other
// character is dropped, which keeps the result inside the alphabet without
// leaking a distinct "malformed" error for the caller to probe.
//
// It is deliberately applied on both sides of the hash: the stored hash is
// computed over the normalized generated code, so hashing a normalized
// submission is what makes the index lookup succeed.
func Normalize(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, ch := range strings.ToUpper(code) {
		switch ch {
		case 'O':
			b.WriteByte('0')
		case 'I', 'L':
			b.WriteByte('1')
		case 'U':
			// U is excluded from the alphabet; the nearest transcription
			// confusion is with V, which is in it.
			b.WriteByte('V')
		default:
			if strings.ContainsRune(codeAlphabet, ch) {
				b.WriteRune(ch)
			}
		}
	}
	return b.String()
}

// hashCode derives the stored representation of a recovery code.
//
// With a pepper configured this is HMAC-SHA-256(pepper, normalized code) — the
// "salted SHA-256" of docs/threat-modeling.md T1, using a single service-wide
// secret rather than a per-row salt so the value stays deterministic and
// therefore indexable. Without one it is plain SHA-256(normalized code), which
// is what docs/data-architecture.md §1.2 specifies. Both produce 32 bytes, so
// the hex encoding is always exactly 64 characters and fits the
// recovery_codes.code_hash VARCHAR(64) column either way.
//
// The pepper is not required for confidentiality here (a 128-bit code is not
// brute-forceable), but when it is present a stolen database dump alone is not
// enough to test candidate codes offline: the attacker also needs the KMS-held
// secret.
func hashCode(pepper []byte, normalized string) string {
	if len(pepper) > 0 {
		mac := hmac.New(sha256.New, pepper)
		_, _ = mac.Write([]byte(normalized))
		return hex.EncodeToString(mac.Sum(nil))
	}
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
