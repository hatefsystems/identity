// PKCE S256 verification for the token endpoint (RFC 7636 §4.6). Only the
// S256 method exists in this codebase: the authorization endpoint refuses to
// store anything but S256 challenges (internal/oidc/authorize.go), so a
// "plain" comparison path is structurally impossible here.

package token

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// code_verifier length bounds per RFC 7636 §4.1.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

// VerifyPKCE reports whether codeVerifier satisfies the stored S256
// codeChallenge: BASE64URL(SHA-256(verifier)) == challenge. The comparison is
// constant-time (docs/architecture.md "Timing Attack Resistance"). Malformed
// verifiers (wrong length or characters outside the unreserved set) are
// rejected before hashing.
func VerifyPKCE(codeVerifier, codeChallenge string) bool {
	if !isValidVerifier(codeVerifier) {
		return false
	}
	digest := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// isValidVerifier checks the RFC 7636 §4.1 grammar: 43-128 characters from
// the unreserved set ALPHA / DIGIT / "-" / "." / "_" / "~".
func isValidVerifier(v string) bool {
	if len(v) < minVerifierLen || len(v) > maxVerifierLen {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_' || r == '~':
		default:
			return false
		}
	}
	return true
}
