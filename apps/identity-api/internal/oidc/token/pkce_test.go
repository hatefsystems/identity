package token

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// challengeFor computes the S256 challenge for a verifier, mirroring what a
// client does per RFC 7636 §4.2.
func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerifyPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	specials := "abcDEF123-._~" + strings.Repeat("x", 30)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{"valid minimum length", verifier, challengeFor(verifier), true},
		{"valid maximum length", strings.Repeat("b", 128), challengeFor(strings.Repeat("b", 128)), true},
		{"valid with unreserved specials", specials, challengeFor(specials), true},
		{"wrong verifier", strings.Repeat("c", 43), challengeFor(verifier), false},
		{"too short", strings.Repeat("a", 42), challengeFor(strings.Repeat("a", 42)), false},
		{"too long", strings.Repeat("a", 129), challengeFor(strings.Repeat("a", 129)), false},
		{"invalid character", strings.Repeat("a", 42) + "!", challengeFor(strings.Repeat("a", 42) + "!"), false},
		{"empty verifier", "", challengeFor(""), false},
		{"empty challenge", verifier, "", false},
		{"challenge is raw verifier (plain method)", verifier, verifier, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifyPKCE(tc.verifier, tc.challenge); got != tc.want {
				t.Errorf("VerifyPKCE(%q, %q) = %v, want %v", tc.verifier, tc.challenge, got, tc.want)
			}
		})
	}
}
