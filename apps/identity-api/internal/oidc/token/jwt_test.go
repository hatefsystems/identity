package token

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// testES256Key generates an ephemeral ES256 signing key for tests.
func testES256Key(t *testing.T) *keys.SigningKey {
	t.Helper()
	key, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	return key
}

// testRS256Key generates an ephemeral RS256 signing key for tests.
func testRS256Key(t *testing.T) *keys.SigningKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &keys.SigningKey{KID: "test-rs256", Alg: keys.AlgRS256, Signer: priv}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, name := range []string{"ES256", "RS256"} {
		t.Run(name, func(t *testing.T) {
			var key *keys.SigningKey
			if name == "ES256" {
				key = testES256Key(t)
			} else {
				key = testRS256Key(t)
			}

			claims := Claims{"iss": "https://id.example", "sub": "user-1", "exp": int64(1900000000)}
			jwt, err := Sign(key, TypAccessToken, claims)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if strings.Count(jwt, ".") != 2 {
				t.Fatalf("expected compact JWS with 3 segments, got %q", jwt)
			}

			got, err := Verify(jwt, key)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got["iss"] != "https://id.example" || got["sub"] != "user-1" {
				t.Errorf("claims round-trip mismatch: %+v", got)
			}
		})
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key := testES256Key(t)
	jwt, err := Sign(key, TypAccessToken, Claims{"sub": "user-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(jwt, ".")
	// Swap the payload for a forged one; the signature must no longer match.
	forged := parts[0] + ".eyJzdWIiOiJhZG1pbiJ9." + parts[2]
	if _, err := Verify(forged, key); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered payload: want ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key := testES256Key(t)
	other := testES256Key(t)
	jwt, err := Sign(key, TypAccessToken, Claims{"sub": "user-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(jwt, other); err == nil {
		t.Error("verification with a different key must fail")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	key := testES256Key(t)
	for _, in := range []string{"", "abc", "a.b", "a.b.c.d", "!!!.###.$$$"} {
		if _, err := Verify(in, key); err == nil {
			t.Errorf("Verify(%q): expected error", in)
		}
	}
}

func TestSignNilKey(t *testing.T) {
	if _, err := Sign(nil, TypJWT, Claims{}); err == nil {
		t.Error("Sign with nil key must fail")
	}
}
