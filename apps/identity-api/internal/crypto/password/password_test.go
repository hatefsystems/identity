package password

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestParameterConstants(t *testing.T) {
	if Memory != 64*1024 {
		t.Errorf("Memory = %d KiB, want %d (64MB)", Memory, 64*1024)
	}
	if Iterations != 3 {
		t.Errorf("Iterations = %d, want 3", Iterations)
	}
	if Parallelism != 4 {
		t.Errorf("Parallelism = %d, want 4", Parallelism)
	}
	if SaltLength != 16 {
		t.Errorf("SaltLength = %d, want 16", SaltLength)
	}
	if KeyLength != 32 {
		t.Errorf("KeyLength = %d, want 32", KeyLength)
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	cases := map[string]string{
		"ascii":      "correct horse battery staple",
		"unicode":    "گذرواژهٔ محرمانه",
		"empty":      "",
		"long":       strings.Repeat("A", 1024),
		"symbols":    "p@$$w0rd!#%&*()_+",
		"whitespace": "  leading and trailing  ",
	}
	for name, pw := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := Hash(pw)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			ok, err := Verify(pw, encoded)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !ok {
				t.Error("Verify returned false for correct password")
			}
		})
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	encoded, err := Hash("the real password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify("not the password", encoded)
	if err != nil {
		t.Fatalf("Verify returned error for mismatch: %v", err)
	}
	if ok {
		t.Error("Verify returned true for wrong password")
	}
}

// TestHashUniqueSalt ensures each Hash call uses a fresh salt, so identical
// passwords produce different encoded strings.
func TestHashUniqueSalt(t *testing.T) {
	pw := "same-password"
	h1, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash #1: %v", err)
	}
	h2, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash #2: %v", err)
	}
	if h1 == h2 {
		t.Error("two hashes of same password are identical; salt not unique")
	}
	// Both must still verify.
	for i, h := range []string{h1, h2} {
		ok, err := Verify(pw, h)
		if err != nil || !ok {
			t.Errorf("hash #%d failed to verify (ok=%v, err=%v)", i+1, ok, err)
		}
	}
}

func TestHashEncodingFormat(t *testing.T) {
	encoded, err := Hash("value")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	wantPrefix := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, Memory, Iterations, Parallelism)
	if !strings.HasPrefix(encoded, wantPrefix) {
		t.Errorf("encoded = %q, want prefix %q", encoded, wantPrefix)
	}
	// Must fit in the password_hash VARCHAR(255) column.
	if len(encoded) > 255 {
		t.Errorf("encoded length = %d, exceeds VARCHAR(255)", len(encoded))
	}
	// Exactly 6 '$'-delimited segments (leading empty + 5).
	if got := len(strings.Split(encoded, "$")); got != 6 {
		t.Errorf("segments = %d, want 6", got)
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	validSalt := base64.RawStdEncoding.EncodeToString(make([]byte, SaltLength))
	validKey := base64.RawStdEncoding.EncodeToString(make([]byte, KeyLength))

	cases := map[string]struct {
		hash    string
		wantErr error
	}{
		"empty":            {"", ErrInvalidHash},
		"not-phc":          {"plaintext", ErrInvalidHash},
		"too-few-fields":   {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt, ErrInvalidHash},
		"wrong-variant":    {"$argon2i$v=19$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrIncompatibleVariant},
		"bad-version":      {"$argon2id$v=99$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrIncompatibleVersion},
		"unparseable-vers": {"$argon2id$vX$m=65536,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"bad-params":       {"$argon2id$v=19$m=abc,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"zero-params":      {"$argon2id$v=19$m=0,t=3,p=4$" + validSalt + "$" + validKey, ErrInvalidHash},
		"bad-salt-b64":     {"$argon2id$v=19$m=65536,t=3,p=4$!!!not-base64!!!$" + validKey, ErrInvalidHash},
		"bad-key-b64":      {"$argon2id$v=19$m=65536,t=3,p=4$" + validSalt + "$!!!bad!!!", ErrInvalidHash},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := Verify("pw", tc.hash)
			if ok {
				t.Error("Verify returned true for malformed hash")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	current, err := Hash("value")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if NeedsRehash(current) {
		t.Error("NeedsRehash = true for current-parameter hash, want false")
	}

	salt := base64.RawStdEncoding.EncodeToString(make([]byte, SaltLength))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, KeyLength))

	weaker := map[string]string{
		"low-memory":      fmt.Sprintf("$argon2id$v=19$m=%d,t=3,p=4$%s$%s", Memory/2, salt, key),
		"low-iterations":  fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=4$%s$%s", Memory, salt, key),
		"low-parallelism": fmt.Sprintf("$argon2id$v=19$m=%d,t=3,p=1$%s$%s", Memory, salt, key),
		"malformed":       "garbage",
	}
	for name, h := range weaker {
		t.Run(name, func(t *testing.T) {
			if !NeedsRehash(h) {
				t.Error("NeedsRehash = false, want true for weaker/invalid params")
			}
		})
	}
}

// TestCrossPasswordVerifyFails guards against any accidental salt reuse or
// truncation making distinct passwords collide.
func TestCrossPasswordVerifyFails(t *testing.T) {
	h1, err := Hash("password-one")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify("password-two", h1)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("password-two verified against password-one hash")
	}
}
