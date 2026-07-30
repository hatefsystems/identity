package session

import (
	"encoding/base64"
	"testing"
)

func TestNewTokenUniqueAndHashed(t *testing.T) {
	token1, hash1, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: unexpected error: %v", err)
	}
	token2, hash2, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: unexpected error: %v", err)
	}

	if token1 == "" || token2 == "" {
		t.Fatal("NewToken returned an empty token")
	}
	if token1 == token2 {
		t.Fatal("NewToken returned identical tokens; expected high-entropy uniqueness")
	}
	if hash1 == hash2 {
		t.Fatal("distinct tokens produced identical hashes")
	}
	if token1 == hash1 {
		t.Fatal("hash must not equal the raw token")
	}
}

func TestNewTokenEntropy(t *testing.T) {
	token, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: unexpected error: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != tokenByteLen {
		t.Fatalf("token entropy = %d bytes, want %d", len(raw), tokenByteLen)
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	token, hash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: unexpected error: %v", err)
	}
	if got := HashToken(token); got != hash {
		t.Fatalf("HashToken not deterministic: got %q, want %q", got, hash)
	}
}

func TestHashTokenDistinctInputs(t *testing.T) {
	if HashToken("alpha") == HashToken("beta") {
		t.Fatal("different inputs hashed to the same digest")
	}
}

func TestHashTokenIsBase64URL(t *testing.T) {
	// SHA-256 is 32 bytes -> 43 chars in unpadded base64url.
	hash := HashToken("some-token")
	raw, err := base64.RawURLEncoding.DecodeString(hash)
	if err != nil {
		t.Fatalf("hash is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("hash decodes to %d bytes, want 32 (SHA-256)", len(raw))
	}
}
