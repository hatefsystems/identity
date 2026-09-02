package privacy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewReclaimTokenEntropyAndEncoding(t *testing.T) {
	token, hash, err := NewReclaimToken()
	if err != nil {
		t.Fatalf("NewReclaimToken: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token %q is not unpadded base64url: %v", token, err)
	}
	if len(raw) != reclaimTokenByteLen {
		t.Errorf("token decodes to %d bytes, want %d (256 bits)", len(raw), reclaimTokenByteLen)
	}

	// The hash must fit deletion_requests.token_hash VARCHAR(64): hex-encoded
	// SHA-256 is exactly 64 characters, always.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want exactly 64 to fit VARCHAR(64)", len(hash))
	}
	if strings.ContainsAny(hash, "+/=") {
		t.Errorf("hash %q is not hex-encoded", hash)
	}

	// The token must never be recoverable from what is persisted.
	if strings.Contains(hash, token) {
		t.Error("hash contains the plaintext token")
	}
	if hash == token {
		t.Error("hash equals the plaintext token")
	}
}

// TestNewReclaimTokenIsUnpredictable is a smoke check on the CSPRNG: distinct calls
// must never collide, and neither must their hashes. A repeated token would let one
// user's reclaim ceremony resolve another's deletion request.
func TestNewReclaimTokenIsUnpredictable(t *testing.T) {
	const iterations = 512
	seenTokens := make(map[string]struct{}, iterations)
	seenHashes := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		token, hash, err := NewReclaimToken()
		if err != nil {
			t.Fatalf("NewReclaimToken #%d: %v", i, err)
		}
		if _, dup := seenTokens[token]; dup {
			t.Fatalf("duplicate token at iteration %d", i)
		}
		if _, dup := seenHashes[hash]; dup {
			t.Fatalf("duplicate hash at iteration %d", i)
		}
		seenTokens[token] = struct{}{}
		seenHashes[hash] = struct{}{}
	}
}

// TestHashReclaimTokenIsStable pins determinism: the lookup key must be
// reproducible from the plaintext, because the index lookup is the only way an
// anonymous caller's token can be resolved.
func TestHashReclaimTokenIsStable(t *testing.T) {
	token, hash, err := NewReclaimToken()
	if err != nil {
		t.Fatalf("NewReclaimToken: %v", err)
	}

	if got := HashReclaimToken(token); got != hash {
		t.Errorf("HashReclaimToken(token) = %q, want the constructor's %q", got, hash)
	}
	if again := HashReclaimToken(token); again != hash {
		t.Errorf("HashReclaimToken is not deterministic: %q then %q", hash, again)
	}
	// A single-character difference must produce a completely different key, or a
	// near-miss token could resolve a real request.
	if HashReclaimToken(token+"x") == hash {
		t.Error("HashReclaimToken collided for a modified token")
	}
	if HashReclaimToken("") == hash {
		t.Error("HashReclaimToken of the empty string equals a real token's hash")
	}
}
