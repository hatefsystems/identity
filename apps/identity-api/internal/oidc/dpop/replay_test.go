package dpop

import (
	"context"
	"testing"
	"time"
)

func TestMemoryReplayGuardFirstUse(t *testing.T) {
	g := NewMemoryReplayGuard()
	fresh, err := g.Remember(context.Background(), "jti-1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Fatal("first use must be reported fresh")
	}
}

func TestMemoryReplayGuardReplay(t *testing.T) {
	g := NewMemoryReplayGuard()
	exp := time.Now().Add(time.Minute)
	if _, err := g.Remember(context.Background(), "jti-1", exp); err != nil {
		t.Fatalf("first Remember: %v", err)
	}
	fresh, err := g.Remember(context.Background(), "jti-1", exp)
	if err != nil {
		t.Fatalf("second Remember: %v", err)
	}
	if fresh {
		t.Fatal("replayed jti must be reported not-fresh")
	}
}

func TestMemoryReplayGuardExpiryReclaims(t *testing.T) {
	now := time.Now()
	g := NewMemoryReplayGuard()
	g.now = func() time.Time { return now }

	// Record jti expiring in the past relative to a later clock read.
	if _, err := g.Remember(context.Background(), "jti-1", now.Add(30*time.Second)); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	// Advance the clock beyond the entry's expiry; the jti may be reused
	// because a proof that old would be rejected as stale anyway.
	now = now.Add(31 * time.Second)
	fresh, err := g.Remember(context.Background(), "jti-1", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Remember after expiry: %v", err)
	}
	if !fresh {
		t.Fatal("expired jti should be reclaimable")
	}
}

func TestMemoryNonceStoreIssueAndValidate(t *testing.T) {
	now := time.Now()
	s := NewMemoryNonceStore(WithNonceClock(func() time.Time { return now }))
	nonce, err := s.Issue(context.Background())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if nonce == "" {
		t.Fatal("empty nonce")
	}
	ok, err := s.Validate(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatal("freshly issued nonce must validate")
	}
}

func TestMemoryNonceStoreSingleUse(t *testing.T) {
	now := time.Now()
	s := NewMemoryNonceStore(WithNonceClock(func() time.Time { return now }))
	nonce, _ := s.Issue(context.Background())

	if ok, _ := s.Validate(context.Background(), nonce); !ok {
		t.Fatal("first validate must succeed")
	}
	if ok, _ := s.Validate(context.Background(), nonce); ok {
		t.Fatal("nonce must be single-use")
	}
}

func TestMemoryNonceStoreExpiry(t *testing.T) {
	now := time.Now()
	s := NewMemoryNonceStore(
		WithNonceTTL(time.Minute),
		WithNonceClock(func() time.Time { return now }),
	)
	nonce, _ := s.Issue(context.Background())

	now = now.Add(2 * time.Minute)
	if ok, _ := s.Validate(context.Background(), nonce); ok {
		t.Fatal("expired nonce must not validate")
	}
}

func TestMemoryNonceStoreRejectsEmpty(t *testing.T) {
	s := NewMemoryNonceStore()
	if ok, _ := s.Validate(context.Background(), ""); ok {
		t.Fatal("empty nonce must never validate")
	}
}

func TestMemoryNonceStoreUniqueNonces(t *testing.T) {
	s := NewMemoryNonceStore()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := s.Issue(context.Background())
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce issued: %q", n)
		}
		seen[n] = true
	}
}
