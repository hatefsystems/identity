package dpop

import (
	"context"
	"errors"
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
	nonce, err := s.Issue(context.Background(), testRealm, testStoreJKT)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if nonce == "" {
		t.Fatal("empty nonce")
	}
	ok, err := s.Validate(context.Background(), testRealm, testStoreJKT, nonce)
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
	nonce, _ := s.Issue(context.Background(), testRealm, testStoreJKT)

	if ok, _ := s.Validate(context.Background(), testRealm, testStoreJKT, nonce); !ok {
		t.Fatal("first validate must succeed")
	}
	if ok, _ := s.Validate(context.Background(), testRealm, testStoreJKT, nonce); ok {
		t.Fatal("nonce must be single-use")
	}
}

func TestMemoryNonceStoreExpiry(t *testing.T) {
	now := time.Now()
	s := NewMemoryNonceStore(
		WithNonceTTL(time.Minute),
		WithNonceClock(func() time.Time { return now }),
	)
	nonce, _ := s.Issue(context.Background(), testRealm, testStoreJKT)

	now = now.Add(2 * time.Minute)
	if ok, _ := s.Validate(context.Background(), testRealm, testStoreJKT, nonce); ok {
		t.Fatal("expired nonce must not validate")
	}
}

func TestMemoryNonceStoreRejectsEmpty(t *testing.T) {
	s := NewMemoryNonceStore()
	if ok, _ := s.Validate(context.Background(), testRealm, testStoreJKT, ""); ok {
		t.Fatal("empty nonce must never validate")
	}
}

func TestMemoryNonceStoreUniqueNonces(t *testing.T) {
	s := NewMemoryNonceStore()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := s.Issue(context.Background(), testRealm, testStoreJKT)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce issued: %q", n)
		}
		seen[n] = true
	}
}

func TestMemoryNonceStoreScopeAndDefaultExpiry(t *testing.T) {
	now := time.Now()
	s := NewMemoryNonceStore(WithNonceClock(func() time.Time { return now }))
	nonce, err := s.Issue(context.Background(), testRealm, testStoreJKT)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range [][2]string{{"other-realm", testStoreJKT}, {testRealm, "other-key"}} {
		if ok, err := s.Validate(context.Background(), scope[0], scope[1], nonce); ok || err != nil {
			t.Fatalf("wrong scope = %v, %v", ok, err)
		}
	}
	for key := range s.issued {
		if key == nonce || len(key) != 43 {
			t.Fatalf("nonce key is not an opaque hash: %q", key)
		}
	}
	now = now.Add(DefaultNonceTTL - time.Nanosecond)
	if ok, err := s.Validate(context.Background(), testRealm, testStoreJKT, nonce); !ok || err != nil {
		t.Fatalf("nonce before default expiry = %v, %v", ok, err)
	}
	nonce, err = s.Issue(context.Background(), testRealm, testStoreJKT)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultNonceTTL)
	if ok, err := s.Validate(context.Background(), testRealm, testStoreJKT, nonce); ok || err != nil {
		t.Fatalf("nonce at default expiry = %v, %v", ok, err)
	}
}

func TestMemoryStoresHonorCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nonces := NewMemoryNonceStore()
	nonce, err := nonces.Issue(context.Background(), testRealm, testStoreJKT)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := nonces.Issue(ctx, testRealm, testStoreJKT); value != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Issue = %q, %v", value, err)
	}
	if ok, err := nonces.Validate(ctx, testRealm, testStoreJKT, nonce); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Validate = %v, %v", ok, err)
	}
	if ok, err := nonces.Validate(context.Background(), testRealm, testStoreJKT, nonce); !ok || err != nil {
		t.Fatalf("canceled validation consumed nonce: %v, %v", ok, err)
	}
	guard := NewMemoryReplayGuard()
	if ok, err := guard.Remember(ctx, "key", time.Now().Add(time.Minute)); ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Remember = %v, %v", ok, err)
	}
	if len(guard.seen) != 0 {
		t.Fatal("canceled Remember changed replay state")
	}
}

func TestMemoryStoresRejectInvalidParams(t *testing.T) {
	nonces := NewMemoryNonceStore()
	for _, scope := range [][2]string{{"", testStoreJKT}, {testRealm, ""}, {" ", testStoreJKT}} {
		if _, err := nonces.Issue(context.Background(), scope[0], scope[1]); err != ErrInvalidParams {
			t.Fatalf("invalid issue scope: %v", err)
		}
		if _, err := nonces.Validate(context.Background(), scope[0], scope[1], "nonce"); err != ErrInvalidParams {
			t.Fatalf("invalid validation scope: %v", err)
		}
	}
	guard := NewMemoryReplayGuard()
	if _, err := guard.Remember(context.Background(), "", time.Now().Add(time.Minute)); err != ErrInvalidParams {
		t.Fatalf("missing replay key: %v", err)
	}
	if _, err := guard.Remember(context.Background(), "key", time.Time{}); err != ErrInvalidParams {
		t.Fatalf("missing replay expiry: %v", err)
	}
	if ok, err := guard.Remember(context.Background(), "key", time.Now().Add(-time.Second)); ok || err != nil {
		t.Fatalf("expired replay claim = %v, %v", ok, err)
	}
	if len(guard.seen) != 0 || len(nonces.issued) != 0 {
		t.Fatal("invalid parameters wrote state")
	}
}

func TestStateKeysAreUnambiguous(t *testing.T) {
	if stateKey("", "ab", "c") == stateKey("", "a", "bc") ||
		stateKey("", "a\x00b", "c") == stateKey("", "a", "b\x00c") {
		t.Fatal("scope components collide across boundaries")
	}
}
