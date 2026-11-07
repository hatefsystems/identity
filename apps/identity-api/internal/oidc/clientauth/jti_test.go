package clientauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemoryJTIGuardFirstUseSucceeds(t *testing.T) {
	g := NewMemoryJTIGuard()
	fresh, err := g.Remember(context.Background(), testClientID, testAudience, "abc", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Error("first use of a jti must report fresh")
	}
}

func TestMemoryJTIGuardReplayRejected(t *testing.T) {
	g := NewMemoryJTIGuard()
	exp := time.Now().Add(time.Minute)
	if fresh, _ := g.Remember(context.Background(), testClientID, testAudience, "abc", exp); !fresh {
		t.Fatal("first use should be fresh")
	}
	fresh, err := g.Remember(context.Background(), testClientID, testAudience, "abc", exp)
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if fresh {
		t.Error("replayed jti must not report fresh")
	}
}

func TestMemoryJTIGuardExpiredEntryReusable(t *testing.T) {
	g := NewMemoryJTIGuard()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return base }

	// Record with a short expiry.
	if fresh, _ := g.Remember(context.Background(), testClientID, testAudience, "abc", base.Add(time.Second)); !fresh {
		t.Fatal("first use should be fresh")
	}

	// Advance beyond expiry: the same jti is now reusable (a replay would
	// anyway be rejected as an expired assertion upstream).
	g.now = func() time.Time { return base.Add(2 * time.Second) }
	fresh, err := g.Remember(context.Background(), testClientID, testAudience, "abc", base.Add(3*time.Second))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Error("expired jti entry should be reclaimable")
	}
}

func TestMemoryJTIGuardDistinctJTIs(t *testing.T) {
	g := NewMemoryJTIGuard()
	exp := time.Now().Add(time.Minute)
	if fresh, _ := g.Remember(context.Background(), testClientID, testAudience, "a", exp); !fresh {
		t.Error("jti a should be fresh")
	}
	if fresh, _ := g.Remember(context.Background(), testClientID, testAudience, "b", exp); !fresh {
		t.Error("jti b should be fresh")
	}
}

func TestMemoryJTIGuardScopedConcurrentClaims(t *testing.T) {
	g := NewMemoryJTIGuard()
	exp := time.Now().Add(time.Minute)
	results := make(chan bool, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := g.Remember(t.Context(), testClientID, testAudience, "shared", exp)
			if err != nil {
				t.Error(err)
			}
			results <- fresh
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for fresh := range results {
		if fresh {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d", winners)
	}
	for _, scope := range [][3]string{{"other", testAudience, "shared"}, {testClientID, "other", "shared"}, {testClientID, testAudience, "other"}} {
		if fresh, err := g.Remember(t.Context(), scope[0], scope[1], scope[2], exp); !fresh || err != nil {
			t.Fatalf("independent scope = %v, %v", fresh, err)
		}
	}
	if replayKey("a:b", "c", "d") == replayKey("a", "b:c", "d") ||
		replayKey("a", "b", "c:d") == replayKey("a", "b:c", "d") {
		t.Fatal("separator injection collided")
	}
}

func TestReplayTTLAndMemoryFailClosed(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, delta := range []time.Duration{time.Nanosecond, time.Millisecond, time.Millisecond + time.Nanosecond, time.Second} {
		ttl, err := replayTTL("client", "aud", "jti", now.Add(delta), now)
		if err != nil || time.Duration(ttl)*time.Millisecond <= delta {
			t.Fatalf("rounded TTL for %s = %d, %v", delta, ttl, err)
		}
	}
	g := NewMemoryJTIGuard()
	g.now = func() time.Time { return now }
	for _, tc := range []struct {
		client, audience, jti string
		exp                   time.Time
	}{
		{"", "aud", "jti", now.Add(time.Minute)},
		{"client", "", "jti", now.Add(time.Minute)},
		{"client", "aud", "", now.Add(time.Minute)},
		{strings.Repeat("c", maxClientIDBytes+1), "aud", "jti", now.Add(time.Minute)},
		{"client", strings.Repeat("a", maxAudienceBytes+1), "jti", now.Add(time.Minute)},
		{"client", "aud", strings.Repeat("j", maxJTIBytes+1), now.Add(time.Minute)},
		{"client", "aud", "\x00", now.Add(time.Minute)},
		{"client", "aud", "\xff", now.Add(time.Minute)},
		{"client", "aud", "jti", time.Time{}},
		{"client", "aud", "jti", now},
		{"client", "aud", "jti", now.Add(-time.Second)},
		{"client", "aud", "jti", now.Add(maxReplayRetention + time.Nanosecond)},
	} {
		if fresh, err := g.Remember(t.Context(), tc.client, tc.audience, tc.jti, tc.exp); fresh || !errors.Is(err, ErrInvalidReplayParams) {
			t.Fatalf("invalid input accepted: %v, %v", fresh, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if fresh, err := g.Remember(ctx, "client", "aud", "jti", now.Add(time.Minute)); fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled claim = %v, %v", fresh, err)
	}
	if len(g.seen) != 0 {
		t.Fatal("invalid claims changed state")
	}
	ctx, cancel = context.WithCancel(t.Context())
	g.now = func() time.Time { cancel(); return now }
	if fresh, err := g.Remember(ctx, "client", "aud", "jti", now.Add(time.Minute)); fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during claim = %v, %v", fresh, err)
	}
	if len(g.seen) != 0 {
		t.Fatal("cancelled claim stored authority")
	}
}
