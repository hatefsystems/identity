package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// testClock is a manually-advanced clock. The sliding-window Lua script scores
// entries by the timestamp the limiter passes in ARGV (not by Redis's own
// clock), so a test that wants to slide the window forward deterministically has
// to advance the limiter's clock, not just miniredis's TTL clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestLimiter spins up an in-process miniredis and returns a RedisLimiter
// wired to it, running the REAL sliding-window Lua script via EVAL/EVALSHA. The
// returned miniredis handle lets a test advance the simulated clock with
// FastForward to exercise key-TTL expiry deterministically.
func newTestLimiter(t *testing.T) (*RedisLimiter, *miniredis.Miniredis, *redis.Client) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	limiter, err := NewRedisLimiter(client)
	if err != nil {
		t.Fatalf("NewRedisLimiter: %v", err)
	}
	return limiter, mr, client
}

func TestNewRedisLimiterRejectsNilClient(t *testing.T) {
	if _, err := NewRedisLimiter(nil); err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}

func TestAllowAdmitsUpToLimitThenRejects(t *testing.T) {
	limiter, _, _ := newTestLimiter(t)
	ctx := context.Background()

	const limit = 3
	for i := 0; i < limit; i++ {
		ok, err := limiter.Allow(ctx, "rate:test:phone", limit, time.Minute)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !ok {
			t.Fatalf("Allow #%d: expected admitted within limit, got rejected", i)
		}
	}

	// The (limit+1)-th request within the window must be rejected.
	ok, err := limiter.Allow(ctx, "rate:test:phone", limit, time.Minute)
	if err != nil {
		t.Fatalf("Allow over limit: %v", err)
	}
	if ok {
		t.Fatal("expected rejection once the window is saturated, got admitted")
	}
}

func TestAllowKeysAreIndependent(t *testing.T) {
	limiter, _, _ := newTestLimiter(t)
	ctx := context.Background()

	// Saturating one key must not consume another key's budget: this is what
	// keeps the per-phone and per-subnet dimensions independent.
	ok, err := limiter.Allow(ctx, "rate:test:a", 1, time.Minute)
	if err != nil || !ok {
		t.Fatalf("first key first call: ok=%v err=%v", ok, err)
	}
	ok, err = limiter.Allow(ctx, "rate:test:a", 1, time.Minute)
	if err != nil {
		t.Fatalf("first key second call: %v", err)
	}
	if ok {
		t.Fatal("first key should be saturated at limit 1")
	}

	ok, err = limiter.Allow(ctx, "rate:test:b", 1, time.Minute)
	if err != nil {
		t.Fatalf("second key first call: %v", err)
	}
	if !ok {
		t.Fatal("second, independent key should still have capacity")
	}
}

func TestAllowWindowSlides(t *testing.T) {
	limiter, mr, _ := newTestLimiter(t)
	ctx := context.Background()

	// Drive the limiter from a manual clock so the timestamps it writes into
	// the ZSET (via ARGV) advance in lock-step with what we assert below. The
	// script evicts entries older than now-window, so sliding the clock is what
	// actually frees the saturated slot.
	clock := newTestClock()
	limiter.now = clock.Now

	// Saturate a 1/second window.
	ok, err := limiter.Allow(ctx, "rate:test:slide", 1, time.Second)
	if err != nil || !ok {
		t.Fatalf("first call: ok=%v err=%v", ok, err)
	}
	ok, err = limiter.Allow(ctx, "rate:test:slide", 1, time.Second)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if ok {
		t.Fatal("expected rejection while the 1s window is saturated")
	}

	// Advance past the window on both clocks: the limiter's clock so the new
	// request's now-window cursor moves beyond the earlier entry (evicting it
	// via ZREMRANGEBYSCORE), and miniredis's so the key TTL tracks along.
	clock.Advance(2 * time.Second)
	mr.FastForward(2 * time.Second)

	ok, err = limiter.Allow(ctx, "rate:test:slide", 1, time.Second)
	if err != nil {
		t.Fatalf("post-slide call: %v", err)
	}
	if !ok {
		t.Fatal("expected capacity to free up after the window slid forward")
	}
}

func TestAllowSetsKeyExpiry(t *testing.T) {
	limiter, mr, _ := newTestLimiter(t)
	ctx := context.Background()

	window := time.Minute
	if _, err := limiter.Allow(ctx, "rate:test:ttl", 5, window); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	ttl := mr.TTL("rate:test:ttl")
	if ttl <= 0 || ttl > window {
		t.Fatalf("expected key TTL to match window duration (~%v), got %v", window, ttl)
	}
}

func TestAllowNonPositiveLimitRejects(t *testing.T) {
	limiter, _, _ := newTestLimiter(t)
	ctx := context.Background()

	ok, err := limiter.Allow(ctx, "rate:test:zero", 0, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if ok {
		t.Fatal("a non-positive limit must reject (fail closed)")
	}
}

// TestAllowFallsBackToEvalOnNoScript exercises the EVALSHA->EVAL recovery path:
// after flushing the script cache the cached SHA is stale, so the limiter must
// transparently reload and still admit the request.
func TestAllowFallsBackToEvalOnNoScript(t *testing.T) {
	limiter, _, client := newTestLimiter(t)
	ctx := context.Background()

	if err := client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("ScriptFlush: %v", err)
	}

	ok, err := limiter.Allow(ctx, "rate:test:noscript", 2, time.Minute)
	if err != nil {
		t.Fatalf("Allow after script flush: %v", err)
	}
	if !ok {
		t.Fatal("expected the request to be admitted via the EVAL fallback")
	}
}
