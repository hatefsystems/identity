package stepup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var testReplayHMACKey = []byte("0123456789abcdef0123456789abcdef")

var replayTestNow = time.Date(2025, time.January, 15, 12, 0, 0, 0, time.UTC)

func newTestRedisReplayGuard(t *testing.T) (*RedisReplayGuard, *miniredis.Miniredis, *redis.Client) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	guard, err := NewRedisReplayGuard(client, testReplayHMACKey)
	if err != nil {
		t.Fatalf("NewRedisReplayGuard: %v", err)
	}
	return guard, mr, client
}

func TestMemoryReplayGuardRemembersOnce(t *testing.T) {
	guard := NewMemoryReplayGuard()
	now := replayTestNow
	guard.now = func() time.Time { return now }

	ctx := context.Background()
	expiry := now.Add(5 * time.Minute)

	fresh, err := guard.Remember(ctx, "stepup:jti:a", expiry)
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Fatal("the first sighting of a key must report fresh")
	}

	fresh, err = guard.Remember(ctx, "stepup:jti:a", expiry)
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if fresh {
		t.Fatal("a repeated key must report as already seen")
	}
}

func TestMemoryReplayGuardKeysAreIndependent(t *testing.T) {
	guard := NewMemoryReplayGuard()
	guard.now = func() time.Time { return replayTestNow }

	ctx := context.Background()
	expiry := replayTestNow.Add(time.Minute)

	for _, key := range []string{"stepup:jti:a", "stepup:jti:b", "stepup:totp:user:hash"} {
		fresh, err := guard.Remember(ctx, key, expiry)
		if err != nil {
			t.Fatalf("Remember(%s): %v", key, err)
		}
		if !fresh {
			t.Fatalf("key %s collided with an unrelated entry", key)
		}
	}
}

// TestMemoryReplayGuardReclaimsExpiredEntries confirms a key becomes reusable
// once it could no longer be accepted anyway, which is what bounds the map.
func TestMemoryReplayGuardReclaimsExpiredEntries(t *testing.T) {
	guard := NewMemoryReplayGuard()
	now := replayTestNow
	guard.now = func() time.Time { return now }

	ctx := context.Background()
	if _, err := guard.Remember(ctx, "stepup:jti:a", now.Add(time.Minute)); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	// Past the entry's expiry the record is dropped: a grant with that jti is
	// rejected on its exp claim long before it reaches the guard, so holding the
	// entry forever would only leak memory.
	now = now.Add(2 * time.Minute)
	fresh, err := guard.Remember(ctx, "stepup:jti:a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if !fresh {
		t.Fatal("an entry past its expiry should have been reclaimed")
	}
	if len(guard.seen) != 1 {
		t.Fatalf("expected the expired entry to be swept, %d entries remain", len(guard.seen))
	}
}

func TestMemoryReplayGuardIsConcurrencySafe(t *testing.T) {
	guard := NewMemoryReplayGuard()
	ctx := context.Background()
	expiry := time.Now().Add(time.Minute)

	const workers = 32
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		go func() {
			fresh, err := guard.Remember(ctx, "stepup:jti:contended", expiry)
			if err != nil {
				results <- false
				return
			}
			results <- fresh
		}()
	}

	freshCount := 0
	for i := 0; i < workers; i++ {
		if <-results {
			freshCount++
		}
	}
	// Exactly one racer may win; anything else means a grant could be spent twice
	// under concurrency.
	if freshCount != 1 {
		t.Fatalf("expected exactly one winner, got %d", freshCount)
	}
}

func TestNewRedisReplayGuardValidatesDependencies(t *testing.T) {
	if _, err := NewRedisReplayGuard(nil, testReplayHMACKey); err == nil {
		t.Fatal("expected a nil Redis client to be rejected")
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	if _, err := NewRedisReplayGuard(client, make([]byte, MinReplayHMACKeyBytes-1)); err == nil {
		t.Fatal("expected a short replay HMAC key to be rejected")
	}
}

func TestNewRedisReplayGuardCopiesHMACKey(t *testing.T) {
	_, mr, _ := newTestRedisReplayGuard(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })

	key := append([]byte(nil), testReplayHMACKey...)
	guard, err := NewRedisReplayGuard(client, key)
	if err != nil {
		t.Fatalf("NewRedisReplayGuard: %v", err)
	}
	before := guard.storageKey("stepup:jti:stable")
	key[0] ^= 0xff
	if after := guard.storageKey("stepup:jti:stable"); after != before {
		t.Fatal("mutating the constructor input changed replay-key identity")
	}
}

func TestRedisReplayGuardUsesAtomicSetNX(t *testing.T) {
	guard, _, _ := newTestRedisReplayGuard(t)
	guard.now = func() time.Time { return replayTestNow }

	ctx := context.Background()
	expiresAt := replayTestNow.Add(5 * time.Minute)

	fresh, err := guard.Remember(ctx, "stepup:jti:shared", expiresAt)
	if err != nil {
		t.Fatalf("first Remember: %v", err)
	}
	if !fresh {
		t.Fatal("first Redis claim must be fresh")
	}

	fresh, err = guard.Remember(ctx, "stepup:jti:shared", expiresAt)
	if err != nil {
		t.Fatalf("second Remember: %v", err)
	}
	if fresh {
		t.Fatal("SET NX must reject a repeated Redis claim")
	}
}

func TestRedisReplayGuardHMACsLogicalKeys(t *testing.T) {
	guard, mr, _ := newTestRedisReplayGuard(t)
	guard.now = func() time.Time { return replayTestNow }

	logicalKey := "stepup:totp:550e8400-e29b-41d4-a716-446655440000:123456"
	if fresh, err := guard.Remember(context.Background(), logicalKey, replayTestNow.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("Remember = (%v, %v), want (true, nil)", fresh, err)
	}

	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("Redis contains %d keys, want 1", len(keys))
	}
	if strings.Contains(keys[0], logicalKey) || strings.Contains(keys[0], "123456") {
		t.Fatalf("Redis key leaks its logical replay value: %q", keys[0])
	}

	mac := hmac.New(sha256.New, testReplayHMACKey)
	_, _ = mac.Write([]byte(logicalKey))
	want := redisReplayKeyPrefix + hex.EncodeToString(mac.Sum(nil))
	if keys[0] != want {
		t.Fatalf("Redis key = %q, want deterministic HMAC key %q", keys[0], want)
	}
}

func TestRedisReplayGuardAppliesExpiryTTL(t *testing.T) {
	guard, mr, _ := newTestRedisReplayGuard(t)
	now := replayTestNow
	guard.now = func() time.Time { return now }

	const logicalKey = "stepup:jti:expiring"
	expiresAt := now.Add(90 * time.Second)
	if fresh, err := guard.Remember(context.Background(), logicalKey, expiresAt); err != nil || !fresh {
		t.Fatalf("Remember = (%v, %v), want (true, nil)", fresh, err)
	}
	if got := mr.TTL(guard.storageKey(logicalKey)); got != 90*time.Second {
		t.Fatalf("Redis TTL = %v, want 90s", got)
	}

	mr.FastForward(91 * time.Second)
	now = now.Add(91 * time.Second)
	if fresh, err := guard.Remember(context.Background(), logicalKey, now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("Remember after expiry = (%v, %v), want reusable key", fresh, err)
	}
}

func TestRedisReplayGuardRejectsInvalidExpiryWithoutWriting(t *testing.T) {
	guard, mr, _ := newTestRedisReplayGuard(t)
	guard.now = func() time.Time { return replayTestNow }

	fresh, err := guard.Remember(context.Background(), "stepup:jti:expired", replayTestNow)
	if err == nil {
		t.Fatal("expected a non-future expiry to fail")
	}
	if fresh {
		t.Fatal("an invalid expiry must fail closed")
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("invalid expiry wrote Redis keys: %v", keys)
	}
}

func TestRedisReplayGuardFailsClosedWhenRedisIsUnavailable(t *testing.T) {
	guard, mr, _ := newTestRedisReplayGuard(t)
	guard.now = func() time.Time { return replayTestNow }
	mr.Close()

	fresh, err := guard.Remember(context.Background(), "stepup:jti:outage", replayTestNow.Add(time.Minute))
	if err == nil {
		t.Fatal("expected Redis outage to be returned")
	}
	if fresh {
		t.Fatal("Redis outage must never be reported as a fresh claim")
	}
}

func TestRedisReplayGuardIsClusterConcurrencySafe(t *testing.T) {
	guard, mr, _ := newTestRedisReplayGuard(t)
	guard.now = func() time.Time { return replayTestNow }

	// A separate client models a second application instance sharing only the
	// Redis deployment and HMAC key with the first.
	secondClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = secondClient.Close() })
	secondGuard, err := NewRedisReplayGuard(secondClient, testReplayHMACKey)
	if err != nil {
		t.Fatalf("NewRedisReplayGuard(second): %v", err)
	}
	secondGuard.now = func() time.Time { return replayTestNow }

	const workers = 32
	results := make(chan bool, workers)
	for i := 0; i < workers; i++ {
		candidate := guard
		if i%2 == 1 {
			candidate = secondGuard
		}
		go func(g *RedisReplayGuard) {
			fresh, err := g.Remember(
				context.Background(), "stepup:jti:cluster-contended", replayTestNow.Add(time.Minute))
			results <- err == nil && fresh
		}(candidate)
	}

	freshCount := 0
	for i := 0; i < workers; i++ {
		if <-results {
			freshCount++
		}
	}
	if freshCount != 1 {
		t.Fatalf("expected exactly one cluster-wide SET NX winner, got %d", freshCount)
	}
}
