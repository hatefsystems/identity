package stepup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// MinReplayHMACKeyBytes is the minimum secret-key length accepted by the
	// distributed replay guard. A 32-byte key provides the full security level
	// of HMAC-SHA-256 and matches the project's other server-side peppers.
	MinReplayHMACKeyBytes = 32

	redisReplayKeyPrefix = "stepup:replay:v1:"
)

// ReplayGuard provides single-use enforcement for the values a grant must only
// ever redeem once: the grant's own jti, and a submitted TOTP passcode inside
// its acceptance window.
//
// The interface is intentionally the same shape as dpop.ReplayGuard and
// clientauth.JTIReplayGuard so a Redis-backed guard can replace the in-memory
// implementation cluster-wide without touching the Service or middleware. The
// Redis implementation stores an opaque HMAC key with a TTL equal to the
// logical value's remaining acceptance lifetime.
//
// Callers namespace their own keys (see jtiGuardKey and totpGuardKey) so the two
// uses cannot collide.
type ReplayGuard interface {
	// Remember records key as used until expiresAt and reports whether it was
	// previously unseen. It returns false when key has already been recorded.
	// expiresAt lets the guard reclaim storage once the value could no longer be
	// accepted anyway.
	Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error)
}

// MemoryReplayGuard is a development/test-only TTL-based guard. Consumption is
// process-local, so production wiring always uses RedisReplayGuard.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // key -> expiry
	now  func() time.Time
}

// ReplayOption customizes a MemoryReplayGuard.
type ReplayOption func(*MemoryReplayGuard)

// WithReplayClock overrides the guard's time source.
//
// Expiry here is compared against instants supplied by the caller, which are
// derived from the Service's clock. In production both are time.Now, but a test
// that moves the Service's clock must move the guard's too or the two disagree
// about whether an entry is still live. Mirrors dpop.WithNonceClock.
func WithReplayClock(now func() time.Time) ReplayOption {
	return func(g *MemoryReplayGuard) {
		if now != nil {
			g.now = now
		}
	}
}

// NewMemoryReplayGuard constructs an empty in-memory replay guard.
func NewMemoryReplayGuard(opts ...ReplayOption) *MemoryReplayGuard {
	g := &MemoryReplayGuard{
		seen: make(map[string]time.Time),
		now:  time.Now,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Remember implements ReplayGuard.
func (g *MemoryReplayGuard) Remember(_ context.Context, key string, expiresAt time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	g.evictExpiredLocked(now)

	if exp, ok := g.seen[key]; ok && exp.After(now) {
		return false, nil
	}
	g.seen[key] = expiresAt
	return true, nil
}

// evictExpiredLocked drops entries whose expiry has passed so the map does not
// grow without bound. The caller must hold g.mu.
func (g *MemoryReplayGuard) evictExpiredLocked(now time.Time) {
	for key, exp := range g.seen {
		if !exp.After(now) {
			delete(g.seen, key)
		}
	}
}

// RedisReplayGuard provides cluster-wide single-use enforcement. Each logical
// replay value is converted to a deterministic HMAC-SHA-256 identifier before
// it reaches Redis. This prevents a Redis keyspace listing from exposing grant
// JTIs or from enabling an offline brute-force search over the six-digit TOTP
// space.
//
// Every application instance must use the same HMAC key. Remember uses Redis
// SET NX with the remaining acceptance lifetime as the key TTL, so exactly one
// concurrent claimant succeeds across the cluster. Redis failures are returned
// with fresh=false; callers must treat that result as a closed failure.
type RedisReplayGuard struct {
	client  *redis.Client
	hmacKey []byte
	now     func() time.Time
}

// NewRedisReplayGuard constructs a distributed replay guard. hmacKey is copied
// so later mutation of the caller's buffer cannot silently change replay-key
// identity between requests.
func NewRedisReplayGuard(client *redis.Client, hmacKey []byte) (*RedisReplayGuard, error) {
	if client == nil {
		return nil, errors.New("stepup: redis client is required for replay protection")
	}
	if len(hmacKey) < MinReplayHMACKeyBytes {
		return nil, fmt.Errorf(
			"stepup: replay HMAC key must be at least %d bytes, got %d",
			MinReplayHMACKeyBytes, len(hmacKey))
	}
	return &RedisReplayGuard{
		client:  client,
		hmacKey: append([]byte(nil), hmacKey...),
		now:     time.Now,
	}, nil
}

// Remember implements ReplayGuard with an atomic SET NX claim and TTL.
func (g *RedisReplayGuard) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if key == "" {
		return false, errors.New("stepup: replay key is required")
	}

	ttl := expiresAt.Sub(g.now())
	if ttl <= 0 {
		return false, fmt.Errorf("stepup: replay expiry must be in the future, got %v", expiresAt)
	}

	fresh, err := g.client.SetNX(ctx, g.storageKey(key), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("stepup: claim replay key in Redis: %w", err)
	}
	return fresh, nil
}

// storageKey returns a versioned, fixed-length Redis key derived from the
// logical replay identity. The logical value itself is never stored in Redis.
func (g *RedisReplayGuard) storageKey(key string) string {
	mac := hmac.New(sha256.New, g.hmacKey)
	_, _ = mac.Write([]byte(key))
	return redisReplayKeyPrefix + hex.EncodeToString(mac.Sum(nil))
}
