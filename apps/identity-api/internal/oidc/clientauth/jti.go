package clientauth

import (
	"context"
	"sync"
	"time"
)

// MemoryJTIGuard is an in-memory, TTL-based JTIReplayGuard suitable for a
// single-instance MVP. It records each assertion's jti until the assertion's
// exp passes, at which point the entry is eligible for reclamation (a replay
// after exp would already be rejected as expired). For a multi-instance
// deployment this is replaced by a Redis-backed guard implementing the same
// interface so single-use is enforced cluster-wide.
type MemoryJTIGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
	now  func() time.Time
}

// NewMemoryJTIGuard constructs an empty in-memory guard.
func NewMemoryJTIGuard() *MemoryJTIGuard {
	return &MemoryJTIGuard{
		seen: make(map[string]time.Time),
		now:  time.Now,
	}
}

// Remember implements JTIReplayGuard. It records jti until expiresAt and
// returns true when jti was previously unseen (or its prior record has already
// expired), or false when jti is currently recorded — a replay.
func (g *MemoryJTIGuard) Remember(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	g.evictExpiredLocked(now)

	if exp, ok := g.seen[jti]; ok && exp.After(now) {
		return false, nil
	}
	g.seen[jti] = expiresAt
	return true, nil
}

// evictExpiredLocked drops entries whose expiry has passed so the map does not
// grow without bound. The caller must hold g.mu.
func (g *MemoryJTIGuard) evictExpiredLocked(now time.Time) {
	for jti, exp := range g.seen {
		if !exp.After(now) {
			delete(g.seen, jti)
		}
	}
}
