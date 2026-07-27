package dpop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// nonceEntropyBytes is the size of a server-issued DPoP nonce before encoding.
// 128 bits is comfortably unguessable and keeps the header compact.
const nonceEntropyBytes = 16

// DefaultNonceTTL bounds the lifetime of a server-issued DPoP-Nonce. It must be
// long enough for a client to complete a request round-trip but short enough
// that a captured nonce is quickly useless.
const DefaultNonceTTL = 5 * time.Minute

// ReplayGuard provides single-use enforcement of DPoP proof jti values. The
// in-memory implementation here backs the single-instance MVP; the interface
// is intentionally identical in shape to clientauth.JTIReplayGuard so a
// Redis-backed guard (key dpop:jti:{jti}, TTL 60s per
// docs/data-architecture.md §3.1) can replace it cluster-wide without touching
// the Validator.
type ReplayGuard interface {
	// Remember records jti as used until expiresAt and reports whether it was
	// previously unseen. It returns false when jti has already been recorded
	// (a replay). expiresAt lets the guard reclaim storage once the proof
	// could no longer be valid anyway.
	Remember(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}

// NonceStore issues and validates the server-supplied DPoP-Nonce values that
// implement the RFC 9449 §8-9 nonce lifecycle. The in-memory implementation
// backs the MVP; a Redis-backed store can replace it for multi-instance
// deployments (a nonce issued by one node must validate on another).
type NonceStore interface {
	// Issue mints a fresh, single-use nonce and records it as currently valid.
	Issue(ctx context.Context) (string, error)
	// Validate reports whether nonce is currently recognized and unexpired.
	// A valid nonce is consumed (single-use) so a captured proof cannot be
	// replayed with the same nonce.
	Validate(ctx context.Context, nonce string) (bool, error)
}

// MemoryReplayGuard is an in-memory, TTL-based ReplayGuard for the MVP. It
// records each proof's jti until the proof's acceptance window passes, at which
// point the entry is eligible for reclamation (a replay after that window would
// already be rejected as stale).
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti -> expiry
	now  func() time.Time
}

// NewMemoryReplayGuard constructs an empty in-memory replay guard.
func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{
		seen: make(map[string]time.Time),
		now:  time.Now,
	}
}

// Remember implements ReplayGuard.
func (g *MemoryReplayGuard) Remember(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
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
func (g *MemoryReplayGuard) evictExpiredLocked(now time.Time) {
	for jti, exp := range g.seen {
		if !exp.After(now) {
			delete(g.seen, jti)
		}
	}
}

// MemoryNonceStore is an in-memory, TTL-based NonceStore for the MVP. Nonces
// are single-use: a successful Validate consumes the nonce so the same proof
// cannot be replayed against it.
type MemoryNonceStore struct {
	mu     sync.Mutex
	issued map[string]time.Time // nonce -> expiry
	ttl    time.Duration
	now    func() time.Time
}

// NonceOption customizes a MemoryNonceStore.
type NonceOption func(*MemoryNonceStore)

// WithNonceTTL overrides the nonce lifetime.
func WithNonceTTL(d time.Duration) NonceOption {
	return func(s *MemoryNonceStore) {
		if d > 0 {
			s.ttl = d
		}
	}
}

// WithNonceClock overrides the time source (tests inject a deterministic clock).
func WithNonceClock(now func() time.Time) NonceOption {
	return func(s *MemoryNonceStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewMemoryNonceStore constructs an empty in-memory nonce store.
func NewMemoryNonceStore(opts ...NonceOption) *MemoryNonceStore {
	s := &MemoryNonceStore{
		issued: make(map[string]time.Time),
		ttl:    DefaultNonceTTL,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Issue implements NonceStore.
func (s *MemoryNonceStore) Issue(_ context.Context) (string, error) {
	buf := make([]byte, nonceEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("dpop: generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictExpiredLocked(now)
	s.issued[nonce] = now.Add(s.ttl)
	return nonce, nil
}

// Validate implements NonceStore. A recognized, unexpired nonce is consumed on
// success (single-use).
func (s *MemoryNonceStore) Validate(_ context.Context, nonce string) (bool, error) {
	if nonce == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.evictExpiredLocked(now)

	exp, ok := s.issued[nonce]
	if !ok || !exp.After(now) {
		return false, nil
	}
	delete(s.issued, nonce)
	return true, nil
}

// evictExpiredLocked drops expired nonces. The caller must hold s.mu.
func (s *MemoryNonceStore) evictExpiredLocked(now time.Time) {
	for nonce, exp := range s.issued {
		if !exp.After(now) {
			delete(s.issued, nonce)
		}
	}
}
