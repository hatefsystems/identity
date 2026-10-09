package dpop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
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

// ReplayGuard provides single-use enforcement of scoped DPoP proof identifiers.
type ReplayGuard interface {
	// Remember records an opaque realm/key/jti key as used through expiresAt
	// (inclusive) and reports whether it was previously unseen. Expired keys
	// are not accepted. Expiry must cover the complete proof acceptance window.
	Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error)
}

// NonceStore issues and validates the server-supplied DPoP-Nonce values that
// implement the RFC 9449 §8-9 nonce lifecycle. Multi-instance deployments use
// Redis so a nonce issued by one node can be validated by another.
type NonceStore interface {
	// Issue mints a fresh, single-use nonce bound to a nonempty realm and JKT.
	Issue(ctx context.Context, realm, jkt string) (string, error)
	// Validate reports whether nonce is currently recognized and unexpired.
	// A valid nonce is consumed (single-use) so a captured proof cannot be
	// replayed with the same nonce.
	Validate(ctx context.Context, realm, jkt, nonce string) (bool, error)
}

// MemoryReplayGuard is a TTL-based ReplayGuard for tests and local development. It
// records each proof's jti until the proof's acceptance window passes, at which
// point the entry is eligible for reclamation (a replay after that window would
// already be rejected as stale).
type MemoryReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // opaque scoped key -> inclusive expiry
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
func (g *MemoryReplayGuard) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" || expiresAt.IsZero() {
		return false, ErrInvalidParams
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}

	now := g.now()
	g.evictExpiredLocked(now)
	if expiresAt.Before(now) {
		return false, nil
	}

	if exp, ok := g.seen[key]; ok && !exp.Before(now) {
		return false, nil
	}
	g.seen[key] = expiresAt
	return true, nil
}

// evictExpiredLocked drops entries whose expiry has passed so the map does not
// grow without bound. The caller must hold g.mu.
func (g *MemoryReplayGuard) evictExpiredLocked(now time.Time) {
	for key, exp := range g.seen {
		if exp.Before(now) {
			delete(g.seen, key)
		}
	}
}

// MemoryNonceStore is a TTL-based NonceStore for tests and local development. Nonces
// are single-use: a successful Validate consumes the nonce so the same proof
// cannot be replayed against it.
type MemoryNonceStore struct {
	mu     sync.Mutex
	issued map[string]time.Time // hash(realm, jkt, nonce) -> expiry
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
func (s *MemoryNonceStore) Issue(ctx context.Context, realm, jkt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(jkt) == "" {
		return "", ErrInvalidParams
	}
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	now := s.now()
	s.evictExpiredLocked(now)
	s.issued[stateKey("", realm, jkt, nonce)] = now.Add(s.ttl)
	return nonce, nil
}

// Validate implements NonceStore. A recognized, unexpired nonce is consumed on
// success (single-use).
func (s *MemoryNonceStore) Validate(ctx context.Context, realm, jkt, nonce string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(jkt) == "" {
		return false, ErrInvalidParams
	}
	if nonce == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}

	now := s.now()
	s.evictExpiredLocked(now)

	key := stateKey("", realm, jkt, nonce)
	exp, ok := s.issued[key]
	if !ok || !exp.After(now) {
		return false, nil
	}
	delete(s.issued, key)
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

// Length-prefix each component so client-controlled identifiers cannot collide
// across scopes by embedding a separator. Neither nonces nor JTIs reach keys.
func stateKey(prefix string, parts ...string) string {
	h := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return prefix + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func newNonce() (string, error) {
	var buf [nonceEntropyBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func stateStoreError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}
