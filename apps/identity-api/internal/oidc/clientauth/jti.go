package clientauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxClientIDBytes   = 256
	maxAudienceBytes   = 2048
	maxJTIBytes        = 256
	maxReplayRetention = 24 * time.Hour
	maxUnixSeconds     = 253402300799
	redisJTIPrefix     = "oidc:clientauth:v1:jti:"
)

var (
	// ErrInvalidReplayParams indicates an invalid replay identity or retention window.
	ErrInvalidReplayParams = errors.New("clientauth: invalid replay parameters")
	// ErrReplayUnavailable indicates failed or malformed shared replay storage.
	ErrReplayUnavailable = errors.New("clientauth: replay storage unavailable")
)

// MemoryJTIGuard is only for explicit local/test construction. It retains each
// scoped assertion until the complete acceptance window ends, including leeway.
type MemoryJTIGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // scoped tuple hash -> exclusive acceptance deadline
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
func (g *MemoryJTIGuard) Remember(ctx context.Context, clientID, audience, jti string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := g.now()
	if _, err := replayTTL(clientID, audience, jti, expiresAt, now); err != nil {
		return false, err
	}
	g.evictExpiredLocked(now)
	key := replayKey(clientID, audience, jti)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if exp, ok := g.seen[key]; ok && exp.After(now) {
		return false, nil
	}
	g.seen[key] = expiresAt
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}

func validReplayPart(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// Length prefixes prevent separator injection; the namespace and hash hide JTIs.
func replayKey(clientID, audience, jti string) string {
	h := sha256.New()
	var size [8]byte
	for _, part := range []string{clientID, audience, jti} {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(part))
	}
	return redisJTIPrefix + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func replayTTL(clientID, audience, jti string, expiresAt, now time.Time) (int64, error) {
	if !validReplayPart(clientID, maxClientIDBytes) || !validReplayPart(audience, maxAudienceBytes) ||
		!validReplayPart(jti, maxJTIBytes) || expiresAt.IsZero() {
		return 0, ErrInvalidReplayParams
	}
	ttl := expiresAt.Sub(now)
	if ttl <= 0 || ttl > maxReplayRetention {
		return 0, ErrInvalidReplayParams
	}
	// Never truncate a sub-millisecond remainder into a shorter Redis lifetime.
	return ttl.Milliseconds() + 1, nil
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
