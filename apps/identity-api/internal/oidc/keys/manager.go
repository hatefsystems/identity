package keys

import (
	"errors"
	"sync"
)

// ErrMissingKeys indicates the manager was constructed or rotated without the
// required key material (active and next must always be present).
var ErrMissingKeys = errors.New("keys: active and next signing keys are required")

// Manager holds the graceful 3-key rotation cycle backing /oauth2/jwks
// (docs/architecture.md "Graceful JWKS Rotation"):
//
//   - active:   currently signing new tokens
//   - next:     pre-generated and published so clients can pre-cache it
//   - previous: recently retired key, kept to verify outstanding unexpired
//     tokens
//
// All methods are safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	active   *SigningKey
	next     *SigningKey
	previous *SigningKey
}

// NewManager builds a Manager from the three rotation slots. active and next
// are mandatory; previous may be nil on a fresh deployment that has never
// rotated.
func NewManager(active, next, previous *SigningKey) (*Manager, error) {
	if active == nil || next == nil {
		return nil, ErrMissingKeys
	}
	return &Manager{active: active, next: next, previous: previous}, nil
}

// Rotate advances the cycle: active becomes previous, next becomes active,
// and newNext takes the next slot. The evicted previous key is dropped.
func (m *Manager) Rotate(newNext *SigningKey) error {
	if newNext == nil {
		return ErrMissingKeys
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.previous = m.active
	m.active = m.next
	m.next = newNext
	return nil
}

// ActiveSigner returns the key currently used to sign new tokens.
func (m *Manager) ActiveSigner() *SigningKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// VerificationKey resolves a key by kid across all slots, returning nil if the
// kid is unknown (e.g. a key evicted more than one rotation ago).
func (m *Manager) VerificationKey(kid string) *SigningKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range []*SigningKey{m.active, m.next, m.previous} {
		if k != nil && k.KID == kid {
			return k
		}
	}
	return nil
}

// JWKSet returns the public JWK set for /oauth2/jwks, ordered active, next,
// previous. Only public parameters are included — the JWK type cannot carry
// private material by construction.
func (m *Manager) JWKSet() JWKSet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := JWKSet{Keys: make([]JWK, 0, 3)}
	for _, k := range []*SigningKey{m.active, m.next, m.previous} {
		if k != nil {
			set.Keys = append(set.Keys, k.PublicJWK)
		}
	}
	return set
}
