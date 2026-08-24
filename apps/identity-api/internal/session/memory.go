package session

import (
	"sort"
	"sync"
	"time"
)

// MemoryStore is a thread-safe, in-memory Store for the single-node MVP. It
// keeps sessions in a map keyed by token hash, plus a secondary index by user
// id for O(user) listing and bulk revocation (the same technique used by
// token.MemoryRefreshTokenStore). Expiry is enforced lazily on read, mirroring
// Redis TTL semantics; the Redis-backed Store replaces it when Redis wiring
// lands.
type MemoryStore struct {
	mu sync.Mutex
	// byHash maps the SHA-256 token hash to the stored session.
	byHash map[string]Session
	// byUser indexes token hashes per user id for listing and bulk revocation.
	byUser map[string]map[string]struct{}
	// now is injectable so expiry behavior is deterministic in tests.
	now func() time.Time
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byHash: make(map[string]Session),
		byUser: make(map[string]map[string]struct{}),
		now:    time.Now,
	}
}

// expired reports whether s has lapsed at instant t, by either the idle or the
// absolute deadline.
func expired(s Session, t time.Time) bool {
	return t.After(s.AbsoluteExpiry) || t.After(s.IdleExpiry)
}

// Create implements Store.
func (m *MemoryStore) Create(tokenHash string, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byHash[tokenHash] = s
	set, ok := m.byUser[s.UserID]
	if !ok {
		set = make(map[string]struct{})
		m.byUser[s.UserID] = set
	}
	set[tokenHash] = struct{}{}
	return nil
}

// Get implements Store. An expired session is deleted and reported as
// ErrSessionNotFound so a lapsed token behaves exactly like an unknown one.
func (m *MemoryStore) Get(tokenHash string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byHash[tokenHash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if expired(s, m.now()) {
		m.deleteLocked(tokenHash, s.UserID)
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

// Touch implements Store.
func (m *MemoryStore) Touch(tokenHash string, idleExpiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byHash[tokenHash]
	if !ok {
		return ErrSessionNotFound
	}
	if expired(s, m.now()) {
		m.deleteLocked(tokenHash, s.UserID)
		return ErrSessionNotFound
	}
	s.IdleExpiry = idleExpiry
	s.LastSeenAt = m.now()
	m.byHash[tokenHash] = s
	return nil
}

// Delete implements Store. Removing an unknown session is not an error.
func (m *MemoryStore) Delete(tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byHash[tokenHash]; ok {
		m.deleteLocked(tokenHash, s.UserID)
	}
	return nil
}

// ListForUser implements Store, returning live sessions newest-first and
// reclaiming any expired entries encountered along the way.
func (m *MemoryStore) ListForUser(userID string) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var out []Session
	for hash := range m.byUser[userID] {
		s, ok := m.byHash[hash]
		if !ok {
			continue
		}
		if expired(s, now) {
			m.deleteLocked(hash, userID)
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// DeleteForUser implements Store. It removes the session with the given public
// ID only when it belongs to userID.
func (m *MemoryStore) DeleteForUser(userID, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash := range m.byUser[userID] {
		s, ok := m.byHash[hash]
		if !ok {
			continue
		}
		if s.ID == sessionID {
			m.deleteLocked(hash, userID)
			return true, nil
		}
	}
	return false, nil
}

// DeleteAllForUser implements Store.
func (m *MemoryStore) DeleteAllForUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash := range m.byUser[userID] {
		delete(m.byHash, hash)
	}
	delete(m.byUser, userID)
	return nil
}

// ClaimRecoveryEnrollment implements Store with a single mutex-protected
// compare-and-set over the restricted session state.
func (m *MemoryStore) ClaimRecoveryEnrollment(userID, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for hash := range m.byUser[userID] {
		s, ok := m.byHash[hash]
		if !ok || s.ID != sessionID {
			continue
		}
		if expired(s, now) {
			m.deleteLocked(hash, userID)
			return false, nil
		}
		if s.Kind != KindRecoveryEnrollment || s.EnrollmentClaimed {
			return false, nil
		}
		s.EnrollmentClaimed = true
		m.byHash[hash] = s
		return true, nil
	}
	return false, nil
}

// ReleaseRecoveryEnrollment implements Store.
func (m *MemoryStore) ReleaseRecoveryEnrollment(userID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash := range m.byUser[userID] {
		s, ok := m.byHash[hash]
		if !ok || s.ID != sessionID {
			continue
		}
		if s.Kind == KindRecoveryEnrollment {
			s.EnrollmentClaimed = false
			m.byHash[hash] = s
		}
		return nil
	}
	return nil
}

// deleteLocked removes a token hash from both indexes. The caller must hold the
// mutex.
func (m *MemoryStore) deleteLocked(tokenHash, userID string) {
	delete(m.byHash, tokenHash)
	if set, ok := m.byUser[userID]; ok {
		delete(set, tokenHash)
		if len(set) == 0 {
			delete(m.byUser, userID)
		}
	}
}
