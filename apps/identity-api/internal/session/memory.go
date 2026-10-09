package session

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore is a single-process Store for isolated tests and development.
// Expiry is reclaimed lazily; all mutations and owner lookups share one lock.
type MemoryStore struct {
	mu     sync.Mutex
	byHash map[string]Session
	byUser map[string]map[string]string // user ID -> public session ID -> token hash
	now    func() time.Time
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore constructs an empty single-process session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byHash: make(map[string]Session),
		byUser: make(map[string]map[string]string),
		now:    time.Now,
	}
}

// Create inserts a live session without replacing existing authority.
func (m *MemoryStore) Create(ctx context.Context, tokenHash string, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if tokenHash == "" || !validSession(s) {
		return ErrStoreUnavailable
	}
	if expired(s, m.now()) {
		return ErrSessionNotFound
	}
	if _, exists := m.byHash[tokenHash]; exists || m.byUser[s.UserID][s.ID] != "" {
		return ErrStoreUnavailable
	}
	m.byHash[tokenHash] = s
	if m.byUser[s.UserID] == nil {
		m.byUser[s.UserID] = make(map[string]string)
	}
	m.byUser[s.UserID][s.ID] = tokenHash
	return nil
}

// Get reads a live session by its bearer-token hash.
func (m *MemoryStore) Get(ctx context.Context, tokenHash string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	return m.getLocked(tokenHash)
}

// GetByID performs an owner-scoped lookup without extending idle expiry.
func (m *MemoryStore) GetByID(ctx context.Context, userID, sessionID string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	return m.getLocked(m.byUser[userID][sessionID])
}

// Touch advances only live sessions and never exceeds absolute expiry.
func (m *MemoryStore) Touch(ctx context.Context, tokenHash string, idleExpiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := m.getLocked(tokenHash)
	if err != nil {
		return err
	}
	if idleExpiry.After(s.AbsoluteExpiry) {
		idleExpiry = s.AbsoluteExpiry
	}
	if idleExpiry.After(s.IdleExpiry) {
		s.IdleExpiry = idleExpiry
	}
	if now := m.now(); now.After(s.LastSeenAt) {
		s.LastSeenAt = now
	}
	m.byHash[tokenHash] = s
	return nil
}

// Delete removes a session and its owner index entry.
func (m *MemoryStore) Delete(ctx context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s, ok := m.byHash[tokenHash]; ok {
		m.deleteLocked(tokenHash, s)
	}
	return nil
}

// ListForUser returns live sessions, newest first.
func (m *MemoryStore) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []Session
	for _, hash := range m.byUser[userID] {
		s, err := m.getLocked(hash)
		if err == ErrSessionNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// DeleteForUser removes a session only when the requested owner matches.
func (m *MemoryStore) DeleteForUser(ctx context.Context, userID, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hash := m.byUser[userID][sessionID]
	s, err := m.getLocked(hash)
	if err == ErrSessionNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	m.deleteLocked(hash, s)
	return true, nil
}

// DeleteAllForUser atomically removes the user's current sessions.
func (m *MemoryStore) DeleteAllForUser(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, hash := range m.byUser[userID] {
		delete(m.byHash, hash)
	}
	delete(m.byUser, userID)
	return nil
}

// ClaimRecoveryEnrollment admits at most one pending replacement-key ceremony.
func (m *MemoryStore) ClaimRecoveryEnrollment(ctx context.Context, userID, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hash := m.byUser[userID][sessionID]
	s, err := m.getLocked(hash)
	if err == ErrSessionNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if s.Kind != KindRecoveryEnrollment || s.EnrollmentClaimed {
		return false, nil
	}
	s.EnrollmentClaimed = true
	m.byHash[hash] = s
	return true, nil
}

// ReleaseRecoveryEnrollment releases a claim only on a still-live restricted session.
func (m *MemoryStore) ReleaseRecoveryEnrollment(ctx context.Context, userID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	hash := m.byUser[userID][sessionID]
	s, err := m.getLocked(hash)
	if err == ErrSessionNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Kind == KindRecoveryEnrollment {
		s.EnrollmentClaimed = false
		m.byHash[hash] = s
	}
	return nil
}

func (m *MemoryStore) getLocked(hash string) (Session, error) {
	s, ok := m.byHash[hash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if !validSession(s) {
		return Session{}, ErrStoreUnavailable
	}
	if expired(s, m.now()) {
		m.deleteLocked(hash, s)
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

func (m *MemoryStore) deleteLocked(hash string, s Session) {
	delete(m.byHash, hash)
	delete(m.byUser[s.UserID], s.ID)
	if len(m.byUser[s.UserID]) == 0 {
		delete(m.byUser, s.UserID)
	}
}
