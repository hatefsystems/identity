package session

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Manager is the lifecycle facade over a Store and a CookieCodec. It owns the
// session policy — absolute and idle lifetimes — and is the single entry point
// handlers use to issue, authenticate, and revoke sessions. It hides token
// generation, hashing, cookie hardening, and expiry clamping so callers never
// touch the raw token or storage key.
//
// The zero value is not usable; construct with NewManager so the cookie
// invariants (see NewCookieCodec) and the TTL policy are validated once at
// startup.
type Manager struct {
	store  Store
	cookie *CookieCodec
	// absoluteTTL is the hard ceiling on a session's lifetime; it is fixed at
	// creation and never extended.
	absoluteTTL time.Duration
	// idleTTL is how long a session may sit idle before it lapses; it slides
	// forward on each authenticated request but is clamped to the absolute
	// deadline.
	idleTTL time.Duration
	// now is injectable so lifetime math is deterministic in tests.
	now func() time.Time
}

// ManagerConfig configures a Manager's lifetime policy.
type ManagerConfig struct {
	// AbsoluteTTL is the maximum lifetime of a session regardless of activity.
	AbsoluteTTL time.Duration
	// IdleTTL is the inactivity window after which a session lapses. It must
	// not exceed AbsoluteTTL (a larger idle window would never bind).
	IdleTTL time.Duration
}

// IssueParams describes the authenticated subject and request context captured
// into a new session. UserID is required; the rest are best-effort audit
// context sourced from the request.
type IssueParams struct {
	// UserID is the authenticated subject the session belongs to (required).
	UserID string
	// IP is the client source address at authentication time.
	IP string
	// UserAgent identifies the client device/browser.
	UserAgent string
	// DPoPJKT binds the session to a DPoP key thumbprint (RFC 9449). Leave
	// empty for a bearer (non-sender-constrained) session.
	DPoPJKT string
}

// Manager sentinel errors.
var (
	// ErrNoSession indicates the request carried no session cookie.
	ErrNoSession = errors.New("session: no session cookie")
	// ErrMissingUserID indicates Issue was called without a subject.
	ErrMissingUserID = errors.New("session: user id is required")
)

// NewManager constructs a Manager from a store, a validated cookie codec, and a
// lifetime policy. It rejects a non-positive TTL or an idle window that exceeds
// the absolute window, so a policy that could never bind fails fast at startup.
func NewManager(store Store, cookie *CookieCodec, cfg ManagerConfig) (*Manager, error) {
	if store == nil {
		return nil, errors.New("session: store is required")
	}
	if cookie == nil {
		return nil, errors.New("session: cookie codec is required")
	}
	if cfg.AbsoluteTTL <= 0 {
		return nil, fmt.Errorf("session: absolute TTL must be positive, got %v", cfg.AbsoluteTTL)
	}
	if cfg.IdleTTL <= 0 {
		return nil, fmt.Errorf("session: idle TTL must be positive, got %v", cfg.IdleTTL)
	}
	if cfg.IdleTTL > cfg.AbsoluteTTL {
		return nil, fmt.Errorf("session: idle TTL %v must not exceed absolute TTL %v", cfg.IdleTTL, cfg.AbsoluteTTL)
	}
	return &Manager{
		store:       store,
		cookie:      cookie,
		absoluteTTL: cfg.AbsoluteTTL,
		idleTTL:     cfg.IdleTTL,
		now:         time.Now,
	}, nil
}

// Issue mints a new session for the authenticated subject, persists it, and
// writes the hardened session cookie to w. It returns the created session so
// the caller can surface its public ID. The raw token exists only long enough
// to be written into the cookie; it is never returned or logged.
func (m *Manager) Issue(w http.ResponseWriter, p IssueParams) (Session, error) {
	if p.UserID == "" {
		return Session{}, ErrMissingUserID
	}

	token, hash, err := NewToken()
	if err != nil {
		return Session{}, err
	}

	now := m.now()
	idleExpiry := now.Add(m.idleTTL)
	absoluteExpiry := now.Add(m.absoluteTTL)
	// Clamp the idle deadline to the absolute ceiling so it can never outlive
	// the session (defensive; the config guarantees idleTTL <= absoluteTTL).
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}

	s := Session{
		ID:             uuid.NewString(),
		UserID:         p.UserID,
		IP:             p.IP,
		UserAgent:      p.UserAgent,
		DPoPJKT:        p.DPoPJKT,
		CreatedAt:      now,
		LastSeenAt:     now,
		AbsoluteExpiry: absoluteExpiry,
		IdleExpiry:     idleExpiry,
	}

	if err := m.store.Create(hash, s); err != nil {
		return Session{}, fmt.Errorf("session: persist: %w", err)
	}

	m.cookie.Write(w, token)
	return s, nil
}

// Authenticate resolves the session bound to the request cookie and slides its
// idle deadline forward (clamped to the absolute ceiling). It returns
// ErrNoSession when no cookie is present and ErrSessionNotFound when the token
// is unknown, revoked, or expired. The returned session reflects the refreshed
// idle deadline.
func (m *Manager) Authenticate(r *http.Request) (Session, error) {
	token, err := m.cookie.Read(r)
	if err != nil {
		return Session{}, ErrNoSession
	}
	hash := HashToken(token)

	s, err := m.store.Get(hash)
	if err != nil {
		return Session{}, err
	}

	// Slide the idle window forward, clamped to the absolute ceiling.
	newIdle := m.now().Add(m.idleTTL)
	if newIdle.After(s.AbsoluteExpiry) {
		newIdle = s.AbsoluteExpiry
	}
	if err := m.store.Touch(hash, newIdle); err != nil {
		// The session lapsed between Get and Touch; treat as not found.
		return Session{}, err
	}
	s.IdleExpiry = newIdle
	s.LastSeenAt = m.now()
	return s, nil
}

// Revoke deletes the session bound to the request cookie and clears the cookie
// on the response. It is idempotent: a missing cookie or unknown session still
// clears the client cookie and returns nil, so logout always succeeds.
func (m *Manager) Revoke(w http.ResponseWriter, r *http.Request) error {
	token, err := m.cookie.Read(r)
	if err == nil {
		if delErr := m.store.Delete(HashToken(token)); delErr != nil {
			return fmt.Errorf("session: revoke: %w", delErr)
		}
	}
	m.cookie.Clear(w)
	return nil
}

// List returns every live session for userID, newest-first, for the
// self-service session list (GET /api/v1/users/me/sessions).
func (m *Manager) List(userID string) ([]Session, error) {
	return m.store.ListForUser(userID)
}

// RevokeByID deletes a single session identified by its public ID, scoped to
// userID so a user can only revoke their own sessions. It reports whether a
// session was removed (false => 404 to the caller).
func (m *Manager) RevokeByID(userID, sessionID string) (bool, error) {
	return m.store.DeleteForUser(userID, sessionID)
}

// RevokeAllForUser deletes every session belonging to userID, backing the
// "log out everywhere" action and the RTR breach response.
func (m *Manager) RevokeAllForUser(userID string) error {
	return m.store.DeleteAllForUser(userID)
}

// CookieName reports the configured session cookie name, exposed for handlers
// and tests that need to reference it.
func (m *Manager) CookieName() string { return m.cookie.Name() }
