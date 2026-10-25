package session

import (
	"context"
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
	store    Store
	accounts AccountState
	cookie   *CookieCodec
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
	// AccountState is mandatory in a DB-backed runtime; nil is for isolated tests.
	AccountState AccountState
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
	AuthVersion    int64
	AuthVersionSet bool
	// UserID is the authenticated subject the session belongs to (required).
	UserID string
	// IP is the client source address at authentication time.
	IP string
	// UserAgent identifies the client device/browser.
	UserAgent string
	// DPoPJKT binds the session to a DPoP key thumbprint (RFC 9449). Normal
	// browser access rejects unbound sessions; a key is earned at fresh login.
	DPoPJKT string
	// Kind defaults to KindAuthenticated. Callers may request only the
	// restricted KindRecoveryEnrollment variant for recovery flows.
	Kind Kind
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
		accounts:    cfg.AccountState,
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
	return m.IssueContext(context.Background(), w, p)
}

// IssueContext preserves the version earned by authentication and serializes
// final issuance with account transitions. No cookie is sent on DB failure.
func (m *Manager) IssueContext(ctx context.Context, w http.ResponseWriter, p IssueParams) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if p.UserID == "" {
		return Session{}, ErrMissingUserID
	}

	token, hash, err := NewToken()
	if err != nil {
		return Session{}, err
	}

	kind := p.Kind
	if kind == "" {
		kind = KindAuthenticated
	}
	if kind != KindAuthenticated && kind != KindRecoveryEnrollment {
		return Session{}, fmt.Errorf("session: unsupported kind %q", kind)
	}

	now := m.now()
	absoluteTTL := m.absoluteTTL
	idleTTL := m.idleTTL
	if kind == KindRecoveryEnrollment {
		absoluteTTL = RecoveryEnrollmentTTL
		idleTTL = RecoveryEnrollmentTTL
	}
	idleExpiry := now.Add(idleTTL)
	absoluteExpiry := now.Add(absoluteTTL)
	// Clamp the idle deadline to the absolute ceiling so it can never outlive
	// the session (defensive; the config guarantees idleTTL <= absoluteTTL).
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}

	s := Session{
		AuthVersion:    p.AuthVersion,
		AuthVersionSet: p.AuthVersionSet,
		ID:             uuid.NewString(),
		Kind:           kind,
		UserID:         p.UserID,
		IP:             p.IP,
		UserAgent:      p.UserAgent,
		DPoPJKT:        p.DPoPJKT,
		CreatedAt:      now,
		LastSeenAt:     now,
		AbsoluteExpiry: absoluteExpiry,
		IdleExpiry:     idleExpiry,
	}

	persist := func() error { return m.store.Create(ctx, hash, s) }
	if m.accounts != nil {
		if !p.AuthVersionSet {
			return Session{}, ErrAccountIneligible
		}
		err = m.accounts.WithActive(ctx, p.UserID, p.AuthVersion, persist)
	} else {
		err = persist()
	}
	if err != nil {
		return Session{}, fmt.Errorf("session: persist: %w", err)
	}

	m.cookie.Write(w, token)
	return s, nil
}

// Resolve checks the cookie and live account authority without renewing any
// activity. HTTP gates must use it before checking the session kind and proof.
func (m *Manager) Resolve(r *http.Request) (Session, error) {
	if err := r.Context().Err(); err != nil {
		return Session{}, err
	}
	token, err := m.cookie.Read(r)
	if err != nil {
		return Session{}, ErrNoSession
	}
	hash := HashToken(token)

	s, err := m.store.Get(r.Context(), hash)
	if err != nil {
		return Session{}, err
	}
	if !validSession(s) {
		return Session{}, ErrStoreUnavailable
	}
	if expired(s, m.now()) {
		return Session{}, ErrSessionNotFound
	}
	if m.accounts != nil {
		if !s.AuthVersionSet {
			return Session{}, ErrAccountIneligible
		}
		if err := m.accounts.Validate(r.Context(), s.UserID, s.AuthVersion); err != nil {
			return Session{}, err
		}
	}

	return s, nil
}

// Authenticate is the combined lifecycle operation for trusted callers. Browser
// middleware instead separates Resolve from renewal after route authorization.
func (m *Manager) Authenticate(r *http.Request) (Session, error) {
	s, err := m.Resolve(r)
	if err != nil {
		return Session{}, err
	}
	return m.renew(r, s)
}

func (m *Manager) renew(r *http.Request, s Session) (Session, error) {
	if err := r.Context().Err(); err != nil {
		return Session{}, err
	}
	token, err := m.cookie.Read(r)
	if err != nil {
		return Session{}, ErrNoSession
	}
	if expired(s, m.now()) {
		return Session{}, ErrSessionNotFound
	}
	// The store independently refuses to resurrect a revoked or expired record.
	now := m.now()
	newIdle := now.Add(m.idleTTL)
	if newIdle.After(s.AbsoluteExpiry) {
		newIdle = s.AbsoluteExpiry
	}
	if newIdle.Before(s.IdleExpiry) {
		newIdle = s.IdleExpiry
	}
	if err := m.store.Touch(r.Context(), HashToken(token), newIdle); err != nil {
		// The session lapsed between Get and Touch; treat as not found.
		return Session{}, err
	}
	s.IdleExpiry = newIdle
	if now.After(s.LastSeenAt) {
		s.LastSeenAt = now
	}
	return s, nil
}

// LookupByID reads live browser authority without extending its lifetime or
// consulting account state. Token callers must check the session kind and the
// captured version, then call AccountState.Validate once for their whole flow.
func (m *Manager) LookupByID(ctx context.Context, userID, sessionID string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	s, err := m.store.GetByID(ctx, userID, sessionID)
	if err != nil {
		return Session{}, err
	}
	if !validSession(s) || s.UserID != userID || s.ID != sessionID {
		return Session{}, ErrStoreUnavailable
	}
	if expired(s, m.now()) {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

// ClaimRecoveryEnrollment atomically reserves a restricted session for one
// enrollment completion. A successful caller must revoke the session; a
// conclusively failed ceremony may release it to permit a retry.
func (m *Manager) ClaimRecoveryEnrollment(ctx context.Context, userID, sessionID string) (bool, error) {
	return m.store.ClaimRecoveryEnrollment(ctx, userID, sessionID)
}

// ReleaseRecoveryEnrollment releases a failed enrollment claim.
func (m *Manager) ReleaseRecoveryEnrollment(ctx context.Context, userID, sessionID string) error {
	return m.store.ReleaseRecoveryEnrollment(ctx, userID, sessionID)
}

// Revoke deletes the session bound to the request cookie and clears the cookie
// on the response. It is idempotent: a missing cookie or unknown session still
// clears the client cookie and returns nil, so logout always succeeds.
//
// The returned Session is the one that was revoked, and the bool reports whether
// anything actually was. The HTTP boundary must authorize a live bound session
// before calling this operation. The result attributes auth.session.logged_out
// without recording anonymous/already-expired no-ops as account events.
//
// The lookup is not atomic with the delete. A concurrent expiry between the two
// only causes a revoked-but-already-gone session to be reported as revoked, which
// is the harmless direction: the cookie is cleared either way, and the audit
// record still names the account that held the token.
func (m *Manager) Revoke(w http.ResponseWriter, r *http.Request) (Session, bool, error) {
	if err := r.Context().Err(); err != nil {
		return Session{}, false, err
	}
	var (
		revoked Session
		ok      bool
	)
	token, err := m.cookie.Read(r)
	if err == nil {
		hash := HashToken(token)
		// A failed lookup must not prevent attempting deletion. Report any
		// infrastructure error rather than claiming logout succeeded.
		s, getErr := m.store.Get(r.Context(), hash)
		if getErr == nil {
			revoked, ok = s, true
		}
		if delErr := m.store.Delete(r.Context(), hash); delErr != nil {
			return Session{}, false, fmt.Errorf("session: revoke: %w", delErr)
		}
		if getErr != nil && !errors.Is(getErr, ErrSessionNotFound) {
			return Session{}, false, fmt.Errorf("session: revoke lookup: %w", getErr)
		}
	}
	m.cookie.Clear(w)
	return revoked, ok, nil
}

// List returns every live session for userID, newest-first, for the
// self-service session list (GET /api/v1/users/me/sessions).
func (m *Manager) List(ctx context.Context, userID string) ([]Session, error) {
	return m.store.ListForUser(ctx, userID)
}

// RevokeByID deletes a single session identified by its public ID, scoped to
// userID so a user can only revoke their own sessions. It reports whether a
// session was removed (false => 404 to the caller).
func (m *Manager) RevokeByID(ctx context.Context, userID, sessionID string) (bool, error) {
	return m.store.DeleteForUser(ctx, userID, sessionID)
}

// RevokeAllForUser deletes every session belonging to userID, backing the
// "log out everywhere" action and the RTR breach response.
func (m *Manager) RevokeAllForUser(ctx context.Context, userID string) error {
	return m.store.DeleteAllForUser(ctx, userID)
}

// CookieName reports the configured session cookie name, exposed for handlers
// and tests that need to reference it.
func (m *Manager) CookieName() string { return m.cookie.Name() }

// ClearCookie removes browser state without making a claim about revocation.
func (m *Manager) ClearCookie(w http.ResponseWriter) { m.cookie.Clear(w) }
