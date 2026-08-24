package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestManager builds a Manager backed by a MemoryStore and a plain
// (non-__Host-, insecure) cookie so tests round-trip cookies over HTTP. Both
// the manager and the store share the same injectable clock via *at.
func newTestManager(t *testing.T, at *time.Time) *Manager {
	t.Helper()
	store := NewMemoryStore()
	store.now = func() time.Time { return *at }

	codec, err := NewCookieCodec(CookieConfig{Name: "session", Secure: false, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}

	m, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: 24 * time.Hour, IdleTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.now = func() time.Time { return *at }
	return m
}

// requestWithCookies copies the Set-Cookie headers from rec onto a fresh GET
// request so a session issued on one response can authenticate the next.
func requestWithCookies(rec *httptest.ResponseRecorder) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(ck)
	}
	return req
}

func TestNewManagerValidation(t *testing.T) {
	codec, err := NewCookieCodec(CookieConfig{Name: "session", Secure: false, TTL: time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}
	store := NewMemoryStore()
	valid := ManagerConfig{AbsoluteTTL: 24 * time.Hour, IdleTTL: 2 * time.Hour}

	if _, err := NewManager(nil, codec, valid); err == nil {
		t.Error("NewManager(nil store) succeeded, want error")
	}
	if _, err := NewManager(store, nil, valid); err == nil {
		t.Error("NewManager(nil codec) succeeded, want error")
	}
	if _, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: 0, IdleTTL: time.Hour}); err == nil {
		t.Error("NewManager(AbsoluteTTL=0) succeeded, want error")
	}
	if _, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 0}); err == nil {
		t.Error("NewManager(IdleTTL=0) succeeded, want error")
	}
	if _, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 2 * time.Hour}); err == nil {
		t.Error("NewManager(IdleTTL > AbsoluteTTL) succeeded, want error")
	}
}

func TestManagerIssueRequiresUserID(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	rec := httptest.NewRecorder()
	if _, err := m.Issue(rec, IssueParams{}); err != ErrMissingUserID {
		t.Fatalf("Issue(no user) error = %v, want ErrMissingUserID", err)
	}
}

func TestManagerIssueWritesCookieAndPersists(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	rec := httptest.NewRecorder()

	s, err := m.Issue(rec, IssueParams{UserID: "user-1", IP: "203.0.113.5", UserAgent: "test-agent"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if s.ID == "" {
		t.Error("Issue returned a session with an empty public ID")
	}
	if !s.AbsoluteExpiry.Equal(now.Add(24 * time.Hour)) {
		t.Errorf("AbsoluteExpiry = %v, want %v", s.AbsoluteExpiry, now.Add(24*time.Hour))
	}
	if !s.IdleExpiry.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("IdleExpiry = %v, want %v", s.IdleExpiry, now.Add(2*time.Hour))
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("Issue did not write a session cookie: %+v", cookies)
	}
	// The raw token must never equal the public ID.
	if cookies[0].Value == s.ID {
		t.Error("session cookie carries the public ID instead of an opaque token")
	}
}

func TestManagerIssueRecoveryEnrollmentIsRestrictedToTenMinutes(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	rec := httptest.NewRecorder()

	s, err := m.Issue(rec, IssueParams{UserID: "user-1", Kind: KindRecoveryEnrollment})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if s.Kind != KindRecoveryEnrollment {
		t.Fatalf("Kind = %q, want %q", s.Kind, KindRecoveryEnrollment)
	}
	want := now.Add(RecoveryEnrollmentTTL)
	if !s.AbsoluteExpiry.Equal(want) || !s.IdleExpiry.Equal(want) {
		t.Fatalf("restricted expiries = %v / %v, want %v", s.AbsoluteExpiry, s.IdleExpiry, want)
	}

	now = want.Add(time.Nanosecond)
	if _, err := m.Authenticate(requestWithCookies(rec)); err != ErrSessionNotFound {
		t.Fatalf("Authenticate after restricted TTL = %v, want ErrSessionNotFound", err)
	}
}

func TestManagerAuthenticateNoCookie(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := m.Authenticate(req); err != ErrNoSession {
		t.Fatalf("Authenticate(no cookie) error = %v, want ErrNoSession", err)
	}
}

func TestManagerIssueThenAuthenticate(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)

	rec := httptest.NewRecorder()
	issued, err := m.Issue(rec, IssueParams{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance one hour, then authenticate; the idle deadline should slide.
	now = now.Add(time.Hour)
	req := requestWithCookies(rec)
	got, err := m.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != issued.ID {
		t.Errorf("Authenticate returned session ID %q, want %q", got.ID, issued.ID)
	}
	if got.UserID != "user-1" {
		t.Errorf("Authenticate returned UserID %q, want user-1", got.UserID)
	}
	wantIdle := now.Add(2 * time.Hour)
	if !got.IdleExpiry.Equal(wantIdle) {
		t.Errorf("IdleExpiry = %v, want slid to %v", got.IdleExpiry, wantIdle)
	}
}

func TestManagerAuthenticateClampsIdleToAbsolute(t *testing.T) {
	now := time.Now()

	// This test needs an idle window that fits inside a shorter absolute
	// ceiling so that sliding the idle deadline forward while the session is
	// still live would overshoot the ceiling. The shared newTestManager uses a
	// 2h idle / 24h absolute policy, under which the session would lapse on
	// idle (at 2h) long before the absolute deadline is ever approached, so we
	// build a dedicated 2h-idle / 3h-absolute manager here.
	store := NewMemoryStore()
	store.now = func() time.Time { return now }
	codec, err := NewCookieCodec(CookieConfig{Name: "session", Secure: false, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}
	m, err := NewManager(store, codec, ManagerConfig{AbsoluteTTL: 3 * time.Hour, IdleTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.now = func() time.Time { return now }

	rec := httptest.NewRecorder()
	issued, err := m.Issue(rec, IssueParams{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance 90 minutes: still inside the 2h idle window (session live), but
	// sliding idle forward by 2h now reaches 3.5h, past the 3h absolute ceiling
	// — so it must be clamped back to the absolute deadline.
	now = now.Add(90 * time.Minute)
	got, err := m.Authenticate(requestWithCookies(rec))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.IdleExpiry.After(issued.AbsoluteExpiry) {
		t.Errorf("IdleExpiry %v exceeded AbsoluteExpiry %v (not clamped)", got.IdleExpiry, issued.AbsoluteExpiry)
	}
	if !got.IdleExpiry.Equal(issued.AbsoluteExpiry) {
		t.Errorf("IdleExpiry = %v, want clamped to %v", got.IdleExpiry, issued.AbsoluteExpiry)
	}
}

func TestManagerAuthenticateExpired(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)

	rec := httptest.NewRecorder()
	if _, err := m.Issue(rec, IssueParams{UserID: "user-1"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance past the absolute ceiling.
	now = now.Add(25 * time.Hour)
	if _, err := m.Authenticate(requestWithCookies(rec)); err != ErrSessionNotFound {
		t.Fatalf("Authenticate(expired) error = %v, want ErrSessionNotFound", err)
	}
}

func TestManagerRevokeIdempotent(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)

	// Revoking with no cookie still succeeds and clears the client cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	if err := m.Revoke(rec, req); err != nil {
		t.Fatalf("Revoke(no cookie): %v", err)
	}
	if len(rec.Result().Cookies()) != 1 {
		t.Fatal("Revoke(no cookie) did not clear the cookie")
	}

	// Issue, then revoke; the session must no longer authenticate.
	issueRec := httptest.NewRecorder()
	if _, err := m.Issue(issueRec, IssueParams{UserID: "user-1"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	revokeRec := httptest.NewRecorder()
	if err := m.Revoke(revokeRec, requestWithCookies(issueRec)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := m.Authenticate(requestWithCookies(issueRec)); err != ErrSessionNotFound {
		t.Fatalf("Authenticate after revoke error = %v, want ErrSessionNotFound", err)
	}
}

func TestManagerListAndRevokeByID(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)

	rec1 := httptest.NewRecorder()
	s1, err := m.Issue(rec1, IssueParams{UserID: "user-1"})
	if err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	rec2 := httptest.NewRecorder()
	if _, err := m.Issue(rec2, IssueParams{UserID: "user-1"}); err != nil {
		t.Fatalf("Issue 2: %v", err)
	}

	sessions, err := m.List("user-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("List returned %d sessions, want 2", len(sessions))
	}

	// Revoke by ID scoped to a different user must not remove it.
	removed, err := m.RevokeByID("user-2", s1.ID)
	if err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	if removed {
		t.Fatal("RevokeByID allowed cross-user revocation")
	}

	removed, err = m.RevokeByID("user-1", s1.ID)
	if err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	if !removed {
		t.Fatal("RevokeByID did not remove the owner's session")
	}
}

func TestManagerRevokeAllForUser(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)

	for i := 0; i < 3; i++ {
		if _, err := m.Issue(httptest.NewRecorder(), IssueParams{UserID: "user-1"}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	if err := m.RevokeAllForUser("user-1"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	sessions, err := m.List("user-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("user-1 still has %d sessions after RevokeAllForUser", len(sessions))
	}
}

func TestManagerCookieName(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	if m.CookieName() != "session" {
		t.Fatalf("CookieName() = %q, want session", m.CookieName())
	}
}
