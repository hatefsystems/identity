package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// newSessionTestServer builds a Server wired with a session manager backed by
// the in-memory store. It uses a non-__Host- cookie name with Secure=false so
// the issued cookie is accepted over the plain-HTTP httptest transport (the
// __Host-/Secure invariant is exercised in the session package's own tests).
func newSessionTestServer(t *testing.T) (*Server, *session.Manager) {
	t.Helper()

	codec, err := session.NewCookieCodec(session.CookieConfig{
		Name:   "session",
		Secure: false,
		TTL:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}

	mgr, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	return New(testConfig(t), nil, Deps{SessionManager: mgr}), mgr
}

// issueSession mints a session via the manager and returns it together with the
// cookies the browser would carry on subsequent requests.
func issueSession(t *testing.T, mgr *session.Manager, p session.IssueParams) (session.Session, []*http.Cookie) {
	t.Helper()

	rec := httptest.NewRecorder()
	s, err := mgr.Issue(rec, p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Issue did not set a session cookie")
	}
	return s, cookies
}

// addCookies copies the supplied cookies onto req, simulating a browser
// re-presenting them.
func addCookies(req *http.Request, cookies []*http.Cookie) {
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
}

func TestLogoutReturns204(t *testing.T) {
	srv, mgr := newSessionTestServer(t)
	_, cookies := issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestLogoutWithoutCookieIsIdempotent(t *testing.T) {
	srv, _ := newSessionTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestListSessionsWithoutCookieUnauthorized(t *testing.T) {
	srv, _ := newSessionTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}

func TestListSessionsWithCookie(t *testing.T) {
	srv, mgr := newSessionTestServer(t)
	s, cookies := issueSession(t, mgr, session.IssueParams{
		UserID:    "user-1",
		IP:        "203.0.113.7",
		UserAgent: "test-agent/1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	var list []sessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(list))
	}

	got := list[0]
	if got.ID != s.ID {
		t.Errorf("ID = %q, want %q", got.ID, s.ID)
	}
	if !got.Current {
		t.Error("Current = false, want true for the requesting session")
	}
	if got.IP != "203.0.113.7" {
		t.Errorf("IP = %q, want %q", got.IP, "203.0.113.7")
	}
	if got.UserAgent != "test-agent/1.0" {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, "test-agent/1.0")
	}
}

// TestListSessionsDoesNotLeakToken re-decodes the response as a generic map and
// asserts no field carries the session token or its storage hash.
func TestListSessionsDoesNotLeakToken(t *testing.T) {
	srv, mgr := newSessionTestServer(t)
	_, cookies := issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var raw []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(raw))
	}

	// Only the public projection fields are permitted in the wire response.
	allowed := map[string]struct{}{
		"id":           {},
		"ip":           {},
		"user_agent":   {},
		"current":      {},
		"created_at":   {},
		"last_seen_at": {},
	}
	for key := range raw[0] {
		if _, ok := allowed[key]; !ok {
			t.Errorf("unexpected field %q leaked in session response", key)
		}
	}
	// Guard against a raw token/hash sneaking in under any name.
	for _, forbidden := range []string{"token", "hash", "token_hash"} {
		if _, ok := raw[0][forbidden]; ok {
			t.Errorf("forbidden field %q present in session response", forbidden)
		}
	}
}

func TestRevokeOwnSessionReturns204(t *testing.T) {
	srv, mgr := newSessionTestServer(t)
	s, cookies := issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/sessions/"+s.ID, nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// The session is revoked: a follow-up authenticated request now fails, and
	// the store no longer lists it.
	if remaining, err := mgr.List("user-1"); err != nil {
		t.Fatalf("List after revoke: %v", err)
	} else if len(remaining) != 0 {
		t.Errorf("len(sessions) after revoke = %d, want 0", len(remaining))
	}
}

func TestRevokeUnknownSessionReturns404(t *testing.T) {
	srv, mgr := newSessionTestServer(t)
	_, cookies := issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/sessions/does-not-exist", nil)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}

// TestSessionRoutesAbsentWithoutManager proves the lifecycle routes are only
// mounted when a session manager is configured: with an empty Deps the logout
// route 404s (mirroring the OIDC-routes-absent-without-keys behavior).
func TestSessionRoutesAbsentWithoutManager(t *testing.T) {
	srv := New(testConfig(t), nil, Deps{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}
