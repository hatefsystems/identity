package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// newSessionTestServer builds a Server wired with a session manager backed by
// the in-memory store. It uses a non-__Host- cookie name with Secure=false so
// the issued cookie is accepted over the plain-HTTP httptest transport (the
// __Host-/Secure invariant is exercised in the session package's own tests).
func newSessionTestServer(t *testing.T) (*Server, *session.Manager, *portalTestClient) {
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

	browser := newPortalTestClient(t, testPortalOrigin)
	cfg := testConfig(t)
	cfg.PortalOrigin = browser.origin
	return New(cfg, nil, Deps{SessionManager: mgr, DPoPValidator: browser.validator}), mgr, browser
}

// issueSession is raw issuance: it preserves deliberately empty or foreign
// bindings. Normal browser fixtures use portalTestClient.issueSession instead.
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
	srv, mgr, browser := newSessionTestServer(t)
	current, cookies := browser.issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	browser.authorize(t, req, current, cookies...)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestLogoutWithoutCookieIsIdempotent(t *testing.T) {
	srv, _, browser := newSessionTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	browser.prepare(req)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestListSessionsWithoutCookieUnauthorized(t *testing.T) {
	srv, _, _ := newSessionTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	requirePortalSessionRequired(t, rec)
	_, _ = io.Copy(io.Discard, rec.Body)
}

func TestListSessionsWithCookie(t *testing.T) {
	srv, mgr, browser := newSessionTestServer(t)
	s, cookies := browser.issueSession(t, mgr, session.IssueParams{
		UserID:    "user-1",
		IP:        "203.0.113.7",
		UserAgent: "test-agent/1.0",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	browser.authorize(t, req, s, cookies...)
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
	srv, mgr, browser := newSessionTestServer(t)
	current, cookies := browser.issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	browser.authorize(t, req, current, cookies...)
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
	srv, mgr, browser := newSessionTestServer(t)
	s, cookies := browser.issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/sessions/"+s.ID, nil)
	browser.authorize(t, req, s, cookies...)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// The session is revoked: a follow-up authenticated request now fails, and
	// the store no longer lists it.
	if remaining, err := mgr.List(t.Context(), "user-1"); err != nil {
		t.Fatalf("List after revoke: %v", err)
	} else if len(remaining) != 0 {
		t.Errorf("len(sessions) after revoke = %d, want 0", len(remaining))
	}
}

func TestRevokeUnknownSessionReturns404(t *testing.T) {
	srv, mgr, browser := newSessionTestServer(t)
	current, cookies := browser.issueSession(t, mgr, session.IssueParams{UserID: "user-1"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/sessions/does-not-exist", nil)
	browser.authorize(t, req, current, cookies...)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}

func TestSessionHandlersPreserveRequestCancellation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			srv, mgr, browser := newSessionTestServer(t)
			current, _ := browser.issueSession(t, mgr, session.IssueParams{UserID: "user-1"})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx = session.WithSession(ctx, current)
			route := chi.NewRouteContext()
			route.URLParams.Add("id", current.ID)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, route)
			req := httptest.NewRequest(method, "/api/v1/users/me/sessions/"+current.ID, nil).WithContext(ctx)
			cancel()
			rec := httptest.NewRecorder()
			// Call the handler directly: cancellation must reach its store call,
			// independently of RequireSession's own cancellation check.
			handler := srv.handleListSessions()
			if method == http.MethodDelete {
				handler = srv.handleRevokeSession()
			}
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("canceled %s returned %d, want unavailable response", method, rec.Code)
			}
			var body sessionErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error != "temporarily_unavailable" {
				t.Fatalf("canceled %s response = %s, err=%v", method, rec.Body.String(), err)
			}
			if _, err := mgr.LookupByID(t.Context(), current.UserID, current.ID); err != nil {
				t.Fatalf("canceled handler revoked a session: %v", err)
			}
		})
	}
}

// TestSessionRoutesAbsentWithoutManager proves the lifecycle routes are only
// mounted when a session manager is configured: with an empty Deps the logout
// route 404s (mirroring the OIDC-routes-absent-without-keys behavior).
func TestSessionRoutesAbsentWithoutManager(t *testing.T) {
	cfg := testConfig(t)
	cfg.PortalOrigin = testPortalOrigin
	srv := New(cfg, nil, Deps{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Origin", cfg.PortalOrigin)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	_, _ = io.Copy(io.Discard, rec.Body)
}
