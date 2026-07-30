package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
)

// okHandler records that it ran and captures the session it observed in the
// request context, so tests can assert both that RequireSession admitted the
// request and that it injected the resolved session.
func okHandler(ran *bool, seen *Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*ran = true
		if s, ok := FromContext(r.Context()); ok {
			*seen = s
		}
		w.WriteHeader(http.StatusOK)
	})
}

func newGuard(t *testing.T, m *Manager) *RequireSession {
	t.Helper()
	rs, err := NewRequireSession(m)
	if err != nil {
		t.Fatalf("NewRequireSession: %v", err)
	}
	return rs
}

func TestNewRequireSessionNilManager(t *testing.T) {
	if _, err := NewRequireSession(nil); err == nil {
		t.Fatal("NewRequireSession(nil) succeeded, want error")
	}
}

func TestMiddlewareNoCookieUnauthorized(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ran {
		t.Fatal("next handler ran despite missing session")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Cookie" {
		t.Errorf("WWW-Authenticate = %q, want Cookie", got)
	}
}

func TestMiddlewareValidSessionInjectsContext(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	issueRec := httptest.NewRecorder()
	issued, err := m.Issue(issueRec, IssueParams{UserID: "user-1", IP: "203.0.113.5"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, requestWithCookies(issueRec))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ran {
		t.Fatal("next handler did not run for a valid session")
	}
	if seen.ID != issued.ID || seen.UserID != "user-1" {
		t.Fatalf("context session = %+v, want ID %q / user-1", seen, issued.ID)
	}
}

func TestMiddlewareExpiredSessionUnauthorized(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	issueRec := httptest.NewRecorder()
	if _, err := m.Issue(issueRec, IssueParams{UserID: "user-1"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance past the absolute ceiling so the session has lapsed.
	now = now.Add(25 * time.Hour)

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, requestWithCookies(issueRec))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ran {
		t.Fatal("next handler ran despite an expired session")
	}
}

func TestMiddlewareDPoPBoundMissingProofUnauthorized(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	issueRec := httptest.NewRecorder()
	if _, err := m.Issue(issueRec, IssueParams{UserID: "user-1", DPoPJKT: "expected-jkt"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	// No DPoP proof in context: a bound session presented as a bare cookie is
	// treated as a replay of a leaked cookie.
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, requestWithCookies(issueRec))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ran {
		t.Fatal("next handler ran for a DPoP-bound session without a proof")
	}
}

func TestMiddlewareDPoPBoundMismatchedProofUnauthorized(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	issueRec := httptest.NewRecorder()
	if _, err := m.Issue(issueRec, IssueParams{UserID: "user-1", DPoPJKT: "expected-jkt"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := requestWithCookies(issueRec)
	req = req.WithContext(dpop.WithProof(req.Context(), &dpop.Proof{JKT: "some-other-jkt"}))

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ran {
		t.Fatal("next handler ran for a DPoP-bound session with a mismatched proof")
	}
}

func TestMiddlewareDPoPBoundMatchingProofOK(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	guard := newGuard(t, m)

	issueRec := httptest.NewRecorder()
	issued, err := m.Issue(issueRec, IssueParams{UserID: "user-1", DPoPJKT: "expected-jkt"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := requestWithCookies(issueRec)
	req = req.WithContext(dpop.WithProof(req.Context(), &dpop.Proof{JKT: "expected-jkt"}))

	var ran bool
	var seen Session
	rec := httptest.NewRecorder()
	guard.Handler(okHandler(&ran, &seen)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ran {
		t.Fatal("next handler did not run for a matching DPoP-bound session")
	}
	if seen.ID != issued.ID {
		t.Fatalf("context session ID = %q, want %q", seen.ID, issued.ID)
	}
}
