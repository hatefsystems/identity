package stepup

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// discardLogger keeps the middleware's warn/error lines out of test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// serveWithSession runs the middleware over a request that already carries a
// session, mirroring the production chain where RequireSession runs first.
func serveWithSession(
	t *testing.T,
	svc *Service,
	sess *session.Session,
	grant string,
) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	guard, err := NewRequireStepUp(svc, discardLogger())
	if err != nil {
		t.Fatalf("NewRequireStepUp: %v", err)
	}

	reached := false
	handler := guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if _, ok := GrantFromContext(r.Context()); !ok {
			t.Error("the handler was reached without a grant in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	if grant != "" {
		req.Header.Set(HeaderStepUpAuth, grant)
	}
	if sess != nil {
		req = req.WithContext(session.WithSession(req.Context(), *sess))
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, reached
}

func TestRequireStepUpAcceptsAValidGrant(t *testing.T) {
	svc, _ := newTestService(t)
	sess := testSession()

	rec, reached := serveWithSession(t, svc, &sess, mint(t, svc))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !reached {
		t.Fatal("the wrapped handler was not reached")
	}
}

// TestRequireStepUpChallengesEveryRejection pins both the status and the body.
//
// The status is 403 rather than 401 on purpose: the session is valid, so what is
// missing is authentication *context*. session.RequireSession already uses a bare
// 401 as the signal the SPA reads as "re-authenticate", and reusing it here would
// bounce the user through a full login instead of the inline step-up overlay.
func TestRequireStepUpChallengesEveryRejection(t *testing.T) {
	sess := testSession()

	tests := []struct {
		name  string
		grant func(t *testing.T, svc *Service) string
	}{
		{
			name:  "no header at all",
			grant: func(*testing.T, *Service) string { return "" },
		},
		{
			name:  "garbage header",
			grant: func(*testing.T, *Service) string { return "not-a-jwt" },
		},
		{
			name: "grant for another session",
			grant: func(t *testing.T, svc *Service) string {
				compact, _, err := svc.Mint(MintParams{UserID: "user-1", SessionID: "sess-other"})
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return compact
			},
		},
		{
			name: "grant for another subject",
			grant: func(t *testing.T, svc *Service) string {
				compact, _, err := svc.Mint(MintParams{UserID: "user-other", SessionID: "sess-1"})
				if err != nil {
					t.Fatalf("Mint: %v", err)
				}
				return compact
			},
		},
		{
			name: "already consumed grant",
			grant: func(t *testing.T, svc *Service) string {
				compact := mint(t, svc)
				if _, err := svc.Validate(context.Background(), compact, sess); err != nil {
					t.Fatalf("priming Validate: %v", err)
				}
				return compact
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)

			rec, reached := serveWithSession(t, svc, &sess, tc.grant(t, svc))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
			}
			if reached {
				t.Fatal("the wrapped handler ran despite the grant being rejected")
			}

			var body challengeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal challenge: %v", err)
			}
			// Every rejection renders identically, so a probe cannot tell a
			// missing header from an expired, replayed, or foreign grant.
			if body.Error != "insufficient_user_authentication" {
				t.Fatalf("error = %q, want insufficient_user_authentication", body.Error)
			}
			if body.ACRValues != ACRStepUp {
				t.Fatalf("acr_values = %q, want %q", body.ACRValues, ACRStepUp)
			}
		})
	}
}

// TestRequireStepUpRejectsAnExpiredGrant exercises the temporal check through
// the middleware, using a clock that advances past the grant's lifetime.
func TestRequireStepUpRejectsAnExpiredGrant(t *testing.T) {
	now := testNow
	svc, _ := newTestServiceAt(t, func() time.Time { return now })
	sess := testSession()

	compact := mint(t, svc)
	now = now.Add(DefaultTokenTTL + time.Second)

	rec, reached := serveWithSession(t, svc, &sess, compact)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if reached {
		t.Fatal("an expired grant reached the handler")
	}
}

// TestRequireStepUpFailsWhenComposedWithoutASession is the middleware-ordering
// guard. RequireStepUp binds the grant to the request's session, so a chain that
// omits RequireSession is a programming error, reported as 500 rather than
// silently treated as an authentication failure.
func TestRequireStepUpFailsWhenComposedWithoutASession(t *testing.T) {
	svc, _ := newTestService(t)

	rec, reached := serveWithSession(t, svc, nil, mint(t, svc))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if reached {
		t.Fatal("the handler ran without a session in context")
	}
}

func TestNewRequireStepUpRejectsANilService(t *testing.T) {
	if _, err := NewRequireStepUp(nil, discardLogger()); err == nil {
		t.Fatal("expected a nil service to be rejected")
	}
}

// TestGrantContextRoundTrip covers the accessor the audit pipeline will use.
func TestGrantContextRoundTrip(t *testing.T) {
	if _, ok := GrantFromContext(context.Background()); ok {
		t.Fatal("an empty context must not yield a grant")
	}

	want := &Grant{UserID: "user-1", SessionID: "sess-1", AMR: []string{"otp"}}
	ctx := WithGrant(context.Background(), want)

	got, ok := GrantFromContext(ctx)
	if !ok {
		t.Fatal("expected the stored grant")
	}
	if got.UserID != want.UserID || got.SessionID != want.SessionID {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	// A nil grant must not be reported as present, so a caller cannot mistake a
	// mis-wired chain for an authorised request.
	if _, ok := GrantFromContext(WithGrant(context.Background(), nil)); ok {
		t.Fatal("a nil grant must not report as present")
	}
}
