package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

const testPermission = "admin.users.read"

// fakeChecker is a PermissionChecker whose verdict and error are set per test.
type fakeChecker struct {
	allowed bool
	err     error

	calls []db.UserHasPermissionParams
}

func (f *fakeChecker) UserHasPermission(_ context.Context, arg db.UserHasPermissionParams) (bool, error) {
	f.calls = append(f.calls, arg)
	if f.err != nil {
		return false, f.err
	}
	return f.allowed, nil
}

// fakeRecorder captures audit events without a transport.
type fakeRecorder struct {
	events []audit.Event
	err    error
}

func (f *fakeRecorder) Record(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return f.err
}

// discardLogger keeps expected-error test output readable.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newRequest builds a request whose context carries sess, mimicking what
// session.RequireSession installs upstream.
func newRequest(sess *session.Session) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	if sess != nil {
		r = r.WithContext(session.WithSession(r.Context(), *sess))
	}
	return r
}

func authenticatedSession(userID string) *session.Session {
	return &session.Session{ID: "sess-1", Kind: session.KindAuthenticated, UserID: userID}
}

func TestNewRequirePermissionValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewRequirePermission(nil, testPermission, nil); err == nil {
		t.Fatal("NewRequirePermission(nil checker) error = nil, want error")
	}
	if _, err := NewRequirePermission(&fakeChecker{}, "", nil); err == nil {
		t.Fatal("NewRequirePermission(empty permission) error = nil, want error")
	}
	g, err := NewRequirePermission(&fakeChecker{}, testPermission, nil)
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}
	if g.Permission() != testPermission {
		t.Fatalf("Permission() = %q, want %q", g.Permission(), testPermission)
	}
}

// TestHandlerMatrix covers the decision table in Task 2 of the plan.
func TestHandlerMatrix(t *testing.T) {
	t.Parallel()

	actor := uuid.New()

	tests := []struct {
		name       string
		session    *session.Session
		checker    *fakeChecker
		wantStatus int
		wantNext   bool
		wantDenial bool
	}{
		{
			name:       "allow",
			session:    authenticatedSession(actor.String()),
			checker:    &fakeChecker{allowed: true},
			wantStatus: http.StatusOK,
			wantNext:   true,
		},
		{
			name:       "deny when permission not held",
			session:    authenticatedSession(actor.String()),
			checker:    &fakeChecker{allowed: false},
			wantStatus: http.StatusForbidden,
			wantDenial: true,
		},
		{
			// Fail closed: an unevaluated check must never read as a pass, and
			// must not read as a policy decision either.
			name:       "store error is 503 not a pass",
			session:    authenticatedSession(actor.String()),
			checker:    &fakeChecker{allowed: true, err: errors.New("connection refused")},
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			// A restricted recovery session must never reach an admin route
			// even if the underlying account holds the permission.
			name:       "restricted recovery session rejected",
			session:    &session.Session{ID: "sess-2", Kind: session.KindRecoveryEnrollment, UserID: actor.String()},
			checker:    &fakeChecker{allowed: true},
			wantStatus: http.StatusForbidden,
			wantDenial: true,
		},
		{
			name:    "unknown session kind rejected",
			session: &session.Session{ID: "sess-3", Kind: "future", UserID: actor.String()},
			checker: &fakeChecker{allowed: true}, wantStatus: http.StatusForbidden, wantDenial: true,
		},
		{
			name:    "empty legacy session kind rejected",
			session: &session.Session{ID: "sess-4", UserID: actor.String()},
			checker: &fakeChecker{allowed: true}, wantStatus: http.StatusForbidden, wantDenial: true,
		},
		{
			// Missing session = middleware wired wrongly = programming error.
			name:       "missing session is 500",
			session:    nil,
			checker:    &fakeChecker{allowed: true},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "malformed user id is 500",
			session:    authenticatedSession("not-a-uuid"),
			checker:    &fakeChecker{allowed: true},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorder := &fakeRecorder{}
			g, err := NewRequirePermission(tc.checker, testPermission, discardLogger(), WithRecorder(recorder))
			if err != nil {
				t.Fatalf("NewRequirePermission: %v", err)
			}

			var nextRan bool
			var seenActor uuid.UUID
			var seenActorOK bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextRan = true
				seenActor, seenActorOK = ActorFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			g.Handler(next).ServeHTTP(rec, newRequest(tc.session))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if nextRan != tc.wantNext {
				t.Fatalf("next handler ran = %v, want %v", nextRan, tc.wantNext)
			}
			if tc.wantNext {
				if !seenActorOK {
					t.Fatal("ActorFromContext reported no actor on the allow path")
				}
				if seenActor != actor {
					t.Fatalf("ActorFromContext = %s, want %s", seenActor, actor)
				}
			}

			denials := 0
			for _, e := range recorder.events {
				if e.EventType == audit.EventAdminAccessDenied {
					denials++
				}
			}
			if tc.wantDenial && denials != 1 {
				t.Fatalf("recorded %d access-denied events, want 1", denials)
			}
			if !tc.wantDenial && denials != 0 {
				t.Fatalf("recorded %d access-denied events, want 0", denials)
			}
		})
	}
}

// TestDenyBodyIsIdenticalAcrossCauses is the anti-enumeration guarantee: a
// caller must not be able to tell "permission not held" from "unknown
// permission id" or "restricted session". If these bodies ever diverge, the
// admin surface becomes an oracle for the capability model.
func TestDenyBodyIsIdenticalAcrossCauses(t *testing.T) {
	t.Parallel()

	actor := uuid.New()

	causes := []struct {
		name       string
		permission string
		session    *session.Session
		checker    *fakeChecker
	}{
		{
			name:       "permission not held",
			permission: testPermission,
			session:    authenticatedSession(actor.String()),
			checker:    &fakeChecker{allowed: false},
		},
		{
			// An id absent from the permissions table simply resolves false;
			// it must be indistinguishable from a real-but-ungranted id.
			name:       "unknown permission id",
			permission: "admin.does.not.exist",
			session:    authenticatedSession(actor.String()),
			checker:    &fakeChecker{allowed: false},
		},
		{
			name:       "restricted recovery session",
			permission: testPermission,
			session:    &session.Session{ID: "s", Kind: session.KindRecoveryEnrollment, UserID: actor.String()},
			checker:    &fakeChecker{allowed: true},
		},
	}

	type capture struct {
		status int
		body   []byte
		ctype  string
	}
	var got []capture

	for _, c := range causes {
		g, err := NewRequirePermission(c.checker, c.permission, discardLogger())
		if err != nil {
			t.Fatalf("NewRequirePermission(%s): %v", c.name, err)
		}
		rec := httptest.NewRecorder()
		g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, newRequest(c.session))

		got = append(got, capture{
			status: rec.Code,
			body:   rec.Body.Bytes(),
			ctype:  rec.Header().Get("Content-Type"),
		})
	}

	for i := 1; i < len(got); i++ {
		if got[i].status != got[0].status {
			t.Fatalf("%s status = %d, but %s status = %d; deny causes must be indistinguishable",
				causes[i].name, got[i].status, causes[0].name, got[0].status)
		}
		if !bytes.Equal(got[i].body, got[0].body) {
			t.Fatalf("%s body = %q, but %s body = %q; deny causes must be byte-identical",
				causes[i].name, got[i].body, causes[0].name, got[0].body)
		}
		if got[i].ctype != got[0].ctype {
			t.Fatalf("%s Content-Type = %q, but %s = %q", causes[i].name, got[i].ctype, causes[0].name, got[0].ctype)
		}
	}

	// And the body must not name the permission that was missing.
	var body errorResponse
	if err := json.Unmarshal(got[0].body, &body); err != nil {
		t.Fatalf("unmarshal deny body: %v", err)
	}
	if body.Error != "forbidden" {
		t.Fatalf("deny body error = %q, want %q", body.Error, "forbidden")
	}
	if bytes.Contains(got[0].body, []byte(testPermission)) {
		t.Fatalf("deny body %q leaks the permission id", got[0].body)
	}
}

// TestCheckerReceivesActorAndPermission proves the guard queries the capability
// graph with the session's subject rather than anything caller-controlled.
func TestCheckerReceivesActorAndPermission(t *testing.T) {
	t.Parallel()

	actor := uuid.New()
	checker := &fakeChecker{allowed: true}
	g, err := NewRequirePermission(checker, "legal.holds.write", discardLogger())
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}

	rec := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newRequest(authenticatedSession(actor.String())))

	if len(checker.calls) != 1 {
		t.Fatalf("UserHasPermission called %d times, want 1", len(checker.calls))
	}
	if checker.calls[0].UserID != actor {
		t.Fatalf("checked UserID = %s, want %s", checker.calls[0].UserID, actor)
	}
	if checker.calls[0].PermissionID != "legal.holds.write" {
		t.Fatalf("checked PermissionID = %q, want %q", checker.calls[0].PermissionID, "legal.holds.write")
	}
}

// TestNoPermissionCheckWithoutSession proves the guard does not consult the
// store at all when the chain is misassembled — a 500 path must not emit a
// database round trip that could be mistaken for an evaluated decision.
func TestNoPermissionCheckWithoutSession(t *testing.T) {
	t.Parallel()

	checker := &fakeChecker{allowed: true}
	g, err := NewRequirePermission(checker, testPermission, discardLogger())
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}

	rec := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newRequest(nil))

	if len(checker.calls) != 0 {
		t.Fatalf("UserHasPermission called %d times without a session, want 0", len(checker.calls))
	}
}

// TestDenialAuditPayload documents exactly what a tripwire event carries.
func TestDenialAuditPayload(t *testing.T) {
	t.Parallel()

	actor := uuid.New()
	recorder := &fakeRecorder{}
	g, err := NewRequirePermission(&fakeChecker{allowed: false}, testPermission, discardLogger(), WithRecorder(recorder))
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}

	rec := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newRequest(authenticatedSession(actor.String())))

	if len(recorder.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(recorder.events))
	}
	e := recorder.events[0]
	if e.EventType != audit.EventAdminAccessDenied {
		t.Fatalf("EventType = %q, want %q", e.EventType, audit.EventAdminAccessDenied)
	}
	if e.ActionStatus != audit.StatusFailure {
		t.Fatalf("ActionStatus = %q, want %q", e.ActionStatus, audit.StatusFailure)
	}
	if e.ActorID != actor {
		t.Fatalf("ActorID = %s, want %s", e.ActorID, actor)
	}
	if e.Payload["permission"] != testPermission {
		t.Fatalf("payload permission = %v, want %q", e.Payload["permission"], testPermission)
	}
	if e.Payload["reason"] != "permission_denied" {
		t.Fatalf("payload reason = %v, want %q", e.Payload["reason"], "permission_denied")
	}
	// Class C: an admin denial must never be ledgered.
	if e.Security != nil {
		t.Fatal("access-denied event carries a SecurityContext; admin events are Class C audit-only")
	}
}

// TestRecorderFailureDoesNotChangeOutcome: auditing observes the guard, it does
// not gate it. A broken audit transport must still produce a 403, not a 500.
func TestRecorderFailureDoesNotChangeOutcome(t *testing.T) {
	t.Parallel()

	g, err := NewRequirePermission(
		&fakeChecker{allowed: false},
		testPermission,
		discardLogger(),
		WithRecorder(&fakeRecorder{err: errors.New("bus unreachable")}),
	)
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}

	rec := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newRequest(authenticatedSession(uuid.New().String())))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d when the audit transport fails", rec.Code, http.StatusForbidden)
	}
}

// TestActorFromContextAbsent guards the accessor's zero-value contract.
func TestActorFromContextAbsent(t *testing.T) {
	t.Parallel()

	actor, ok := ActorFromContext(context.Background())
	if ok {
		t.Fatal("ActorFromContext reported an actor on a bare context")
	}
	if actor != uuid.Nil {
		t.Fatalf("ActorFromContext = %s, want uuid.Nil", actor)
	}
}

// TestDenyResponseIsNoStore: an authorization decision must not be cached.
func TestDenyResponseIsNoStore(t *testing.T) {
	t.Parallel()

	g, err := NewRequirePermission(&fakeChecker{allowed: false}, testPermission, discardLogger())
	if err != nil {
		t.Fatalf("NewRequirePermission: %v", err)
	}

	rec := httptest.NewRecorder()
	g.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, newRequest(authenticatedSession(uuid.New().String())))

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestLivePermissionChecksPrecedeGrantConsumption(t *testing.T) {
	key, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal(err)
	}
	nextKey, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal(err)
	}
	keyManager, err := keys.NewManager(key, nextKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := stepup.New(stepup.Config{Issuer: "https://identity.test"}, keyManager, &permissionTestUser{}, nil, &permissionTestUser{}, stepup.NewMemoryReplayGuard())
	if err != nil {
		t.Fatal(err)
	}
	stepGuard, err := stepup.NewRequireStepUp(steps, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	checker := &fakeChecker{}
	permissionGuard, err := NewRequirePermission(checker, testPermission, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	sess := authenticatedSession(uuid.NewString())
	grant, _, err := steps.Mint(stepup.MintParams{UserID: sess.UserID, SessionID: sess.ID, AMR: []string{"otp"}})
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	handler := permissionGuard.Handler(stepGuard.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	})))
	for _, tc := range []struct {
		allowed bool
		err     error
		status  int
	}{
		{false, nil, http.StatusForbidden},
		{true, errors.New("permission database unavailable"), http.StatusServiceUnavailable},
		{true, nil, http.StatusNoContent},
		{false, nil, http.StatusForbidden},
	} {
		checker.allowed, checker.err = tc.allowed, tc.err
		req := newRequest(sess)
		req.Header.Set(stepup.HeaderStepUpAuth, grant)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
		}
	}
	if called != 1 || len(checker.calls) != 4 {
		t.Fatalf("calls=%d permission reads=%d", called, len(checker.calls))
	}
	if _, err := steps.Validate(context.Background(), grant, *sess); !errors.Is(err, stepup.ErrGrantConsumed) {
		t.Fatalf("successful request did not consume grant: %v", err)
	}
}

type permissionTestUser struct{}

func (*permissionTestUser) GetUserByID(context.Context, uuid.UUID) (db.User, error) {
	return db.User{}, errors.New("grant validation must not reload MFA user data")
}

func (*permissionTestUser) VerifyEnabledCode(context.Context, uuid.UUID, string) error {
	return errors.New("grant validation must not reverify MFA")
}
