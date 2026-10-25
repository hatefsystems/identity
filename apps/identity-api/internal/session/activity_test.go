package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
)

type activityTestStore struct {
	Store
	touches  int
	touchErr error
	getErr   error
}

func (s *activityTestStore) Touch(ctx context.Context, hash string, expiry time.Time) error {
	s.touches++
	if s.touchErr != nil {
		return s.touchErr
	}
	return s.Store.Touch(ctx, hash, expiry)
}

func (s *activityTestStore) Get(ctx context.Context, hash string) (Session, error) {
	if s.getErr != nil {
		return Session{}, s.getErr
	}
	return s.Store.Get(ctx, hash)
}

func TestResolveDoesNotRenewActivity(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	store := &activityTestStore{Store: m.store}
	m.store = store
	issue := httptest.NewRecorder()
	issued, err := m.Issue(issue, IssueParams{UserID: "user", DPoPJKT: "key"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	resolved, err := m.Resolve(requestWithCookies(issue))
	if err != nil {
		t.Fatal(err)
	}
	if store.touches != 0 || !resolved.IdleExpiry.Equal(issued.IdleExpiry) || !resolved.LastSeenAt.Equal(issued.LastSeenAt) {
		t.Fatal("resolving a cookie renewed activity before authorization")
	}
}

func TestActivityOnlyAfterFullAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name   string
		jkt    string
		proof  string
		kind   Kind
		status int
		want   int
		touch  int
	}{
		{name: "unbound", status: 200, want: 401},
		{name: "missing proof", jkt: "key", status: 200, want: 401},
		{name: "wrong proof", jkt: "key", proof: "other", status: 200, want: 401},
		{name: "wrong kind", jkt: "key", proof: "key", kind: KindRecoveryEnrollment, status: 200, want: 401},
		{name: "stepup or rbac denied", jkt: "key", proof: "key", status: 403, want: 403},
		{name: "invalid body", jkt: "key", proof: "key", status: 400, want: 400},
		{name: "downstream unavailable", jkt: "key", proof: "key", status: 503, want: 503},
		{name: "successful read", jkt: "key", proof: "key", status: 200, want: 200, touch: 1},
		{name: "successful mutation", jkt: "key", proof: "key", status: 204, want: 204, touch: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			m := newTestManager(t, &now)
			store := &activityTestStore{Store: m.store}
			m.store = store
			issue := httptest.NewRecorder()
			issued, err := m.Issue(issue, IssueParams{UserID: "user", DPoPJKT: tc.jkt, Kind: tc.kind})
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			r := requestWithCookies(issue)
			if tc.proof != "" {
				r = r.WithContext(dpop.WithProof(r.Context(), &dpop.Proof{JKT: tc.proof}))
			}
			response := httptest.NewRecorder()
			newGuard(t, m).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})).ServeHTTP(response, r)
			if response.Code != tc.want || store.touches != tc.touch {
				t.Fatalf("status=%d touches=%d, want %d/%d", response.Code, store.touches, tc.want, tc.touch)
			}
			current, err := m.Resolve(r)
			if err != nil {
				t.Fatal(err)
			}
			if tc.touch == 0 && (!current.IdleExpiry.Equal(issued.IdleExpiry) || !current.LastSeenAt.Equal(issued.LastSeenAt)) {
				t.Fatal("denial changed activity timestamps")
			}
			if tc.touch == 1 && !current.IdleExpiry.After(issued.IdleExpiry) {
				t.Fatal("authorized request did not renew activity")
			}
		})
	}
}

func TestActivityDependencyFailureWithholdsHandlerBody(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	store := &activityTestStore{Store: m.store, touchErr: errors.New("unavailable")}
	m.store = store
	issue := httptest.NewRecorder()
	if _, err := m.Issue(issue, IssueParams{UserID: "user", DPoPJKT: "key"}); err != nil {
		t.Fatal(err)
	}
	r := requestWithCookies(issue)
	r = r.WithContext(dpop.WithProof(r.Context(), &dpop.Proof{JKT: "key"}))
	response := httptest.NewRecorder()
	newGuard(t, m).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"codes":["ONE-TIME-SECRET"]}`))
	})).ServeHTTP(response, r)
	if response.Code != 503 || strings.Contains(response.Body.String(), "ONE-TIME-SECRET") || !strings.Contains(response.Body.String(), "temporarily_unavailable") {
		t.Fatalf("dependency failure released an unsafe response: %d %s", response.Code, response.Body.String())
	}
	store.getErr = errors.New("database or Redis unavailable")
	response = httptest.NewRecorder()
	newGuard(t, m).Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler admitted") })).ServeHTTP(response, r)
	if response.Code != 503 || response.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("dependency error was misclassified as cookie/session loss")
	}
}
