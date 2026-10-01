package session

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

type testAccountState struct {
	version int64
	active  bool
	err     error
}

func (a *testAccountState) Validate(_ context.Context, _ string, version int64) error {
	if a.err != nil {
		return a.err
	}
	if !a.active || a.version != version {
		return ErrAccountIneligible
	}
	return nil
}
func (a *testAccountState) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	return fn()
}
func (*testAccountState) Epoch(context.Context) (int64, error) { return 1, nil }

func TestAccountVersionCannotResurrectSessionsAcrossManagers(t *testing.T) {
	for _, kind := range []Kind{KindAuthenticated, KindRecoveryEnrollment} {
		t.Run(string(kind), func(t *testing.T) {
			now := time.Now()
			state := &testAccountState{active: true}
			first, second := newTestManager(t, &now), newTestManager(t, &now)
			first.accounts, second.accounts = state, state
			issued := make([]*httptest.ResponseRecorder, 0, 2)
			for _, manager := range []*Manager{first, second} {
				rec := httptest.NewRecorder()
				if _, err := manager.Issue(rec, IssueParams{UserID: "subject", Kind: kind, AuthVersionSet: true}); err != nil {
					t.Fatal(err)
				}
				issued = append(issued, rec)
			}
			state.active, state.version = false, 1
			for i, manager := range []*Manager{first, second} {
				if _, err := manager.Authenticate(requestWithCookies(issued[i])); !errors.Is(err, ErrAccountIneligible) {
					t.Fatalf("banned session: %v", err)
				}
			}
			state.active, state.version = true, 2
			for i, manager := range []*Manager{first, second} {
				if _, err := manager.Authenticate(requestWithCookies(issued[i])); !errors.Is(err, ErrAccountIneligible) {
					t.Fatalf("resurrected session: %v", err)
				}
				stale := httptest.NewRecorder()
				if _, err := manager.Issue(stale, IssueParams{UserID: "subject", Kind: kind, AuthVersionSet: true}); !errors.Is(err, ErrAccountIneligible) {
					t.Fatalf("restamped ceremony: %v", err)
				}
				if len(stale.Result().Cookies()) != 0 {
					t.Fatal("failed issuance wrote cookie")
				}
				fresh := httptest.NewRecorder()
				if _, err := manager.Issue(fresh, IssueParams{UserID: "subject", Kind: kind, AuthVersion: 2, AuthVersionSet: true}); err != nil {
					t.Fatal(err)
				}
				if _, err := manager.Authenticate(requestWithCookies(fresh)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestAccountStateFailsClosedOnMissingSnapshotAndStorageFailure(t *testing.T) {
	now := time.Now()
	m := newTestManager(t, &now)
	state := &testAccountState{active: true}
	m.accounts = state
	if _, err := m.Issue(httptest.NewRecorder(), IssueParams{UserID: "subject"}); !errors.Is(err, ErrAccountIneligible) {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := m.Issue(rec, IssueParams{UserID: "subject", AuthVersionSet: true}); err != nil {
		t.Fatal(err)
	}
	state.err = errors.New("database unavailable")
	if _, err := m.Authenticate(requestWithCookies(rec)); !errors.Is(err, state.err) {
		t.Fatalf("storage failure: %v", err)
	}
	if _, err := m.Issue(httptest.NewRecorder(), IssueParams{UserID: "subject", AuthVersionSet: true}); !errors.Is(err, state.err) {
		t.Fatal(err)
	}
}
