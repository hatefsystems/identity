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

type testEvidenceAccountState struct {
	*testAccountState
	required bool
	checks   int
}

func (a *testEvidenceAccountState) ValidateEvidence(ctx context.Context, id string, version int64, kind Kind, evidence Evidence) error {
	a.checks++
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	if kind == KindAuthenticated && a.required && (!evidence.TOTPSet || !evidence.TOTP || evidence.AuthenticatedAt.IsZero()) {
		return ErrAccountIneligible
	}
	return nil
}

func (a *testEvidenceAccountState) WithActiveEvidence(ctx context.Context, id string, version int64, kind Kind, evidence Evidence, fn func() error) error {
	if err := a.ValidateEvidence(ctx, id, version, kind, evidence); err != nil {
		return err
	}
	return fn()
}

func TestCurrentMFAPolicyAtIssuanceUseAndRenewal(t *testing.T) {
	for _, method := range []string{MethodPassword, MethodContactCode, MethodPasskey, ""} {
		t.Run(method, func(t *testing.T) {
			now := time.Now().UTC()
			manager := newTestManager(t, &now)
			accounts := &testEvidenceAccountState{testAccountState: &testAccountState{active: true}}
			manager.accounts = accounts
			evidence := Evidence{}
			if method != "" {
				evidence = Evidence{PrimaryMethod: method, UV: UVNotApplicable, TOTPSet: true, AuthenticatedAt: now}
				if method == MethodPasskey {
					evidence.UV = UVVerified
				}
			}
			params := IssueParams{UserID: "subject", AuthVersionSet: true, Evidence: evidence}
			if method == MethodContactCode {
				if _, err := manager.Issue(httptest.NewRecorder(), params); !errors.Is(err, ErrAccountIneligible) {
					t.Fatal("contact context was optional")
				}
				params.CheckPrimaryFactor = func(ctx context.Context) error { return ctx.Err() }
			}
			w := httptest.NewRecorder()
			issued, err := manager.Issue(w, params)
			if err != nil || issued.Evidence != evidence {
				t.Fatalf("evidence changed at issuance: %+v %v", issued.Evidence, err)
			}
			accounts.required = true
			denied := httptest.NewRecorder()
			if _, err := manager.Issue(denied, params); !errors.Is(err, ErrAccountIneligible) || len(denied.Result().Cookies()) != 0 {
				t.Fatalf("required MFA issued session/cookie: %v", err)
			}
			request := requestWithCookies(w)
			if _, err := manager.Resolve(request); !errors.Is(err, ErrAccountIneligible) {
				t.Fatalf("current MFA bypass on use: %v", err)
			}
			if _, err := manager.renew(request, issued); !errors.Is(err, ErrAccountIneligible) {
				t.Fatalf("current MFA bypass after resolve: %v", err)
			}
			if method == "" {
				return
			}
			params.Evidence.TOTP = true
			fresh := httptest.NewRecorder()
			if _, err := manager.Issue(fresh, params); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Minute)
			resolved, err := manager.Authenticate(requestWithCookies(fresh))
			if err != nil || resolved.Evidence != params.Evidence || accounts.checks < 6 {
				t.Fatalf("earned evidence lost on renewal: %+v %v", resolved.Evidence, err)
			}
		})
	}
}
