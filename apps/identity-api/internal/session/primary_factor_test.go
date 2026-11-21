package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type primaryFactorAccount struct {
	testAccountState
	locked bool
}

func (a *primaryFactorAccount) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	a.locked = true
	defer func() { a.locked = false }()
	return fn()
}

func TestMutablePrimaryFactorIsCheckedInsideIssuanceAuthority(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		failure error
	}{{"valid", nil}, {"revoked", ErrAccountIneligible}, {"unavailable", ErrStoreUnavailable}} {
		failure := scenario.failure
		t.Run(scenario.name, func(t *testing.T) {
			now := time.Now().UTC()
			manager := newTestManager(t, &now)
			accounts := &primaryFactorAccount{testAccountState: testAccountState{active: true}}
			manager.accounts = accounts
			called := false
			params := IssueParams{UserID: "subject", AuthVersionSet: true,
				Evidence: Evidence{PrimaryMethod: MethodContactCode, UV: UVNotApplicable, TOTPSet: true, AuthenticatedAt: now},
				CheckPrimaryFactor: func(ctx context.Context) error {
					if !accounts.locked || ctx.Err() != nil {
						t.Fatal("mutable proof checked outside issuance authority")
					}
					called = true
					return failure
				}}
			body, err := json.Marshal(params)
			if err != nil || strings.Contains(string(body), "CheckPrimaryFactor") {
				t.Fatal("runtime proof callback entered persisted state")
			}
			response := httptest.NewRecorder()
			_, err = manager.Issue(response, params)
			if !called || accounts.locked {
				t.Fatal("issuance did not complete the locked proof check")
			}
			records, listErr := manager.List(context.Background(), params.UserID)
			if listErr != nil {
				t.Fatal(listErr)
			}
			if failure != nil {
				if !errors.Is(err, failure) || len(records) != 0 || len(response.Result().Cookies()) != 0 {
					t.Fatalf("rejected proof minted authority: %v", err)
				}
			} else if err != nil || len(records) != 1 || len(response.Result().Cookies()) != 1 {
				t.Fatalf("valid proof did not issue session: %v", err)
			}
		})
	}
}
