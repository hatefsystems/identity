package webauthn

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func TestCredentialPolicyListingMatchesDeletion(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		f := newFixture(t)
		for range count {
			f.register(t, newSoftAuthenticator(t))
		}
		rows, err := f.svc.ListCredentialsWithPolicy(f.ctx(), f.user.ID)
		if err != nil || rows == nil || len(rows) != count {
			t.Fatalf("listing count=%d: %v, %v", count, rows, err)
		}
		for _, row := range rows {
			if row.CanRemove != (count > 1) {
				t.Fatalf("listing count=%d: can_remove=%v", count, row.CanRemove)
			}
		}
		if count > 0 {
			err := f.svc.DeleteCredential(f.ctx(), f.user.ID, rows[0].ID)
			if (err == nil) != rows[0].CanRemove {
				t.Fatalf("listing/deletion disagree: can_remove=%v err=%v", rows[0].CanRemove, err)
			}
		}
	}
}

func TestPolicyOperationsRecheckSessionAuthority(t *testing.T) {
	for _, list := range []bool{false, true} {
		f := newFixture(t)
		row := f.register(t, f.auth)
		f.register(t, newSoftAuthenticator(t))
		f.svc.accounts = &ceremonyEpoch{}
		for _, current := range []session.Session{
			{UserID: f.user.ID.String(), AuthVersion: 1, AuthVersionSet: true},
			{UserID: f.user.ID.String()},
			{UserID: uuid.NewString(), AuthVersionSet: true},
		} {
			ctx := session.WithSession(f.ctx(), current)
			var err error
			if list {
				_, err = f.svc.ListCredentialsWithPolicy(ctx, f.user.ID)
			} else {
				err = f.svc.DeleteCredential(ctx, f.user.ID, row.ID)
			}
			if !errors.Is(err, ErrAccountNotActive) || f.creds.count(f.user.ID) != 2 {
				t.Fatalf("list=%v accepted stale/substituted authority: %v", list, err)
			}
		}
	}
}

func TestDatabaseStoresCannotBypassTransactions(t *testing.T) {
	f := newFixture(t)
	for _, users := range []bool{false, true} {
		if users {
			f.svc.users = db.New(nil)
		} else {
			f.svc.creds = db.New(nil)
		}
		called := false
		err := f.svc.runInTx(context.Background(), func(UserStore, CredentialStore) error {
			called = true
			return nil
		})
		if err == nil || called {
			t.Fatal("production store ran without a transaction")
		}
	}
}

func TestMissingPolicyAuthorityFailsBeforeAccountLock(t *testing.T) {
	f := newFixture(t)
	ft := &fakeTransacter{}
	f.svc.tx = ft
	f.svc.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true})
	err := f.svc.DeleteCredential(f.ctx(), f.user.ID, []byte("credential"))
	if !errors.Is(err, username.ErrUnavailable) || !ft.rollbackCalled || ft.commitCalled {
		t.Fatalf("missing policy authority did not fail closed: %v", err)
	}
	if len(ft.statements) != 1 || ft.statements[0] != "SET TRANSACTION ISOLATION LEVEL READ COMMITTED" {
		t.Fatalf("account lock preceded authority admission: %v", ft.statements)
	}
}

func TestSharedProtectionErrorIdentity(t *testing.T) {
	if !errors.Is(ErrLastCredential, accountpolicy.ErrLastCredential) || !errors.Is(ErrLastFactor, accountpolicy.ErrLastFactor) {
		t.Fatal("passkey errors lost shared policy identity")
	}
}
