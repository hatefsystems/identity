package webauthn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type ceremonyEpoch struct {
	next atomic.Int64
}

func (e *ceremonyEpoch) Epoch(context.Context) (int64, error) { return e.next.Add(1), nil }
func (*ceremonyEpoch) Validate(context.Context, string, int64) error {
	return errors.New("unexpected account validation: WebAuthn uses its user store")
}
func (*ceremonyEpoch) WithActive(context.Context, string, int64, func() error) error {
	return errors.New("unexpected account issuance: WebAuthn uses its transaction")
}

func restrictAndReactivate(f *ceremonyFixture, epoch *ceremonyEpoch) {
	f.users.mu.Lock()
	defer f.users.mu.Unlock()
	u := f.users.byID[f.user.ID]
	for _, status := range []string{"banned", "active"} {
		u.Status = status
		u.AuthVersion++
		u.AuthEpoch = epoch.next.Add(1)
	}
	f.users.byID[u.ID] = u
}

func TestLoginCeremoniesCannotReviveAcrossInstances(t *testing.T) {
	for _, discoverable := range []bool{false, true} {
		name := "named"
		if discoverable {
			name = "discoverable"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.register(t, f.auth)
			epoch := &ceremonyEpoch{}
			other := newFixture(t).svc
			other.users, other.creds = f.users, f.creds
			f.svc.accounts, other.accounts = epoch, epoch
			begin := func(svc *Service) []byte {
				t.Helper()
				var options *protocol.CredentialAssertion
				var err error
				if discoverable {
					options, err = svc.BeginDiscoverableLogin(f.ctx())
				} else {
					options, err = svc.BeginLogin(f.ctx(), f.user.Email)
				}
				if err != nil {
					t.Fatal(err)
				}
				return f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))
			}
			instances := []*Service{f.svc, other}
			bodies := [][]byte{begin(instances[0]), begin(instances[1])}
			restrictAndReactivate(f, epoch)
			for i, svc := range instances {
				if result, err := svc.FinishLoginVersioned(f.ctx(), bodies[i]); err == nil || result.ID != uuid.Nil {
					t.Fatalf("instance %d revived pre-ban ceremony: %+v %v", i, result, err)
				}
			}
			if len(f.creds.updated) != 0 {
				t.Fatal("stale ceremony updated authenticator counter")
			}
			for i, svc := range instances {
				result, err := svc.FinishLoginVersioned(f.ctx(), begin(svc))
				if err != nil || result.ID != f.user.ID || result.AuthVersion != 2 {
					t.Fatalf("instance %d fresh login: %+v %v", i, result, err)
				}
			}
		})
	}
}

// The barrier models a restriction winning after cryptographic verification but
// before the transaction locks and re-reads the account.
type accountLockBarrier struct {
	UserStore
	entered chan struct{}
	release chan struct{}
}

func (b *accountLockBarrier) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	close(b.entered)
	select {
	case <-b.release:
		return b.UserStore.GetUserByIDForUpdate(ctx, id)
	case <-ctx.Done():
		return db.User{}, ctx.Err()
	}
}

func TestCeremonyCommitRechecksVersionAfterConcurrentReactivation(t *testing.T) {
	for _, flow := range []Flow{FlowLoginNamed, FlowLoginDiscoverable, FlowRegistration, FlowRecoveryRegistration, FlowStepUp} {
		t.Run(flow.String(), func(t *testing.T) {
			f := newFixture(t)
			f.register(t, f.auth)
			epoch := &ceremonyEpoch{}
			f.svc.accounts = epoch
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			kind := session.KindAuthenticated
			if flow == FlowRecoveryRegistration {
				kind = session.KindRecoveryEnrollment
			}
			ctx = session.WithSession(ctx, session.Session{ID: "test-session", UserID: f.user.ID.String(), Kind: kind, AuthVersionSet: true})
			var finish func() error
			switch flow {
			case FlowRegistration, FlowRecoveryRegistration:
				options, err := f.svc.beginRegistration(ctx, f.user.ID, "test-session", flow, flow == FlowRecoveryRegistration)
				if err != nil {
					t.Fatal(err)
				}
				body := newSoftAuthenticator(t).attestation(challengeOf(options.Response.Challenge))
				finish = func() error {
					_, err := f.svc.finishRegistration(ctx, f.user.ID, "test-session", flow, flow == FlowRecoveryRegistration, body)
					return err
				}
			case FlowStepUp:
				options, err := f.svc.BeginStepUp(ctx, f.user.ID, "test-session")
				if err != nil {
					t.Fatal(err)
				}
				body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))
				finish = func() error { return f.svc.FinishStepUp(ctx, f.user.ID, "test-session", body) }
			default:
				var options *protocol.CredentialAssertion
				var err error
				if flow == FlowLoginNamed {
					options, err = f.svc.BeginLogin(ctx, f.user.Email)
				} else {
					options, err = f.svc.BeginDiscoverableLogin(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))
				finish = func() error { _, err := f.svc.FinishLoginVersioned(ctx, body); return err }
			}
			barrier := &accountLockBarrier{UserStore: f.users, entered: make(chan struct{}), release: make(chan struct{})}
			f.svc.users = barrier
			result := make(chan error, 1)
			go func() { result <- finish() }()
			select {
			case <-barrier.entered:
			case err := <-result:
				t.Fatalf("ceremony failed before account lock: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			restrictAndReactivate(f, epoch)
			close(barrier.release)
			if err := <-result; !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("concurrent cutoff not enforced: %v", err)
			}
			if len(f.creds.updated) != 0 || len(f.creds.byUser[f.user.ID]) != 1 {
				t.Fatal("stale ceremony persisted credential changes")
			}
		})
	}
}
