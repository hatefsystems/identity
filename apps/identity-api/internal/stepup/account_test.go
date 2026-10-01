package stepup

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

type grantAccountState struct {
	version   atomic.Int64
	blocked   atomic.Bool
	err       error
	commitErr error
}

func (a *grantAccountState) Validate(_ context.Context, _ string, version int64) error {
	if a.err != nil {
		return a.err
	}
	if a.blocked.Load() || a.version.Load() != version {
		return session.ErrAccountIneligible
	}
	return nil
}

func (a *grantAccountState) WithActive(ctx context.Context, id string, version int64, fn func() error) error {
	if err := a.Validate(ctx, id, version); err != nil {
		return err
	}
	if err := fn(); err != nil {
		return err
	}
	return a.commitErr
}

func (*grantAccountState) Epoch(context.Context) (int64, error) { return 1, nil }

func TestGrantsCannotReviveAcrossInstances(t *testing.T) {
	first, _ := newTestService(t)
	second, _ := newTestService(t)
	state := &grantAccountState{}
	// Versions are BIGINTs; the signed claim must not lose precision through JSON.
	state.version.Store(1<<53 + 1)
	first.accounts, second.accounts = state, state
	second.keys, second.guard = first.keys, first.guard
	sess := session.Session{ID: "session", UserID: uuid.NewString(), Kind: session.KindAuthenticated, AuthVersion: state.version.Load(), AuthVersionSet: true}
	p := MintParams{UserID: sess.UserID, SessionID: sess.ID, AMR: amrTOTP, AuthVersion: sess.AuthVersion, AuthVersionSet: true}
	old, _, err := first.Mint(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []bool{true, false} {
		state.blocked.Store(banned)
		state.version.Add(1)
		for _, svc := range []*Service{first, second} {
			if grant, err := svc.Validate(context.Background(), old, sess); !errors.Is(err, ErrGrantNotForSession) || grant != nil {
				t.Fatalf("banned=%v: stale grant=%v err=%v", banned, grant, err)
			}
			if compact, _, err := svc.Mint(p); !errors.Is(err, ErrAccountNotActive) || compact != "" {
				t.Fatalf("banned=%v: restamped grant, err=%v", banned, err)
			}
		}
	}
	p.AuthVersion, sess.AuthVersion = state.version.Load(), state.version.Load()
	fresh, _, err := first.Mint(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Validate(context.Background(), fresh, sess); err != nil {
		t.Fatalf("fresh authentication after reactivation: %v", err)
	}
	if _, err := first.Validate(context.Background(), fresh, sess); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("cross-instance replay: %v", err)
	}
}

func TestGrantAccountFailureReturnsNoArtifactAndDoesNotConsume(t *testing.T) {
	svc, _ := newTestService(t)
	state := &grantAccountState{}
	svc.accounts = state
	sess := session.Session{ID: "session", UserID: uuid.NewString(), Kind: session.KindAuthenticated, AuthVersionSet: true}
	p := MintParams{UserID: sess.UserID, SessionID: sess.ID, AMR: amrTOTP, AuthVersionSet: true}
	compact, _, err := svc.Mint(p)
	if err != nil {
		t.Fatal(err)
	}
	state.err = errors.New("database unavailable")
	if grant, err := svc.Validate(context.Background(), compact, sess); !errors.Is(err, state.err) || grant != nil {
		t.Fatalf("account outage: grant=%v err=%v", grant, err)
	}
	state.err = nil
	if _, err := svc.Validate(context.Background(), compact, sess); err != nil {
		t.Fatalf("outage burned grant: %v", err)
	}
	state.commitErr = errors.New("commit outcome unknown")
	if compact, expires, err := svc.Mint(p); !errors.Is(err, state.commitErr) || compact != "" || !expires.IsZero() {
		t.Fatalf("failed commit exposed artifact: token present=%v expires=%v err=%v", compact != "", expires, err)
	}
}

func TestChallengeRequiresCurrentAuthenticatedSession(t *testing.T) {
	user := db.User{ID: uuid.New(), Status: "active", AuthVersion: 2, IsMfaEnabled: true}
	valid := session.Session{ID: "session", UserID: user.ID.String(), Kind: session.KindAuthenticated, AuthVersion: 2, AuthVersionSet: true}
	for _, name := range []string{"valid", "missing", "stale", "unstamped", "recovery", "unknown", "foreign session", "foreign user"} {
		t.Run(name, func(t *testing.T) {
			svc := newServiceWith(t, &fakeUserStore{user: user}, nil, &fakeTOTP{}, nil)
			svc.accounts = &grantAccountState{}
			sess := valid
			switch name {
			case "stale":
				sess.AuthVersion = 0
			case "unstamped":
				sess.AuthVersionSet = false
			case "recovery":
				sess.Kind = session.KindRecoveryEnrollment
			case "unknown":
				sess.Kind = ""
			case "foreign session":
				sess.ID = "other"
			case "foreign user":
				sess.UserID = uuid.NewString()
			}
			ctx := context.Background()
			if name != "missing" {
				ctx = session.WithSession(ctx, sess)
			}
			result, err := svc.Challenge(ctx, user.ID, valid.ID)
			if name == "valid" {
				if err != nil || len(result.Methods) != 1 || result.Methods[0] != MethodTOTP {
					t.Fatalf("valid challenge: %+v %v", result, err)
				}
			} else if !errors.Is(err, ErrAccountNotActive) || result != nil {
				t.Fatalf("stale session disclosed factors: %+v %v", result, err)
			}
		})
	}
}

func TestChallengeDoesNotFallbackAfterConcurrentAccountRestriction(t *testing.T) {
	for _, tc := range []struct{ passkeyErr, want error }{
		{webauthn.ErrAccountNotActive, ErrAccountNotActive},
		{webauthn.ErrUserNotFound, ErrUserNotFound},
	} {
		svc := newServiceWith(t, &fakeUserStore{user: db.User{IsMfaEnabled: true}}, &fakePasskeys{beginErr: tc.passkeyErr}, &fakeTOTP{}, nil)
		if result, err := svc.Challenge(context.Background(), uuid.New(), "session"); !errors.Is(err, tc.want) || result != nil {
			t.Fatalf("restriction fell back to TOTP: %+v %v", result, err)
		}
	}
}

type blockedTOTP struct {
	entered chan struct{}
	release chan struct{}
}

func (f *blockedTOTP) VerifyEnabledCode(ctx context.Context, _ uuid.UUID, _ string) error {
	close(f.entered)
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestVerifyCannotRestampFactorAcrossBanAndReactivation(t *testing.T) {
	user := db.User{ID: uuid.New(), Status: "active"}
	factor := &blockedTOTP{entered: make(chan struct{}), release: make(chan struct{})}
	svc := newServiceWith(t, &fakeUserStore{user: user}, nil, factor, nil)
	state := &grantAccountState{}
	svc.accounts = state
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = session.WithSession(ctx, session.Session{ID: "session", UserID: user.ID.String(), Kind: session.KindAuthenticated, AuthVersionSet: true})
	result := make(chan error, 1)
	go func() {
		compact, _, err := svc.Verify(ctx, VerifyParams{UserID: user.ID, SessionID: "session", Method: MethodTOTP, Code: "123456"})
		if compact != "" {
			err = errors.New("in-flight pre-ban factor minted a grant")
		}
		result <- err
	}()
	select {
	case <-factor.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	state.version.Store(2)
	close(factor.release)
	if err := <-result; !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("factor completed across ban/reactivation: %v", err)
	}
}
