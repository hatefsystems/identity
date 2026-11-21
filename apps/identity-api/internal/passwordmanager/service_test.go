package passwordmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type passwordSessions struct {
	current session.Session
	err     error
	calls   int
}

func (s *passwordSessions) LookupByID(context.Context, string, string) (session.Session, error) {
	s.calls++
	return s.current, s.err
}

type passwordLimiter struct {
	allowed bool
	err     error
	calls   int
}

func (l *passwordLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	l.calls++
	return l.allowed, l.err
}

type passwordBeginner struct{ calls int }

func (d *passwordBeginner) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	d.calls++
	return nil, errors.New("unexpected transaction")
}

func passwordSession() session.Session {
	return session.Session{
		UserID: uuid.NewString(), ID: uuid.NewString(), Kind: session.KindAuthenticated,
		AuthVersion: 7, AuthVersionSet: true, DPoPJKT: "fixture-browser-binding",
		AbsoluteExpiry: time.Now().Add(time.Hour), IdleExpiry: time.Now().Add(time.Hour),
	}
}

func passwordGrant(sess session.Session) *stepup.Grant {
	return &stepup.Grant{
		UserID: sess.UserID, SessionID: sess.ID, AuthVersion: sess.AuthVersion,
		AuthVersionSet: true, DPoPJKT: sess.DPoPJKT,
		ExpiresAt: time.Now().Add(time.Minute), AMR: []string{"hwk", "user"},
	}
}

func TestNewRequiresBoundedSharedDependencies(t *testing.T) {
	sess := &passwordSessions{current: passwordSession()}
	database := &passwordBeginner{}
	limiter := &passwordLimiter{allowed: true}
	complete := Deps{DB: database, Queries: db.New(nil), Sessions: sess, Limiter: limiter}
	for _, missing := range []string{"database", "queries", "sessions", "limiter"} {
		t.Run(missing, func(t *testing.T) {
			deps := complete
			switch missing {
			case "database":
				deps.DB = nil
			case "queries":
				deps.Queries = nil
			case "sessions":
				deps.Sessions = nil
			case "limiter":
				deps.Limiter = nil
			}
			if svc, err := New(deps); svc != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("missing dependency admitted: service=%v error=%v", svc, err)
			}
		})
	}
	svc, err := New(complete)
	if err != nil || svc.hash == nil || svc.verify == nil {
		t.Fatalf("shared derivation hooks were not initialized: %v", err)
	}
}

func TestPasswordMutationRejectsInvalidInputBeforeAuthorityOrDerivation(t *testing.T) {
	for _, tc := range []struct {
		name, operation, secret string
		want                    error
	}{
		{"unknown operation", "replace", "private fixture secret", ErrInvalid},
		{"remove with secret", "remove", "private fixture secret", ErrInvalid},
		{"too few scalars", "add", strings.Repeat("\u0633", 14), password.ErrTooShort},
		{"too many bytes", "change", strings.Repeat("\U0001f600", 257), password.ErrTooLong},
		{"invalid UTF8", "add", strings.Repeat("a", 15) + "\xff", password.ErrInvalidUTF8},
		{"compromised", "change", "123456789012345", password.ErrCompromisedPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := passwordSession()
			sessions := &passwordSessions{current: current}
			limiter, database := &passwordLimiter{allowed: true}, &passwordBeginner{}
			svc, err := New(Deps{DB: database, Queries: db.New(nil), Sessions: sessions, Limiter: limiter})
			if err != nil {
				t.Fatal(err)
			}
			svc.hash = func(context.Context, string) (string, error) { t.Fatal("invalid input derived"); return "", nil }
			svc.verify = func(context.Context, string, string) (bool, error) {
				t.Fatal("invalid input verified")
				return false, nil
			}
			changed, err := svc.Mutate(t.Context(), current, tc.operation, tc.secret, Authorization{Grant: passwordGrant(current)}, "203.0.113.8")
			if changed || !errors.Is(err, tc.want) || sessions.calls != 0 || limiter.calls != 0 || database.calls != 0 {
				t.Fatalf("invalid input reached authority: changed=%v error=%v calls=%d/%d/%d", changed, err, sessions.calls, limiter.calls, database.calls)
			}
		})
	}
}

func TestPasswordGrantRequiresEveryEarnedBindingAndStrongFactor(t *testing.T) {
	for _, mutation := range []string{"subject", "session", "version", "missing version", "browser", "expiry", "password", "contact", "recovery", "UP without UV", "UV without hardware", "nil"} {
		t.Run(mutation, func(t *testing.T) {
			current := passwordSession()
			grant := passwordGrant(current)
			switch mutation {
			case "subject":
				grant.UserID = uuid.NewString()
			case "session":
				grant.SessionID = uuid.NewString()
			case "version":
				grant.AuthVersion++
			case "missing version":
				grant.AuthVersionSet = false
			case "browser":
				grant.DPoPJKT = "foreign-browser"
			case "expiry":
				grant.ExpiresAt = time.Now().Add(-time.Second)
			case "password":
				grant.AMR = []string{"pwd"}
			case "contact":
				grant.AMR = []string{"email"}
			case "recovery":
				grant.AMR = []string{"recovery_code"}
			case "UP without UV":
				grant.AMR = []string{"hwk"}
			case "UV without hardware":
				grant.AMR = []string{"user"}
			case "nil":
				grant = nil
			}
			if err := checkGrant(current, grant); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("invalid earned binding accepted: %v", err)
			}
		})
	}
	current := passwordSession()
	for _, amr := range [][]string{{"otp"}, {"hwk", "user"}} {
		grant := passwordGrant(current)
		grant.AMR = amr
		if err := checkGrant(current, grant); err != nil {
			t.Fatalf("strong factor rejected: %v", err)
		}
	}
}

func TestPasswordMutationLiveAuthorityAndExclusiveAuthorization(t *testing.T) {
	for _, mode := range []string{"missing", "foreign session", "changed version", "changed browser", "expired", "restricted", "backend down", "no authorization", "both authorizations", "proof for add", "proof disabled", "invalid IP", "rate denied", "rate unavailable"} {
		t.Run(mode, func(t *testing.T) {
			current := passwordSession()
			sessions := &passwordSessions{current: current}
			limiter, database := &passwordLimiter{allowed: true}, &passwordBeginner{}
			auth, operation, sourceIP, want := Authorization{Grant: passwordGrant(current)}, "change", "203.0.113.8", ErrUnauthorized
			switch mode {
			case "missing":
				sessions.err = session.ErrSessionNotFound
			case "foreign session":
				sessions.current.ID = uuid.NewString()
			case "changed version":
				sessions.current.AuthVersion++
			case "changed browser":
				sessions.current.DPoPJKT = "foreign"
			case "expired":
				sessions.current.IdleExpiry = time.Now().Add(-time.Second)
			case "restricted":
				sessions.current.Kind = session.KindRecoveryEnrollment
			case "backend down":
				sessions.err, want = errors.New("Redis unavailable"), ErrUnavailable
			case "no authorization":
				auth = Authorization{}
			case "both authorizations":
				auth.Proof = "opaque-proof"
			case "proof for add":
				auth, operation = Authorization{Proof: "opaque-proof"}, "add"
			case "proof disabled":
				auth = Authorization{Proof: "opaque-proof"}
			case "invalid IP":
				sourceIP, want = "invalid", ErrInvalid
			case "rate denied":
				limiter.allowed, want = false, ErrRateLimited
			case "rate unavailable":
				limiter.err, want = errors.New("Redis unavailable"), ErrUnavailable
			}
			svc, err := New(Deps{DB: database, Queries: db.New(nil), Sessions: sessions, Limiter: limiter})
			if err != nil {
				t.Fatal(err)
			}
			changed, err := svc.Mutate(t.Context(), current, operation, "private fixture secret", auth, sourceIP)
			if changed || !errors.Is(err, want) || database.calls != 0 {
				t.Fatalf("denial reached SQL: changed=%v error=%v transactions=%d", changed, err, database.calls)
			}
		})
	}
}
