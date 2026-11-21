// Package passwordmanager performs freshly authorized, version-fenced password mutations.
package passwordmanager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

// Errors expose only fixed categories, never credential or dependency details.
var (
	ErrInvalid        = errors.New("passwordmanager: invalid request")
	ErrUnauthorized   = errors.New("passwordmanager: fresh authority unavailable")
	ErrConflict       = errors.New("passwordmanager: operation conflicts with account state")
	ErrUnavailable    = errors.New("passwordmanager: dependency unavailable")
	ErrRateLimited    = errors.New("passwordmanager: rate limited")
	ErrOutcomeUnknown = errors.New("passwordmanager: commit outcome unknown")
)

// Beginner opens short caller-owned transactions without retries.
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// SessionReader checks live Redis authority without renewing or acquiring SQL locks.
type SessionReader interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// Proofs admits only password-change authority and consumes it with the mutation.
type Proofs interface {
	CheckPasswordChange(context.Context, session.Session, string) error
	ConsumePasswordChangeTx(context.Context, pgx.Tx, session.Session, string) error
}

// Deps shares current login policy, rate admission and account/session infrastructure.
type Deps struct {
	DB       Beginner
	Queries  *db.Queries
	Sessions SessionReader
	Limiter  ratelimit.Limiter
	Policy   accountpolicy.Policy
	Proofs   Proofs
}

// Authorization contains exactly one admitted Step-up grant or purpose-bound proof.
type Authorization struct {
	Grant *stepup.Grant
	Proof string
}

// Service does not issue sessions or retain plaintext passwords.
type Service struct {
	deps   Deps
	hash   func(context.Context, string) (string, error)
	verify func(context.Context, string, string) (bool, error)
}

// New requires shared bounded infrastructure; proof issuance can remain disabled.
func New(deps Deps) (*Service, error) {
	if deps.DB == nil || deps.Queries == nil || deps.Sessions == nil || deps.Limiter == nil {
		return nil, ErrUnavailable
	}
	return &Service{deps: deps, hash: password.HashContext, verify: password.VerifyContext}, nil
}

func (s *Service) live(ctx context.Context, sess session.Session) error {
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil || id.String() != sess.UserID || sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.AuthVersion < 0 || sess.ID == "" || sess.DPoPJKT == "" {
		return ErrUnauthorized
	}
	current, err := s.deps.Sessions.LookupByID(ctx, sess.UserID, sess.ID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return ErrUnauthorized
		}
		return ErrUnavailable
	}
	now := time.Now()
	if current.UserID != sess.UserID || current.ID != sess.ID || current.Kind != session.KindAuthenticated || !current.AuthVersionSet || current.AuthVersion != sess.AuthVersion || current.DPoPJKT != sess.DPoPJKT || !now.Before(current.AbsoluteExpiry) || !now.Before(current.IdleExpiry) {
		return ErrUnauthorized
	}
	return nil
}

func checkGrant(sess session.Session, grant *stepup.Grant) error {
	if grant == nil || grant.UserID != sess.UserID || grant.SessionID != sess.ID || !grant.AuthVersionSet || grant.AuthVersion != sess.AuthVersion || grant.DPoPJKT != sess.DPoPJKT || !time.Now().Before(grant.ExpiresAt) {
		return ErrUnauthorized
	}
	if !slices.Contains(grant.AMR, "otp") && (!slices.Contains(grant.AMR, "hwk") || !slices.Contains(grant.AMR, "user")) {
		return ErrUnauthorized
	}
	return nil
}

// Mutate derives outside all account locks, then rechecks every earned binding.
// A false result is an authorized no-op that preserves the verifier and session.
func (s *Service) Mutate(ctx context.Context, sess session.Session, operation, secret string, auth Authorization, sourceIP string) (bool, error) {
	if operation != "add" && operation != "change" && operation != "remove" || operation == "remove" && secret != "" {
		return false, ErrInvalid
	}
	if operation != "remove" {
		if err := password.Validate(secret); err != nil {
			return false, err
		}
	}
	if err := s.live(ctx, sess); err != nil {
		return false, err
	}
	if (auth.Grant == nil) == (auth.Proof == "") {
		return false, ErrUnauthorized
	}
	if auth.Proof != "" {
		if operation != "change" || s.deps.Proofs == nil {
			return false, ErrUnauthorized
		}
		if err := s.deps.Proofs.CheckPasswordChange(ctx, sess, auth.Proof); err != nil {
			return false, err
		}
	} else if err := checkGrant(sess, auth.Grant); err != nil {
		return false, err
	}
	subnet := ratelimit.Subnet(sourceIP)
	if sourceIP == "" || strings.HasPrefix(subnet, "invalid/") {
		return false, ErrInvalid
	}
	for _, budget := range []struct {
		key   string
		limit int
	}{
		{"rate:actionproof:password:mutation:account:" + sess.UserID, 5},
		{"rate:actionproof:password:mutation:source:" + subnet, 20},
	} {
		allowed, err := s.deps.Limiter.Allow(ctx, budget.key, budget.limit, time.Minute)
		if err != nil {
			return false, ErrUnavailable
		}
		if !allowed {
			return false, ErrRateLimited
		}
	}
	id, _ := uuid.Parse(sess.UserID)
	expected, err := s.deps.Queries.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUnauthorized
	}
	if err != nil {
		return false, ErrUnavailable
	}
	if expected.Status != "active" || expected.DeletedAt.Valid || expected.AuthVersion != sess.AuthVersion {
		return false, ErrUnauthorized
	}
	if operation != "remove" && (!s.deps.Policy.PasswordLoginEnabled || operation == "add" && expected.PasswordHash != nil || operation == "change" && expected.PasswordHash == nil) {
		return false, ErrConflict
	}
	// Capture the policy epoch before deriving, releasing its lock immediately.
	preflightCtx, preflightCancel := context.WithTimeout(ctx, 10*time.Second)
	preflight, err := s.deps.DB.BeginTx(preflightCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		preflightCancel()
		return false, ErrUnavailable
	}
	authority, err := s.deps.Policy.Guard(preflightCtx, preflight)
	rollback(preflightCtx, preflight)
	preflightCancel()
	if err != nil {
		return false, err
	}
	var proposed *string
	noop := operation == "remove" && expected.PasswordHash == nil
	if operation == "change" {
		noop, err = s.verify(ctx, secret, *expected.PasswordHash)
		if err != nil {
			return false, err
		}
		if noop {
			proposed = expected.PasswordHash
		}
	}
	if operation != "remove" && !noop {
		hash, err := s.hash(ctx, secret)
		if err != nil {
			return false, err
		}
		proposed = &hash
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, ErrUnavailable
	}
	defer rollback(ctx, tx)
	currentAuthority, err := s.deps.Policy.Guard(ctx, tx)
	if err != nil {
		return false, err
	}
	if currentAuthority != authority {
		return false, ErrUnauthorized
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return false, ErrUnavailable
	}
	q := s.deps.Queries.WithTx(tx)
	current, err := q.GetUserByIDForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUnauthorized
	}
	if err != nil {
		return false, ErrUnavailable
	}
	if current.Status != "active" || current.DeletedAt.Valid || current.AuthVersion != sess.AuthVersion || !sameVerifier(current.PasswordHash, expected.PasswordHash) {
		return false, ErrUnauthorized
	}
	if err := s.live(ctx, sess); err != nil {
		return false, err
	}
	if auth.Grant != nil {
		if err := checkGrant(sess, auth.Grant); err != nil {
			return false, err
		}
	}
	current.PasswordHash = proposed
	state, err := s.deps.Policy.Read(ctx, tx, current, currentAuthority)
	if err != nil {
		return false, err
	}
	if operation != "remove" && !state.Password {
		return false, ErrConflict
	}
	if err := state.Check(); err != nil {
		return false, err
	}
	if auth.Grant != nil {
		if slices.Contains(auth.Grant.AMR, "hwk") && slices.Contains(auth.Grant.AMR, "user") {
			if state.Passkeys == 0 {
				return false, ErrUnauthorized
			}
		} else if !state.TOTP {
			return false, ErrUnauthorized
		}
	} else if err := s.deps.Proofs.ConsumePasswordChangeTx(ctx, tx, sess, auth.Proof); err != nil {
		return false, err
	}
	if auth.Grant != nil {
		if err := checkGrant(sess, auth.Grant); err != nil {
			return false, err
		}
	}
	if !noop {
		rows, err := q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{ID: id, PasswordHash: proposed})
		if err != nil || rows != 1 {
			return false, ErrUnavailable
		}
		if err := q.RevokeUserCredentials(ctx, id); err != nil {
			return false, ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrOutcomeUnknown
	}
	return !noop, nil
}

func sameVerifier(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func rollback(ctx context.Context, tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}
