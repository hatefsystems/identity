package main

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/passwordmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type passwordChangeCeremony struct{ service *actionproof.Service }

func (p passwordChangeCeremony) Challenge(ctx context.Context, sess session.Session, secret, channel, source string) (string, time.Time, error) {
	return p.service.ChallengePasswordChange(ctx, sess, secret, channel, source)
}

func (p passwordChangeCeremony) Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return p.service.VerifyPasswordChange(ctx, sess, challenge, code)
}

func buildPasswordManager(pool *pgxpool.Pool, sessions *session.Manager, limiter ratelimit.Limiter, policy accountpolicy.Policy, proofs *actionproof.Service) (*passwordmanager.Service, error) {
	if pool == nil || sessions == nil || limiter == nil {
		return nil, nil
	}
	deps := passwordmanager.Deps{DB: pool, Queries: db.New(pool), Sessions: sessions, Limiter: limiter, Policy: policy}
	if proofs != nil {
		deps.Proofs = proofs
	}
	return passwordmanager.New(deps)
}
