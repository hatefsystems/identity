package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/server"
)

// Enabling admin is explicit and fails startup if any required dependency is
// absent. Hold management needs encryption, independently of lookup indexing.
func buildAdminServices(cfg config.AdminConfig, environment string, pool *pgxpool.Pool, redisClient *redis.Client) (server.Deps, error) {
	var deps server.Deps
	if !cfg.Enabled {
		return deps, nil
	}
	if pool == nil || redisClient == nil {
		return deps, errors.New("admin: PostgreSQL and Redis are required")
	}
	crypto, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return deps, err
	}
	provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
	if err != nil {
		return deps, err
	}
	enc, err := envelope.New(provider)
	if err != nil {
		return deps, err
	}
	auditCfg, err := config.LoadAudit(environment)
	if err != nil {
		return deps, err
	}
	if !auditCfg.HasNATS() {
		return deps, errors.New("admin: durable audit delivery requires NATS configuration")
	}
	actions, err := adminaction.New(pool, enc, auditCfg.Subject, cfg.ContextRetention)
	if err != nil {
		return deps, err
	}
	queries := db.New(pool)
	opts := []legalhold.Option{
		legalhold.WithReleasedMetadataRetention(cfg.LegalReleasedRetention),
		legalhold.WithMaxQueryWindow(cfg.AuditMaxWindow),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var fixtureCheck func(context.Context) error
	if raw := os.Getenv("ADMIN_LOOKUP_FIXTURE_ID"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return deps, errors.New("admin: invalid lookup fixture ID")
		}
		pepper, err := config.LoadBlindIndexPepper()
		if err != nil {
			return deps, err
		}
		indexer, err := blindindex.New(pepper)
		if err != nil {
			return deps, err
		}
		fixtureCheck = func(ctx context.Context) error { return legalhold.VerifyLookupFixture(ctx, pool, indexer, id) }
		if err := fixtureCheck(ctx); err != nil {
			return deps, errors.New("admin: signer lookup fixture missing or key mismatch")
		}
		opts = append(opts, legalhold.WithLookup(indexer, true))
	}
	holds, err := legalhold.New(queries, enc, opts...)
	if err != nil {
		return deps, err
	}
	if err := holds.CheckCrypto(ctx); err != nil {
		return deps, err
	}
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return deps, errors.New("admin: limiter unavailable")
	}
	limiter, err := ratelimit.NewRedisLimiter(redisClient)
	if err != nil {
		return deps, err
	}
	deps.AdminActions, deps.AdminStore, deps.RBAC = actions, queries, queries
	deps.LegalHold, deps.AdminLimiter = holds, limiter
	deps.AdminReady = func(ctx context.Context) error {
		if fixtureCheck != nil {
			if err := fixtureCheck(ctx); err != nil {
				return err
			}
		}
		if err := pool.Ping(ctx); err != nil {
			return errors.New("admin: database unavailable")
		}
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return errors.New("admin: limiter unavailable")
		}
		return holds.CheckCrypto(ctx)
	}
	return deps, nil
}
