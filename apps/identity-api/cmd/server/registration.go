package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

func buildRegistrationService(environment string, pool *pgxpool.Pool, redisClient *redis.Client, passkeys *webauthn.Service, phones *smsotp.Service) (*registration.Service, func(context.Context) error, error) {
	cfg, err := config.LoadRegistration(environment)
	if err != nil || !cfg.Enabled {
		return nil, nil, err
	}
	if pool == nil || redisClient == nil || passkeys == nil || phones == nil || !phones.DeliveryEnabled() {
		return nil, nil, errors.New("main: enabled registration requires durable ownership and passkey dependencies")
	}
	crypto, err := config.LoadCrypto()
	if err != nil {
		return nil, nil, err
	}
	provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
	if err != nil {
		return nil, nil, err
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		return nil, nil, err
	}
	indexer, err := blindindex.New(crypto.BlindIndexPepper, crypto.BlindIndexPepperVersion)
	if err != nil {
		return nil, nil, err
	}
	store, err := registration.NewStore(pool, cipher, cfg.PendingCapacity)
	if err != nil {
		return nil, nil, err
	}
	transport, err := smtptransport.New(cfg.SMTP)
	if err != nil {
		return nil, nil, err
	}
	email, err := registration.NewEmail(registration.EmailConfig{From: cfg.SMTP.From, PublicOrigin: cfg.PublicOrigin}, transport)
	if err != nil {
		return nil, nil, err
	}
	limiter, err := ratelimit.NewRedisLimiter(redisClient)
	if err != nil {
		return nil, nil, err
	}
	ready := func(ctx context.Context) error {
		if store.CheckReady(ctx) != nil {
			return errors.New("main: registration storage is not ready")
		}
		if redisClient.Ping(ctx).Err() != nil {
			return errors.New("main: registration proof authority is not ready")
		}
		if transport.Check(ctx, true) != nil {
			return errors.New("main: registration SMTPUTF8 relay is not ready")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ready(ctx); err != nil {
		return nil, nil, err
	}
	// Probe the dedicated cleanup login without using its mutation capability.
	// Deployment still requires independently supervised cleanup scheduling.
	cleanup, err := config.LoadRegistrationCleanup()
	if err != nil {
		return nil, nil, err
	}
	cleanupPoolConfig, err := pgxpool.ParseConfig(cleanup.DatabaseURL)
	if err != nil {
		return nil, nil, errors.New("main: registration cleanup identity is not configured")
	}
	cleanupPoolConfig.MaxConns = 1
	cleanupPool, err := pgxpool.NewWithConfig(ctx, cleanupPoolConfig)
	if err != nil {
		return nil, nil, errors.New("main: registration cleanup identity is unavailable")
	}
	defer cleanupPool.Close()
	if registration.CheckCleanupReady(ctx, cleanupPool) != nil {
		return nil, nil, errors.New("main: registration cleanup identity is not ready")
	}
	service, err := registration.NewService(registration.Deps{Store: store, Database: pool, Email: email, Phone: phones,
		WebAuthn: passkeys, Encryptor: cipher, Indexer: indexer, Limiter: limiter,
		GlobalDailyLimit: cfg.GlobalDailyLimit, EmailHourlyLimit: cfg.EmailHourlyLimit})
	if err != nil {
		return nil, nil, err
	}
	return service, ready, nil
}
