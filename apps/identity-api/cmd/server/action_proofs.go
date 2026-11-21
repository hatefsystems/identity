package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

func buildAccountDeletionProofs(environment string, pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service) (*actionproof.Service, error) {
	cfg, err := config.LoadAccountDeletionProofs(environment)
	if err != nil || !cfg.Enabled {
		return nil, err
	}
	if pool == nil || client == nil || sessions == nil {
		return nil, errors.New("main: account deletion proofs require database, Redis and live sessions")
	}
	crypto, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return nil, err
	}
	provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
	if err != nil {
		return nil, err
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		return nil, err
	}
	store, err := contactcode.NewRedisStore(client)
	if err != nil {
		return nil, err
	}
	var email contactcode.Sender
	if cfg.EmailEnabled {
		transport, err := smtptransport.New(cfg.SMTP)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = transport.Check(ctx, true)
		cancel()
		if err != nil {
			return nil, errors.New("main: account deletion proof SMTPUTF8 relay unavailable")
		}
		email, err = contactcode.NewDeletionEmail(cfg.SMTP.From, transport)
		if err != nil {
			return nil, err
		}
	}
	if !cfg.SMSEnabled {
		sms = nil
	}
	codes, err := contactcode.New(contactcode.Config{HashKey: cfg.CodeKey, DeletionEmail: email}, store, sms, nil)
	if err != nil {
		return nil, err
	}
	if !codes.DeletionChannelEnabled(contactcode.ChannelEmail) && !codes.DeletionChannelEnabled(contactcode.ChannelSMS) {
		return nil, errors.New("main: account deletion proofs require configured purpose-specific delivery")
	}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		return nil, err
	}
	return actionproof.New(actionproof.Config{BindingKey: cfg.BindingKey}, actionproof.Deps{
		DB: pool, Queries: db.New(pool), Codes: codes, Cipher: cipher, Limiter: limiter, Sessions: sessions,
	})
}

type deletionProofCleanup interface {
	CleanupExpired(context.Context, int32) (int64, error)
}

// One finite batch per minute bounds maintenance even during sustained traffic.
// Shutdown cancels and joins this worker; diagnostics never contain proof data.
func maintainAccountDeletionProofs(ctx context.Context, proofs deletionProofCleanup, logger *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		batchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := proofs.CleanupExpired(batchCtx, 1000)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("account deletion proof cleanup unavailable")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
