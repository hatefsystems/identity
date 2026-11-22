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
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp/smsir"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

func buildAccountDeletionProofs(environment string, pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service) (*actionproof.Service, error) {
	cfg, err := config.LoadAccountDeletionProofs(environment)
	if err != nil || !cfg.Enabled {
		return nil, err
	}
	return buildActionProofs(pool, client, sessions, sms, cfg.EmailEnabled, cfg.SMSEnabled, cfg.CodeKey, cfg.BindingKey, cfg.SMTP, contactcode.PurposeAccountDeletion)
}

func buildPasswordChangeProofs(environment string, pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service) (*actionproof.Service, error) {
	cfg, err := config.LoadPasswordChangeProofs(environment)
	if err != nil || !cfg.Enabled {
		return nil, err
	}
	return buildActionProofs(pool, client, sessions, sms, cfg.EmailEnabled, cfg.SMSEnabled, cfg.CodeKey, cfg.BindingKey, cfg.SMTP, contactcode.PurposePasswordChange)
}

func buildFirstPasskeyProofs(environment string, pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service) (*actionproof.Service, error) {
	cfg, err := config.LoadFirstPasskeyProofs(environment)
	if err != nil || !cfg.Enabled {
		return nil, err
	}
	return buildActionProofs(pool, client, sessions, sms, cfg.EmailEnabled, cfg.SMSEnabled, cfg.CodeKey, cfg.BindingKey, cfg.SMTP, contactcode.PurposeFirstPasskey)
}

func buildFirstPasskeySMSSender(environment string) (smsotp.Sender, error) {
	cfg, err := config.LoadFirstPasskeyProofs(environment)
	if err != nil || !cfg.SMSEnabled {
		return nil, err
	}
	sms, err := config.LoadSMS(environment)
	if err != nil {
		return nil, err
	}
	return smsir.New(smsir.Config{APIKey: sms.GatewayAPIKey, TemplateID: cfg.FirstTemplateID, CodeParameter: sms.CodeParameter})
}

// The existing SMS service owns shared policy; main installs this purpose sender
// into smsotp.Config.PasswordChangeSender without enabling deletion delivery.
func buildPasswordChangeSMSSender(environment string) (smsotp.Sender, error) {
	cfg, err := config.LoadPasswordChangeProofs(environment)
	if err != nil || !cfg.SMSEnabled {
		return nil, err
	}
	sms, err := config.LoadSMS(environment)
	if err != nil {
		return nil, err
	}
	return smsir.New(smsir.Config{APIKey: sms.GatewayAPIKey, TemplateID: cfg.ChangeTemplateID, CodeParameter: sms.CodeParameter})
}

func buildActionProofs(pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service, emailEnabled, smsEnabled bool, codeKey, bindingKey []byte, smtp smtptransport.Config, purpose string) (*actionproof.Service, error) {
	if pool == nil || client == nil || sessions == nil {
		return nil, errors.New("main: action proofs require database, Redis and live sessions")
	}
	smsReady := purpose == contactcode.PurposeAccountDeletion && sms.DeletionDeliveryEnabled() || purpose == contactcode.PurposePasswordChange && sms.PasswordChangeDeliveryEnabled() || purpose == contactcode.PurposeFirstPasskey && sms.FirstPasskeyDeliveryEnabled()
	if smsEnabled && !smsReady {
		return nil, errors.New("main: action proofs require configured purpose-specific SMS delivery")
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
	if emailEnabled {
		transport, err := smtptransport.New(smtp)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = transport.Check(ctx, true)
		cancel()
		if err != nil {
			return nil, errors.New("main: action proof SMTPUTF8 relay unavailable")
		}
		switch purpose {
		case contactcode.PurposeFirstPasskey:
			email, err = contactcode.NewFirstPasskeyEmail(smtp.From, transport)
		case contactcode.PurposePasswordChange:
			email, err = contactcode.NewPasswordChangeEmail(smtp.From, transport)
		default:
			email, err = contactcode.NewDeletionEmail(smtp.From, transport)
		}
		if err != nil {
			return nil, err
		}
	}
	if !smsEnabled {
		sms = nil
	}
	codeConfig := contactcode.Config{HashKey: codeKey}
	switch purpose {
	case contactcode.PurposeFirstPasskey:
		codeConfig.FirstPasskeyEmail = email
	case contactcode.PurposePasswordChange:
		codeConfig.PasswordChangeEmail = email
	default:
		codeConfig.DeletionEmail = email
	}
	codes, err := contactcode.New(codeConfig, store, sms, nil)
	if err != nil {
		return nil, err
	}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		return nil, err
	}
	deps := actionproof.Deps{
		DB: pool, Queries: db.New(pool), Codes: codes, Cipher: cipher, Limiter: limiter, Sessions: sessions,
	}
	if purpose == contactcode.PurposeFirstPasskey {
		return actionproof.NewFirstPasskey(actionproof.Config{BindingKey: bindingKey}, deps)
	}
	if purpose == contactcode.PurposePasswordChange {
		return actionproof.NewPasswordChange(actionproof.Config{BindingKey: bindingKey}, deps)
	}
	return actionproof.New(actionproof.Config{BindingKey: bindingKey}, deps)
}

type deletionProofCleanup interface {
	CleanupExpired(context.Context, int32) (int64, error)
}

// One finite batch per minute bounds maintenance even during sustained traffic.
// Shutdown cancels and joins this worker; diagnostics never contain proof data.
func maintainAccountDeletionProofs(ctx context.Context, proofs deletionProofCleanup, logger *slog.Logger) {
	maintainActionProofs(ctx, proofs.CleanupExpired, logger, "account deletion proof cleanup unavailable")
}

type passwordChangeProofCleanup interface {
	CleanupExpiredPasswordChange(context.Context, int32) (int64, error)
}

func maintainPasswordChangeProofs(ctx context.Context, proofs passwordChangeProofCleanup, logger *slog.Logger) {
	maintainActionProofs(ctx, proofs.CleanupExpiredPasswordChange, logger, "password change proof cleanup unavailable")
}

type firstPasskeyProofCleanup interface {
	CleanupExpiredFirstPasskey(context.Context, int32) (int64, error)
}

func maintainFirstPasskeyProofs(ctx context.Context, proofs firstPasskeyProofCleanup, logger *slog.Logger) {
	maintainActionProofs(ctx, proofs.CleanupExpiredFirstPasskey, logger, "first passkey proof cleanup unavailable")
}

func maintainActionProofs(ctx context.Context, cleanup func(context.Context, int32) (int64, error), logger *slog.Logger, diagnostic string) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		batchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err := cleanup(batchCtx, 1000)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn(diagnostic)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
