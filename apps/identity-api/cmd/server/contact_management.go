package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp/smsir"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

func buildContactSMSSenders(environment string) (smsotp.Sender, smsotp.Sender, error) {
	cfg, err := config.LoadContactManagement(environment)
	if err != nil || !cfg.ProofSMSEnabled {
		return nil, nil, err
	}
	sms, err := config.LoadSMS(environment)
	if err != nil {
		return nil, nil, err
	}
	change, err := smsir.New(smsir.Config{APIKey: sms.GatewayAPIKey, TemplateID: cfg.ChangeTemplateID, CodeParameter: sms.CodeParameter})
	if err != nil {
		return nil, nil, err
	}
	removal, err := smsir.New(smsir.Config{APIKey: sms.GatewayAPIKey, TemplateID: cfg.RemovalTemplateID, CodeParameter: sms.CodeParameter})
	return change, removal, err
}

// The unified writer is available for read/removal even without code providers.
// Configured finite code/proof readers remain installed when issuance is off.
func buildContactMaintenance(environment string, pool *pgxpool.Pool, client *redis.Client, sessions *session.Manager, sms *smsotp.Service, policy accountpolicy.Policy) (*contactmanager.Service, *actionproof.Service, error) {
	cfg, err := config.LoadContactManagement(environment)
	if err != nil {
		return nil, nil, err
	}
	if pool == nil {
		if len(cfg.CodeKey) > 0 || len(cfg.BindingKey) > 0 || cfg.EmailOwnershipEnabled || cfg.ProofsEnabled {
			return nil, nil, errors.New("main: contact maintenance readers require database and Redis")
		}
		return nil, nil, nil
	}
	crypto, err := config.LoadEnvelopeCrypto()
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
	deps := contactmanager.Deps{DB: pool, Queries: db.New(pool), Sessions: sessions, Cipher: cipher, Policy: policy}
	// Reads and provider-free removals do not need the phone blind-index key.
	if os.Getenv(config.EnvBlindIndexPepper) != "" {
		pepper, err := config.LoadBlindIndexPepper()
		if err != nil {
			return nil, nil, err
		}
		version, err := config.LoadBlindIndexPepperVersion()
		if err != nil {
			return nil, nil, err
		}
		deps.Indexer, err = blindindex.New(pepper, version)
		if err != nil {
			return nil, nil, err
		}
	}
	var codes *contactcode.Service
	var limiter ratelimit.Limiter
	if len(cfg.CodeKey) > 0 {
		if client == nil {
			return nil, nil, errors.New("main: retained contact code readers require Redis")
		}
		store, err := contactcode.NewRedisStore(client)
		if err != nil {
			return nil, nil, err
		}
		codeConfig := contactcode.Config{HashKey: cfg.CodeKey}
		if cfg.ProofEmailEnabled || cfg.EmailOwnershipEnabled {
			transport, err := smtptransport.New(cfg.SMTP)
			if err != nil {
				return nil, nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = transport.Check(ctx, true)
			cancel()
			if err != nil {
				return nil, nil, errors.New("main: contact maintenance SMTPUTF8 relay unavailable")
			}
			if cfg.ProofEmailEnabled {
				codeConfig.ContactChangeEmail, err = contactcode.NewContactChangeEmail(cfg.SMTP.From, transport)
				if err != nil {
					return nil, nil, err
				}
				codeConfig.ContactRemovalEmail, err = contactcode.NewContactRemovalEmail(cfg.SMTP.From, transport)
				if err != nil {
					return nil, nil, err
				}
			}
			if cfg.EmailOwnershipEnabled {
				codeConfig.ContactOwnershipEmail, err = contactcode.NewContactOwnershipEmail(cfg.SMTP.From, transport)
				if err != nil {
					return nil, nil, err
				}
			}
		}
		codes, err = contactcode.New(codeConfig, store, sms, nil)
		if err != nil {
			return nil, nil, err
		}
		limiter, err = ratelimit.NewRedisLimiter(client)
		if err != nil {
			return nil, nil, err
		}
		deps.Codes = codes
	}
	var proofs *actionproof.Service
	if len(cfg.BindingKey) > 0 {
		proofs, err = actionproof.NewContacts(actionproof.Config{BindingKey: cfg.BindingKey, ContactIssuanceEnabled: cfg.ProofsEnabled}, actionproof.Deps{DB: pool, Queries: db.New(pool), Codes: codes, Cipher: cipher, Limiter: limiter, Sessions: sessions})
		if err != nil {
			return nil, nil, err
		}
		proofs.SetAccountPolicy(policy)
		deps.Proofs = proofs
	}
	manager, err := contactmanager.New(deps)
	return manager, proofs, err
}
