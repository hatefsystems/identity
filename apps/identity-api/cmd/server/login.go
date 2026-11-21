package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/login"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func buildLoginService(environment string, pool *pgxpool.Pool, client *redis.Client, users *username.Store, factor *mfa.Service, sms *smsotp.Service) (*login.Service, bool, error) {
	cfg, err := config.LoadLogin(environment)
	if err != nil {
		return nil, false, err
	}
	if pool == nil || client == nil || factor == nil {
		if cfg.Enabled {
			return nil, false, errors.New("main: enabled login requires database, Redis and MFA verifier")
		}
		return nil, false, nil
	}
	if cfg.Enabled && users == nil {
		return nil, false, errors.New("main: username login requires admitted username authority")
	}
	sc, err := config.LoadStepUp(environment)
	if err != nil {
		return nil, false, err
	}
	if len(sc.ReplayHMACKey) == 0 {
		if cfg.Enabled {
			return nil, false, errors.New("main: login requires shared TOTP replay HMAC key")
		}
		return nil, false, nil
	}
	guard, err := stepup.NewRedisReplayGuard(client, sc.ReplayHMACKey)
	if err != nil {
		return nil, false, err
	}
	pending, err := login.NewRedisPending(client)
	if err != nil {
		return nil, false, err
	}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		return nil, false, err
	}
	deps := login.Deps{Users: db.New(pool), Pending: pending, TOTP: factor, Replay: guard, Accounts: session.NewDBAccountState(pool), Limiter: limiter}
	if users != nil {
		deps.Usernames = users
	}
	if cfg.Enabled {
		crypto, err := config.LoadEnvelopeCrypto()
		if err != nil {
			return nil, false, err
		}
		provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
		if err != nil {
			return nil, false, err
		}
		cipher, err := envelope.New(provider)
		if err != nil {
			return nil, false, err
		}
		store, err := contactcode.NewRedisStore(client)
		if err != nil {
			return nil, false, err
		}
		var email contactcode.Sender
		if cfg.EmailEnabled {
			transport, err := smtptransport.New(cfg.SMTP)
			if err != nil {
				return nil, false, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err = transport.Check(ctx, true)
			cancel()
			if err != nil {
				return nil, false, errors.New("main: login SMTPUTF8 relay unavailable")
			}
			email, err = contactcode.NewEmail(cfg.SMTP.From, transport)
			if err != nil {
				return nil, false, err
			}
		}
		deps.Codes, err = contactcode.New(contactcode.Config{HashKey: cfg.HashKey}, store, sms, email)
		if err != nil {
			return nil, false, err
		}
		deps.Contacts = login.DBContacts{Queries: db.New(pool), Cipher: cipher}
	}
	svc, err := login.New(deps)
	return svc, cfg.Enabled, err
}
