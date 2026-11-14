package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func buildUsernameService(pool *pgxpool.Pool) (*username.Store, func(context.Context) error, error) {
	cfg, err := config.LoadUsername()
	if err != nil || !cfg.Enabled {
		return nil, nil, err
	}
	if pool == nil {
		return nil, nil, errors.New("main: enabled usernames require DATABASE_URL")
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
	store, err := username.NewStore(pool, cipher, cfg.Normalizer)
	if err != nil {
		return nil, nil, err
	}
	ready := func(ctx context.Context) error {
		if store.CheckReady(ctx) != nil {
			return errors.New("main: username namespace is not ready")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ready(ctx); err != nil {
		return nil, nil, err
	}
	return store, ready, nil
}
