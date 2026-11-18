package main

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func buildPrivateProfileService(pool *pgxpool.Pool, names *username.Store, sessions *session.Manager) (*profile.PrivateService, error) {
	if pool == nil || sessions == nil {
		return nil, nil
	}
	cipher, err := buildProfileCipher()
	if err != nil {
		return nil, err
	}
	return profile.NewPrivate(pool, cipher, names, geography.New(pool), sessions)
}

func buildProfileService(pool *pgxpool.Pool) (*profile.Service, error) {
	cipher, err := buildProfileCipher()
	if err != nil {
		return nil, err
	}
	return profile.New(pool, cipher)
}

func buildProfileCipher() (username.Cipher, error) {
	crypto, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return nil, err
	}
	defer clear(crypto.MasterKEK)
	provider, err := kms.NewMockProvider(crypto.MasterKEK, crypto.MasterKEKVersion)
	if err != nil {
		return nil, err
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}
