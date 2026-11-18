package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func TestPrivateProfileCompositionWithoutUsernameConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv(config.EnvMasterKEK, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x48}, 32)))
	t.Setenv(config.EnvMasterKEKVersion, "1")
	// No dial occurs during composition. No username default/policy is invented.
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/private_composition?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(session.NewMemoryStore(), cookie, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := buildPrivateProfileService(pool, nil, manager)
	if err != nil || svc == nil {
		t.Fatal("private profile depends on optional username configuration")
	}
	if _, err := buildProfileService(pool); err != nil {
		t.Fatal("public evidence-reader cipher composition failed")
	}
	for _, test := range []struct {
		pool    *pgxpool.Pool
		manager *session.Manager
	}{{nil, manager}, {pool, nil}} {
		if svc, err := buildPrivateProfileService(test.pool, nil, test.manager); err != nil || svc != nil {
			t.Fatal("absent mandatory dependency should disable composition")
		}
	}
	// The cipher remains the existing authenticated envelope implementation.
	cipher, err := buildProfileCipher()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("synthetic private composition")
	blob, err := cipher.Encrypt(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cipher.Decrypt(t.Context(), blob)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatal("composed envelope did not round trip")
	}
}
