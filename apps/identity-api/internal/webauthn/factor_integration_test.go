//go:build integration

// These tests exercise the account-level authentication-factor invariant with
// real PostgreSQL transactions. Unit-test stores cannot prove that concurrent
// requests actually serialize on the shared users row.
package webauthn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

const factorIntegrationTimeout = 2 * time.Minute

// factorBeginBarrier opens each transaction and then holds it until both race
// participants have begun. This prevents a scheduler-only serial execution
// from making a concurrency test pass without exercising PostgreSQL locking.
type factorBeginBarrier struct {
	pool *pgxpool.Pool

	mu        sync.Mutex
	remaining int
	release   chan struct{}
}

func newFactorBeginBarrier(pool *pgxpool.Pool, participants int) *factorBeginBarrier {
	return &factorBeginBarrier{
		pool:      pool,
		remaining: participants,
		release:   make(chan struct{}),
	}
}

func (b *factorBeginBarrier) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	b.arrive()
	if err != nil {
		return nil, err
	}

	select {
	case <-b.release:
		return tx, nil
	case <-ctx.Done():
		_ = tx.Rollback(context.Background())
		return nil, ctx.Err()
	}
}

func (b *factorBeginBarrier) arrive() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.remaining <= 0 {
		return
	}
	b.remaining--
	if b.remaining == 0 {
		close(b.release)
	}
}

// factorTestEncryptor is required to construct the MFA service. Disable never
// encrypts or decrypts, but keeping a functioning implementation makes the
// fixture safe if that setup changes.
type factorTestEncryptor struct{}

func (factorTestEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (factorTestEncryptor) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

func openFactorIntegrationPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL is required for integration-tag factor concurrency tests")
	}

	sqldb, err := migrate.Open(ctx, url)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	if err := sqldb.Close(); err != nil {
		t.Fatalf("close migration database: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	if cfg.MaxConns < 8 {
		cfg.MaxConns = 8
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open PostgreSQL pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func createFactorIntegrationUser(ctx context.Context, t *testing.T, pool *pgxpool.Pool, label string) uuid.UUID {
	t.Helper()

	q := db.New(pool)
	user, err := q.CreateUser(ctx, db.CreateUserParams{
		Email:  fmt.Sprintf("factor-%s-%s@test.local", label, uuid.NewString()),
		Status: "active",
	})
	if err != nil {
		t.Fatalf("create factor test user: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
			t.Errorf("cleanup factor test user %s: %v", user.ID, err)
		}
	})
	return user.ID
}

func createFactorIntegrationCredential(ctx context.Context, t *testing.T, q *db.Queries, userID uuid.UUID) []byte {
	t.Helper()

	credentialID := []byte("factor-test-" + uuid.NewString())
	if _, err := q.CreateWebauthnCredential(ctx, db.CreateWebauthnCredentialParams{
		ID:              credentialID,
		UserID:          userID,
		PublicKey:       []byte("test-cose-public-key"),
		AttestationType: "none",
		UserPresent:     true,
		UserVerified:    true,
		Aaguid:          uuid.New(),
	}); err != nil {
		t.Fatalf("create WebAuthn credential: %v", err)
	}
	return credentialID
}

func newFactorIntegrationWebAuthn(t *testing.T, q *db.Queries, tx Transacter) *Service {
	t.Helper()

	svc, err := New(Config{
		RPID:             "identity.test",
		RPDisplayName:    "Factor integration test",
		RPOrigins:        []string{"https://identity.test"},
		ChallengeTTL:     time.Minute,
		MockChallengeKey: []byte("factor-integration-mock-key-32b"),
	}, q, q, NewMemoryChallengeStore(), WithTransacter(tx))
	if err != nil {
		t.Fatalf("construct WebAuthn service: %v", err)
	}
	return svc
}

func TestIntegrationConcurrentPasskeyDeletionsLeaveOneCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()

	pool := openFactorIntegrationPool(ctx, t)
	q := db.New(pool)
	userID := createFactorIntegrationUser(ctx, t, pool, "delete-delete")
	first := createFactorIntegrationCredential(ctx, t, q, userID)
	second := createFactorIntegrationCredential(ctx, t, q, userID)

	barrier := newFactorBeginBarrier(pool, 2)
	svc := newFactorIntegrationWebAuthn(t, q, barrier)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, credentialID := range [][]byte{first, second} {
		credentialID := append([]byte(nil), credentialID...)
		go func() {
			<-start
			results <- svc.DeleteCredential(ctx, userID, credentialID)
		}()
	}
	close(start)

	var succeeded, refused int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLastCredential):
			refused++
		default:
			t.Fatalf("concurrent DeleteCredential returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 || refused != 1 {
		t.Fatalf("delete outcomes: succeeded=%d refused_last=%d, want 1 and 1", succeeded, refused)
	}

	remaining, err := q.ListWebauthnCredentialsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list remaining credentials: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("credentials after simultaneous deletion = %d, want exactly 1", len(remaining))
	}
}

func TestIntegrationPasskeyDeletionRacingMFADisablePreservesLoginPasskey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), factorIntegrationTimeout)
	defer cancel()

	pool := openFactorIntegrationPool(ctx, t)
	q := db.New(pool)
	userID := createFactorIntegrationUser(ctx, t, pool, "delete-mfa")
	credentialID := createFactorIntegrationCredential(ctx, t, q, userID)

	if affected, err := q.SetMfaTotpSecret(ctx, db.SetMfaTotpSecretParams{
		ID:                     userID,
		MfaTotpSecretEncrypted: []byte("integration-encrypted-totp-secret"),
	}); err != nil || affected != 1 {
		t.Fatalf("store TOTP secret: affected=%d error=%v", affected, err)
	}
	if affected, err := q.EnableMfa(ctx, userID); err != nil || affected != 1 {
		t.Fatalf("enable TOTP: affected=%d error=%v", affected, err)
	}

	// Both services share this barrier and the production users-row mutex. The
	// final passkey is the only factor currently capable of issuing a login
	// session, so deletion must be refused even while TOTP teardown is racing.
	barrier := newFactorBeginBarrier(pool, 2)
	webAuthnService := newFactorIntegrationWebAuthn(t, q, barrier)
	mfaService, err := mfa.New(mfa.Config{}, q, factorTestEncryptor{}, mfa.WithTransacter(barrier))
	if err != nil {
		t.Fatalf("construct MFA service: %v", err)
	}

	start := make(chan struct{})
	deleteResult := make(chan error, 1)
	disableResult := make(chan error, 1)
	go func() {
		<-start
		deleteResult <- webAuthnService.DeleteCredential(ctx, userID, credentialID)
	}()
	go func() {
		<-start
		disableResult <- mfaService.Disable(ctx, userID)
	}()
	close(start)

	if err := <-deleteResult; !errors.Is(err, ErrLastCredential) {
		t.Fatalf("racing final-passkey deletion = %v, want ErrLastCredential", err)
	}
	if err := <-disableResult; err != nil {
		t.Fatalf("racing MFA disable: %v", err)
	}

	remaining, err := q.CountWebauthnCredentialsByUser(ctx, userID)
	if err != nil {
		t.Fatalf("count remaining passkeys: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("login-capable passkeys after deletion/MFA race = %d, want 1", remaining)
	}
	user, err := q.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.IsMfaEnabled || len(user.MfaTotpSecretEncrypted) != 0 {
		t.Fatalf("MFA disable did not finish atomically: enabled=%v secret_bytes=%d", user.IsMfaEnabled, len(user.MfaTotpSecretEncrypted))
	}
}
