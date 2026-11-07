//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

func phoneIntegrationServices(t *testing.T) (context.Context, *pgxpool.Pool, *smsotp.RedisOTPStore) {
	t.Helper()
	dsn, redisURL := os.Getenv("DATABASE_URL"), os.Getenv("REDIS_URL")
	if dsn == "" || redisURL == "" {
		if os.Getenv("REQUIRE_SMS_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL and REDIS_URL are required for mandatory phone integration")
		}
		t.Skip("isolated PostgreSQL and Redis fixtures not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid fixture database configuration")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal("configured fixture database unavailable")
	}
	name := "phone_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal("cannot create run-owned phone database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("cannot drop run-owned phone database")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned phone database migration failed")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid Redis fixture configuration")
	}
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("configured Redis fixture unavailable")
	}
	store, err := smsotp.NewRedisOTPStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, store
}

type phoneIntegrationEncryptor struct {
	admitted chan struct{}
	release  chan struct{}
}

func (e phoneIntegrationEncryptor) Encrypt(ctx context.Context, p []byte) ([]byte, error) {
	if e.admitted != nil {
		close(e.admitted)
		select {
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return append([]byte("enc_"), p...), nil
}

func TestPhoneHTTPRealRedisPostgresRevocationFenceIntegration(t *testing.T) {
	ctx, pool, otps := phoneIntegrationServices(t)
	fx := setupPhoneTestFixture(t, true)
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,status) VALUES($1,$2,'active')", fx.userID, uuid.NewString()+"@phone.invalid"); err != nil {
		t.Fatal(err)
	}
	users, err := smsotp.NewUserStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	gate := phoneIntegrationEncryptor{make(chan struct{}), make(chan struct{})}
	svc, err := smsotp.New(smsotp.Config{HashPepper: []byte(strings.Repeat("p", 32))}, users, gate, phoneFakeIndexer{}, &phoneFakeLimiter{true}, otps, fx.sender)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &phoneAuditRecorder{}
	fx.server = New(config.Config{Environment: "development", PortalOrigin: fx.browser.origin}, nil, Deps{SMSOTP: svc, SessionManager: fx.sessionManager, DPoPValidator: fx.browser.validator, StepUp: fx.stepUp, AuditRecorder: recorder})
	id, err := svc.SendCode(ctx, fx.userID, fx.sess.AuthVersion, fx.sess.ID, "+989123456789", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = otps.Delete(cleanup, id)
	})
	body, _ := json.Marshal(phoneVerifyRequest{id, fx.sender.code()})
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		fx.server.handlePhoneVerify().ServeHTTP(w, profileHandlerRequest(fx.sess, http.MethodPost, string(body)))
		close(done)
	}()
	select {
	case <-gate.admitted:
	case <-ctx.Done():
		t.Fatal("HTTP proof admission barrier timed out")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("phone fixture transaction rollback failed")
		}
	}()
	if err := pglock.LockAccount(ctx, tx, fx.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", fx.userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	<-done
	if w.Code != 401 || recorder.count(audit.EventPhoneVerified) != 0 {
		t.Fatal("stale admitted HTTP verification succeeded or audited success")
	}
	u, err := db.New(pool).GetUserByID(ctx, fx.userID)
	if err != nil || u.PhoneEncrypted != nil {
		t.Fatal("stale phone persisted")
	}
}
func TestPhoneHTTPDisabledRealPostgresRemovalOneAuditIntegration(t *testing.T) {
	ctx, pool, _ := phoneIntegrationServices(t)
	fx := setupPhoneTestFixture(t, true)
	if _, err := pool.Exec(ctx, "INSERT INTO users(id,email,status,phone_encrypted,phone_blind_index) VALUES($1,$2,'active',$3,$4)", fx.userID, uuid.NewString()+"@phone.invalid", []byte("encrypted"), "index-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	users, err := smsotp.NewUserStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := smsotp.NewDisabled(users)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &phoneAuditRecorder{}
	fx.server.deps.SMSOTP = disabled
	fx.server.deps.AuditRecorder = recorder
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			fx.server.handlePhoneRemove().ServeHTTP(w, profileHandlerRequest(fx.sess, http.MethodDelete, ""))
			if w.Code != 204 {
				t.Errorf("removal status=%d", w.Code)
			}
		}()
	}
	wg.Wait()
	if recorder.count(audit.EventPhoneRemoved) != 1 {
		t.Fatal("real SQL removal emitted duplicate audit event")
	}
}
