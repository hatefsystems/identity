//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func openRecoveryHandlerIntegrationPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL is required for integration-tag recovery handler tests")
	}
	sqlDB, err := migrate.Open(ctx, url)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	if err := migrate.Up(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close migration database: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	if cfg.MaxConns < 4 {
		cfg.MaxConns = 4
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

func TestIntegrationRecoveryDoubleSubmissionIssuesOneRestrictedSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool := openRecoveryHandlerIntegrationPool(ctx, t)
	q := db.New(pool)
	user, err := q.CreateUser(ctx, db.CreateUserParams{
		Email:  "recovery-handler-" + uuid.NewString() + "@test.local",
		Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
			t.Errorf("cleanup user: %v", err)
		}
	})

	codes, err := recovery.New(recovery.Config{}, q, recovery.WithTransacter(pool))
	if err != nil {
		t.Fatalf("recovery.New: %v", err)
	}
	transactions := recovery.NewMemoryTransactionStore()
	flow, err := recovery.NewFlowService(codes, q, transactions, 0)
	if err != nil {
		t.Fatalf("NewFlowService: %v", err)
	}
	batch, err := codes.Generate(ctx, user.ID, "203.0.113.8")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	first, err := flow.Start(ctx, user.Email)
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	second, err := flow.Start(ctx, user.Email)
	if err != nil {
		t.Fatalf("second Start: %v", err)
	}

	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", Secure: false, TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}
	sessions, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessions,
		Recovery:       codes,
		RecoveryFlow:   flow,
	})

	type result struct {
		status  int
		cookies []*http.Cookie
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for _, transactionID := range []string{first.TransactionID, second.TransactionID} {
		transactionID := transactionID
		go func() {
			<-start
			body, marshalErr := json.Marshal(recoveryVerifyRequest{TransactionID: transactionID, Code: batch.Codes[0]})
			if marshalErr != nil {
				results <- result{status: 0}
				return
			}
			req := httptest.NewRequest(http.MethodPost, recoveryVerifyPath, bytes.NewReader(body))
			req.RemoteAddr = "203.0.113.8:4242"
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			results <- result{status: rec.Code, cookies: rec.Result().Cookies()}
		}()
	}
	close(start)

	var succeeded, rejected, issuedCookies int
	for range 2 {
		result := <-results
		switch result.status {
		case http.StatusOK:
			succeeded++
			issuedCookies += len(result.cookies)
		case http.StatusUnauthorized:
			rejected++
		default:
			t.Fatalf("unexpected recovery response status %d", result.status)
		}
	}
	if succeeded != 1 || rejected != 1 || issuedCookies != 1 {
		t.Fatalf("success/rejected/cookies = %d/%d/%d, want 1/1/1", succeeded, rejected, issuedCookies)
	}
	live, err := sessions.List(user.ID.String())
	if err != nil {
		t.Fatalf("List sessions: %v", err)
	}
	if len(live) != 1 || live[0].Kind != session.KindRecoveryEnrollment {
		t.Fatalf("sessions = %+v, want exactly one restricted session", live)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, user.ID).Scan(&rows); err != nil {
		t.Fatalf("count recovery rows: %v", err)
	}
	if rows != batch.Count-1 {
		t.Fatalf("recovery rows = %d, want %d after one physical deletion", rows, batch.Count-1)
	}
}
