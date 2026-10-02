//go:build integration

package signer_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

func TestAuditSubjectLockAgainstConcurrentDeletionIntegration(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required")
		}
		t.Skip("DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	migrationDB, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migrationDB.Close() }()
	if err := migrate.Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, deleteFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "signer locks first", true: "deletion locks first"}[deleteFirst], func(t *testing.T) {
			user, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Email: uuid.NewString() + "@test.invalid", Status: "active"})
			if err != nil {
				t.Fatal(err)
			}
			signTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = signTx.Rollback(context.Background()) }()
			deleteTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = deleteTx.Rollback(context.Background()) }()
			assertBlocked := func(err error) {
				t.Helper()
				var pgErr *pgconn.PgError
				if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
					t.Fatalf("expected incompatible row lock, got %v", err)
				}
			}
			if deleteFirst {
				if _, err := deleteTx.Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := signTx.Exec(ctx, "SET LOCAL lock_timeout='150ms'"); err != nil {
					t.Fatal(err)
				}
				_, err := db.New(signTx).LockAuditSubjects(ctx, []uuid.UUID{user.ID})
				assertBlocked(err)
				if err := signTx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if err := deleteTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				ids, err := db.New(signTx).LockAuditSubjects(ctx, []uuid.UUID{uuid.New(), user.ID})
				if err != nil || len(ids) != 1 || ids[0] != user.ID {
					t.Fatalf("live-subject resolution: %v %v", ids, err)
				}
				if _, err := deleteTx.Exec(ctx, "SET LOCAL lock_timeout='150ms'"); err != nil {
					t.Fatal(err)
				}
				_, err = deleteTx.Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID)
				assertBlocked(err)
				if err := deleteTx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if err := signTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, "DELETE FROM users WHERE id=$1", user.ID); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			ids, err := db.New(tx).LockAuditSubjects(ctx, []uuid.UUID{user.ID})
			if err != nil || len(ids) != 0 {
				t.Fatalf("deleted subject must become NULL attachment: %v %v", ids, err)
			}
		})
	}
}
