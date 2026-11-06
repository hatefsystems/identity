//go:build integration

package legalpolicy

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// Privilege acceptance uses the complete installed schema, not the historical
// pre-retention schema fixture whose guard functions still expose PUBLIC EXECUTE.
func newPolicyPrivilegeIntegration(t *testing.T) *policyIntegration {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL required for restricted policy installation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	root, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close(context.Background()) })
	database := "policy_privilege_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := root.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := root.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop run-owned policy privilege database: %v", err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		t.Fatal("DATABASE_URL must be a PostgreSQL URL")
	}
	parsed.Path = "/" + database
	dsn = parsed.String()
	migrationDB, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = migrate.Up(ctx, migrationDB)
	_ = migrationDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &policyIntegration{ctx: ctx, pool: pool, admin: pool, schema: "public"}
}
