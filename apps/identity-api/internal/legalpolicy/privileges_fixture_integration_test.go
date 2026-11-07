//go:build integration

package legalpolicy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// Governance and privilege acceptance share a complete run-owned installation.
func newPolicyPrivilegeIntegration(t *testing.T) *policyIntegration {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
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
	if _, err := root.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatalf("create run-owned policy database with test provisioning credentials: %v", err)
	}
	t.Logf("run-owned policy database: %s", database)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := root.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Errorf("drop run-owned policy privilege database: %v", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = database
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 6
	migrationDB := stdlib.OpenDB(*cfg.ConnConfig)
	err = migrate.Up(ctx, migrationDB)
	_ = migrationDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	actions, err := adminaction.New(pool, noContextEncryption{}, "identity.audit.policy-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &policyIntegration{ctx: ctx, pool: pool, admin: pool, actions: actions, schema: "public"}
}
