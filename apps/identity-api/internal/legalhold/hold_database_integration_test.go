//go:build integration

package legalhold

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

func disposableHoldDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for legal hold integration tests")
	}
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error("legal hold administration connection cleanup failed")
		}
	})
	name := "hold_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Logf("run-owned legal hold fixture database: %s", name)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop legal hold test database: %v", err)
		}
		var exists bool
		if err := admin.QueryRowContext(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("legal hold database cleanup not confirmed")
		}
	})
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.Database = name
	poolConfig.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}

func holdMigrationMetadata(ctx context.Context, t *testing.T, pool *pgxpool.Pool) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, table := range []string{"goose_db_version", "identity_schema_version"} {
		var relation *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, "public."+table).Scan(&relation); err != nil {
			t.Fatal(err)
		}
		result[table] = nil
		if relation == nil {
			continue
		}
		var data []byte
		if err := pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]')::text FROM `+
			pgx.Identifier{"public", table}.Sanitize()+` v`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		result[table] = data
		var sequence *string
		if err := pool.QueryRow(ctx, `SELECT pg_get_serial_sequence($1,'id')`, "public."+table).Scan(&sequence); err != nil {
			t.Fatal(err)
		}
		if sequence != nil {
			if err := pool.QueryRow(ctx, `SELECT jsonb_build_object('last_value',last_value,'is_called',is_called)::text FROM `+*sequence).Scan(&data); err != nil {
				t.Fatal(err)
			}
			result[table+"_sequence"] = data
		}
	}
	return result
}
