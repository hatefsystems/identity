// Package migrate wraps goose to apply the embedded SQL migrations
// (db/migrations) against PostgreSQL. It is consumed by the cmd/migrate CLI
// and by integration tests, guaranteeing both paths run the identical,
// version-tracked schema that sqlc generates code from.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"

	// Registers the pgx/v5 driver under database/sql ("pgx") for goose. The
	// application itself keeps using the native pgx pool; only the migration
	// runner goes through database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/db"
)

// NewProvider returns a goose provider bound to the embedded migration files
// and the given database handle. Version state is tracked in the standard
// goose_db_version table.
func NewProvider(sqldb *sql.DB) (*goose.Provider, error) {
	// The embed FS is rooted at db/, so strip the migrations/ prefix.
	fsys, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrate: sub filesystem: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, fsys)
	if err != nil {
		return nil, fmt.Errorf("migrate: new provider: %w", err)
	}
	return provider, nil
}

// Open connects to PostgreSQL via the pgx stdlib driver and verifies the
// connection. The caller owns closing the returned handle. databaseURL must
// come from the environment/KMS — never hardcode credentials (DoD #3).
func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("migrate: DATABASE_URL is empty")
	}
	sqldb, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("migrate: open database: %w", err)
	}
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("migrate: ping database: %w", err)
	}
	return sqldb, nil
}

// Up applies all pending migrations.
func Up(ctx context.Context, sqldb *sql.DB) error {
	provider, err := NewProvider(sqldb)
	if err != nil {
		return err
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate: up: %w", err)
	}
	return nil
}

// Down rolls back the most recently applied migration.
func Down(ctx context.Context, sqldb *sql.DB) error {
	provider, err := NewProvider(sqldb)
	if err != nil {
		return err
	}
	if _, err := provider.Down(ctx); err != nil {
		return fmt.Errorf("migrate: down: %w", err)
	}
	return nil
}

// Reset rolls back every applied migration (down to version 0). Used by
// integration tests to verify Down sections leave a clean database.
func Reset(ctx context.Context, sqldb *sql.DB) error {
	provider, err := NewProvider(sqldb)
	if err != nil {
		return err
	}
	if _, err := provider.DownTo(ctx, 0); err != nil {
		return fmt.Errorf("migrate: reset: %w", err)
	}
	return nil
}

// Status reports each known migration and whether it has been applied.
func Status(ctx context.Context, sqldb *sql.DB) ([]*goose.MigrationStatus, error) {
	provider, err := NewProvider(sqldb)
	if err != nil {
		return nil, err
	}
	statuses, err := provider.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: status: %w", err)
	}
	return statuses, nil
}
