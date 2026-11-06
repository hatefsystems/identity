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
	"math"

	"github.com/pressly/goose/v3"

	// Registers the pgx/v5 driver under database/sql ("pgx") for goose. The
	// application itself keeps using the native pgx pool; only the migration
	// runner goes through database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/db"
)

// NewProvider returns a guarded provider bound to the embedded migration files
// and the given database handle. Version state is tracked in the standard
// goose_db_version table.
func NewProvider(sqldb *sql.DB) (*Provider, error) {
	if sqldb == nil {
		return nil, fmt.Errorf("migrate: database is required")
	}
	// The embed FS is rooted at db/, so strip the migrations/ prefix.
	fsys, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrate: sub filesystem: %w", err)
	}
	_, err = goose.NewProvider(goose.DialectPostgres, sqldb, fsys)
	if err != nil {
		return nil, fmt.Errorf("migrate: new provider: %w", err)
	}
	return &Provider{db: sqldb, files: fsys}, nil
}

// Provider does not expose an unguarded goose provider. Each mutating entrypoint
// installs its preflight on goose's own connection, including ApplyVersion.
type Provider struct {
	db    *sql.DB
	files fs.FS
}

func (p *Provider) runner(target int64, one, up bool) (*goose.Provider, error) {
	return goose.NewProvider(goose.DialectPostgres, p.db, p.files,
		goose.WithSessionLocker(migrationLocker{target: target, one: one, up: up}))
}

// Up applies all pending migrations with worker exclusion and v1 preflight.
func (p *Provider) Up(ctx context.Context) ([]*goose.MigrationResult, error) {
	return p.UpTo(ctx, math.MaxInt64)
}

// UpTo applies pending migrations through the specified version.
func (p *Provider) UpTo(ctx context.Context, version int64) ([]*goose.MigrationResult, error) {
	r, err := p.runner(version, false, true)
	if err != nil {
		return nil, err
	}
	return r.UpTo(ctx, version)
}

// UpByOne applies the next pending migration with the same guarded connection.
func (p *Provider) UpByOne(ctx context.Context) (*goose.MigrationResult, error) {
	r, err := p.runner(math.MaxInt64, true, true)
	if err != nil {
		return nil, err
	}
	return r.UpByOne(ctx)
}

// ApplyVersion applies exactly one migration in the specified direction.
func (p *Provider) ApplyVersion(ctx context.Context, version int64, up bool) (*goose.MigrationResult, error) {
	r, err := p.runner(version, false, up)
	if err != nil {
		return nil, err
	}
	return r.ApplyVersion(ctx, version, up)
}

// Down attempts the most recent rollback, honoring forward-only SQL boundaries.
func (p *Provider) Down(ctx context.Context) (*goose.MigrationResult, error) {
	r, err := p.runner(0, true, false)
	if err != nil {
		return nil, err
	}
	return r.Down(ctx)
}

// DownTo attempts rollback to the specified version under worker exclusion.
func (p *Provider) DownTo(ctx context.Context, version int64) ([]*goose.MigrationResult, error) {
	r, err := p.runner(version, false, false)
	if err != nil {
		return nil, err
	}
	return r.DownTo(ctx, version)
}

// Status reports the applied state of the embedded migrations.
func (p *Provider) Status(ctx context.Context) ([]*goose.MigrationStatus, error) {
	r, err := p.runner(0, false, false)
	if err != nil {
		return nil, err
	}
	return r.Status(ctx)
}

// GetDBVersion reports the highest applied migration version.
func (p *Provider) GetDBVersion(ctx context.Context) (int64, error) {
	r, err := p.runner(0, false, false)
	if err != nil {
		return 0, err
	}
	return r.GetDBVersion(ctx)
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
	return UpTo(ctx, sqldb, math.MaxInt64)
}

// UpTo applies pending migrations through a declared cutover boundary.
func UpTo(ctx context.Context, sqldb *sql.DB, version int64) error {
	provider, err := NewProvider(sqldb)
	if err != nil {
		return err
	}
	if _, err := provider.UpTo(ctx, version); err != nil {
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
