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
// and the given database handle. Version state uses a distinct baseline lineage
// in public.identity_schema_version, never the legacy goose_db_version table.
func NewProvider(sqldb *sql.DB) (*Provider, error) {
	if sqldb == nil {
		return nil, fmt.Errorf("migrate: database is required")
	}
	// The embed FS is rooted at db/, so strip the migrations/ prefix.
	fsys, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("migrate: sub filesystem: %w", err)
	}
	_, err = goose.NewProvider(goose.DialectPostgres, sqldb, fsys, goose.WithTableName(versionTable))
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

func (p *Provider) runner(exactUp int64) (*goose.Provider, error) {
	locker := &migrationLocker{exactUp: exactUp}
	r, err := goose.NewProvider(goose.DialectPostgres, p.db, p.files,
		goose.WithTableName(versionTable), goose.WithSessionLocker(locker))
	if err != nil {
		return nil, err
	}
	locker.sources = r.ListSources()
	return r, nil
}

func (p *Provider) inspect(ctx context.Context, sources []*goose.Source) (lineage, error) {
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return lineage{}, fmt.Errorf("migrate: lineage inventory connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return inventory(ctx, conn, sources)
}

func (p *Provider) prepare(ctx context.Context, target, exactUp int64) (*goose.Provider, lineage, error) {
	r, err := p.runner(exactUp)
	if err != nil {
		return nil, lineage{}, err
	}
	sources := r.ListSources()
	if target != math.MaxInt64 && target != 0 {
		known := false
		for _, source := range sources {
			known = known || source.Version == target
		}
		if !known {
			return nil, lineage{}, fmt.Errorf("migrate: target %d is not bundled: %w; legacy targets require separately scoped fresh setup", target, goose.ErrVersionNotFound)
		}
	}
	state, err := p.inspect(ctx, sources)
	if err == nil && exactUp > 1 {
		if _, baseline := state.applied[1]; !baseline {
			err = fmt.Errorf("%w: exact future application requires installed baseline 1", ErrLineage)
		}
	}
	return r, state, err
}

// Up applies all pending migrations with worker exclusion and lineage inventory.
func (p *Provider) Up(ctx context.Context) ([]*goose.MigrationResult, error) {
	return p.UpTo(ctx, math.MaxInt64)
}

// UpTo applies pending migrations through the specified version.
func (p *Provider) UpTo(ctx context.Context, version int64) ([]*goose.MigrationResult, error) {
	if version < 1 {
		return nil, fmt.Errorf("migrate: up target must be positive")
	}
	r, _, err := p.prepare(ctx, version, 0)
	if err != nil {
		return nil, err
	}
	// Goose's pending check initializes metadata without its locker. Its Status
	// path takes the locker; initialize there first, on this SAME fresh provider.
	if _, err := r.Status(ctx); err != nil {
		return nil, err
	}
	return r.UpTo(ctx, version)
}

// UpByOne applies the next pending migration with the same guarded connection.
func (p *Provider) UpByOne(ctx context.Context) (*goose.MigrationResult, error) {
	r, _, err := p.prepare(ctx, math.MaxInt64, 0)
	if err != nil {
		return nil, err
	}
	if _, err := r.Status(ctx); err != nil {
		return nil, err
	}
	return r.UpByOne(ctx)
}

// ApplyVersion applies exactly one migration in the specified direction.
func (p *Provider) ApplyVersion(ctx context.Context, version int64, up bool) (*goose.MigrationResult, error) {
	if version < 1 {
		return nil, fmt.Errorf("migrate: exact target must be positive")
	}
	if version == 1 && !up {
		return nil, ErrForwardOnly
	}
	var exactUp int64
	if up {
		exactUp = version
	}
	r, _, err := p.prepare(ctx, version, exactUp)
	if err != nil {
		return nil, err
	}
	return r.ApplyVersion(ctx, version, up)
}

// Down attempts the most recent rollback, honoring forward-only SQL boundaries.
func (p *Provider) Down(ctx context.Context) (*goose.MigrationResult, error) {
	r, state, err := p.prepare(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	if state.version == 0 {
		return nil, goose.ErrNoNextVersion
	}
	return r.Down(ctx)
}

// DownTo attempts rollback to the specified version under worker exclusion.
func (p *Provider) DownTo(ctx context.Context, version int64) ([]*goose.MigrationResult, error) {
	if version == 0 {
		return nil, ErrForwardOnly
	}
	if version < 0 {
		return nil, fmt.Errorf("migrate: down target must be positive")
	}
	r, state, err := p.prepare(ctx, version, 0)
	if err != nil {
		return nil, err
	}
	if state.version == 0 {
		return nil, nil
	}
	return r.DownTo(ctx, version)
}

// Status is strictly read-only, including on a fresh database.
func (p *Provider) Status(ctx context.Context) ([]*goose.MigrationStatus, error) {
	r, state, err := p.prepare(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	statuses := make([]*goose.MigrationStatus, 0, len(r.ListSources()))
	for _, source := range r.ListSources() {
		status := &goose.MigrationStatus{Source: source, State: goose.StatePending}
		if timestamp, applied := state.applied[source.Version]; applied {
			status.State, status.AppliedAt = goose.StateApplied, timestamp
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// GetDBVersion reports the highest applied migration version.
func (p *Provider) GetDBVersion(ctx context.Context) (int64, error) {
	_, state, err := p.prepare(ctx, 0, 0)
	if err != nil {
		return 0, err
	}
	return state.version, nil
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

// UpTo applies pending migrations through a bundled migration version.
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

// Reset refuses before rollback, including when future migrations are installed.
func Reset(_ context.Context, _ *sql.DB) error {
	return ErrForwardOnly
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
