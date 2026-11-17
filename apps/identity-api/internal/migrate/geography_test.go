package migrate

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/hatefsystems/identity/apps/identity-api/db"
)

func TestGeographyUpgradeAtomicFailureAndForwardRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	database := openTestDB(ctx, t)
	p, err := NewProvider(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	execFixture(ctx, t, database, `INSERT INTO users(email,display_name) VALUES('geography-upgrade@fixture.invalid','Preserved')`)
	files := fstest.MapFS{}
	for _, path := range []string{"00001_initial_schema.sql", "00002_registration_attempts.sql", "00003_username_reservations.sql", "00004_geography_catalog.sql"} {
		raw, err := db.Migrations.ReadFile("migrations/" + path)
		if err != nil {
			t.Fatal(err)
		}
		if path == "00004_geography_catalog.sql" {
			raw = []byte(strings.Replace(string(raw), "-- +goose Down", "SELECT 1/0;\n-- +goose Down", 1))
		}
		files[path] = &fstest.MapFile{Data: raw}
	}
	broken := &Provider{db: database, files: files}
	if _, err := broken.Up(ctx); err == nil {
		t.Fatal("failed geography migration accepted")
	}
	if version, err := p.GetDBVersion(ctx); err != nil || version != 3 {
		t.Fatal("failed migration damaged lineage", version, err)
	}
	var exists bool
	if database.QueryRowContext(ctx, `SELECT to_regclass('public.geography_catalogs') IS NOT NULL`).Scan(&exists) != nil || exists {
		t.Fatal("partial geography catalog survived")
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal("forward retry", err)
	}
	var preserved bool
	if database.QueryRowContext(ctx, `SELECT display_name='Preserved' AND auth_version=0 AND username_key IS NULL FROM users WHERE email='geography-upgrade@fixture.invalid'`).Scan(&preserved) != nil || !preserved {
		t.Fatal("upgrade changed account")
	}
	before := metadataSnapshot(ctx, t, database)
	if _, err := p.Down(ctx); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatal("geography rollback allowed", err)
	}
	if _, err := p.Up(ctx); err != nil || before != metadataSnapshot(ctx, t, database) {
		t.Fatal("forward-only/no-op changed history", err)
	}
}
