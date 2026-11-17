//go:build integration

package geography

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type geoFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	svc    *Service
	config *pgxpool.Config
}

// Only create/migrate a uniquely named child database. The provisioning schema
// and all existing databases remain untouched; cleanup is explicitly confirmed.
func geographyFixture(t *testing.T, upgrade bool) geoFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL provisioning access is required")
	}
	ctx, stop := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(stop)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid provisioning configuration")
	}
	t.Cleanup(admin.Close)
	const inventory = `SELECT COALESCE(jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner) ORDER BY oid)::text,'[]') FROM pg_catalog.pg_class WHERE relnamespace='public'::regnamespace`
	var before string
	if admin.QueryRow(ctx, inventory).Scan(&before) != nil {
		t.Fatal("provisioning schema unavailable")
	}
	name := "geography_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Log("run-owned geography fixture:", name)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("geography database cleanup failed", err)
		}
		var exists bool
		if admin.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists) != nil || exists {
			t.Error("geography database cleanup not confirmed")
		}
		var after string
		if admin.QueryRow(cleanup, inventory).Scan(&after) != nil || after != before {
			t.Error("provisioning schema changed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = sqlDB.Close() }()
	var actual string
	if sqlDB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&actual) != nil || actual != name {
		t.Fatal("migration target not run-owned")
	}
	if upgrade {
		if migrate.UpTo(ctx, sqlDB, 3) != nil {
			t.Fatal("cannot install version3")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO users(email,display_name) VALUES('upgrade@geography.invalid','Preserved')`); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrate.Up(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqlDB); err != nil {
		t.Fatal("migration no-op", err)
	}
	if upgrade {
		var preserved bool
		if pool.QueryRow(ctx, `SELECT display_name='Preserved' AND username_key IS NULL AND auth_version=0 FROM users WHERE email='upgrade@geography.invalid'`).Scan(&preserved) != nil || !preserved {
			t.Fatal("upgrade changed existing account")
		}
	}
	return geoFixture{ctx, pool, New(pool), cfg}
}
func geoExec(t *testing.T, f geoFixture, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}
func geoCount(t *testing.T, f geoFixture, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func geoImport(t *testing.T, f geoFixture, s *Snapshot) Plan {
	t.Helper()
	p, err := f.svc.Check(f.ctx, s)
	if err != nil {
		t.Fatal("check", err)
	}
	got, err := f.svc.Import(f.ctx, s, p.PlanDigest, p.RetirementDigest)
	if err != nil {
		t.Fatal("import", err)
	}
	return got
}

func TestGeographySnapshotsNoOpConcurrencyAndHistory(t *testing.T) {
	f := geographyFixture(t, false)
	if _, err := f.svc.Provinces(f.ctx, ListInput{Country: "IR"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uninitialized returned success")
	}
	initial := fixtureSnapshot(t, syntheticCities, nil)
	plan, err := f.svc.Check(f.ctx, initial)
	if err != nil || plan.Additions != 7 || plan.Retirements != 0 || plan.PlanDigest == "" {
		t.Fatal(plan, err)
	}
	if geoCount(t, f, `SELECT count(*) FROM geography_catalogs`) != 0 {
		t.Fatal("check wrote catalog")
	}
	if _, err := f.svc.Import(f.ctx, initial, strings.Repeat("0", 64), ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("unchecked digest accepted")
	}
	const workers = 4
	results := make(chan Plan, workers)
	failures := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() { p, err := f.svc.Import(f.ctx, initial, plan.PlanDigest, ""); results <- p; failures <- err })
	}
	wg.Wait()
	noops := 0
	for range workers {
		p := <-results
		err := <-failures
		if err != nil || p.CatalogRevision != "1" {
			t.Fatal("identical concurrency", p, err)
		}
		if p.NoOp {
			noops++
		}
	}
	if noops != workers-1 || geoCount(t, f, `SELECT count(*) FROM geography_catalogs`) != 1 || geoCount(t, f, `SELECT count(*) FROM geography_place_versions`) != 7 {
		t.Fatal("identical import duplicated rows")
	}
	var before string
	if f.pool.QueryRow(f.ctx, `SELECT row_to_json(c)::text FROM geography_catalogs c WHERE revision=1`).Scan(&before) != nil {
		t.Fatal("catalog read")
	}
	repeated, err := f.svc.Import(f.ctx, initial, plan.PlanDigest, "")
	if err != nil || !repeated.NoOp {
		t.Fatal("repeat import", err)
	}
	var after string
	if f.pool.QueryRow(f.ctx, `SELECT row_to_json(c)::text FROM geography_catalogs c WHERE revision=1`).Scan(&after) != nil || after != before {
		t.Fatal("no-op changed timestamps")
	}
	one := "1"
	nextCities := strings.Replace(syntheticCities, `{"Id":13,"Name":"Village","ParentId":12,"CenterType":7},`, "", 1)
	nextCities = strings.Replace(nextCities, `"Name":"Shared","ParentId":10`, `"Name":"Renamed","ParentId":2`, 1)
	next := fixtureSnapshot(t, nextCities, &one)
	changePlan, err := f.svc.Check(f.ctx, next)
	if err != nil || changePlan.Retirements != 1 || changePlan.Edits != 1 || changePlan.Reparenting != 2 || changePlan.RetirementDigest == "" {
		t.Fatal("change plan", changePlan, err)
	}
	if _, err := f.svc.Import(f.ctx, next, changePlan.PlanDigest, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("retirement not acknowledged", err)
	}
	if geoCount(t, f, `SELECT count(*) FROM geography_catalogs`) != 1 {
		t.Fatal("refused retirement changed catalog")
	}
	second, err := f.svc.Import(f.ctx, next, changePlan.PlanDigest, changePlan.RetirementDigest)
	if err != nil || second.CatalogRevision != "2" {
		t.Fatal(second, err)
	}
	current, err := f.svc.Lookup(f.ctx, "11", "")
	if err != nil || current.Label != "Renamed" || current.Province.ID != "2" || len(current.Ancestors) != 1 {
		t.Fatal("current ancestry", current, err)
	}
	historical, err := f.svc.Lookup(f.ctx, "11", "1")
	if err != nil || historical.Label != "Shared" || historical.Province.ID != "1" || len(historical.Ancestors) != 2 || historical.Selectable {
		t.Fatal("historical ancestry", historical, err)
	}
	retired, err := f.svc.Lookup(f.ctx, "13", "")
	if err != nil || !retired.Retired || retired.Selectable || retired.CatalogRevision != "1" || retired.Province.ID != "1" {
		t.Fatal("retired last-seen resolution", retired, err)
	}
	if _, err := f.svc.Lookup(f.ctx, "13", "2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("nonmembership fabricated")
	}
	if _, err := f.svc.Check(f.ctx, initial); !errors.Is(err, ErrCatalogChanged) {
		t.Fatal("stale manifest accepted")
	}
	if _, err := f.svc.Import(f.ctx, initial, plan.PlanDigest, ""); !errors.Is(err, ErrCatalogChanged) {
		t.Fatal("noncurrent reused without checked plan")
	}
	two := "2"
	reactivation := fixtureSnapshot(t, syntheticCities, &two)
	reactivatePlan, err := f.svc.Check(f.ctx, reactivation)
	if err != nil || reactivatePlan.Reactivations != 1 {
		t.Fatal("reactivation plan", reactivatePlan, err)
	}
	third := geoImport(t, f, reactivation)
	if third.CatalogRevision != "3" {
		t.Fatal(third)
	}
	identity, err := db.New(f.pool).GeographyIdentity(f.ctx, 13)
	if err != nil || identity.FirstSeenRevision != 1 || identity.LastSeenRevision != 3 {
		t.Fatal("stable identity lost", identity, err)
	}
	old, err := f.svc.Lookup(f.ctx, "11", "2")
	if err != nil || old.Label != "Renamed" || old.Province.ID != "2" || old.Selectable {
		t.Fatal("reactivation changed prior snapshot", err)
	}
	if geoCount(t, f, `SELECT count(*) FROM geography_places`) != 7 || geoCount(t, f, `SELECT count(*) FROM geography_place_versions`) != 20 {
		t.Fatal("not full immutable snapshots")
	}
}

func TestGeographySearchPaginationValidationAndRollback(t *testing.T) {
	f := geographyFixture(t, true)
	// Exact labels demonstrate normalized/literal prefix admission without data fixtures.
	cities := strings.Replace(syntheticCities, `"Name":"Shared","ParentId":10`, `"Name":"\u064a\u0643\u200cName","ParentId":10`, 1)
	cities = strings.Replace(cities, `"Name":"Shared","ParentId":11`, `"Name":"%_\\Literal","ParentId":11`, 1)
	geoImport(t, f, fixtureSnapshot(t, cities, nil))
	p, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Query: "\u06cc\u06a9 Name"})
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != "11" || p.Items[0].Label != "\u064a\u0643\u200cName" {
		t.Fatal("normalization changed display", p, err)
	}
	for _, query := range []string{"%", "%_", "%_\\"} {
		p, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Query: query})
		if err != nil || len(p.Items) != 1 || p.Items[0].ID != "12" {
			t.Fatal("literal wildcard search", p, err)
		}
	}
	empty, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Query: "No match"})
	if err != nil || empty.Items == nil || len(empty.Items) != 0 {
		t.Fatal("empty valid search", err)
	}
	var cursor string
	ids := make(map[string]bool)
	for {
		page, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Limit: 1, Cursor: cursor})
		if err != nil || len(page.Items) > 1 {
			t.Fatal("pagination", err)
		}
		for _, p := range page.Items {
			if ids[p.ID] {
				t.Fatal("duplicate keyset result")
			}
			ids[p.ID] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
		if len(cursor) > 2048 {
			t.Fatal("oversized cursor")
		}
	}
	if len(ids) != 3 {
		t.Fatal("pagination lost membership", ids)
	}
	validated, err := f.svc.Validate(f.ctx, LocationInput{Country: "IR", ProvinceID: "1", LocalityID: "13"})
	if err != nil || validated.CatalogRevision != "1" {
		t.Fatal("validator", err)
	}
	if _, err := f.svc.Validate(f.ctx, LocationInput{Country: "IR", ProvinceID: "1"}); err != nil {
		t.Fatal("optional locality rejected")
	}
	for _, in := range []LocationInput{{"IR", "1", "20"}, {"IR", "10", "11"}, {"IR", "1", "10"}, {"IR", "1", "999"}} {
		if _, err := f.svc.Validate(f.ctx, in); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid location accepted", in, err)
		}
	}
	first, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Limit: 1})
	if err != nil || first.NextCursor == "" {
		t.Fatal(err)
	}
	one := "1"
	changed := fixtureSnapshot(t, strings.Replace(cities, "Village", "Changed", 1), &one)
	plan, err := f.svc.Check(f.ctx, changed)
	if err != nil {
		t.Fatal(err)
	}
	// An injected failure occurs after catalog/types/identities are staged.
	geoExec(t, f, `CREATE FUNCTION geography_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected failure'; END $$;
      CREATE TRIGGER geography_fixture_failure BEFORE UPDATE ON geography_catalog_state FOR EACH ROW EXECUTE FUNCTION geography_fixture_failure()`)
	if _, err := f.svc.Import(f.ctx, changed, plan.PlanDigest, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal("atomic failure missing", err)
	}
	if geoCount(t, f, `SELECT count(*) FROM geography_catalogs`) != 1 || geoCount(t, f, `SELECT count(*) FROM geography_place_versions`) != 7 || geoCount(t, f, `SELECT count(*) FROM geography_places WHERE last_seen_revision<>1`) != 0 {
		t.Fatal("rollback left partial snapshot/metadata")
	}
	geoExec(t, f, `DROP TRIGGER geography_fixture_failure ON geography_catalog_state; DROP FUNCTION geography_fixture_failure()`)
	geoImport(t, f, changed)
	if _, err := f.svc.Localities(f.ctx, ListInput{Country: "IR", ProvinceID: "1", Limit: 1, Cursor: first.NextCursor}); !errors.Is(err, ErrCatalogChanged) {
		t.Fatal("pagination crossed revision", err)
	}
	if _, err := f.svc.Lookup(f.ctx, "999", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown lookup", err)
	}
}

func TestGeographyRestrictedLoginsAndImmutablePermissions(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgrade"}[upgrade], func(t *testing.T) {
			f := geographyFixture(t, upgrade)
			readerName := "geo_reader_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			importerName := "geo_importer_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			password := uuid.NewString()
			reader := pgx.Identifier{readerName}.Sanitize()
			importer := pgx.Identifier{importerName}.Sanitize()
			geoExec(t, f, "CREATE ROLE "+reader+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
			geoExec(t, f, "CREATE ROLE "+importer+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				for _, role := range []string{reader, importer} {
					if _, err := f.pool.Exec(ctx, "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
						t.Error("role cleanup", err)
					}
				}
			})
			tables := "geography_catalogs,geography_types,geography_places,geography_place_versions,geography_catalog_state"
			geoExec(t, f, "GRANT USAGE ON SCHEMA public TO "+reader+","+importer)
			geoExec(t, f, "GRANT SELECT ON "+tables+" TO "+reader+","+importer)
			geoExec(t, f, "GRANT INSERT(revision,country,source_release,cities_sha256,types_sha256,cities_bytes,types_bytes,place_count,type_count,province_count,importer_version,normalization_version) ON geography_catalogs TO "+importer)
			geoExec(t, f, "GRANT INSERT ON geography_types,geography_places,geography_place_versions TO "+importer)
			geoExec(t, f, "GRANT UPDATE(last_seen_revision) ON geography_places TO "+importer)
			geoExec(t, f, "GRANT UPDATE(active_revision) ON geography_catalog_state TO "+importer)
			login := func(name string) *pgxpool.Pool {
				cfg := f.config.Copy()
				cfg.ConnConfig.User = name
				cfg.ConnConfig.Password = password
				p, err := pgxpool.NewWithConfig(f.ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				var current string
				if p.QueryRow(f.ctx, `SELECT current_user`).Scan(&current) != nil || current != name {
					t.Fatal("restricted login not observed")
				}
				return p
			}
			readPool := login(readerName)
			importPool := login(importerName)
			if err := CheckPrivileges(f.ctx, readPool, false); err != nil {
				t.Fatal("reader privilege proof", err)
			}
			if err := CheckPrivileges(f.ctx, importPool, true); err != nil {
				t.Fatal("importer privilege proof", err)
			}
			if err := CheckPrivileges(f.ctx, f.pool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("owner accepted as operator")
			}
			geoExec(t, f, "REVOKE INSERT(source_release) ON geography_catalogs FROM "+importer)
			if err := CheckPrivileges(f.ctx, importPool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("missing required column accepted")
			}
			geoExec(t, f, "GRANT INSERT(source_release) ON geography_catalogs TO "+importer)
			geoExec(t, f, "GRANT INSERT(writing_tx) ON geography_catalogs TO "+importer)
			if err := CheckPrivileges(f.ctx, importPool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("extra insert column accepted")
			}
			geoExec(t, f, "REVOKE INSERT(writing_tx) ON geography_catalogs FROM "+importer)
			geoExec(t, f, "GRANT INSERT ON geography_catalogs TO "+importer)
			if err := CheckPrivileges(f.ctx, importPool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("full table insert accepted")
			}
			geoExec(t, f, "REVOKE INSERT ON geography_catalogs FROM "+importer)
			geoExec(t, f, "GRANT INSERT(revision,country,source_release,cities_sha256,types_sha256,cities_bytes,types_bytes,place_count,type_count,province_count,importer_version,normalization_version) ON geography_catalogs TO "+importer)
			geoExec(t, f, "GRANT SELECT ON users TO "+importer)
			if err := CheckPrivileges(f.ctx, importPool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("account privilege accepted")
			}
			geoExec(t, f, "REVOKE SELECT ON users FROM "+importer)
			geoExec(t, f, "ALTER TABLE geography_place_versions DISABLE TRIGGER geography_versions_guard")
			if err := CheckPrivileges(f.ctx, importPool, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("disabled immutable guard accepted")
			}
			geoExec(t, f, "ALTER TABLE geography_place_versions ENABLE TRIGGER geography_versions_guard")
			if err := CheckPrivileges(f.ctx, importPool, true); err != nil {
				t.Fatal("restored privilege proof", err)
			}
			snapshot := fixtureSnapshot(t, syntheticCities, nil)
			plan, err := New(readPool).Check(f.ctx, snapshot)
			if err != nil {
				t.Fatal("reader check", err)
			}
			result, err := New(importPool).Import(f.ctx, snapshot, plan.PlanDigest, "")
			if err != nil || result.CatalogRevision != "1" {
				t.Fatal("narrow importer", result, err)
			}
			if _, err := New(readPool).Provinces(f.ctx, ListInput{Country: "IR"}); err != nil {
				t.Fatal("reader service", err)
			}
			for _, pool := range []*pgxpool.Pool{readPool, importPool} {
				for _, sql := range []string{`SELECT * FROM users`, `CREATE TABLE public.geo_forbidden(id integer)`, `DELETE FROM geography_places`, `TRUNCATE geography_place_versions`, `UPDATE geography_catalogs SET source_release='tamper'`, `UPDATE geography_place_versions SET label='tamper'`, `UPDATE geography_types SET label='tamper'`, `UPDATE geography_places SET first_seen_revision=1`} {
					if _, err := pool.Exec(f.ctx, sql); err == nil {
						t.Fatal("restricted role accepted forbidden operation", sql)
					}
				}
			}
			if _, err := readPool.Exec(f.ctx, `UPDATE geography_catalog_state SET active_revision=1`); err == nil {
				t.Fatal("reader can mutate state")
			}
			// Even owner writes cannot rewrite snapshots, add late members, or delete identities.
			for _, sql := range []string{`UPDATE geography_catalogs SET source_release='tamper'`, `UPDATE geography_place_versions SET label='tamper'`, `UPDATE geography_types SET label='tamper'`, `DELETE FROM geography_places`, `TRUNCATE geography_catalogs CASCADE`, `INSERT INTO geography_types(revision,id,label) VALUES(1,9,'Late')`, `UPDATE geography_places SET first_seen_revision=1,last_seen_revision=1`, `DELETE FROM geography_catalog_state`} {
				if _, err := f.pool.Exec(f.ctx, sql); err == nil {
					t.Fatal("immutable snapshot bypass", sql)
				}
			}
		})
	}
}

func TestGeographyMigrationImportExclusionAndQueryTimeout(t *testing.T) {
	f := geographyFixture(t, false)
	snapshot := fixtureSnapshot(t, syntheticCities, nil)
	plan, err := f.svc.Check(f.ctx, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []int64{pglock.MigrationKey, pglock.GeographyImportKey} {
		blocker, err := f.pool.Acquire(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := blocker.Exec(f.ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
		_, err = f.svc.Import(ctx, snapshot, plan.PlanDigest, "")
		cancel()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal("import ignored exclusion", key, err)
		}
		if _, err := blocker.Exec(f.ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Fatal(err)
		}
		blocker.Release()
	}
	if geoCount(t, f, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`) != 0 {
		t.Fatal("import cancellation leaked locks")
	}
	geoImport(t, f, snapshot)
	blocker, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(blocker)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE geography_place_versions IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = f.svc.Provinces(f.ctx, ListInput{Country: "IR"})
	if !errors.Is(err, ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatal("read deadline unavailable", err)
	}
	rollback(blocker)
	if _, err := f.svc.Provinces(f.ctx, ListInput{Country: "IR"}); err != nil {
		t.Fatal("timeout poisoned read pool", err)
	}
}
