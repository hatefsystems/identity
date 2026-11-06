//go:build integration

package legalhold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

func disposableHoldDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for backfill integration tests")
	}
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error("backfill administration connection cleanup failed")
		}
	})
	name := "hold_backfill_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Logf("run-owned legal hold fixture database: %s", name)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop backfill test database: %v", err)
		}
		var exists bool
		if err := admin.QueryRowContext(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("backfill database cleanup not confirmed")
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

const expandedHoldChecks = `
    ADD CONSTRAINT legal_holds_details_exclusive CHECK (
        details_encrypted IS NULL OR
        (reason IS NULL AND requesting_authority IS NULL AND legal_basis IS NULL)),
    ADD CONSTRAINT legal_holds_request_details CHECK (
        idempotency_key IS NULL OR details_encrypted IS NOT NULL OR
        (NOT is_active AND details_purged_at IS NOT NULL))`

// This isolated storage-shape fixture is not an application migration lineage.
func backfillDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, pool := disposableHoldDatabase(t)
	if _, err := pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE public.legal_holds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,
    applied_by UUID NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    released_by UUID,
    request_kind TEXT NOT NULL DEFAULT 'legal_hold' CHECK (request_kind IN ('legal_hold','preservation')),
    idempotency_key UUID,
    details_encrypted BYTEA,
    details_purged_at TIMESTAMPTZ,
    reason TEXT,
    requesting_authority VARCHAR(255),
    legal_basis VARCHAR(255)
);
ALTER TABLE public.legal_holds `+expandedHoldChecks+`;
CREATE UNIQUE INDEX legal_holds_request_identity ON public.legal_holds(account_ref,request_kind,idempotency_key)
    WHERE idempotency_key IS NOT NULL;`); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

// Contraction exercises compatibility storage only, never a supported upgrade.
func contractHoldStorage(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE public.legal_holds IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM public.legal_holds
        WHERE reason IS NOT NULL OR requesting_authority IS NOT NULL OR legal_basis IS NOT NULL
        OR NOT ((details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL)
            OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL))) THEN
        RAISE EXCEPTION 'test storage contraction requires complete backfill or released/purged tombstones';
    END IF;
END $$;
ALTER TABLE public.legal_holds
    DROP CONSTRAINT legal_holds_details_exclusive,
    DROP CONSTRAINT legal_holds_request_details,
    DROP COLUMN reason,
    DROP COLUMN requesting_authority,
    DROP COLUMN legal_basis,
    ADD CONSTRAINT legal_holds_encrypted_or_purged CHECK (
        (details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL)
        OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL));`); err != nil {
		return err
	}
	return tx.Commit(ctx)
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

func insertLegacyHold(ctx context.Context, t *testing.T, pool *pgxpool.Pool, released bool, kind string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO legal_holds(id,account_ref,applied_by,reason,requesting_authority,legal_basis,
		request_kind,is_active,released_at,review_at,applied_at) VALUES($1,$2,$3,'fixture reason','fixture court','fixture basis',$4,
		$5,CASE WHEN $5 THEN NULL ELSE '2026-01-02Z'::timestamptz END,'2026-01-03Z','2026-01-01Z')`, id, uuid.New(), uuid.New(), kind, !released)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestBackfillBoundedRetriesAndPhysicalContractionIntegration(t *testing.T) {
	ctx, pool := backfillDatabase(t)
	metadata := holdMigrationMetadata(ctx, t, pool)
	defer clearRestoreInventory(metadata)
	s, _ := testService(t)
	s.store = db.New(pool)
	ids := []uuid.UUID{insertLegacyHold(ctx, t, pool, false, KindHold), insertLegacyHold(ctx, t, pool, true, KindHold), insertLegacyHold(ctx, t, pool, false, KindPreservation)}
	converted := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: KindPreservation, Reason: "converted fixture", RequestingAuthority: "fixture court", LegalBasis: "fixture basis"}
	blob, err := s.seal(ctx, converted)
	if err != nil {
		t.Fatal(err)
	}
	existing, err := db.New(pool).CreateEncryptedLegalHold(ctx, db.CreateEncryptedLegalHoldParams{ID: converted.RecordID, AccountRef: converted.AccountRef,
		AppliedBy: uuid.New(), RequestKind: converted.Kind, IdempotencyKey: uuid.NullUUID{UUID: uuid.New(), Valid: true}, DetailsEncrypted: blob})
	if err != nil {
		t.Fatal(err)
	}
	var before []db.LegalHold
	for _, invalid := range []struct {
		query, code string
		id          uuid.UUID
	}{
		{`INSERT INTO public.legal_holds SELECT * FROM public.legal_holds WHERE id=$1`, "23505", existing.ID},
		{`INSERT INTO public.legal_holds(id,account_ref,applied_by,request_kind,idempotency_key,details_encrypted)
SELECT uuid_generate_v4(),account_ref,applied_by,request_kind,idempotency_key,details_encrypted FROM public.legal_holds WHERE id=$1`, "23505", existing.ID},
		{`UPDATE public.legal_holds SET reason='plaintext beside ciphertext' WHERE id=$1`, "23514", existing.ID},
		{`UPDATE public.legal_holds SET idempotency_key=uuid_generate_v4() WHERE id=$1`, "23514", ids[0]},
		{`UPDATE public.legal_holds SET request_kind='unknown' WHERE id=$1`, "23514", ids[0]},
	} {
		_, err := pool.Exec(ctx, invalid.query, invalid.id)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != invalid.code {
			t.Fatalf("expanded fixture did not enforce real PK, replay or details checks: %v", err)
		}
	}
	for _, id := range ids {
		row, err := db.New(pool).GetLegalHold(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, row)
	}
	if err := s.CheckCrypto(ctx); !errors.Is(err, ErrBackfillRequired) {
		t.Fatalf("legacy readiness: %v", err)
	}
	beforeRefusal := restoreInventory(ctx, t, pool)
	defer clearRestoreInventory(beforeRefusal)
	if err := contractHoldStorage(ctx, pool); err == nil {
		t.Fatal("premature contraction succeeded")
	}
	afterRefusal := restoreInventory(ctx, t, pool)
	compareRestoreInventory(t, beforeRefusal, afterRefusal)
	clearRestoreInventory(afterRefusal)
	compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, pool))
	for i := 0; i < len(ids); i++ {
		if count, err := s.Backfill(ctx, pool, 1); err != nil || count != 1 {
			t.Fatalf("bounded retry: %d %v", count, err)
		}
	}
	if count, err := s.Backfill(ctx, pool, 1); err != nil || count != 0 {
		t.Fatalf("completed retry: %d %v", count, err)
	}
	for i, id := range ids {
		row, err := db.New(pool).GetLegalHold(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		hold, err := s.openHold(ctx, row)
		if err != nil || hold.Details.RecordID != id || hold.Details.AccountRef != before[i].AccountRef || hold.Details.Kind != before[i].RequestKind || hold.Details.Reason != "fixture reason" {
			t.Fatalf("bound details: %v", err)
		}
		row.DetailsEncrypted = nil
		oldJSON, _ := json.Marshal(before[i])
		newJSON, _ := json.Marshal(row)
		if !bytes.Equal(oldJSON, newJSON) {
			t.Fatal("backfill changed identity, kind, replay key or clocks")
		}
	}
	if err := s.CheckCrypto(ctx); err != nil {
		t.Fatal(err)
	}
	preserved, err := db.New(pool).GetLegalHold(ctx, existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(existing)
	afterJSON, _ := json.Marshal(preserved)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("already encrypted request/replay key changed")
	}
	if err := contractHoldStorage(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if count, err := s.Backfill(ctx, pool, 1); err != nil || count != 0 {
		t.Fatalf("contracted backfill: %d %v", count, err)
	}
	if err := s.CheckCrypto(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		row, err := db.New(pool).GetLegalHold(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.openHold(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, pool))
}

type backfillWrongBinding struct{ Encryptor }

func (e backfillWrongBinding) Encrypt(ctx context.Context, plain []byte) ([]byte, error) {
	var details Details
	if json.Unmarshal(plain, &details) != nil {
		return nil, ErrUnavailable
	}
	details.AccountRef = uuid.New()
	changed, _ := json.Marshal(details)
	defer clear(changed)
	return e.Encryptor.Encrypt(ctx, changed)
}

type backfillWrongKey struct {
	Encryptor
	other Encryptor
}

func (e backfillWrongKey) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	return e.other.Decrypt(ctx, blob)
}

func TestBackfillFailuresPreservePlaintextAndMetadataIntegration(t *testing.T) {
	for _, failure := range []string{"binding", "wrong-key", "update", "commit", "stored-ciphertext"} {
		t.Run(failure, func(t *testing.T) {
			ctx, pool := backfillDatabase(t)
			if _, err := pool.Exec(ctx, `CREATE TABLE public.goose_db_version (
id SERIAL PRIMARY KEY, version_id BIGINT NOT NULL, is_applied BOOLEAN NOT NULL,
tstamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
INSERT INTO public.goose_db_version(version_id,is_applied) VALUES(0,true),(1,true)`); err != nil {
				t.Fatal(err)
			}
			metadata := holdMigrationMetadata(ctx, t, pool)
			defer clearRestoreInventory(metadata)
			s, _ := testService(t)
			s.store = db.New(pool)
			id := insertLegacyHold(ctx, t, pool, false, KindHold)
			var before, after string
			if err := pool.QueryRow(ctx, `SELECT to_jsonb(h)::text FROM legal_holds h WHERE id=$1`, id).Scan(&before); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "binding":
				s.encryptor = backfillWrongBinding{s.encryptor}
			case "wrong-key":
				provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x63}, 32), 1)
				if err != nil {
					t.Fatal(err)
				}
				other, err := envelope.New(provider)
				if err != nil {
					t.Fatal(err)
				}
				s.encryptor = backfillWrongKey{s.encryptor, other}
			case "update", "commit":
				if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_backfill() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture update failure'; END $$`); err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER reject_backfill BEFORE UPDATE ON legal_holds FOR EACH ROW EXECUTE FUNCTION reject_backfill()`
				if failure == "commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_backfill AFTER UPDATE ON legal_holds DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_backfill()`
				}
				if _, err := pool.Exec(ctx, trigger); err != nil {
					t.Fatal(err)
				}
			case "stored-ciphertext":
				if _, err := pool.Exec(ctx, `CREATE FUNCTION corrupt_backfill() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.details_encrypted := '\x01'; RETURN NEW; END $$;
					CREATE TRIGGER corrupt_backfill BEFORE UPDATE ON legal_holds FOR EACH ROW EXECUTE FUNCTION corrupt_backfill()`); err != nil {
					t.Fatal(err)
				}
			}
			if count, err := s.Backfill(ctx, pool, 1); err == nil || count != 0 {
				t.Fatalf("failure accepted: %d %v", count, err)
			}
			if err := pool.QueryRow(ctx, `SELECT to_jsonb(h)::text FROM legal_holds h WHERE id=$1`, id).Scan(&after); err != nil || before != after {
				t.Fatal("failed backfill changed row")
			}
			compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, pool))
		})
	}
}

func TestBackfillAndReadinessRejectPartialSchemaIntegration(t *testing.T) {
	ctx, pool := backfillDatabase(t)
	s, _ := testService(t)
	s.store = db.New(pool)
	if _, err := pool.Exec(ctx, `ALTER TABLE legal_holds DROP CONSTRAINT legal_holds_details_exclusive, DROP COLUMN reason`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Backfill(ctx, pool, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("partial backfill: %v", err)
	}
	if err := s.CheckCrypto(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("partial readiness: %v", err)
	}
	for _, sql := range []string{
		`ALTER TABLE legal_holds ADD COLUMN reason TEXT, ADD CONSTRAINT legal_holds_details_exclusive CHECK(details_encrypted IS NULL OR (reason IS NULL AND requesting_authority IS NULL AND legal_basis IS NULL)); ALTER TABLE legal_holds ADD COLUMN unexpected TEXT`,
		`ALTER TABLE legal_holds DROP COLUMN unexpected; ALTER TABLE legal_holds ALTER COLUMN request_kind TYPE varchar`,
		`ALTER TABLE legal_holds ALTER COLUMN request_kind TYPE text; ALTER TABLE legal_holds DROP CONSTRAINT legal_holds_request_details`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Backfill(ctx, pool, 1); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unexpected layout backfill: %v", err)
		}
		if err := s.CheckCrypto(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unexpected layout readiness: %v", err)
		}
	}
}

func TestBackfillStorageContractionRefusesUnexpectedDependenciesIntegration(t *testing.T) {
	ctx, pool := backfillDatabase(t)
	s, _ := testService(t)
	s.store = db.New(pool)
	id := insertLegacyHold(ctx, t, pool, false, KindHold)
	if n, err := s.Backfill(ctx, pool, 1); err != nil || n != 1 {
		t.Fatalf("prepare verified ciphertext: %d %v", n, err)
	}
	if _, err := pool.Exec(ctx, `CREATE VIEW public.hold_plaintext_dependency AS SELECT reason FROM public.legal_holds`); err != nil {
		t.Fatal(err)
	}
	metadata := holdMigrationMetadata(ctx, t, pool)
	defer clearRestoreInventory(metadata)
	before := restoreInventory(ctx, t, pool)
	defer clearRestoreInventory(before)
	err := contractHoldStorage(ctx, pool)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "2BP01" {
		t.Fatalf("unexpected dependency must stop non-CASCADE contraction: %v", err)
	}
	after := restoreInventory(ctx, t, pool)
	compareRestoreInventory(t, before, after)
	clearRestoreInventory(after)
	if expanded, err := legalHoldSchema(ctx, db.New(pool)); err != nil || !expanded {
		t.Fatalf("failed DDL did not roll back expanded columns/checks: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.hold_plaintext_dependency') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatal("contraction removed unexpected dependency")
	}
	if _, err := pool.Exec(ctx, `DROP VIEW public.hold_plaintext_dependency`); err != nil {
		t.Fatal(err)
	}
	if err := contractHoldStorage(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`UPDATE public.legal_holds SET details_encrypted=NULL`,
		`UPDATE public.legal_holds SET details_encrypted='\x'`,
		`UPDATE public.legal_holds SET details_purged_at=now()`,
		`UPDATE public.legal_holds SET details_encrypted=NULL,details_purged_at=now(),is_active=false`,
	} {
		_, err := pool.Exec(ctx, invalid)
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "legal_holds_encrypted_or_purged" {
			t.Fatalf("final ciphertext/tombstone constraint not enforced: %v", err)
		}
	}
	row, err := db.New(pool).GetLegalHold(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.openHold(ctx, row); err != nil {
		t.Fatal("constraint failures changed verified ciphertext")
	}
	compareRestoreInventory(t, metadata, holdMigrationMetadata(ctx, t, pool))
}

func TestBackfillFullBaselineNoWorkIntegration(t *testing.T) {
	ctx, pool := restoreDatabase(t)
	s, _ := testService(t)
	s.store = db.New(pool)
	before := restoreInventory(ctx, t, pool)
	defer clearRestoreInventory(before)
	for range 2 {
		if n, err := s.Backfill(ctx, pool, 1); err != nil || n != 0 {
			t.Fatalf("fresh full baseline backfill must be a no-op: %d %v", n, err)
		}
		if err := s.CheckCrypto(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after := restoreInventory(ctx, t, pool)
	compareRestoreInventory(t, before, after)
	clearRestoreInventory(after)
}
