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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

func backfillDatabase(t *testing.T) (context.Context, *pgxpool.Pool, *migrate.Provider) {
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
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop backfill test database: %v", err)
		}
		var exists bool
		if err := admin.QueryRowContext(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("backfill database cleanup not confirmed")
		}
	})
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	sqldb := stdlib.OpenDB(*cfg)
	t.Cleanup(func() {
		if err := sqldb.Close(); err != nil {
			t.Error("backfill migration connection cleanup failed")
		}
	})
	p, err := migrate.NewProvider(sqldb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 19); err != nil {
		t.Fatal(err)
	}
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
	return ctx, pool, p
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
	ctx, pool, p := backfillDatabase(t)
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
	if _, err := p.ApplyVersion(ctx, 20, true); err == nil {
		t.Fatal("premature contraction succeeded")
	}
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
	if _, err := p.ApplyVersion(ctx, 20, true); err != nil {
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

func TestBackfillFailuresPreservePlaintextAndVersionIntegration(t *testing.T) {
	for _, failure := range []string{"binding", "wrong-key", "update", "commit", "stored-ciphertext"} {
		t.Run(failure, func(t *testing.T) {
			ctx, pool, p := backfillDatabase(t)
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
			if version, err := p.GetDBVersion(ctx); err != nil || version != 19 {
				t.Fatalf("version %d: %v", version, err)
			}
		})
	}
}

func TestBackfillAndReadinessRejectPartialSchemaIntegration(t *testing.T) {
	ctx, pool, _ := backfillDatabase(t)
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
