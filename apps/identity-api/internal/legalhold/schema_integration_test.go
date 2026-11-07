//go:build integration

package legalhold

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func TestFinalLegalHoldConstraintsIntegration(t *testing.T) {
	ctx, pool := restoreDatabase(t)
	s, _ := testService(t)
	s.store = db.New(pool)
	details := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: KindHold,
		Reason: "fixture reason", RequestingAuthority: "fixture court", LegalBasis: "fixture basis"}
	blob, err := s.seal(ctx, details)
	if err != nil {
		t.Fatal(err)
	}
	row, err := db.New(pool).CreateEncryptedLegalHold(ctx, db.CreateEncryptedLegalHoldParams{
		ID: details.RecordID, AccountRef: details.AccountRef, AppliedBy: uuid.New(), RequestKind: details.Kind,
		IdempotencyKey: uuid.NullUUID{UUID: uuid.New(), Valid: true}, DetailsEncrypted: blob})
	if err != nil {
		t.Fatal(err)
	}
	before := restoreInventory(ctx, t, pool)
	defer clearRestoreInventory(before)
	for _, invalid := range []struct{ query, code, constraint string }{
		{`UPDATE public.legal_holds SET details_encrypted=NULL`, "23514", "legal_holds_encrypted_or_purged"},
		{`UPDATE public.legal_holds SET details_encrypted='\x'`, "23514", "legal_holds_encrypted_or_purged"},
		{`UPDATE public.legal_holds SET details_purged_at=now()`, "23514", "legal_holds_encrypted_or_purged"},
		{`UPDATE public.legal_holds SET details_encrypted=NULL,details_purged_at=now(),is_active=false`, "23514", "legal_holds_encrypted_or_purged"},
		{`UPDATE public.legal_holds SET request_kind='unknown'`, "23514", "legal_holds_request_kind_check"},
		{`INSERT INTO public.legal_holds SELECT * FROM public.legal_holds`, "23505", "legal_holds_pkey"},
		{`INSERT INTO public.legal_holds(id,account_ref,applied_by,request_kind,idempotency_key,details_encrypted)
SELECT uuid_generate_v4(),account_ref,applied_by,request_kind,idempotency_key,details_encrypted FROM public.legal_holds`, "23505", "legal_holds_request_identity"},
	} {
		_, err := pool.Exec(ctx, invalid.query)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != invalid.code || pgErr.ConstraintName != invalid.constraint {
			t.Fatalf("final constraint %s not enforced: %v", invalid.constraint, err)
		}
	}
	after := restoreInventory(ctx, t, pool)
	compareRestoreInventory(t, before, after)
	clearRestoreInventory(after)
	if err := s.CheckCrypto(ctx); err != nil {
		t.Fatalf("constraint failures changed verified ciphertext: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE public.legal_holds SET details_encrypted=NULL,details_purged_at=now(),is_active=false,released_at=now() WHERE id=$1`, row.ID); err != nil {
		t.Fatal("legitimate tombstone rejected")
	}
	if err := s.CheckCrypto(ctx); err != nil {
		t.Fatalf("legitimate tombstone failed readiness: %v", err)
	}
}

func TestFinalLegalHoldReadinessRejectsMalformedSchemaIntegration(t *testing.T) {
	for _, invalid := range []struct{ name, sql string }{
		{"missing-table", `ALTER TABLE public.legal_holds RENAME TO unexpected_holds`},
		{"expanded-null", `ALTER TABLE public.legal_holds ADD COLUMN reason TEXT, ADD COLUMN requesting_authority VARCHAR(255), ADD COLUMN legal_basis VARCHAR(255)`},
		{"expanded-empty", `ALTER TABLE public.legal_holds ADD COLUMN reason TEXT DEFAULT '', ADD COLUMN requesting_authority VARCHAR(255) DEFAULT '', ADD COLUMN legal_basis VARCHAR(255) DEFAULT ''`},
		{"partial", `ALTER TABLE public.legal_holds DROP COLUMN review_at`},
		{"unexpected-column", `ALTER TABLE public.legal_holds ADD COLUMN unexpected TEXT`},
		{"wrong-type", `ALTER TABLE public.legal_holds ALTER COLUMN review_at TYPE timestamp`},
		{"wrong-nullability", `ALTER TABLE public.legal_holds ALTER COLUMN applied_by DROP NOT NULL`},
		{"missing-details-check", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_encrypted_or_purged`},
		{"unvalidated-details-check", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_encrypted_or_purged;
ALTER TABLE public.legal_holds ADD CONSTRAINT legal_holds_encrypted_or_purged CHECK (
(details_encrypted IS NOT NULL AND octet_length(details_encrypted)>0 AND details_purged_at IS NULL)
OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL)) NOT VALID`},
		{"weakened-details-check", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_encrypted_or_purged;
ALTER TABLE public.legal_holds ADD CONSTRAINT legal_holds_encrypted_or_purged CHECK (true)`},
		{"weakened-kind-check", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_request_kind_check;
ALTER TABLE public.legal_holds ADD CONSTRAINT legal_holds_request_kind_check CHECK (true)`},
		{"unvalidated-kind-check", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_request_kind_check;
ALTER TABLE public.legal_holds ADD CONSTRAINT legal_holds_request_kind_check CHECK (request_kind IN ('legal_hold','preservation')) NOT VALID`},
		{"missing-replay-index", `DROP INDEX public.legal_holds_request_identity`},
		{"nonunique-replay-index", `DROP INDEX public.legal_holds_request_identity;
CREATE INDEX legal_holds_request_identity ON public.legal_holds(account_ref,request_kind,idempotency_key) WHERE idempotency_key IS NOT NULL`},
		{"wrong-replay-index", `DROP INDEX public.legal_holds_request_identity;
CREATE UNIQUE INDEX legal_holds_request_identity ON public.legal_holds(account_ref,idempotency_key) WHERE idempotency_key IS NOT NULL`},
		{"wrong-replay-predicate", `DROP INDEX public.legal_holds_request_identity;
CREATE UNIQUE INDEX legal_holds_request_identity ON public.legal_holds(account_ref,request_kind,idempotency_key) WHERE is_active`},
		{"missing-primary-key", `ALTER TABLE public.legal_holds DROP CONSTRAINT legal_holds_pkey CASCADE`},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			ctx, pool := restoreDatabase(t)
			s, _ := testService(t)
			s.store = db.New(pool)
			if err := s.CheckCrypto(ctx); err != nil {
				t.Fatalf("final empty baseline not ready: %v", err)
			}
			if invalid.name == "expanded-empty" {
				details := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: KindHold,
					Reason: "fixture", RequestingAuthority: "court", LegalBasis: "order"}
				blob, err := s.seal(ctx, details)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.New(pool).CreateEncryptedLegalHold(ctx, db.CreateEncryptedLegalHoldParams{
					ID: details.RecordID, AccountRef: details.AccountRef, AppliedBy: uuid.New(), RequestKind: KindHold, DetailsEncrypted: blob}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Exec(ctx, invalid.sql); err != nil {
				t.Fatal(err)
			}
			before := restoreInventory(ctx, t, pool)
			defer clearRestoreInventory(before)
			if err := s.CheckCrypto(ctx); err != ErrUnavailable {
				t.Fatalf("malformed layout passed readiness: %v", err)
			}
			if n, err := s.CleanupReleased(ctx, pool, 1); n != 0 || err != ErrUnavailable {
				t.Fatalf("cleanup accepted malformed layout: %d %v", n, err)
			}
			after := restoreInventory(ctx, t, pool)
			compareRestoreInventory(t, before, after)
			clearRestoreInventory(after)
		})
	}
}

func TestFinalLegalHoldReadinessPreservesRowsAndKeysIntegration(t *testing.T) {
	for _, failure := range []string{"valid", "retained-generation", "missing-key", "wrong-key", "corrupt", "record-binding", "account-binding", "kind-binding"} {
		t.Run(failure, func(t *testing.T) {
			ctx, pool := restoreDatabase(t)
			s, _ := testService(t)
			s.store = db.New(pool)
			var rows []db.LegalHold
			for _, kind := range []string{KindHold, KindPreservation} {
				details := Details{RecordID: uuid.New(), AccountRef: uuid.New(), Kind: kind,
					Reason: "retained fixture reason", RequestingAuthority: "fixture court", LegalBasis: "fixture basis"}
				blob, err := s.seal(ctx, details)
				if err != nil {
					t.Fatal(err)
				}
				row, err := db.New(pool).CreateEncryptedLegalHold(ctx, db.CreateEncryptedLegalHoldParams{
					ID: details.RecordID, AccountRef: details.AccountRef, AppliedBy: uuid.New(), RequestKind: kind,
					IdempotencyKey: uuid.NullUUID{UUID: uuid.New(), Valid: true}, DetailsEncrypted: blob})
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, row)
			}
			if _, err := pool.Exec(ctx, `UPDATE public.legal_holds SET is_active=false,released_at='2026-01-02Z',released_by=applied_by WHERE id=$1`, rows[1].ID); err != nil {
				t.Fatal(err)
			}
			var mutation string
			switch failure {
			case "retained-generation", "missing-key", "wrong-key":
				version := byte(1)
				if failure != "wrong-key" {
					version = 2
				}
				provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x63}, 32), version)
				if err != nil {
					t.Fatal(err)
				}
				if failure == "retained-generation" {
					if err := provider.AddKEK(1, bytes.Repeat([]byte{0x51}, 32)); err != nil {
						t.Fatal(err)
					}
				}
				s.encryptor, err = envelope.New(provider)
				if err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				mutation = `UPDATE public.legal_holds SET details_encrypted='\x01' WHERE id=$1`
			case "record-binding":
				mutation = `UPDATE public.legal_holds SET details_encrypted=(SELECT details_encrypted FROM public.legal_holds WHERE id<>$1) WHERE id=$1`
			case "account-binding":
				mutation = `UPDATE public.legal_holds SET account_ref=uuid_generate_v4() WHERE id=$1`
			case "kind-binding":
				mutation = `UPDATE public.legal_holds SET request_kind='preservation' WHERE id=$1`
			}
			if mutation != "" {
				if _, err := pool.Exec(ctx, mutation, rows[0].ID); err != nil {
					t.Fatal(err)
				}
			}
			before := restoreInventory(ctx, t, pool)
			defer clearRestoreInventory(before)
			valid := failure == "valid" || failure == "retained-generation"
			for range 2 {
				err := s.CheckCrypto(ctx)
				if valid {
					if err != nil {
						t.Fatalf("encrypted active/released rows rejected: %v", err)
					}
				} else if err != ErrUnavailable {
					t.Fatalf("retained key/binding failure accepted: %v", err)
				}
			}
			if !valid {
				if n, err := s.CleanupReleased(ctx, pool, 1); n != 0 || err != ErrUnavailable {
					t.Fatalf("cleanup erased invalid retained evidence: %d %v", n, err)
				}
			}
			after := restoreInventory(ctx, t, pool)
			compareRestoreInventory(t, before, after)
			clearRestoreInventory(after)
		})
	}
}

func TestFinalLegalHoldBaselineReadinessDoesNotMutateIntegration(t *testing.T) {
	ctx, pool := restoreDatabase(t)
	s, _ := testService(t)
	s.store = db.New(pool)
	before := restoreInventory(ctx, t, pool)
	defer clearRestoreInventory(before)
	for range 2 {
		if err := s.CheckCrypto(ctx); err != nil {
			t.Fatal(err)
		}
	}
	after := restoreInventory(ctx, t, pool)
	compareRestoreInventory(t, before, after)
	clearRestoreInventory(after)
}
