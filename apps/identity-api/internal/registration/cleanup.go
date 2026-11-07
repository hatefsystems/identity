package registration

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// CleanupTimeout bounds one cleanup pass, including command startup probes.
const CleanupTimeout = 30 * time.Second

// CleanupStats reports committed deletions and deferred batch candidates.
type CleanupStats struct {
	Considered int
	Deleted    int64
	Held       int
	Contended  int
}

// CleanupPrivileges is an allowlist for an actual dedicated login. In particular
// SELECT FOR UPDATE is not used: it would require an unnecessary UPDATE grant.
func CleanupPrivileges() dbprivilege.Contract {
	return dbprivilege.Contract{Tables: []dbprivilege.Table{
		{Name: "public.registration_attempts", Select: true, Delete: true},
		{Name: "public.legal_holds", Select: true},
	}}
}

// APIUpdateColumns deliberately excludes ID/capability/JKT/creation/expiry.
// Account birth has its own existing grants; operators combine this list with
// the API's reviewed contract, never with the cleanup identity's DELETE grant.
func APIUpdateColumns() []string {
	return []string{"details_encrypted", "email_token_hash", "email_token_issued_at", "email_token_expires_at", "email_verified_at",
		"sms_verification_ref", "phone_verified_at", "challenge_revision", "row_revision", "passkey_created_at", "passkey_expires_at",
		"state", "terminal_at", "receipt_expires_at", "completion_fingerprint", "result_user_id"}
}

// CheckCleanupReady validates the actual restricted login and schema without writes.
func CheckCleanupReady(ctx context.Context, database db.DBTX) error {
	if err := dbprivilege.Check(ctx, database, CleanupPrivileges()); err != nil {
		return err
	}
	return CheckSchema(ctx, database)
}

// CheckSchema is read-only and bounded. It refuses unconstrained or shadow
// storage before cleanup or public enrollment, without running migrations.
func CheckSchema(ctx context.Context, database db.DBTX) error {
	if database == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ready bool
	err := database.QueryRow(ctx, `SELECT
      (SELECT array_agg(a.attname::text || ':' || pg_catalog.format_type(a.atttypid,a.atttypmod) || ':' || a.attnotnull::text ORDER BY a.attnum)
        FROM pg_catalog.pg_attribute a WHERE a.attrelid=pg_catalog.to_regclass('public.registration_attempts') AND a.attnum>0 AND NOT a.attisdropped)
        = ARRAY['id:uuid:true','capability_hash:bytea:true','jkt:text:true','details_encrypted:bytea:false',
          'email_token_hash:bytea:false','email_token_issued_at:timestamp with time zone:false','email_token_expires_at:timestamp with time zone:false',
          'email_verified_at:timestamp with time zone:false','sms_verification_ref:uuid:false','phone_verified_at:timestamp with time zone:false',
          'challenge_revision:bigint:true','row_revision:bigint:true','passkey_created_at:timestamp with time zone:false',
          'passkey_expires_at:timestamp with time zone:false','state:text:true','created_at:timestamp with time zone:true',
          'expires_at:timestamp with time zone:true','terminal_at:timestamp with time zone:false',
          'receipt_expires_at:timestamp with time zone:false','completion_fingerprint:bytea:false','result_user_id:uuid:false']
      AND (SELECT count(*)=14 AND bool_and(convalidated AND NOT condeferrable)
        FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts'))
      AND (SELECT count(*)=5 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND contype='c' AND conname IN ('registration_attempt_times','registration_email_times','registration_phone_proof','registration_passkey_times','registration_state_material'))
      AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) ~ '(true|false)')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND contype='p' AND conkey=ARRAY[1]::smallint[])
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND contype='c' AND pg_catalog.pg_get_constraintdef(oid)='CHECK ((octet_length(capability_hash) = 32))')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND conname='registration_attempt_times' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%expires_at = (created_at + ''00:15:00''::interval)%'
        AND pg_catalog.pg_get_constraintdef(oid) LIKE '%receipt_expires_at = (terminal_at + ''01:00:00''::interval)%')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND conname='registration_email_times' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%email_token_issued_at + ''00:10:00''::interval%')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND conname='registration_passkey_times' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%passkey_created_at + ''00:05:00''::interval%')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND contype='f' AND confrelid=pg_catalog.to_regclass('public.users') AND confdeltype='c'
        AND conkey=ARRAY[21]::smallint[] AND confkey=ARRAY[1]::smallint[])
      AND (SELECT count(*)=3 AND bool_and(i.indisvalid AND i.indisready) FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=pg_catalog.to_regclass('public.registration_attempts')
        AND c.relname IN ('idx_registration_pending_expiry','idx_registration_receipt_expiry','idx_registration_result_user'))
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=pg_catalog.to_regclass('public.idx_registration_pending_expiry')
        AND indkey='17 1'::int2vector AND pg_catalog.pg_get_expr(indpred,indrelid)='(state = ''pending''::text)')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=pg_catalog.to_regclass('public.idx_registration_receipt_expiry')
        AND indkey='19 1'::int2vector AND pg_catalog.pg_get_expr(indpred,indrelid)='(state = ANY (ARRAY[''completed''::text, ''failed''::text]))')
      AND EXISTS(SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=pg_catalog.to_regclass('public.idx_registration_result_user')
        AND indkey='21'::int2vector AND pg_catalog.pg_get_expr(indpred,indrelid)='(result_user_id IS NOT NULL)')`).Scan(&ready)
	if err != nil || !ready {
		return ErrUnavailable
	}
	return nil
}

// CheckReady validates schema and a bound envelope round trip without storing it.
func (s *Store) CheckReady(ctx context.Context) error {
	if err := CheckSchema(ctx, s.database); err != nil {
		return err
	}
	capability, err := NewCapability()
	if err != nil {
		return err
	}
	defer clear(capability)
	hash, _ := HashCapability(capability)
	now := s.now().UTC().Truncate(time.Microsecond)
	d := Details{AttemptID: uuid.New(), JKT: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Purpose: Purpose,
		Email: "readiness@example.invalid", Phone: "+989123456789", UserHandle: make([]byte, 8)}
	blob, err := s.seal(ctx, d)
	if err != nil {
		return ErrUnavailable
	}
	_, err = s.open(ctx, db.RegistrationAttempt{ID: d.AttemptID, Jkt: d.JKT, CapabilityHash: hash, DetailsEncrypted: blob,
		State: "pending", CreatedAt: timestamp(now), ExpiresAt: timestamp(now.Add(PendingLifetime))})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Cleanup removes at most one batch. Each candidate commits independently, so a
// later dependency failure cannot undo completed progress. A held/contended row
// is deferred; an expired capability never becomes valid after hold release.
func Cleanup(ctx context.Context, database Database, batchSize int32) (CleanupStats, error) {
	stats := CleanupStats{}
	if database == nil || batchSize < 1 || batchSize > 500 {
		return stats, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, CleanupTimeout)
	defer cancel()
	cutoff := timestamp(time.Now())
	tx, err := begin(ctx, database)
	if err != nil {
		return stats, err
	}
	candidates, err := db.New(tx).ListExpiredRegistrationAttempts(ctx, db.ListExpiredRegistrationAttemptsParams{Cutoff: cutoff, BatchSize: batchSize})
	rollback(tx)
	if err != nil || len(candidates) > int(batchSize) {
		return stats, ErrUnavailable
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		stats.Considered++
		if candidate.ID == uuid.Nil || candidate.State != "pending" && candidate.State != "completed" && candidate.State != "failed" ||
			candidate.State == "completed" && (!candidate.ResultUserID.Valid || candidate.ResultUserID.UUID == uuid.Nil) ||
			candidate.State != "completed" && candidate.ResultUserID.Valid {
			return stats, ErrInvalid
		}
		tx, err := begin(ctx, database)
		if err != nil {
			return stats, err
		}
		count, held, err := func() (int64, bool, error) {
			defer rollback(tx)
			q := db.New(tx)
			if candidate.State == "completed" {
				// Exactly the same lock/key as legalhold and account erasure.
				// The next deciding read is a separate READ COMMITTED statement.
				if err := pglock.LockAccount(ctx, tx, candidate.ResultUserID.UUID); err != nil {
					return 0, false, err
				}
				held, err := q.RegistrationAttemptHeld(ctx, candidate.ResultUserID.UUID)
				if err != nil {
					return 0, false, err
				}
				if held {
					return 0, true, nil
				}
			}
			count, err := q.DeleteExpiredRegistrationAttempt(ctx, db.DeleteExpiredRegistrationAttemptParams{
				ID: candidate.ID, Cutoff: cutoff, ResultUserID: candidate.ResultUserID,
			})
			if err != nil || count < 0 || count > 1 {
				return 0, false, errOrUnavailable(err)
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, false, err
			}
			return count, false, nil
		}()
		if held {
			stats.Held++
			continue
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			stats.Contended++
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			return stats, ErrUnavailable
		}
		stats.Deleted += count
	}
	return stats, nil
}

func errOrUnavailable(err error) error {
	if err != nil {
		return err
	}
	return ErrUnavailable
}
