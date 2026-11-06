package legalhold

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Backfill converts one bounded batch of legacy legal records. Each ciphertext
// is decrypted and bound to its row before the same transaction clears ALL
// plaintext columns. Re-run until zero, then CheckCrypto gates readiness. This
// operator-only path must run with intake disabled and a backup/key recovery plan.
func (s *Service) Backfill(ctx context.Context, pool *pgxpool.Pool, limit int) (int, error) {
	if pool == nil || limit < 1 || limit > 1000 {
		return 0, ErrInvalidRequest
	}
	expanded, err := legalHoldSchema(ctx, db.New(pool))
	if err != nil {
		return 0, err
	}
	if !expanded {
		check := *s
		check.store = db.New(pool)
		if err := check.CheckCrypto(ctx); err != nil {
			return 0, err
		}
		return 0, nil
	}
	rows, err := pool.Query(ctx, `SELECT id, account_ref FROM legal_holds
		WHERE reason IS NOT NULL OR requesting_authority IS NOT NULL OR legal_basis IS NOT NULL
		OR (details_encrypted IS NULL AND details_purged_at IS NULL) ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return 0, ErrUnavailable
	}
	type candidate struct{ id, account uuid.UUID }
	var batch []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.account); err != nil {
			rows.Close()
			return 0, ErrUnavailable
		}
		batch = append(batch, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, ErrUnavailable
	}
	count := 0
	for _, c := range batch {
		err := func() error {
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				return ErrUnavailable
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if err := pglock.LockAccount(ctx, tx, c.account); err != nil {
				return ErrUnavailable
			}
			// Legacy plaintext belongs only to this operator projection, never to
			// generated current models or runtime read fallbacks.
			var legacy struct{ reason, authority, basis *string }
			err = tx.QueryRow(ctx, `SELECT reason, requesting_authority, legal_basis FROM public.legal_holds
				WHERE id=$1 FOR UPDATE`, c.id).Scan(&legacy.reason, &legacy.authority, &legacy.basis)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return ErrUnavailable
			}
			row, err := db.New(tx).GetLegalHold(ctx, c.id)
			if err != nil {
				return ErrUnavailable
			}
			if len(row.DetailsEncrypted) != 0 || row.DetailsPurgedAt.Valid {
				if legacy.reason != nil || legacy.authority != nil || legacy.basis != nil {
					return ErrBackfillRequired
				}
				if _, err := s.openHold(ctx, row); err != nil {
					return err
				}
				return nil
			}
			if legacy.reason == nil || legacy.authority == nil || legacy.basis == nil {
				return ErrBackfillRequired
			}
			details := Details{RecordID: row.ID, AccountRef: row.AccountRef, Kind: row.RequestKind,
				Reason: *legacy.reason, RequestingAuthority: *legacy.authority, LegalBasis: *legacy.basis}
			blob, err := s.seal(ctx, details)
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE legal_holds SET details_encrypted=$2,
				reason=NULL, requesting_authority=NULL, legal_basis=NULL WHERE id=$1`, c.id, blob)
			if err != nil {
				return ErrUnavailable
			}
			stored, err := db.New(tx).GetLegalHold(ctx, c.id)
			if err != nil {
				return ErrUnavailable
			}
			opened, err := s.openHold(ctx, stored)
			if err != nil || opened.Details != details {
				return ErrUnavailable
			}
			var plaintextCleared bool
			if err := tx.QueryRow(ctx, `SELECT reason IS NULL AND requesting_authority IS NULL AND legal_basis IS NULL
				FROM legal_holds WHERE id=$1`, c.id).Scan(&plaintextCleared); err != nil || !plaintextCleared {
				return ErrUnavailable
			}
			if err := tx.Commit(ctx); err != nil {
				return ErrUnavailable
			}
			count++
			return nil
		}()
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

func legalHoldSchema(ctx context.Context, q interface {
	GetLegalHoldSchema(context.Context) (db.GetLegalHoldSchemaRow, error)
}) (bool, error) {
	row, err := q.GetLegalHoldSchema(ctx)
	if err != nil || row.CurrentCount != 12 ||
		((row.LegacyCount != 3 || row.ColumnCount != 15) && (row.LegacyCount != 0 || row.ColumnCount != 12)) {
		return false, ErrUnavailable
	}
	return row.LegacyCount == 3, nil
}

// CleanupReleased destroys narratives after the configured release-relative
// retention, unless ANY independent hold on the account is active. It does not
// restart retention on another hold's release. Opaque idempotency tombstones
// remain and cause conflicts rather than ever reapplying a released request.
// The deployment policy must explicitly approve retention of those tombstones.
func (s *Service) CleanupReleased(ctx context.Context, pool *pgxpool.Pool, limit int) (int64, error) {
	if !s.IntakeEnabled() || pool == nil || limit < 1 || limit > 1000 {
		return 0, ErrInvalidRequest
	}
	cutoff := s.now().UTC().Add(-s.releasedRetention).Truncate(time.Microsecond)
	rows, err := pool.Query(ctx, `SELECT DISTINCT lh.account_ref FROM legal_holds lh
		WHERE NOT lh.is_active AND lh.released_at < $1 AND lh.details_purged_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM legal_holds active WHERE active.account_ref=lh.account_ref AND active.is_active)
		ORDER BY lh.account_ref LIMIT $2`, cutoff, limit)
	if err != nil {
		return 0, ErrUnavailable
	}
	var accounts []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) != nil {
			rows.Close()
			return 0, ErrUnavailable
		}
		accounts = append(accounts, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, ErrUnavailable
	}
	var count int64
	for _, account := range accounts {
		err := func() error {
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				return ErrUnavailable
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if err := pglock.LockAccount(ctx, tx, account); err != nil {
				return ErrUnavailable
			}
			result, err := tx.Exec(ctx, `UPDATE legal_holds SET details_encrypted=NULL,
				details_purged_at=clock_timestamp()
				WHERE id IN (SELECT id FROM legal_holds WHERE account_ref=$1 AND NOT is_active
				AND released_at < $2 AND details_purged_at IS NULL AND details_encrypted IS NOT NULL ORDER BY released_at,id LIMIT $3)
				AND NOT EXISTS (SELECT 1 FROM legal_holds active WHERE active.account_ref=$1 AND active.is_active)`,
				account, cutoff, limit-int(count))
			if err != nil {
				return ErrUnavailable
			}
			if err := tx.Commit(ctx); err != nil {
				return ErrUnavailable
			}
			count += result.RowsAffected()
			return nil
		}()
		if err != nil {
			return count, err
		}
		if count >= int64(limit) {
			break
		}
	}
	return count, nil
}
