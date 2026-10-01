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
	rows, err := pool.Query(ctx, `SELECT id, account_ref FROM legal_holds
		WHERE details_encrypted IS NULL AND details_purged_at IS NULL ORDER BY id LIMIT $1`, limit)
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
			row, err := db.New(tx).GetLegalHold(ctx, c.id)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return ErrUnavailable
			}
			if len(row.DetailsEncrypted) != 0 || row.DetailsPurgedAt.Valid {
				return nil
			}
			if row.Reason == nil || row.RequestingAuthority == nil || row.LegalBasis == nil {
				return ErrBackfillRequired
			}
			kind := KindHold
			if *row.LegalBasis == LegalBasisPreservation {
				kind = KindPreservation
			}
			details := Details{RecordID: row.ID, AccountRef: row.AccountRef, Kind: kind,
				Reason: *row.Reason, RequestingAuthority: *row.RequestingAuthority, LegalBasis: *row.LegalBasis}
			blob, err := s.seal(ctx, details)
			if err != nil {
				return err
			}
			row.DetailsEncrypted, row.RequestKind = blob, kind
			row.Reason, row.RequestingAuthority, row.LegalBasis = nil, nil, nil
			opened, err := s.openHold(ctx, row)
			if err != nil || opened.Details != details {
				return ErrUnavailable
			}
			_, err = tx.Exec(ctx, `UPDATE legal_holds SET details_encrypted=$2, request_kind=$3,
				reason=NULL, requesting_authority=NULL, legal_basis=NULL WHERE id=$1`, c.id, blob, kind)
			if err != nil {
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
				reason=NULL, requesting_authority=NULL, legal_basis=NULL, details_purged_at=clock_timestamp()
				WHERE id IN (SELECT id FROM legal_holds WHERE account_ref=$1 AND NOT is_active
				AND released_at < $2 AND details_purged_at IS NULL ORDER BY released_at,id LIMIT $3)
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
