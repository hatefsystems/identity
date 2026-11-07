package legalhold

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func legalHoldSchema(ctx context.Context, q interface {
	GetLegalHoldSchema(context.Context) (db.GetLegalHoldSchemaRow, error)
}) error {
	row, err := q.GetLegalHoldSchema(ctx)
	if err != nil || row.CurrentCount != 12 || row.ColumnCount != 12 || !row.ConstraintsValid {
		return ErrUnavailable
	}
	return nil
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
	check := *s
	check.store = db.New(pool)
	if err := check.CheckCrypto(ctx); err != nil {
		return 0, err
	}
	cutoff := s.now().UTC().Add(-s.releasedRetention).Truncate(time.Microsecond)
	rows, err := pool.Query(ctx, `SELECT DISTINCT lh.account_ref FROM public.legal_holds lh
		WHERE NOT lh.is_active AND lh.released_at < $1 AND lh.details_purged_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM public.legal_holds active WHERE active.account_ref=lh.account_ref AND active.is_active)
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
			result, err := tx.Exec(ctx, `UPDATE public.legal_holds SET details_encrypted=NULL,
				details_purged_at=clock_timestamp()
				WHERE id IN (SELECT id FROM public.legal_holds WHERE account_ref=$1 AND NOT is_active
				AND released_at < $2 AND details_purged_at IS NULL AND details_encrypted IS NOT NULL ORDER BY released_at,id LIMIT $3)
				AND NOT EXISTS (SELECT 1 FROM public.legal_holds active WHERE active.account_ref=$1 AND active.is_active)`,
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
