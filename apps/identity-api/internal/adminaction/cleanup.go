package adminaction

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// CleanupExpired removes only restricted action context, never outbox evidence or
// legal idempotency tombstones. Use a maintenance identity distinct from the API
// and publisher. Original retain_until is unchanged by hold release.
func CleanupExpired(ctx context.Context, beginner Beginner, batchSize int32) (int64, error) {
	if beginner == nil || batchSize < 1 || batchSize > 500 {
		return 0, errors.New("adminaction: cleanup database and batch size 1..500 required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	asOf := timestamp(time.Now())
	tx, err := beginReadCommitted(ctx, beginner)
	if err != nil {
		return 0, ErrUnavailable
	}
	candidates, err := db.New(tx).ListExpiredAdminActionContexts(ctx, db.ListExpiredAdminActionContextsParams{AsOf: asOf, BatchSize: batchSize})
	rollback(ctx, tx)
	if err != nil {
		return 0, ErrUnavailable
	}
	var deleted int64
	for _, candidate := range candidates {
		tx, err := beginReadCommitted(ctx, beginner)
		if err != nil {
			return deleted, ErrUnavailable
		}
		count, err := func() (int64, error) {
			defer rollback(ctx, tx)
			if candidate.AccountRef.Valid {
				if err := pglock.LockAccount(ctx, tx, candidate.AccountRef.UUID); err != nil {
					return 0, ErrUnavailable
				}
			}
			// This statement gets a fresh READ COMMITTED snapshot after acquiring
			// the same account lock as hold creation/release and GDPR purge.
			n, err := db.New(tx).DeleteExpiredAdminActionContext(ctx, db.DeleteExpiredAdminActionContextParams{ActionID: candidate.ActionID, AsOf: asOf})
			if err != nil {
				return 0, ErrUnavailable
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, ErrUnavailable
			}
			return n, nil
		}()
		if err != nil {
			return deleted, err
		}
		deleted += count
	}
	return deleted, nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
