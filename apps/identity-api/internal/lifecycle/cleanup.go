package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// CleanupPublished requires a separately scoped maintenance identity. It never
// expires unpublished intent or audit evidence and does not contact a broker.
// Invalid rows are retained and reported after unrelated candidates progress.
func CleanupPublished(ctx context.Context, beginner Beginner, retention time.Duration, batchSize int32) (int64, error) {
	if beginner == nil || retention < time.Microsecond || batchSize < 1 || batchSize > 500 {
		return 0, errors.New("lifecycle: cleanup database, positive retention and batch size 1..500 required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cutoff := pgtype.Timestamptz{Time: time.Now().UTC().Add(-retention).Truncate(time.Microsecond), Valid: true}
	tx, err := beginReadCommitted(ctx, beginner)
	if err != nil {
		return 0, dependencyError(ctx)
	}
	candidates, err := db.New(tx).ListExpiredLifecycleEvents(ctx, db.ListExpiredLifecycleEventsParams{Cutoff: cutoff, BatchSize: batchSize})
	rollback(ctx, tx)
	if err != nil || len(candidates) > int(batchSize) {
		return 0, dependencyError(ctx)
	}
	var deleted int64
	invalid := false
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return deleted, ctx.Err()
		}
		if !expiredLifecycleRow(candidate, cutoff.Time) {
			continue
		}
		_, accountID, err := decodeOutboxEvent(candidate)
		if err != nil {
			invalid = true
			continue
		}
		tx, err := beginReadCommitted(ctx, beginner)
		if err != nil {
			return deleted, dependencyError(ctx)
		}
		count, err := func() (int64, error) {
			defer rollback(ctx, tx)
			if err := pglock.LockAccount(ctx, tx, accountID); err != nil {
				return 0, dependencyError(ctx)
			}
			q := db.New(tx)
			// Fresh READ COMMITTED statements after the account lock close both
			// the hold-creation race and a payload/metadata repair race.
			row, err := q.GetExpiredLifecycleEventForUpdate(ctx, db.GetExpiredLifecycleEventForUpdateParams{ID: candidate.ID, Cutoff: cutoff})
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, nil
			}
			if err != nil {
				return 0, dependencyError(ctx)
			}
			if !expiredLifecycleRow(row, cutoff.Time) {
				return 0, nil
			}
			_, freshAccountID, err := decodeOutboxEvent(row)
			if err != nil || row.ID != candidate.ID || freshAccountID != accountID {
				return 0, ErrInvalidEvent
			}
			count, err := q.DeleteExpiredLifecycleEvent(ctx, db.DeleteExpiredLifecycleEventParams{ID: row.ID, Cutoff: cutoff, AccountRef: accountID})
			if err != nil || count < 0 || count > 1 {
				return 0, dependencyError(ctx)
			}
			if err := tx.Commit(ctx); err != nil {
				return 0, dependencyError(ctx)
			}
			return count, nil
		}()
		if errors.Is(err, ErrInvalidEvent) {
			invalid = true
			continue
		}
		if err != nil {
			return deleted, err
		}
		deleted += count
	}
	if invalid {
		return deleted, ErrInvalidEvent
	}
	return deleted, nil
}

func expiredLifecycleRow(row db.EventOutbox, cutoff time.Time) bool {
	return !row.AdminAction && row.PublishedAt.Valid && row.PublishedAt.InfinityModifier == pgtype.Finite && row.PublishedAt.Time.Before(cutoff)
}
