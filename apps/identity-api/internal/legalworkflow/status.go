package legalworkflow

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
)

// BacklogCount explicitly marks a capped count as a lower bound, not a total.
type BacklogCount struct {
	Count      int64 `json:"count"`
	LowerBound bool  `json:"lower_bound"`
}

// Status contains no account, hold, case, policy or narrative identifiers.
// HeldExpired is pre-existing backlog; CleanupResult.Held is a per-run race check.
type Status struct {
	AsOf                     time.Time    `json:"as_of"`
	Limit                    int          `json:"limit"`
	EligibleExpired          BacklogCount `json:"eligible_expired"`
	HeldExpired              BacklogCount `json:"held_expired"`
	OldestEligibleAgeSeconds *int64       `json:"oldest_eligible_age_seconds"`
	DueReviews               BacklogCount `json:"due_reviews"`
	OverdueReviews           BacklogCount `json:"overdue_reviews"`
}

// StatusSnapshot works independently of intake, encryption keys or attribution.
// Each category aggregates at most limit+1 ordered scheduling rows in one
// read-only snapshot; statement/deadline bounds also cover candidate discovery.
func StatusSnapshot(ctx context.Context, pool *pgxpool.Pool, environment string, limit int, asOf time.Time) (Status, error) {
	if pool == nil || limit < 1 || limit > 1000 || asOf.IsZero() {
		return Status{}, ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Status{}, ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='20s'`); err != nil {
		return Status{}, ErrUnavailable
	}
	p, err := legalpolicy.LoadBaseline(ctx, tx, uuid.Nil, environment)
	if err != nil {
		return Status{}, ErrUnavailable
	}
	result := Status{AsOf: asOf.UTC().Truncate(time.Microsecond), Limit: limit}
	for _, category := range []struct {
		name  string
		count *BacklogCount
	}{
		{"eligible", &result.EligibleExpired}, {"held", &result.HeldExpired},
		{"due", &result.DueReviews}, {"overdue", &result.OverdueReviews},
	} {
		var n int64
		var oldest *time.Time
		query := statusExpiredSQL
		if category.name == "due" || category.name == "overdue" {
			query = statusReviewsSQL
		}
		err = tx.QueryRow(ctx, query, result.AsOf, limit+1, category.name, p.ReleasedHoldRetentionSeconds).Scan(&n, &oldest)
		if err != nil {
			return Status{}, ErrUnavailable
		}
		category.count.Count = n
		if n > int64(limit) {
			category.count.Count = int64(limit)
			category.count.LowerBound = true
		}
		if category.name == "eligible" && oldest != nil {
			age := int64(result.AsOf.Sub(*oldest) / time.Second)
			result.OldestEligibleAgeSeconds = &age
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Status{}, ErrUnavailable
	}
	return result, nil
}

const statusExpiredSQL = `SELECT count(*)::bigint,min(at) FROM (
    SELECT at FROM (
      SELECT c.expires_at AS at, EXISTS(SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref
        WHERE s.case_id=c.id AND h.is_active) AS held
      FROM legal_cases c WHERE c.status<>'erased' AND c.expires_at<=$1
      UNION ALL
      SELECT h.released_at + make_interval(secs => $4::double precision),
        EXISTS(SELECT 1 FROM legal_holds other WHERE other.account_ref=r.account_ref AND other.is_active)
      FROM legal_hold_reviews r JOIN legal_holds h ON h.id=r.hold_id
      WHERE NOT h.is_active AND h.released_at + make_interval(secs => $4::double precision)<=$1
    ) work WHERE held=($3='held') ORDER BY at LIMIT $2
  ) bounded`

const statusReviewsSQL = `SELECT count(*)::bigint,min(at) FROM (
    SELECT at FROM (
      SELECT c.next_review_at AS at FROM legal_cases c WHERE c.status='open' AND c.next_review_at<=$1
        AND (c.expires_at>$1 OR EXISTS(SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref
          WHERE s.case_id=c.id AND h.is_active))
      UNION ALL
      SELECT CASE WHEN r.hold_id IS NULL THEN h.review_at ELSE r.next_review_at END
      FROM legal_holds h LEFT JOIN legal_hold_reviews r ON r.hold_id=h.id WHERE h.is_active
        AND (CASE WHEN r.hold_id IS NULL THEN h.review_at ELSE r.next_review_at END)<=$1
    ) work WHERE ($3='due' OR at<$1) AND $4::bigint>0 ORDER BY at LIMIT $2
  ) bounded`
