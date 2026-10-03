package legalreport

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// CountReceived must run only after an authoritative, idempotent intake
// transition in its transaction. This helper does not commit or deduplicate.
func CountReceived(ctx context.Context, tx pgx.Tx, receivedAt time.Time) error {
	return count(ctx, tx, receivedAt, "received")
}

// CountAnswered increments the delivery-time cohort, not the intake cohort.
// The caller's persisted final-delivery transition prevents duplicate counting.
func CountAnswered(ctx context.Context, tx pgx.Tx, deliveredAt time.Time, outcome string) error {
	switch outcome {
	case "full_disclosure", "partial_disclosure", "no_responsive_data", "refusal", "preservation_acknowledgement":
	default:
		return ErrInvalidRequest
	}
	return count(ctx, tx, deliveredAt, outcome)
}

func count(ctx context.Context, tx pgx.Tx, at time.Time, category string) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 || at.After(time.Now()) {
		return ErrInvalidRequest
	}
	if err := db.New(tx).CountLegalTransparency(ctx, db.CountLegalTransparencyParams{At: pgtype.Timestamptz{Time: at.UTC(), Valid: true}, Category: category}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func sanitize(year int, coverageStart time.Time, totals Totals) (json.RawMessage, error) {
	if year < 1 || year > 9998 || totals.Received < 0 || totals.Answered < 0 {
		return nil, ErrInvalidRequest
	}
	cells := []int64{totals.FullDisclosure, totals.PartialDisclosure, totals.NoResponsiveData, totals.Refusal, totals.PreservationAcknowledgement}
	var sum int64
	suppressed := false
	for _, n := range cells {
		if n < 0 || sum > math.MaxInt64-n {
			return nil, ErrInvalidRequest
		}
		sum += n
		suppressed = suppressed || (n > 0 && n < 5)
	}
	if sum != totals.Answered {
		return nil, ErrInvalidRequest
	}
	start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	// Counter availability cannot prove that every real request was entered or
	// that intake stayed enabled continuously. Never label it complete coverage.
	status := "partial"
	if coverageStart.IsZero() || !coverageStart.Before(start.AddDate(1, 0, 0)) {
		status = "no_coverage"
	}
	a := Artifact{SchemaVersion: SchemaVersion, Year: year,
		Coverage: Coverage{Status: status, LateEntriesPossible: true},
		Received: suppress(totals.Received), Answered: suppress(totals.Answered),
		Outcomes: OutcomeBreakdown{Suppressed: suppressed}}
	if !suppressed {
		a.Outcomes.Counts = &OutcomeCounts{totals.FullDisclosure, totals.PartialDisclosure, totals.NoResponsiveData, totals.Refusal, totals.PreservationAcknowledgement}
	}
	return json.Marshal(a)
}

func suppress(n int64) Cell {
	if n > 0 && n < 5 {
		return Cell{Suppressed: true}
	}
	return Cell{Count: &n}
}
