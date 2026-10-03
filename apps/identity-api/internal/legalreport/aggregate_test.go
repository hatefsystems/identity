package legalreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSuppressionThresholds(t *testing.T) {
	for _, n := range []int64{0, 1, 2, 3, 4, 5, 6, math.MaxInt64} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			cell := suppress(n)
			if n > 0 && n < 5 {
				if !cell.Suppressed || cell.Count != nil {
					t.Fatalf("small cell disclosed: %+v", cell)
				}
			} else if cell.Suppressed || cell.Count == nil || *cell.Count != n {
				t.Fatalf("measured zero/non-small value lost: %+v", cell)
			}
		})
	}
}

func TestSanitizeComplementarySuppression(t *testing.T) {
	coverage := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for field := 0; field < 5; field++ {
		for small := int64(1); small < 5; small++ {
			t.Run(fmt.Sprintf("outcome%d_count%d", field, small), func(t *testing.T) {
				counts := []int64{5, 5, 5, 5, 5}
				counts[field] = small
				totals := Totals{Received: small, Answered: 20 + small, FullDisclosure: counts[0], PartialDisclosure: counts[1], NoResponsiveData: counts[2], Refusal: counts[3], PreservationAcknowledgement: counts[4]}
				payload, err := sanitize(2024, coverage, totals)
				if err != nil {
					t.Fatal(err)
				}
				artifact := assertPrivateArtifact(t, payload)
				if !artifact.Received.Suppressed || artifact.Received.Count != nil || artifact.Answered.Count == nil || *artifact.Answered.Count != totals.Answered {
					t.Fatalf("total suppression: %+v", artifact)
				}
				if !artifact.Outcomes.Suppressed || artifact.Outcomes.Counts != nil {
					t.Fatalf("complementary counts reconstruct the small cell: %s", payload)
				}
				var raw map[string]json.RawMessage
				if err = json.Unmarshal(payload, &raw); err != nil {
					t.Fatal(err)
				}
				var outcomes map[string]json.RawMessage
				if err = json.Unmarshal(raw["outcomes"], &outcomes); err != nil {
					t.Fatal(err)
				}
				assertKeys(t, outcomes, "suppressed")
			})
		}
	}
	// Different suppressed values must not acquire a secondary source-version,
	// breakdown, percentage or timestamp field that distinguishes the inputs.
	var first []byte
	for small := int64(1); small < 5; small++ {
		payload, err := sanitize(2024, coverage, Totals{Received: small, Answered: small, Refusal: small})
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = payload
		} else if !bytes.Equal(first, payload) {
			t.Fatalf("suppressed inputs distinguishable: %s versus %s", first, payload)
		}
	}
}

func TestSanitizeMeasuredZeroAndConsistentLargeOutcomes(t *testing.T) {
	for _, totals := range []Totals{{}, {Received: 5, Answered: 15, FullDisclosure: 5, Refusal: 10}} {
		payload, err := sanitize(2024, time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC), totals)
		if err != nil {
			t.Fatal(err)
		}
		a := assertPrivateArtifact(t, payload)
		if a.Received.Count == nil || *a.Received.Count != totals.Received || a.Answered.Count == nil || *a.Answered.Count != totals.Answered || a.Outcomes.Suppressed || a.Outcomes.Counts == nil {
			t.Fatalf("zero/non-small totals: %s", payload)
		}
		c := a.Outcomes.Counts
		if c.FullDisclosure+c.PartialDisclosure+c.NoResponsiveData+c.Refusal+c.PreservationAcknowledgement != *a.Answered.Count {
			t.Fatalf("inconsistent outcome sum: %s", payload)
		}
	}
}

func TestSanitizeCoverageNeverPromisesCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		start  time.Time
		status string
	}{
		{"never collected", time.Time{}, "no_coverage"},
		{"before year", time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC), "partial"},
		{"year boundary", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "partial"},
		{"midyear", time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC), "partial"},
		{"after year", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), "no_coverage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := sanitize(2024, tc.start, Totals{})
			if err != nil {
				t.Fatal(err)
			}
			a := assertPrivateArtifact(t, payload)
			if a.Coverage.Status != tc.status || !a.Coverage.LateEntriesPossible {
				t.Fatalf("dishonest coverage: %+v", a.Coverage)
			}
		})
	}
}

func TestSanitizeRejectsInvalidTotals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		year   int
		totals Totals
	}{
		{"zero year", 0, Totals{}}, {"upper year", 9999, Totals{}},
		{"negative received", 2024, Totals{Received: -1}},
		{"negative answered", 2024, Totals{Answered: -1}},
		{"negative outcome", 2024, Totals{FullDisclosure: -1}},
		{"missing outcomes", 2024, Totals{Answered: 1}},
		{"excess outcomes", 2024, Totals{Answered: 1, Refusal: 2}},
		{"overflow", 2024, Totals{Answered: math.MaxInt64, FullDisclosure: math.MaxInt64, Refusal: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sanitize(tc.year, time.Now(), tc.totals); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type counterTx struct {
	pgx.Tx
	called bool
	err    error
	args   []any
}

func (tx *counterTx) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	tx.called = true
	tx.args = args
	return pgconn.CommandTag{}, tx.err
}

func TestCountersValidateBeforeDatabaseAndNormalizeUTC(t *testing.T) {
	ctx := context.Background()
	if err := CountReceived(ctx, nil, time.Now()); !errors.Is(err, ErrTransactionRequired) {
		t.Fatalf("missing transaction=%v", err)
	}
	for _, at := range []time.Time{{}, time.Now().Add(time.Hour), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		tx := &counterTx{}
		if err := CountReceived(ctx, tx, at); !errors.Is(err, ErrInvalidRequest) || tx.called {
			t.Fatalf("invalid timestamp reached database: %v", err)
		}
	}
	for _, category := range []string{"", "answered", "received", "rejected", "FULL_DISCLOSURE"} {
		tx := &counterTx{}
		if err := CountAnswered(ctx, tx, time.Now(), category); !errors.Is(err, ErrInvalidRequest) || tx.called {
			t.Fatalf("invalid outcome %q reached database: %v", category, err)
		}
	}
	at := time.Date(2024, 1, 1, 1, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	for _, category := range []string{"full_disclosure", "partial_disclosure", "no_responsive_data", "refusal", "preservation_acknowledgement"} {
		tx := &counterTx{}
		if err := CountAnswered(ctx, tx, at, category); err != nil || !tx.called || len(tx.args) != 2 || tx.args[1] != category {
			t.Fatalf("UTC/category binding: %+v %v", tx.args, err)
		}
		bound, ok := tx.args[0].(pgtype.Timestamptz)
		if !ok || !bound.Valid || bound.Time.Location() != time.UTC || !bound.Time.Equal(at) {
			t.Fatalf("timestamp not normalized without changing instant: %+v", tx.args[0])
		}
	}
	tx := &counterTx{err: errors.New("private database error")}
	if err := CountReceived(ctx, tx, at); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("database error not redacted: %v", err)
	}
}

func assertKeys(t *testing.T, raw map[string]json.RawMessage, want ...string) {
	t.Helper()
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sort.Strings(want)
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("artifact fields=%v, want=%v", keys, want)
	}
}

func assertPrivateArtifact(t *testing.T, payload []byte) Artifact {
	t.Helper()
	var a Artifact
	if err := json.Unmarshal(payload, &a); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "schema_version", "year", "coverage", "received", "answered", "outcomes")
	var coverage map[string]json.RawMessage
	if err := json.Unmarshal(raw["coverage"], &coverage); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, coverage, "status", "late_entries_possible")
	if a.SchemaVersion != SchemaVersion || (a.Coverage.Status != "partial" && a.Coverage.Status != "no_coverage") || !a.Coverage.LateEntriesPossible {
		t.Fatalf("unexpected public contract: %s", payload)
	}
	for _, name := range []string{"received", "answered"} {
		var cell map[string]json.RawMessage
		if err := json.Unmarshal(raw[name], &cell); err != nil {
			t.Fatal(err)
		}
		if _, shown := cell["count"]; shown {
			assertKeys(t, cell, "count", "suppressed")
		} else {
			assertKeys(t, cell, "suppressed")
		}
	}
	return a
}
