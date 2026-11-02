package legalhold

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
)

type fixtureRow struct {
	value string
	err   error
}

func (r fixtureRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	*dst[0].(*string) = r.value
	return nil
}

type fixtureReader struct {
	row   fixtureRow
	query string
	args  []any
}

func (r *fixtureReader) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	r.query, r.args = query, args
	return r.row
}

func TestLookupFixtureRejectsMissingAndMismatchedSignerKeys(t *testing.T) {
	id := uuid.New()
	indexer, err := blindindex.New([]byte(strings.Repeat("a", 32)), 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := blindindex.New([]byte(strings.Repeat("b", 32)), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		row       fixtureRow
		wantError bool
	}{
		{"matching", fixtureRow{value: indexer.Compute(LookupFixtureEmail(id))}, false},
		{"wrong signer key", fixtureRow{value: other.Compute(LookupFixtureEmail(id))}, true},
		{"missing fixture", fixtureRow{err: pgx.ErrNoRows}, true},
		{"storage failure", fixtureRow{err: errors.New("unavailable")}, true},
		{"different probe", fixtureRow{value: indexer.Compute(LookupFixtureEmail(uuid.New()))}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &fixtureReader{row: tc.row}
			err := VerifyLookupFixture(context.Background(), reader, indexer, id)
			if (err != nil) != tc.wantError {
				t.Fatalf("verification: %v", err)
			}
			for _, required := range []string{"FROM security_ledger_chain c", "JOIN security_event_ledger l ON l.seq=c.seq", "c.event_id=$1", "l.client_id=$2", "l.event_type=$3", "l.identity_blind_index IS NOT NULL"} {
				if !strings.Contains(reader.query, required) {
					t.Fatalf("fixture query omitted canonical-v2 binding %q", required)
				}
			}
			if len(reader.args) != 3 || reader.args[0] != id || reader.args[1] != LookupFixtureClient || reader.args[2] != audit.EventLoginSucceeded {
				t.Fatal("fixture verification lost synthetic marker or event binding")
			}
		})
	}
	for _, tc := range []struct {
		reader  FixtureReader
		indexer BlindIndexer
		id      uuid.UUID
	}{
		{nil, indexer, id}, {&fixtureReader{}, nil, id}, {&fixtureReader{}, indexer, uuid.Nil},
	} {
		if err := VerifyLookupFixture(context.Background(), tc.reader, tc.indexer, tc.id); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("missing fixture dependency did not fail closed: %v", err)
		}
	}
}
