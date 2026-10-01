package legalhold

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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

type fixtureReader struct{ row fixtureRow }

func (r fixtureReader) QueryRow(context.Context, string, ...any) pgx.Row { return r.row }

func TestLookupFixtureRejectsMissingAndMismatchedSignerKeys(t *testing.T) {
	id := uuid.New()
	indexer, err := blindindex.New([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := blindindex.New([]byte(strings.Repeat("b", 32)))
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
			err := VerifyLookupFixture(context.Background(), fixtureReader{tc.row}, indexer, id)
			if (err != nil) != tc.wantError {
				t.Fatalf("verification: %v", err)
			}
		})
	}
}
