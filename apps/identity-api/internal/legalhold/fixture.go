package legalhold

import (
	"context"
	"crypto/subtle"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// LookupFixtureClient marks an explicit synthetic signer probe, never user data.
const LookupFixtureClient = "admin-lookup-probe-v1"

// LookupFixtureEmail is public synthetic material, derived from the probe ID.
func LookupFixtureEmail(id uuid.UUID) string {
	return "lookup-probe-" + id.String() + "@identity.invalid"
}

// FixtureReader reads a persisted signer result without access to live contacts.
type FixtureReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// VerifyLookupFixture checks the configured lookup key against a legacy-envelope
// probe indexed by the deployed signer. Pin the signer/producer/lookup pepper;
// re-run the probe after key or signer deployment changes. It is not a trust
// anchor for historical chain integrity or a completeness assertion.
func VerifyLookupFixture(ctx context.Context, reader FixtureReader, indexer BlindIndexer, id uuid.UUID) error {
	if reader == nil || indexer == nil || id == uuid.Nil {
		return ErrUnavailable
	}
	var index string
	err := reader.QueryRow(ctx, `SELECT identity_blind_index FROM security_event_ledger
		WHERE id=$1 AND client_id=$2 AND event_type=$3 AND identity_blind_index IS NOT NULL`,
		id, LookupFixtureClient, audit.EventLoginSucceeded).Scan(&index)
	if err != nil || subtle.ConstantTimeCompare([]byte(index), []byte(indexer.Compute(LookupFixtureEmail(id)))) != 1 {
		return ErrUnavailable
	}
	return nil
}
