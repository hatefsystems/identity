package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ErrAccountIneligible includes revoked versions, inactive and deleted accounts.
var ErrAccountIneligible = errors.New("session: account authentication is no longer valid")

// AccountState is the shared, authoritative revocation boundary. WithActive
// holds the account row lock while issuing artifacts with a previously captured
// version; it must never replace that version with a newly read one.
type AccountState interface {
	Validate(context.Context, string, int64) error
	WithActive(context.Context, string, int64, func() error) error
	Epoch(context.Context) (int64, error)
}

// DBAccountState uses primary PostgreSQL state, not a process-local cache.
type DBAccountState struct {
	pool    *pgxpool.Pool
	queries *db.Queries
}

// NewDBAccountState uses primary database state as the revocation boundary.
func NewDBAccountState(pool *pgxpool.Pool) *DBAccountState {
	return &DBAccountState{pool: pool, queries: db.New(pool)}
}

// Validate rejects stale versions and accounts ineligible for authentication.
func (a *DBAccountState) Validate(ctx context.Context, userID string, version int64) error {
	id, err := uuid.Parse(userID)
	if err != nil || version < 0 {
		return ErrAccountIneligible
	}
	state, err := a.queries.GetAccountAuthState(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountIneligible
	}
	if err != nil {
		return fmt.Errorf("session: account state: %w", err)
	}
	if state.Status != "active" || state.DeletedAt.Valid || state.AuthVersion != version {
		return ErrAccountIneligible
	}
	return nil
}

// WithActive serializes artifact issuance with account restrictions.
func (a *DBAccountState) WithActive(ctx context.Context, userID string, version int64, fn func() error) error {
	id, err := uuid.Parse(userID)
	if err != nil || version < 0 {
		return ErrAccountIneligible
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	state, err := db.New(tx).GetAccountAuthStateForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAccountIneligible
	}
	if err != nil {
		return err
	}
	if state.Status != "active" || state.DeletedAt.Valid || state.AuthVersion != version {
		return ErrAccountIneligible
	}
	if err := fn(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Epoch allocates a strict ordering boundary for a usernameless ceremony.
func (a *DBAccountState) Epoch(ctx context.Context) (int64, error) {
	return a.queries.NextAccountAuthEpoch(ctx)
}
