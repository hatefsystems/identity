package profile

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Errors are deliberately independent of database errors, names, and identities.
var (
	ErrUnauthorized    = errors.New("profile: unauthorized")
	ErrInvalidRevision = errors.New("profile: invalid revision")
	ErrConflict        = errors.New("profile: revision conflict")
	ErrUnavailable     = errors.New("profile: dependency unavailable")
)

// Database requires real transaction support; writes have no unprotected fallback.
type Database interface {
	db.DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Profile contains only the fields approved for first-party self-service.
type Profile struct {
	ID                uuid.UUID
	Email             string
	DisplayName       string
	Status            string
	LifecycleRevision string
}

// UpdateResult identifies a committed change without exposing prior name values.
type UpdateResult struct {
	Profile Profile
	Changed bool
}

// Service reads current snapshots and serializes profile changes with moderation.
type Service struct {
	database Database
	queries  *db.Queries
}

// New uses the primary pool and opens no connections of its own.
func New(database Database) (*Service, error) {
	if database == nil || (reflect.ValueOf(database).Kind() == reflect.Pointer && reflect.ValueOf(database).IsNil()) {
		return nil, ErrUnavailable
	}
	return &Service{database: database, queries: db.New(database)}, nil
}

func parseRevision(raw string) (int64, error) {
	if len(raw) == 0 || len(raw) > 19 {
		return 0, ErrInvalidRevision
	}
	revision, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || revision < 0 || strconv.FormatInt(revision, 10) != raw {
		return 0, ErrInvalidRevision
	}
	return revision, nil
}

func projection(row db.GetUserProfileRow, id uuid.UUID, authVersion int64) (Profile, error) {
	if row.ID != id || row.Status != "active" || row.AuthVersion != authVersion {
		return Profile{}, ErrUnauthorized
	}
	name, err := NormalizeName(row.DisplayName)
	if err != nil || name != row.DisplayName || row.LifecycleRevision < 0 {
		return Profile{}, ErrUnavailable
	}
	return Profile{ID: row.ID, Email: row.Email, DisplayName: row.DisplayName, Status: row.Status,
		LifecycleRevision: strconv.FormatInt(row.LifecycleRevision, 10)}, nil
}

// Get checks the captured authentication version and profile in one DB snapshot.
func (s *Service) Get(ctx context.Context, id uuid.UUID, authVersion int64) (Profile, error) {
	if id == uuid.Nil || authVersion < 0 {
		return Profile{}, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	row, err := s.queries.GetUserProfile(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrUnauthorized
	}
	if err != nil {
		return Profile{}, ErrUnavailable
	}
	return projection(row, id, authVersion)
}

// Update requires a canonical decimal-string revision and the authentication
// version captured by the session. The name, revision and v2 intent commit once.
func (s *Service) Update(ctx context.Context, id uuid.UUID, authVersion int64, displayName, expectedRevision string) (UpdateResult, error) {
	if id == uuid.Nil || authVersion < 0 {
		return UpdateResult{}, ErrUnauthorized
	}
	name, err := NormalizeName(displayName)
	if err != nil {
		return UpdateResult{}, err
	}
	revision, err := parseRevision(expectedRevision)
	if err != nil {
		return UpdateResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return UpdateResult{}, ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return UpdateResult{}, ErrUnavailable
	}
	q := db.New(tx)
	locked, err := q.GetUserProfileForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return UpdateResult{}, ErrUnauthorized
	}
	if err != nil {
		return UpdateResult{}, ErrUnavailable
	}
	current, err := projection(db.GetUserProfileRow(locked), id, authVersion)
	if err != nil {
		return UpdateResult{}, err
	}
	if locked.LifecycleRevision != revision {
		return UpdateResult{}, ErrConflict
	}
	if name == current.DisplayName {
		// The lock is released by rollback; even updated_at remains untouched.
		return UpdateResult{Profile: current}, nil
	}
	count, err := q.UpdateUserDisplayName(ctx, db.UpdateUserDisplayNameParams{
		ID: id, DisplayName: name, AuthVersion: authVersion, LifecycleRevision: revision,
	})
	if err != nil || count != 1 {
		return UpdateResult{}, ErrUnavailable
	}
	next, err := lifecycle.EnqueueDisplayNameChange(ctx, q, id, locked.Status)
	if err != nil || next != revision+1 {
		return UpdateResult{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return UpdateResult{}, ErrUnavailable
	}
	current.DisplayName, current.LifecycleRevision = name, strconv.FormatInt(next, 10)
	return UpdateResult{Profile: current, Changed: true}, nil
}
