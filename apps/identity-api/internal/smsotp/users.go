package smsotp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Database provides queries and transactions required for locked account mutations.
type Database interface {
	db.DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// PostgresUserStore fences phone writes under account advisory and row locks.
type PostgresUserStore struct {
	database Database
	queries  *db.Queries
}

// NewUserStore constructs the transactional user store without querying the database.
func NewUserStore(database Database) (*PostgresUserStore, error) {
	if database == nil || (reflect.ValueOf(database).Kind() == reflect.Pointer && reflect.ValueOf(database).IsNil()) {
		return nil, ErrUnavailable
	}
	return &PostgresUserStore{database, db.New(database)}, nil
}

// GetUserByID loads a nondeleted account with a bounded database deadline.
func (s *PostgresUserStore) GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u, err := s.queries.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, pgx.ErrNoRows
	}
	if err != nil {
		return db.User{}, ErrUnavailable
	}
	return u, nil
}

// SetPhoneIfCurrent writes encrypted phone data only under current account authority.
func (s *PostgresUserStore) SetPhoneIfCurrent(ctx context.Context, id uuid.UUID, version int64, encrypted []byte, index string) error {
	_, err := s.mutate(ctx, id, version, encrypted, index, false)
	return err
}

// RemovePhoneIfCurrent conditionally removes the phone and reports a committed change.
func (s *PostgresUserStore) RemovePhoneIfCurrent(ctx context.Context, id uuid.UUID, version int64) (bool, error) {
	return s.mutate(ctx, id, version, nil, "", true)
}
func (s *PostgresUserStore) mutate(ctx context.Context, id uuid.UUID, version int64, encrypted []byte, index string, remove bool) (bool, error) {
	if id == uuid.Nil || version < 0 {
		return false, ErrStaleSession
	}
	if !remove && (len(encrypted) == 0 || index == "") {
		return false, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, ErrUnavailable
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return false, ErrUnavailable
	}
	q := db.New(tx)
	u, err := q.GetAccountAuthStateForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrUserNotFound
	}
	if err != nil {
		return false, ErrUnavailable
	}
	if u.DeletedAt.Valid || u.Status != "active" {
		return false, ErrAccountNotActive
	}
	if u.AuthVersion != version {
		return false, ErrStaleSession
	}
	var count int64
	if remove {
		count, err = q.RemoveUserPhoneIfAuthorized(ctx, db.RemoveUserPhoneIfAuthorizedParams{ID: id, AuthVersion: version})
	} else {
		count, err = q.SetUserPhoneIfAuthorized(ctx, db.SetUserPhoneIfAuthorizedParams{ID: id, AuthVersion: version, PhoneEncrypted: encrypted, PhoneBlindIndex: &index})
	}
	if err != nil || count < 0 || count > 1 || !remove && count != 1 {
		return false, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrUnavailable
	}
	return count == 1, nil
}
