package lifecycle

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ErrEnqueue is safe to log: database errors may contain identifiers or payloads.
var ErrEnqueue = errors.New("lifecycle: durable intent unavailable")

// EventStore must be bound to the caller's business transaction.
type EventStore interface {
	InsertLifecycleEvent(context.Context, db.InsertLifecycleEventParams) error
}

// Store adds revision allocation under the business operation's user row lock.
type Store interface {
	EventStore
	AdvanceUserLifecycleRevision(context.Context, uuid.UUID) (int64, error)
}

// CreateUser inserts an account and its creation intent. The caller owns tx and
// must roll it back on any error. Synthetic operator probes use the raw query.
func CreateUser(ctx context.Context, tx pgx.Tx, arg db.CreateUserParams) (db.User, error) {
	if tx == nil || (arg.Status != "active" && arg.Status != "pending_verification") {
		return db.User{}, ErrInvalidEvent
	}
	q := db.New(tx)
	user, err := q.CreateUser(ctx, arg)
	if err != nil {
		return db.User{}, ErrEnqueue
	}
	revision, err := q.AdvanceUserLifecycleRevision(ctx, user.ID)
	if err != nil || revision != 1 {
		return db.User{}, ErrEnqueue
	}
	if err := enqueue(ctx, q, user.ID, revision, SubjectCreated, user.Status, []string{"email", "status"}, SchemaVersion); err != nil {
		return db.User{}, err
	}
	user.LifecycleRevision = revision
	return user, nil
}

// EnqueueStatusChange runs after the status mutation, before transaction commit.
// Callers compare states read under the same user row lock, never a stale lookup.
func EnqueueStatusChange(ctx context.Context, store Store, id uuid.UUID, before, after string) error {
	if before == after {
		return nil
	}
	if store == nil || id == uuid.Nil {
		return ErrInvalidEvent
	}
	subject := SubjectUpdated
	if after == "suspended" {
		subject = SubjectSuspended
	}
	revision, err := store.AdvanceUserLifecycleRevision(ctx, id)
	if err != nil {
		return ErrEnqueue
	}
	return enqueue(ctx, store, id, revision, subject, after, []string{"status"}, SchemaVersion)
}

// EnqueueDisplayNameChange follows a real name update under the account row lock.
// The caller handles no-ops and rolls back both the name and revision on failure.
// Values are intentionally absent from this API and from the durable intent.
func EnqueueDisplayNameChange(ctx context.Context, store Store, id uuid.UUID, status string) (int64, error) {
	if store == nil || id == uuid.Nil || status != "active" {
		return 0, ErrInvalidEvent
	}
	revision, err := store.AdvanceUserLifecycleRevision(ctx, id)
	if err != nil {
		return 0, ErrEnqueue
	}
	if err := enqueue(ctx, store, id, revision, SubjectUpdated, status, []string{"display_name"}, SchemaVersionV2); err != nil {
		return 0, err
	}
	return revision, nil
}

// EnqueueDeletion runs only after an exactly-one-row, hold-checked DELETE in the
// same transaction. The removed, locked user supplied previousRevision.
func EnqueueDeletion(ctx context.Context, store EventStore, id uuid.UUID, previousRevision int64) error {
	if store == nil || previousRevision < 0 || previousRevision == math.MaxInt64 {
		return ErrInvalidEvent
	}
	return enqueue(ctx, store, id, previousRevision+1, SubjectDeleted, "", nil, SchemaVersion)
}

func enqueue(ctx context.Context, store EventStore, id uuid.UUID, revision int64, subject, status string, fields []string, version uint32) error {
	eventID, err := uuid.NewRandom()
	if err != nil {
		return ErrEnqueue
	}
	// PostgreSQL timestamps have microsecond precision. Persist the same instant
	// in the envelope and indexed row so validation remains stable after reload.
	at := time.Now().UTC().Truncate(time.Microsecond)
	event, err := newEvent(version, eventID, id, revision, subject, status, fields, at)
	if err != nil {
		return err
	}
	encoded, err := MarshalEvent(event)
	if err != nil {
		return err
	}
	if err := store.InsertLifecycleEvent(ctx, db.InsertLifecycleEventParams{
		ID: eventID, Subject: subject, Payload: string(encoded),
		CreatedAt:       pgtype.Timestamptz{Time: at, Valid: true},
		LifecycleUserID: uuid.NullUUID{UUID: id, Valid: true}, LifecycleRevision: &revision,
	}); err != nil {
		return ErrEnqueue
	}
	return nil
}
