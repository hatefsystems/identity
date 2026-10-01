// Package adminaction couples privileged business transactions with durable,
// sanitized Class C audit intent. Only the signer writes cryptographic chains.
package adminaction

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Errors distinguish audit availability from invalid privileged metadata.
var (
	ErrUnavailable    = errors.New("adminaction: durable audit unavailable")
	ErrNoOperation    = errors.New("adminaction: request transaction required")
	ErrInvalidEvent   = errors.New("adminaction: invalid audit metadata")
	ErrInvalidDetails = errors.New("adminaction: invalid restricted context")
)

const maxDetailsBytes = 64 * 1024

// Beginner opens a business and audit transaction.
type Beginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// Encryptor seals restricted action context.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
}

// Service commits privileged changes and durable audit intent together.
type Service struct {
	beginner  Beginner
	encryptor Encryptor
	subject   string
	retention time.Duration
}

// New requires an approved, explicit narrative retention period. There is no
// production or development retention default in this package.
func New(beginner Beginner, encryptor Encryptor, subject string, retention time.Duration) (*Service, error) {
	if beginner == nil || encryptor == nil || !validSubject(subject) || retention < time.Microsecond {
		return nil, errors.New("adminaction: database, encryption, audit subject and positive retention required")
	}
	return &Service{beginner: beginner, encryptor: encryptor, subject: subject, retention: retention}, nil
}

func validSubject(subject string) bool {
	if subject == "" || len(subject) > 100 || subject == "identity.user.deleted" || strings.ContainsAny(subject, "*> \t\r\n") {
		return false
	}
	for _, token := range strings.Split(subject, ".") {
		if token == "" {
			return false
		}
	}
	return true
}

// Operation is request-scoped and must not be used concurrently. Business code
// uses Tx/Queries but MUST leave Commit/Rollback to the response boundary.
type Operation struct {
	Tx      pgx.Tx
	Queries *db.Queries
	ID      uuid.UUID
	Event   audit.Event
	// AfterCommit performs optional local credential cleanup after durable commit.
	AfterCommit func() error

	service    *Service
	occurredAt time.Time
	details    json.RawMessage
	detailsErr error
	closed     bool
}

// Begin opens a request operation using READ COMMITTED isolation.
func (s *Service) Begin(ctx context.Context) (*Operation, error) {
	tx, err := beginReadCommitted(ctx, s.beginner)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Operation{Tx: tx, Queries: db.New(tx), ID: uuid.New(), service: s,
		occurredAt: time.Now().UTC().Truncate(time.Microsecond)}, nil
}

type contextKey struct{}

// WithContext attaches an operation to the request.
func WithContext(ctx context.Context, op *Operation) context.Context {
	return context.WithValue(ctx, contextKey{}, op)
}

// FromContext retrieves the request operation.
func FromContext(ctx context.Context) (*Operation, bool) {
	op, ok := ctx.Value(contextKey{}).(*Operation)
	return op, ok && op != nil
}

// SetEvent merges operation metadata without erasing authenticated request
// actor/network defaults. A newly authenticated actor may fill an absent default.
// Success/failure event type and status replace earlier guard defaults.
func SetEvent(ctx context.Context, event audit.Event) {
	op, ok := FromContext(ctx)
	if !ok {
		return
	}
	old := op.Event
	if event.EventType == "" {
		event.EventType = old.EventType
	}
	if event.ActionStatus == "" {
		event.ActionStatus = old.ActionStatus
	}
	if old.ActorID != uuid.Nil {
		event.ActorID = old.ActorID
	}
	if old.ActorSPIFFEID != "" {
		event.ActorSPIFFEID = old.ActorSPIFFEID
	}
	if old.ClientIP != "" {
		event.ClientIP = old.ClientIP
	}
	if old.UserAgent != "" {
		event.UserAgent = old.UserAgent
	}
	if event.SubjectID == nil {
		event.SubjectID = old.SubjectID
	}
	payload := make(map[string]any, len(old.Payload)+len(event.Payload))
	for key, value := range old.Payload {
		payload[key] = value
	}
	for key, value := range event.Payload {
		payload[key] = value
	}
	event.Payload = payload
	event.Security = nil
	op.Event = event
}

// SetDetails stores bounded JSON for encryption at Commit. A failed call poisons
// this operation, preventing a caller that ignores the error from committing.
// Lookup identifiers and blind indexes must never be supplied, even here.
func SetDetails(ctx context.Context, details any) error {
	op, ok := FromContext(ctx)
	if !ok {
		return ErrNoOperation
	}
	if op.closed {
		return pgx.ErrTxClosed
	}
	encoded, err := json.Marshal(details)
	if err != nil || len(encoded) > maxDetailsBytes || string(encoded) == "null" {
		op.detailsErr = ErrInvalidDetails
		return ErrInvalidDetails
	}
	op.details = encoded
	return nil
}

// Commit encrypts context and appends outbox intent before committing changes.
func (op *Operation) Commit(ctx context.Context) error {
	if op.closed {
		return pgx.ErrTxClosed
	}
	if op.service == nil || op.Tx == nil {
		return ErrNoOperation
	}
	defer func() { _ = op.Rollback(context.WithoutCancel(ctx)) }()
	if op.detailsErr != nil {
		return op.detailsErr
	}
	event, err := sanitizedEvent(op.Event, op.ID)
	if err != nil {
		return err
	}
	env, err := audit.NewEnvelope(event, op.ID, op.occurredAt)
	if err != nil {
		return ErrInvalidEvent
	}
	encoded, err := json.Marshal(env)
	if err != nil {
		return ErrInvalidEvent
	}
	if len(op.details) != 0 {
		// The existing envelope implementation has no caller-supplied AAD. Bind
		// the encrypted value to its row using authenticated plaintext instead.
		plaintext, err := json.Marshal(struct {
			ActionID uuid.UUID       `json:"action_id"`
			Details  json.RawMessage `json:"details"`
		}{op.ID, op.details})
		if err != nil {
			return ErrInvalidDetails
		}
		ciphertext, encryptErr := op.service.encryptor.Encrypt(ctx, plaintext)
		clear(plaintext)
		if encryptErr != nil || len(ciphertext) == 0 {
			return ErrUnavailable
		}
		account := uuid.NullUUID{}
		if op.Event.SubjectID != nil {
			account = uuid.NullUUID{UUID: *op.Event.SubjectID, Valid: true}
		}
		if err := op.Queries.InsertAdminActionContext(ctx, db.InsertAdminActionContextParams{
			ActionID: op.ID, AccountRef: account, DetailsEncrypted: ciphertext,
			CreatedAt: timestamp(op.occurredAt), RetainUntil: timestamp(op.occurredAt.Add(op.service.retention)),
		}); err != nil {
			return ErrUnavailable
		}
	}
	if err := op.Queries.InsertAdminActionOutbox(ctx, db.InsertAdminActionOutboxParams{
		ID: op.ID, Subject: op.service.subject, Payload: string(encoded), CreatedAt: timestamp(op.occurredAt),
	}); err != nil {
		return ErrUnavailable
	}
	if err := op.Tx.Commit(ctx); err != nil {
		return ErrUnavailable
	}
	op.closed = true
	clear(op.details)
	op.details = nil
	return nil
}

// Rollback discards business changes and marks the operation closed.
func (op *Operation) Rollback(ctx context.Context) error {
	if op.closed {
		return nil
	}
	op.closed = true
	clear(op.details)
	op.details = nil
	if op.Tx == nil {
		return nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := op.Tx.Rollback(rollbackCtx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Record writes an attempt in a new, bounded transaction after the business
// transaction has rolled back. It never uses the best-effort audit recorder.
func (s *Service) Record(ctx context.Context, event audit.Event) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	op, err := s.Begin(ctx)
	if err != nil {
		return err
	}
	op.Event = event
	return op.Commit(ctx)
}

func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}

// Override connection-level defaults: preservation/cleanup decisions must get a
// fresh statement snapshot after waiting for the shared account advisory lock.
func beginReadCommitted(ctx context.Context, beginner Beginner) (pgx.Tx, error) {
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
		rollback(ctx, tx)
		return nil, err
	}
	return tx, nil
}
