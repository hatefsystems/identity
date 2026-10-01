// Package signer contains the single-threaded worker that turns queued audit
// envelopes into the two cryptographic hash chains.
//
// # Why a single writer
//
// Both ledgers are chained: chain_hash(N) = SHA-256(chain_hash(N-1) ||
// serialize(record(N))). That recurrence is only well defined if exactly one writer
// assigns chain positions. Two signers would read the same tip, each extend it, and
// produce two rows claiming the same predecessor — a forked chain that can never be
// repaired, because both tables have UPDATE and DELETE revoked. The PostgreSQL
// advisory lock is what enforces "one", and failing to acquire it is therefore fatal
// rather than something to log and work around.
//
// # Why the database is the only source of truth for the tip
//
// The tip is cached in memory for the duration of a run purely to avoid a query per
// batch. Any commit failure invalidates that cache — the transaction may have
// partially applied from the connection's point of view, and a retry must not build
// on a guess — so the tip is re-read from the database before the batch is retried.
package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Store is the database surface the signer needs. It is narrow and hand-declared
// (matching privacy.PurgeStore) for two reasons: unit tests can drive the whole
// batch state machine against a fake, and the post-MVP move of audit storage to
// ClickHouse becomes a new adapter rather than a rewrite of the signer.
type Store interface {
	// GetLatestAuditLogChainHash returns the current audit chain tip, or
	// pgx.ErrNoRows before the genesis record.
	GetLatestAuditLogChainHash(ctx context.Context) (string, error)
	// GetLatestSecurityEventChainHash returns the current ledger chain tip, or
	// pgx.ErrNoRows before the genesis record.
	GetLatestSecurityEventChainHash(ctx context.Context) (string, error)
	// FilterExistingAuditLogIDs returns the subset of ids already persisted.
	FilterExistingAuditLogIDs(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// FilterExistingSecurityEventIDs returns the subset of ids already persisted.
	FilterExistingSecurityEventIDs(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// GetUserEmailForBlindIndex returns the account's email so the signer can derive
	// identity_blind_index. It returns pgx.ErrNoRows once the subject is purged.
	GetUserEmailForBlindIndex(ctx context.Context, id uuid.UUID) (string, error)
	// LockAuditSubjects returns and locks surviving optional FK attachments in
	// UUID order until the batch transaction commits.
	LockAuditSubjects(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// InsertAuditLogs batch-writes audit rows via COPY.
	InsertAuditLogs(ctx context.Context, arg []db.InsertAuditLogsParams) (int64, error)
	// InsertSecurityEvents batch-writes ledger rows via COPY.
	InsertSecurityEvents(ctx context.Context, arg []db.InsertSecurityEventsParams) (int64, error)
}

// BatchTx is one batch's transaction: a transaction-bound Store plus its
// commit/rollback control.
//
// Both COPYs must land together. If the ledger insert failed after the audit insert
// committed, the ledger chain would be missing records that the audit chain already
// counted, and there is no way to insert them later at the right chain position.
//
// It is an interface rather than a closure so a unit test can assert that a batch
// was rolled back and Nak'ed rather than committed — the difference between "retry
// safely" and "silently lose the batch", which is otherwise unobservable without a
// live database.
type BatchTx interface {
	// Store returns the transaction-bound query set.
	Store() Store
	// Commit makes both COPYs durable together.
	Commit(ctx context.Context) error
	// Rollback discards both. It must be safe to call after Commit.
	Rollback(ctx context.Context) error
}

// BatchTxOpener opens one transaction per batch.
type BatchTxOpener interface {
	BeginBatch(ctx context.Context) (BatchTx, error)
}

// Transacter is the subset of *pgxpool.Pool the opener needs.
type Transacter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PgBatchTxOpener opens pgx transactions for batches.
type PgBatchTxOpener struct {
	tx Transacter
}

// NewPgBatchTxOpener constructs a BatchTxOpener over a pgx pool.
func NewPgBatchTxOpener(tx Transacter) (*PgBatchTxOpener, error) {
	if tx == nil {
		return nil, errors.New("signer: transacter is required")
	}
	return &PgBatchTxOpener{tx: tx}, nil
}

// BeginBatch implements BatchTxOpener.
func (o *PgBatchTxOpener) BeginBatch(ctx context.Context) (BatchTx, error) {
	tx, err := o.tx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("signer: begin batch transaction: %w", err)
	}
	return &pgBatchTx{tx: tx, store: db.New(tx)}, nil
}

// pgBatchTx is the pgx-backed BatchTx.
type pgBatchTx struct {
	tx    pgx.Tx
	store Store
}

func (t *pgBatchTx) Store() Store                     { return t.store }
func (t *pgBatchTx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

// Rollback discards the transaction. pgx.ErrTxClosed is swallowed so the deferred
// rollback after a successful commit is a no-op rather than a spurious error.
func (t *pgBatchTx) Rollback(ctx context.Context) error {
	if err := t.tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

// NewPoolStore returns the pool-bound query set used for the startup chain-tip
// reads, which happen outside any batch transaction.
func NewPoolStore(pool *pgxpool.Pool) (Store, error) {
	if pool == nil {
		return nil, errors.New("signer: pool is required")
	}
	return db.New(pool), nil
}
