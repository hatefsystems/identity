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
// The audit tip is cached while the daemon holds the single-writer lock. Ledger
// batches instead read the protected logical head under a short coordination lock,
// because retention can remove even the last surviving payload row. Any uncertain
// commit requires re-reading both tips before processing another batch.
package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Store is the database surface the signer needs. It is narrow and hand-declared
// (matching privacy.PurgeStore) for two reasons: unit tests can drive the whole
// batch state machine against a fake, and the post-MVP move of audit storage to
// ClickHouse becomes a new adapter rather than a rewrite of the signer.
type Store interface {
	// GetLatestAuditLogChainHash returns the current audit chain tip, or
	// pgx.ErrNoRows before the genesis record.
	GetLatestAuditLogChainHash(ctx context.Context) (string, error)
	// GetSignerLedgerHead reads the initialized logical head and proof consistency
	// from one statement snapshot. A missing row is an error, never genesis.
	GetSignerLedgerHead(ctx context.Context) (db.GetSignerLedgerHeadRow, error)
	// AdvanceSecurityLedgerHead validates the actual newly inserted terminal row.
	AdvanceSecurityLedgerHead(ctx context.Context, arg db.AdvanceSecurityLedgerHeadParams) error
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
	// LockAccounts takes UUID-ordered advisory locks before any subject row locks.
	LockAccounts(ctx context.Context, ids []uuid.UUID) error
	// ValidateLedgerState checks all live bodies and checkpoint transitions on
	// startup/recovery, in bounded pages while the coordination lock is held.
	ValidateLedgerState(ctx context.Context, through int64) error
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
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
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
	tx, err := o.tx.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("signer: begin batch transaction: %w", err)
	}
	batch := &pgBatchTx{tx: tx, store: db.New(tx)}
	// Server-side waits remain bounded even if the caller's connection loses its
	// deadline. Rollback has its own budget because ctx may already be cancelled.
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '2s'; SET LOCAL statement_timeout = '30s'; SET LOCAL idle_in_transaction_session_timeout = '30s'"); err != nil {
		_ = batch.Rollback(ctx)
		return nil, fmt.Errorf("signer: set batch timeouts: %w", err)
	}
	if err := pglock.LockLedger(ctx, tx); err != nil {
		_ = batch.Rollback(ctx)
		return nil, fmt.Errorf("signer: lock ledger: %w", err)
	}
	return batch, nil
}

// pgBatchTx is the pgx-backed BatchTx.
type pgBatchTx struct {
	tx    pgx.Tx
	store Store
}

func (t *pgBatchTx) Store() Store                     { return t.store }
func (t *pgBatchTx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

func (t *pgBatchTx) LockAccounts(ctx context.Context, ids []uuid.UUID) error {
	ids = slices.Clone(ids)
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	for _, id := range slices.Compact(ids) {
		if err := pglock.LockAccount(ctx, t.tx, id); err != nil {
			return err
		}
	}
	return nil
}

func (t *pgBatchTx) ValidateLedgerState(ctx context.Context, through int64) error {
	source := ledgerproof.NewSource(t.tx)
	params := ledgerproof.Params{ThroughSeq: through, HasThrough: true, Limit: 1000}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := ledgerproof.Verify(ctx, source, params)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLedgerStateInvalid, err)
		}
		// Erased history is not content verification, but its validated boundary
		// digests still permit safe future appends. Never invent erased bodies.
		if result.FailureReason != nil && *result.FailureReason != "no_retained_records" {
			return fmt.Errorf("%w: %s", ErrLedgerStateInvalid, *result.FailureReason)
		}
		if result.Complete {
			return nil
		}
		if result.NextAfterSeq == nil || result.LastHash == nil || *result.NextAfterSeq <= params.AfterSeq {
			return fmt.Errorf("%w: incomplete proof traversal", ErrLedgerStateInvalid)
		}
		params.AfterSeq = *result.NextAfterSeq
		params.PredecessorHash = *result.LastHash
	}
}

// Rollback discards the transaction. pgx.ErrTxClosed is swallowed so the deferred
// rollback after a successful commit is a no-op rather than a spurious error.
func (t *pgBatchTx) Rollback(ctx context.Context) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := t.tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

const rollbackTimeout = 5 * time.Second

// NewPoolStore returns the pool-bound query set used for the startup chain-tip
// reads, which happen outside any batch transaction.
func NewPoolStore(pool *pgxpool.Pool) (Store, error) {
	if pool == nil {
		return nil, errors.New("signer: pool is required")
	}
	return db.New(pool), nil
}
