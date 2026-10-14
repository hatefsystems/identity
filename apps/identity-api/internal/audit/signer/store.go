// Package signer contains the single-threaded worker that turns queued audit
// envelopes into the two cryptographic hash chains.
//
// # Why a single writer
//
// Both ledgers are chained over leaf digests:
//
//	leaf_hash(N)  = SHA-256( leaf_prefix  || serialize(record(N)) )
//	chain_hash(N) = SHA-256( chain_prefix || chain_hash(N-1) || leaf_hash(N) )
//
// That recurrence is only well defined if exactly one writer assigns chain
// positions. Two signers would read the same tip, each extend it, and produce two
// nodes claiming the same predecessor — a forked chain that can never be repaired,
// because the chain tables have UPDATE and DELETE revoked with no maintenance
// exemption. The PostgreSQL advisory lock is what enforces "one", and failing to
// acquire it is therefore fatal rather than something to log and work around.
//
// # Why the signer allocates seq itself
//
// The :copyfrom writers cannot read back generated identity values, so payload
// rows could not reference chain rows the database numbered. The signer therefore
// reserves a block of sequence values per batch and supplies them to both COPYs.
// This is sound only because of the single-writer lock, and it makes "seq order IS
// chain order" a property the writer guarantees rather than one that emerges.
//
// # Why the database is the only source of truth for the tip
//
// Both tips are read from their durable head rows under the coordination lock.
// Under canonical format v1 this mattered because retention could remove the last
// surviving payload row and make an erased span look like the tip. In v2 the chain
// table is never deleted, so its own MAX(seq) is authoritative too — the head is
// retained because it is the value an operator can reconcile out of band, and
// because advancing it is where per-batch linkage gets verified server-side.
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
	// GetAuditLogHead reads the audit chain's durable head and whether it is
	// consistent with the chain table, from one statement snapshot. A missing row
	// is an error, never genesis: an uninitialized head and a genuinely empty
	// chain are different states, and treating the first as the second is how a
	// signer restarts at genesis over existing history.
	GetAuditLogHead(ctx context.Context) (db.GetAuditLogHeadRow, error)
	// GetSecurityLedgerHead is the ledger counterpart.
	GetSecurityLedgerHead(ctx context.Context) (db.GetSecurityLedgerHeadRow, error)
	// AdvanceChainHead verifies linkage across the declared span and moves one
	// head forward.
	AdvanceChainHead(ctx context.Context, arg db.AdvanceChainHeadParams) error
	// AllocateAuditLogSeqs reserves chain positions for one audit batch.
	AllocateAuditLogSeqs(ctx context.Context, count int32) ([]int64, error)
	// AllocateSecurityLedgerSeqs reserves chain positions for one ledger batch.
	AllocateSecurityLedgerSeqs(ctx context.Context, count int32) ([]int64, error)
	// FilterExistingAuditLogIDs returns the subset of event ids already present in
	// the audit chain table.
	FilterExistingAuditLogIDs(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// FilterExistingSecurityEventIDs is the ledger counterpart.
	FilterExistingSecurityEventIDs(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// GetUserEmailForBlindIndex returns the account's email so the signer can derive
	// identity_blind_index. It returns pgx.ErrNoRows once the subject is purged.
	GetUserEmailForBlindIndex(ctx context.Context, id uuid.UUID) (string, error)
	// LockAuditSubjects returns and locks surviving optional FK attachments in
	// UUID order until the batch transaction commits.
	LockAuditSubjects(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// InsertAuditLogChain batch-writes audit chain nodes via COPY.
	InsertAuditLogChain(ctx context.Context, arg []db.InsertAuditLogChainParams) (int64, error)
	// InsertAuditLogs batch-writes audit payload rows via COPY.
	InsertAuditLogs(ctx context.Context, arg []db.InsertAuditLogsParams) (int64, error)
	// InsertSecurityLedgerChain batch-writes ledger chain nodes via COPY.
	InsertSecurityLedgerChain(ctx context.Context, arg []db.InsertSecurityLedgerChainParams) (int64, error)
	// InsertSecurityEvents batch-writes ledger payload rows via COPY.
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
	// ValidateLedgerState walks the retained chain on startup/recovery, in bounded
	// pages while the coordination lock is held.
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

// ValidateLedgerState walks the whole retained chain before the signer appends to
// it, so a signer never extends a chain it has not confirmed.
//
// Unlike v1 this can always reach a definitive answer: every node is retained, so
// there is no erased span whose contents have to be taken on trust from stored
// boundary digests. An absent payload is still verifiable as a *node*, and whether
// its absence was lawful is decided by ledgerproof against the erasure records.
func (t *pgBatchTx) ValidateLedgerState(ctx context.Context, through int64) error {
	source := ledgerproof.NewSource(t.tx, ledgerproof.ChainLedger)
	params := ledgerproof.Params{
		Chain: ledgerproof.ChainLedger, ThroughSeq: through, HasThrough: true, Limit: 1000,
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := ledgerproof.Verify(ctx, source, params)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrLedgerStateInvalid, err)
		}
		if result.FailureReason != nil {
			// "no_stored_records" over a non-empty declared range means the chain
			// does not reach the head it claims, which is not something to append on
			// top of.
			return fmt.Errorf("%w: %s", ErrLedgerStateInvalid, *result.FailureReason)
		}
		if result.Complete {
			return nil
		}
		next, ok := result.NextParams(params)
		if !ok || next.AfterSeq <= params.AfterSeq {
			return fmt.Errorf("%w: incomplete proof traversal", ErrLedgerStateInvalid)
		}
		params = next
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
