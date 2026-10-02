package ledgerproof

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Beginner must be a pool (not the already account-locked admin transaction).
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// VerifySnapshot opens a separate, bounded, read-only snapshot. It never takes
// the ledger coordination lock and never commits administrative audit intent.
func VerifySnapshot(ctx context.Context, pool Beginner, params Params) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Result{}, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '10s'; SET LOCAL lock_timeout = '2s'"); err != nil {
		return Result{}, err
	}
	return Verify(ctx, NewSource(tx), params)
}

// Store is a proof reader over a caller-owned transaction. Workers can reuse it
// under their write locks; HTTP verification must use VerifySnapshot instead.
type Store struct{ queries *db.Queries }

// NewSource does not acquire locks or start a transaction.
func NewSource(conn db.DBTX) *Store { return &Store{queries: db.New(conn)} }

// Head reads explicit initialization and both live and erased terminal nodes.
func (s *Store) Head(ctx context.Context) (Head, error) {
	h, err := s.queries.GetLedgerVerificationHead(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, ErrMissingHead
	}
	return Head{Seq: h.Seq, Hash: h.ChainHash, MaxSeq: h.MaxSeq}, err
}

// Boundary returns at most four candidates, enough to reject ambiguous proof.
func (s *Store) Boundary(ctx context.Context, seq int64) ([]Step, error) {
	return s.nodes(ctx, db.ListLedgerVerificationNodesParams{AfterSeq: seq, ThroughSeq: seq, BoundaryOnly: true, NodeLimit: 4})
}

// Page bounds live records and erased spans together, not just surviving bodies.
func (s *Store) Page(ctx context.Context, after, through int64, limit int32) ([]Step, error) {
	return s.nodes(ctx, db.ListLedgerVerificationNodesParams{AfterSeq: after, ThroughSeq: through, NodeLimit: limit})
}

func (s *Store) nodes(ctx context.Context, params db.ListLedgerVerificationNodesParams) ([]Step, error) {
	rows, err := s.queries.ListLedgerVerificationNodes(ctx, params)
	if err != nil {
		return nil, err
	}
	steps := make([]Step, 0, len(rows))
	for _, row := range rows {
		step := Step{Checkpoint: Checkpoint{FirstSeq: row.FirstSeq, LastSeq: row.LastSeq,
			PredecessorSeq: row.PredecessorSeq, PredecessorHash: row.PredecessorHash,
			TerminalHash: row.TerminalHash, ErasedCount: row.ErasedCount}}
		if row.Overlaps {
			step.Problem = "checkpoint_overlap"
		} else if !row.PredecessorMatches {
			step.Problem = "checkpoint_link_mismatch"
		}
		if !row.Erased {
			var record db.SecurityEventLedger
			if err := json.Unmarshal(row.LiveRecord, &record); err != nil {
				return nil, err
			}
			if record.Seq != row.FirstSeq {
				step.Problem = "missing_proof"
			}
			body := Record(record)
			step.Record = &body
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// Record projects the signed fields without changing historical timestamps.
func Record(e db.SecurityEventLedger) audit.LedgerRecord {
	return audit.LedgerRecord{ID: e.ID.String(), AccountRef: e.AccountRef.String(),
		IdentityBlindIndex: e.IdentityBlindIndex, EventType: e.EventType,
		ClientIP: e.ClientIp, IPSubnet: e.IpSubnet, UserAgent: e.UserAgent,
		DeviceFingerprint: e.DeviceFingerprint, ClientID: e.ClientID, Scope: e.Scope,
		Timestamp: e.Timestamp.Time, RetainUntil: e.RetainUntil.Time}
}
