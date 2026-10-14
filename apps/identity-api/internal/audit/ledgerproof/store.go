package ledgerproof

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Beginner opens the read-only snapshot a verification runs in.
type Beginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// VerifySnapshot runs one verification pass inside a bounded READ ONLY REPEATABLE
// READ transaction, so the head and every node come from one snapshot. Without
// that, a batch committed mid-walk would make an intact chain look like it ends
// before its head.
func VerifySnapshot(ctx context.Context, pool Beginner, params Params) (Result, error) {
	if pool == nil {
		return Result{}, errors.New("ledgerproof: database is required")
	}
	// A verification pass is operator-triggered and read-only, but it walks a
	// table that grows without bound, so both the client and the server need a
	// ceiling. Without the client-side deadline a wedged snapshot would hold a
	// connection indefinitely.
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return Result{}, fmt.Errorf("ledgerproof: begin snapshot: %w", err)
	}
	// Cleanup runs on a context detached from ctx: ctx may already be cancelled,
	// and a rollback that cannot run leaks the connection.
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancelCleanup()
		_ = tx.Rollback(cleanup)
	}()

	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '2s'"); err != nil {
		return Result{}, fmt.Errorf("ledgerproof: bound snapshot: %w", err)
	}
	return Verify(ctx, NewSource(tx, params.Chain), params)
}

const (
	// snapshotTimeout bounds one whole verification pass.
	snapshotTimeout = 15 * time.Second
	// rollbackTimeout bounds the detached cleanup.
	rollbackTimeout = 5 * time.Second
)

// Store is the PostgreSQL-backed Source for one chain.
type Store struct {
	queries *db.Queries
	chain   Chain
}

// NewSource builds a Source over any connection or transaction.
func NewSource(conn db.DBTX, chain Chain) *Store {
	return &Store{queries: db.New(conn), chain: chain}
}

// Head implements Source.
func (s *Store) Head(ctx context.Context) (Head, error) {
	if s.chain == ChainAudit {
		row, err := s.queries.GetAuditLogHead(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return Head{}, ErrMissingHead
		}
		if err != nil {
			return Head{}, err
		}
		maxSeq, err := s.queries.GetAuditLogHighWaterSeq(ctx)
		if err != nil {
			return Head{}, err
		}
		return Head{Seq: row.Seq, MaxSeq: maxSeq, Hash: row.ChainHash}, nil
	}
	row, err := s.queries.GetLedgerVerificationHead(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return Head{}, ErrMissingHead
	}
	if err != nil {
		return Head{}, err
	}
	return Head{Seq: row.Seq, MaxSeq: row.MaxSeq, Hash: row.ChainHash}, nil
}

// HashAt implements Source.
func (s *Store) HashAt(ctx context.Context, seq int64) ([]byte, error) {
	var (
		hash []byte
		err  error
	)
	if s.chain == ChainAudit {
		hash, err = s.queries.GetAuditLogChainHashBySeq(ctx, seq)
	} else {
		hash, err = s.queries.GetSecurityEventChainHashBySeq(ctx, seq)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownSeq
	}
	return hash, err
}

// Page implements Source.
func (s *Store) Page(ctx context.Context, after, through int64, limit int32) ([]Node, error) {
	if s.chain == ChainAudit {
		return s.auditPage(ctx, after, through, limit)
	}
	return s.ledgerPage(ctx, after, through, limit)
}

func (s *Store) auditPage(ctx context.Context, after, through int64, limit int32) ([]Node, error) {
	rows, err := s.queries.ListAuditLogChainForVerification(ctx, db.ListAuditLogChainForVerificationParams{
		AfterSeq: after, ThroughSeq: through, PageLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(rows))
	for _, row := range rows {
		node := Node{Seq: row.Seq, LeafHash: row.LeafHash, ChainHash: row.ChainHash}
		if row.PayloadPresent {
			record := auditRecordFromRow(row)
			node.Recompute = func() (audit.Digest, error) { return audit.LeafAudit(record) }
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func (s *Store) ledgerPage(ctx context.Context, after, through int64, limit int32) ([]Node, error) {
	rows, err := s.queries.ListSecurityLedgerChainForVerification(ctx, db.ListSecurityLedgerChainForVerificationParams{
		AfterSeq: after, ThroughSeq: through, PageLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(rows))
	for _, row := range rows {
		node := Node{Seq: row.Seq, LeafHash: row.LeafHash, ChainHash: row.ChainHash}
		if row.PayloadPresent {
			record := ledgerRecordFromRow(row)
			node.Recompute = func() (audit.Digest, error) { return audit.LeafLedger(record) }
		}
		if row.ErasureOperationID.Valid {
			op := row.ErasureOperationID.UUID.String()
			node.ErasureOperation = &op
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// The two projections must stay exhaustive: a column that is persisted but
// omitted here would be absent from the recomputed leaf, so it could be rewritten
// at will while verification still passed. The serializer's side of that contract
// is pinned by audit.TestSerializeLedgerCoversEveryField and its audit twin.

func auditRecordFromRow(row db.ListAuditLogChainForVerificationRow) audit.AuditRecord {
	rec := audit.AuditRecord{ID: row.EventID.String()}
	if row.ActorID.Valid {
		rec.ActorID = row.ActorID.UUID.String()
	}
	if row.ActorSpiffeID != nil {
		rec.ActorSPIFFEID = *row.ActorSpiffeID
	}
	if row.EventType != nil {
		rec.EventType = *row.EventType
	}
	if row.ActionStatus != nil {
		rec.ActionStatus = *row.ActionStatus
	}
	if row.ClientIp != nil {
		rec.ClientIP = *row.ClientIp
	}
	if row.UserAgent != nil {
		rec.UserAgent = *row.UserAgent
	}
	if row.Payload != nil {
		rec.Payload = *row.Payload
	}
	if row.Timestamp.Valid {
		rec.Timestamp = row.Timestamp.Time
	}
	return rec
}

func ledgerRecordFromRow(row db.ListSecurityLedgerChainForVerificationRow) audit.LedgerRecord {
	rec := audit.LedgerRecord{
		ID:                 row.EventID.String(),
		IdentityBlindIndex: row.IdentityBlindIndex,
		ClientIP:           row.ClientIp,
		IPSubnet:           row.IpSubnet,
		UserAgent:          row.UserAgent,
		DeviceFingerprint:  row.DeviceFingerprint,
		ClientID:           row.ClientID,
		Scope:              row.Scope,
	}
	if row.AccountRef.Valid {
		rec.AccountRef = row.AccountRef.UUID.String()
	}
	if row.BlindIndexVersion != nil {
		rec.BlindIndexVersion = *row.BlindIndexVersion
	}
	if row.EventType != nil {
		rec.EventType = *row.EventType
	}
	if row.Timestamp.Valid {
		rec.Timestamp = row.Timestamp.Time
	}
	if row.RetainUntil.Valid {
		rec.RetainUntil = row.RetainUntil.Time
	}
	return rec
}
