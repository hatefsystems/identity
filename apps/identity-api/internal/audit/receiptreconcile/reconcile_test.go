package receiptreconcile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func receiptEvidence(t *testing.T, signed bool) evidence {
	t.Helper()
	id := uuid.New()
	cutoff := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	spans := [][2]int64{{1, 3}, {7, 9}}
	hash, err := ledgerproof.SpanManifest(spans, 6, 10)
	if err != nil {
		t.Fatal(err)
	}
	env, err := audit.NewEnvelope(audit.Event{EventType: audit.EventLegalLedgerPurged, ActionStatus: audit.StatusSuccess,
		ActorSPIFFEID: audit.LedgerRetentionActorSPIFFEID,
		Payload: map[string]any{"operation_id": id.String(), "cutoff": audit.FormatChainTime(cutoff), "deleted_count": 6,
			"held_count": 0, "dry_run": false, "outcome": "purged", "highwater_seq": 10, "span_manifest_version": 1, "span_manifest_sha256": hash}}, id, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	e := evidence{id: id, spans: spans, erasedAt: []time.Time{cutoff, cutoff}, outbox: &env}
	if signed {
		rec := env.AuditRecord()
		leaf, err := audit.LeafAudit(rec)
		if err != nil {
			t.Fatal(err)
		}
		e.record, e.chainSeq, e.leaf = &rec, 5, leaf.Bytes()
	}
	return e
}

func rewrite(t *testing.T, e *evidence, mutate func(map[string]any)) {
	t.Helper()
	var content map[string]any
	if err := json.Unmarshal([]byte(e.outbox.Payload), &content); err != nil {
		t.Fatal(err)
	}
	mutate(content)
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	e.outbox.Payload = string(encoded)
	if e.record != nil {
		rec := e.outbox.AuditRecord()
		leaf, err := audit.LeafAudit(rec)
		if err != nil {
			t.Fatal(err)
		}
		e.record, e.leaf = &rec, leaf.Bytes()
	}
}

func TestReceiptAssuranceStates(t *testing.T) {
	last := int64(5)
	proof := ledgerproof.Result{Verified: true, Complete: true, LastSeq: &last}
	for _, tc := range []struct {
		name        string
		signed      bool
		mutate      func(*testing.T, *evidence)
		proof       ledgerproof.Result
		unavailable bool
		want        state
	}{
		{"pending", false, nil, proof, false, recordedPending},
		{"chained", true, nil, proof, false, chained},
		{"chain only retained body", true, func(_ *testing.T, e *evidence) { e.outbox = nil }, proof, false, chained},
		{"equivalent timezone representation", true, func(_ *testing.T, e *evidence) {
			e.record.Timestamp = e.record.Timestamp.In(time.FixedZone("database-local", 12600))
		}, proof, false, chained},
		{"missing intent", false, func(_ *testing.T, e *evidence) { e.outbox = nil }, proof, false, missingUnavailable},
		{"missing spans", false, func(_ *testing.T, e *evidence) { e.spans = nil }, proof, false, missingUnavailable},
		{"missing chained body", true, func(_ *testing.T, e *evidence) { e.record = nil }, proof, false, missingUnavailable},
		{"bad outbox", false, func(_ *testing.T, e *evidence) { e.badOutbox = true }, proof, false, invalid},
		{"oversized retained receipt", true, func(_ *testing.T, e *evidence) { e.badRecord = true }, proof, false, invalid},
		{"manifest tamper", true, func(t *testing.T, e *evidence) {
			rewrite(t, e, func(m map[string]any) { m["span_manifest_sha256"] = strings.Repeat("a", 64) })
		}, proof, false, invalid},
		{"upper case manifest", false, func(t *testing.T, e *evidence) {
			rewrite(t, e, func(m map[string]any) {
				m["span_manifest_sha256"] = strings.ToUpper(m["span_manifest_sha256"].(string))
			})
		}, proof, false, invalid},
		{"span tamper", true, func(_ *testing.T, e *evidence) { e.spans[1] = [2]int64{8, 10} }, proof, false, invalid},
		{"legacy", true, func(t *testing.T, e *evidence) {
			rewrite(t, e, func(m map[string]any) { delete(m, "span_manifest_version"); delete(m, "span_manifest_sha256") })
		}, proof, false, legacyUnbound},
		{"legacy pending", false, func(t *testing.T, e *evidence) {
			rewrite(t, e, func(m map[string]any) { delete(m, "span_manifest_version"); delete(m, "span_manifest_sha256") })
		}, proof, false, legacyUnbound},
		{"half manifest", true, func(t *testing.T, e *evidence) {
			rewrite(t, e, func(m map[string]any) { delete(m, "span_manifest_version") })
		}, proof, false, invalid},
		{"leaf mismatch", true, func(_ *testing.T, e *evidence) { e.leaf = audit.Genesis().Bytes() }, proof, false, invalid},
		{"outbox chain disagree", true, func(_ *testing.T, e *evidence) { e.record.Payload = "{}" }, proof, false, invalid},
		{"capped spans", false, func(_ *testing.T, e *evidence) { e.spansCapped = true }, proof, false, incomplete},
		{"partial uncovered proof", true, nil, ledgerproof.Result{Verified: true, LastSeq: new(int64)}, false, incomplete},
		{"partial covered proof", true, nil, ledgerproof.Result{Verified: true, LastSeq: &last}, false, chained},
		{"proof unavailable", true, nil, proof, true, incomplete},
		{"invalid proof", true, nil, ledgerproof.Result{}, false, invalid},
		{"pending independent of proof", false, nil, ledgerproof.Result{}, true, recordedPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := receiptEvidence(t, tc.signed)
			if tc.mutate != nil {
				tc.mutate(t, &e)
			}
			if got := classify(e, tc.proof, tc.unavailable); got != tc.want {
				t.Fatalf("state=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestHeldOnlyReceiptCommitsEmptyManifest(t *testing.T) {
	e := receiptEvidence(t, false)
	e.spans, e.erasedAt = nil, nil
	e.outbox.EventType = audit.EventLegalLedgerPurgeSkipped
	hash, _ := ledgerproof.SpanManifest(nil, 0, 10)
	rewrite(t, &e, func(m map[string]any) {
		m["deleted_count"] = 0
		m["held_count"] = 1
		m["outcome"] = "held"
		m["span_manifest_sha256"] = hash
	})
	if got := classify(e, ledgerproof.Result{}, true); got != recordedPending {
		t.Fatalf("held-only state=%v", got)
	}
}

func TestReceiptDecoderStrictAndLegacyFields(t *testing.T) {
	e := receiptEvidence(t, false)
	for _, payload := range []string{
		strings.Replace(e.outbox.Payload, `"deleted_count":6`, `"deleted_count":6,"deleted_count":6`, 1),
		strings.Replace(e.outbox.Payload, `"deleted_count":6`, `"Deleted_count":6`, 1),
		strings.Replace(e.outbox.Payload, `"dry_run":false`, `"dry_run":null`, 1),
		strings.Replace(e.outbox.Payload, `"span_manifest_version":1`, `"span_manifest_version":null`, 1),
		e.outbox.Payload + "{}", `[]`, strings.Repeat("x", 4097),
	} {
		if _, ok := decodeReceipt(payload); ok {
			t.Fatal("invalid receipt decoded")
		}
	}
}

type failingPool struct {
	tx       *failingTx
	opts     pgx.TxOptions
	deadline time.Time
}

func (p *failingPool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	p.opts = opts
	p.deadline, _ = ctx.Deadline()
	return p.tx, nil
}

type failingTx struct {
	pgx.Tx
	sql             string
	rollback        bool
	cleanupErr      error
	cleanupDeadline time.Time
}

func (t *failingTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	t.sql = sql
	return pgconn.CommandTag{}, errors.New("sensitive-database-detail")
}
func (t *failingTx) Rollback(ctx context.Context) error {
	t.rollback = true
	t.cleanupErr = ctx.Err()
	t.cleanupDeadline, _ = ctx.Deadline()
	return nil
}

func TestSnapshotOptionsReadOnlyDeadlineCleanupAndSanitizedError(t *testing.T) {
	for _, opts := range []Options{{0, 1}, {1001, 1}, {1, 0}, {1, 10001}} {
		if _, err := ReconcileSnapshot(context.Background(), &failingPool{}, opts); !errors.Is(err, ErrOptions) {
			t.Fatal("unbounded options accepted")
		}
	}
	tx := &failingTx{}
	pool := &failingPool{tx: tx}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := ReconcileSnapshot(ctx, pool, Options{1, 1})
	if !errors.Is(err, ErrDatabase) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unsanitized error %v", err)
	}
	if pool.opts.IsoLevel != pgx.RepeatableRead || pool.opts.AccessMode != pgx.ReadOnly || pool.deadline.IsZero() || !tx.rollback || tx.cleanupErr != nil || tx.cleanupDeadline.IsZero() {
		t.Fatal("unsafe snapshot/cleanup")
	}
	if !strings.Contains(tx.sql, "statement_timeout") || !strings.Contains(tx.sql, "lock_timeout") {
		t.Fatal("missing server bounds")
	}
}

type linkDB struct {
	db.DBTX
	head  ledgerproof.Head
	nodes []db.ListLedgerReceiptProofNodesRow
	pages int
}
type scanRow func(...any) error

func (r scanRow) Scan(out ...any) error { return r(out...) }
func (d *linkDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	return scanRow(func(out ...any) error {
		switch {
		case strings.Contains(sql, "GetAuditLogHead"):
			*out[0].(*int64) = d.head.Seq
			*out[1].(*[]byte) = d.head.Hash
			*out[2].(*bool) = !d.head.Invalid
		case strings.Contains(sql, "GetAuditLogHighWaterSeq"):
			*out[0].(*int64) = d.head.MaxSeq
		case strings.Contains(sql, "GetAuditLogChainHashBySeq"):
			for _, node := range d.nodes {
				if node.Seq == args[0].(int64) {
					*out[0].(*[]byte) = node.ChainHash
					return nil
				}
			}
			return pgx.ErrNoRows
		default:
			return errors.New("unexpected receipt query")
		}
		return nil
	})
}

type linkRows struct {
	pgx.Rows
	nodes []db.ListLedgerReceiptProofNodesRow
	index int
}

func (r *linkRows) Next() bool { r.index++; return r.index <= len(r.nodes) }
func (r *linkRows) Scan(out ...any) error {
	n := r.nodes[r.index-1]
	*out[0].(*int64) = n.Seq
	*out[1].(*[]byte) = n.LeafHash
	*out[2].(*[]byte) = n.ChainHash
	return nil
}
func (r *linkRows) Err() error { return nil }
func (r *linkRows) Close()     {}
func (d *linkDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "ListLedgerReceiptProofNodes") || strings.Contains(sql, "payload") {
		return nil, errors.New("unrelated narrative read")
	}
	d.pages++
	after, through, limit := args[0].(int64), args[1].(int64), args[2].(int32)
	var nodes []db.ListLedgerReceiptProofNodesRow
	for _, n := range d.nodes {
		if n.Seq > after && n.Seq <= through && len(nodes) < int(limit) {
			nodes = append(nodes, n)
		}
	}
	return &linkRows{nodes: nodes}, nil
}
func newLinkDB(count int) *linkDB {
	d := &linkDB{}
	previous := audit.Genesis()
	for i := 1; i <= count; i++ {
		leaf := audit.ChainAudit(audit.Genesis(), previous)
		previous = audit.ChainAudit(previous, leaf)
		d.nodes = append(d.nodes, db.ListLedgerReceiptProofNodesRow{Seq: int64(i), LeafHash: leaf.Bytes(), ChainHash: previous.Bytes()})
	}
	d.head = ledgerproof.Head{Seq: int64(count), MaxSeq: int64(count), Hash: previous.Bytes()}
	return d
}

func TestReceiptLinkageBoundedPagesAndPartialCoverage(t *testing.T) {
	for _, limit := range []int{1, 100, 101} {
		d := newLinkDB(101)
		result, err := verifyLinks(context.Background(), d, limit)
		if err != nil || !result.Verified || result.Checked != limit || result.LastSeq == nil || *result.LastSeq != int64(limit) || result.Complete != (limit == 101) {
			t.Fatalf("bounded linkage %+v %v", result, err)
		}
		if d.pages != (limit+99)/100 {
			t.Fatal("linkage query not100-node paginated")
		}
	}
}

func TestReceiptLinkageInvalidHeadAndCorruption(t *testing.T) {
	for _, mutate := range []func(*linkDB){
		func(d *linkDB) { d.head.Hash = audit.LedgerGenesis().Bytes() },
		func(d *linkDB) { d.head.Invalid = true },
		func(d *linkDB) { d.head.Seq++ },
		func(d *linkDB) { d.nodes[0].LeafHash = audit.Genesis().Bytes() },
	} {
		d := newLinkDB(3)
		mutate(d)
		result, err := verifyLinks(context.Background(), d, 10)
		if err != nil || result.Verified || result.Complete {
			t.Fatalf("corrupt linkage verified %+v %v", result, err)
		}
	}
	d := newLinkDB(0)
	result, err := verifyLinks(context.Background(), d, 10)
	if err != nil || !result.Verified || !result.Complete || d.pages != 0 {
		t.Fatal("initialized empty linkage not handled")
	}
	d.head.Hash = audit.LedgerGenesis().Bytes()
	result, err = verifyLinks(context.Background(), d, 10)
	if err != nil || result.Verified || result.Complete {
		t.Fatal("false genesis accepted on empty linkage")
	}
}
