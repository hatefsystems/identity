//go:build integration

package retention

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/receiptreconcile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func (f *workerFixture) hold(t *testing.T, conn workerExecutor, account uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x73}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(legalhold.Details{RecordID: id, AccountRef: account, Kind: legalhold.KindHold,
		Reason: "retention integration", RequestingAuthority: "fixture court", LegalBasis: "fixture legal claims"})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := enc.Encrypt(f.ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	workerExec(t, f.ctx, conn, `INSERT INTO public.legal_holds
(id,account_ref,details_encrypted,applied_by) VALUES($1,$2,$3,$4)`, id, account, sealed, uuid.New())
	return id
}

func (f *workerFixture) login(t *testing.T, kind string) *pgxpool.Pool {
	t.Helper()
	name := "retention_" + kind + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	quoted := pgx.Identifier{name}.Sanitize()
	password := uuid.NewString()
	workerExec(t, f.ctx, f.admin, "CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.admin.Exec(ctx, "DROP OWNED BY "+quoted); err != nil {
			t.Errorf("remove run-owned login grants: %v", err)
		}
		if _, err := f.admin.Exec(ctx, "DROP ROLE "+quoted); err != nil {
			t.Errorf("drop run-owned login: %v", err)
		}
	})
	workerExec(t, f.ctx, f.admin, "GRANT USAGE ON SCHEMA public TO "+quoted)
	switch kind {
	case "signer":
		workerExec(t, f.ctx, f.admin, "GRANT SELECT,INSERT ON public.audit_log_chain,public.security_ledger_chain,public.mvp_audit_logs,public.security_event_ledger TO "+quoted)
		workerExec(t, f.ctx, f.admin, "GRANT SELECT ON public.audit_log_head,public.security_ledger_head,public.security_ledger_erasures,public.users TO "+quoted)
		workerExec(t, f.ctx, f.admin, "GRANT UPDATE(id) ON public.users TO "+quoted)
		workerExec(t, f.ctx, f.admin, "GRANT USAGE ON SEQUENCE public.audit_log_chain_seq,public.security_ledger_chain_seq TO "+quoted)
		workerExec(t, f.ctx, f.admin, "GRANT EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) TO "+quoted)
	case "publisher":
		workerExec(t, f.ctx, f.admin, "GRANT SELECT ON public.event_outbox TO "+quoted)
		workerExec(t, f.ctx, f.admin, "GRANT UPDATE(published_at,attempts,next_attempt_at,last_error) ON public.event_outbox TO "+quoted)
		workerExec(t, f.ctx, f.admin, "ALTER TABLE public.event_outbox ENABLE ROW LEVEL SECURITY")
		predicate := "(admin_action AND subject='" + f.subject + "')"
		workerExec(t, f.ctx, f.admin, "CREATE POLICY retention_publisher_read ON public.event_outbox FOR SELECT TO "+quoted+" USING "+predicate)
		workerExec(t, f.ctx, f.admin, "CREATE POLICY retention_publisher_delivery ON public.event_outbox FOR UPDATE TO "+quoted+" USING "+predicate+" WITH CHECK "+predicate)
		workerExec(t, f.ctx, f.admin, "CREATE POLICY retention_purge_intent ON public.event_outbox FOR INSERT TO identity_ledger_purge WITH CHECK "+predicate)
	case "reconcile":
		workerExec(t, f.ctx, f.admin, "GRANT SELECT ON public.security_ledger_erasures,public.event_outbox,public.mvp_audit_logs,public.audit_log_chain,public.audit_log_head TO "+quoted)
		workerExec(t, f.ctx, f.admin, "CREATE POLICY retention_reconcile_read ON public.event_outbox FOR SELECT TO "+quoted+" USING (admin_action AND subject='"+f.subject+"')")
	default:
		t.Fatal("unknown fixture login kind")
	}
	cfg, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = name, password
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func waitWorker(t *testing.T, f *workerFixture, query string, want int, args ...any) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if f.count(t, query, args...) == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("bounded worker observation timed out")
		case <-ticker.C:
		}
	}
}

type receiptTracePool struct {
	pool *pgxpool.Pool
	t    *testing.T
}

func (p receiptTracePool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.pool.BeginTx(ctx, opts)
	return receiptTraceTx{Tx: tx, t: p.t}, err
}

type receiptTraceTx struct {
	pgx.Tx
	t *testing.T
}

func (t receiptTraceTx) trace(err error) {
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.t.Logf("receipt query failed SQLSTATE=%s", pgErr.Code)
		} else {
			t.t.Log("receipt query failed without PostgreSQL error response")
		}
	}
}
func (t receiptTraceTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := t.Tx.Exec(ctx, sql, args...)
	t.trace(err)
	return tag, err
}
func (t receiptTraceTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows, err := t.Tx.Query(ctx, sql, args...)
	t.trace(err)
	return rows, err
}

type receiptTraceRow struct {
	pgx.Row
	tx receiptTraceTx
}

func (r receiptTraceRow) Scan(out ...any) error {
	err := r.Row.Scan(out...)
	if !errors.Is(err, pgx.ErrNoRows) {
		r.tx.trace(err)
	}
	return err
}
func (t receiptTraceTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return receiptTraceRow{Row: t.Tx.QueryRow(ctx, sql, args...), tx: t}
}

func TestWorkerReceiptRealPipelinePendingRestartAndRedelivery(t *testing.T) {
	f := newWorkerFixture(t)
	f.seed(t, expired(t, uuid.New(), 400*24*time.Hour))
	workerExec(t, f.ctx, f.admin, "INSERT INTO public.audit_log_head VALUES(true,0,$1)", audit.Genesis().Bytes())
	if stats := f.run(t, 10, 100, false); stats.Deleted != 1 {
		t.Fatal("real worker did not erase")
	}
	reconcilePool := f.login(t, "reconcile")
	if err := receiptreconcile.ProbePrivileges(f.ctx, reconcilePool); err != nil {
		t.Fatal(err)
	}
	check := func(wantPending, wantChained int) {
		t.Helper()
		summary, err := receiptreconcile.ReconcileSnapshot(f.ctx, receiptTracePool{pool: reconcilePool, t: t}, receiptreconcile.Options{Limit: 10, ProofLimit: 100})
		if err != nil || summary.RecordedPending != wantPending || summary.Chained != wantChained || summary.Invalid != 0 || summary.Incomplete != 0 || !summary.InventoryComplete || !summary.ProofComplete {
			t.Fatalf("receipt pipeline assurance: %+v %v", summary, err)
		}
	}
	check(1, 0)
	publisherPool := f.login(t, "publisher")
	if err := adminaction.ProbePublisher(f.ctx, publisherPool, f.subject); err != nil {
		t.Fatal(err)
	}
	publisher, err := adminaction.NewPublisher(publisherPool, f.js, f.subject, adminaction.PublisherConfig{PublishTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// No stream exists: a real publisher outage keeps intent pending.
	if n, err := publisher.RunOnce(f.ctx); n != 0 || !errors.Is(err, adminaction.ErrPublish) {
		t.Fatalf("publisher outage: %d %v", n, err)
	}
	check(1, 0)
	stream := "RETENTION_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := natsjs.EnsureStream(f.ctx, f.js, natsjs.StreamOptions{Name: stream, Subjects: []string{f.subject}, MaxBytes: 1024 * 1024}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.js.DeleteStream(ctx, stream); err != nil {
			t.Errorf("delete run-owned stream: %v", err)
		}
	})
	consumer, err := natsjs.EnsureConsumer(f.ctx, f.js, stream, natsjs.ConsumerOptions{Durable: "receipt", FilterSubject: f.subject, AckWait: 45 * time.Second, MaxAckPending: 10, MaxDeliver: 5})
	if err != nil {
		t.Fatal(err)
	}
	signerPool := f.login(t, "signer")
	if err := signer.ProbePrivileges(f.ctx, signerPool); err != nil {
		t.Fatal(err)
	}
	store, err := signer.NewPoolStore(signerPool)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := signer.NewPgBatchTxOpener(signerPool)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := pglock.NewPgAdvisoryLocker(signerPool, pglock.AuditSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := signer.New(signer.Config{BatchSize: 1, FlushInterval: 50 * time.Millisecond, LedgerRetention: 365 * 24 * time.Hour}, store, opener, consumer,
		signer.WithAdvisoryLocker(locker), signer.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	// Pending receipt is legitimate at restart, and the purge lifetime lock must
	// not collide with signer/audit append coordination.
	lifetime, err := f.worker.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	workerExec(t, f.ctx, lifetime, "SELECT pg_advisory_lock($1)", pglock.SecurityLedgerPurgeKey)
	defer func() {
		_, _ = lifetime.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", pglock.SecurityLedgerPurgeKey)
		lifetime.Release()
	}()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.RunUntilDone(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("signer shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("signer did not stop")
		}
	})
	workerExec(t, f.ctx, f.admin, "UPDATE public.event_outbox SET next_attempt_at=statement_timestamp()")
	if n, err := publisher.RunOnce(f.ctx); err != nil || n != 1 {
		t.Fatalf("publisher: %d %v", n, err)
	}
	waitWorker(t, f, "SELECT count(*) FROM public.audit_log_chain", 1)
	check(0, 1)
	var raw string
	if err := f.admin.QueryRow(f.ctx, "SELECT payload::text FROM public.event_outbox").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	// New broker message, same durable event ID: signer dedup, not the finite
	// JetStream duplicate window, must suppress the second Class C receipt.
	if _, err := f.js.Publish(f.ctx, f.subject, []byte(raw), jetstream.WithMsgID(uuid.NewString())); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := consumer.Info(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.Delivered.Stream >= 2 && info.NumAckPending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("signer did not acknowledge redelivery")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := f.count(t, "SELECT count(*) FROM public.audit_log_chain"); got != 1 {
		t.Fatal("redelivery chained duplicate receipt")
	}
	check(0, 1)
	account := uuid.New()
	seeded := f.seed(t, expired(t, account, 400*24*time.Hour))
	f.hold(t, f.admin, account)
	result, err := f.store.Purge(f.ctx, f.boundary(t), []Candidate{seeded[0].Candidate}, false)
	if err != nil || result.Held != 1 || result.Deleted != 0 {
		t.Fatalf("held-only intent: %+v %v", result, err)
	}
	check(1, 1)
	capped, err := receiptreconcile.ReconcileSnapshot(f.ctx, reconcilePool, receiptreconcile.Options{Limit: 1, ProofLimit: 100})
	if err != nil || capped.Inspected != 1 || !capped.InventoryCapped || capped.InventoryComplete {
		t.Fatalf("inventory cap: %+v %v", capped, err)
	}
	if n, err := publisher.RunOnce(f.ctx); err != nil || n != 1 {
		t.Fatalf("held receipt publisher: %d %v", n, err)
	}
	waitWorker(t, f, "SELECT count(*) FROM public.audit_log_chain", 2)
	check(0, 2)
	partial, err := receiptreconcile.ReconcileSnapshot(f.ctx, reconcilePool, receiptreconcile.Options{Limit: 10, ProofLimit: 1})
	if err != nil || partial.Chained != 1 || partial.Incomplete != 1 || !partial.ProofVerified || partial.ProofComplete || partial.ProofChecked != 1 || !partial.InventoryComplete {
		t.Fatalf("partial proof falsely certified uncovered receipt: %+v %v", partial, err)
	}
	var original audit.Envelope
	if err := json.Unmarshal([]byte(raw), &original); err != nil {
		t.Fatal(err)
	}
	var receiptSeq int64
	if err := f.admin.QueryRow(f.ctx, "SELECT seq FROM public.audit_log_chain WHERE event_id=$1", original.EventID).Scan(&receiptSeq); err != nil {
		t.Fatal(err)
	}
	// Corrupt an originally empty user agent without changing its signed leaf.
	// Bounded projections must flag corruption, never replace it with valid ''.
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.mvp_audit_logs WHERE seq=$1", receiptSeq)
	workerExec(t, f.ctx, f.admin, `INSERT INTO public.mvp_audit_logs
(seq,actor_id,actor_spiffe_id,event_type,action_status,client_ip,user_agent,payload,timestamp)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, receiptSeq, original.ActorID, original.ActorSPIFFEID, original.EventType, original.ActionStatus, original.ClientIP, strings.Repeat("x", 8192), original.Payload, original.OccurredAt)
	corrupt, err := receiptreconcile.ReconcileSnapshot(f.ctx, reconcilePool, receiptreconcile.Options{Limit: 10, ProofLimit: 100})
	if err != nil || corrupt.Invalid != 1 || corrupt.Chained != 1 || !corrupt.ProofVerified || !corrupt.ProofComplete {
		t.Fatalf("oversized corruption hidden by bounded projection: %+v %v", corrupt, err)
	}
	assure := func(chained, legacy, missing, invalid, proofNodes int) {
		t.Helper()
		summary, err := receiptreconcile.ReconcileSnapshot(f.ctx, reconcilePool, receiptreconcile.Options{Limit: 10, ProofLimit: 100})
		if err != nil || summary.Inspected != chained+legacy+missing+invalid || summary.Chained != chained ||
			summary.LegacyUnbound != legacy || summary.MissingUnavailable != missing || summary.Invalid != invalid ||
			summary.RecordedPending != 0 || summary.Incomplete != 0 || !summary.InventoryComplete || summary.InventoryCapped ||
			!summary.ProofVerified || !summary.ProofComplete || summary.ProofChecked != proofNodes {
			t.Fatalf("real reader receipt classification: %+v %v", summary, err)
		}
	}
	stageReceipt := func(change func(map[string]json.RawMessage)) audit.Envelope {
		t.Helper()
		seeded := f.seed(t, expired(t, uuid.New(), 400*24*time.Hour))
		// This pipeline already owns the purge lifetime lease. Execute its real
		// batch rather than start a second service that must report overlap.
		result, err := f.store.Purge(f.ctx, f.boundary(t), []Candidate{seeded[0].Candidate}, false)
		if err != nil || result.Deleted != 1 {
			t.Fatalf("real worker did not create fixture receipt intent: %+v %v", result, err)
		}
		var wire string
		if err := f.admin.QueryRow(f.ctx, "SELECT payload FROM public.event_outbox WHERE published_at IS NULL").Scan(&wire); err != nil {
			t.Fatal(err)
		}
		var receipt audit.Envelope
		if err := json.Unmarshal([]byte(wire), &receipt); err != nil {
			t.Fatal(err)
		}
		var content map[string]json.RawMessage
		if err := json.Unmarshal([]byte(receipt.Payload), &content); err != nil {
			t.Fatal(err)
		}
		// Owner-driven fixtures alter only NEW, not-yet-signed intent. Existing
		// signed history is never upgraded, re-signed or retrocertified here.
		change(content)
		payload, err := json.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}
		receipt.Payload = string(payload)
		encoded, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		workerExec(t, f.ctx, f.admin, "UPDATE public.event_outbox SET payload=$2 WHERE id=$1", receipt.EventID, string(encoded))
		return receipt
	}
	tampered := stageReceipt(func(content map[string]json.RawMessage) {
		content["span_manifest_sha256"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
	})
	assure(1, 0, 0, 2, 2)
	if n, err := publisher.RunOnce(f.ctx); err != nil || n != 1 {
		t.Fatalf("tampered fixture receipt publication: %d %v", n, err)
	}
	waitWorker(t, f, "SELECT count(*) FROM public.audit_log_chain", 3)
	var tamperedLeaf []byte
	if err := f.admin.QueryRow(f.ctx, "SELECT leaf_hash FROM public.audit_log_chain WHERE event_id=$1", tampered.EventID).Scan(&tamperedLeaf); err != nil {
		t.Fatal(err)
	}
	expectedLeaf, err := audit.LeafAudit(tampered.AuditRecord())
	if err != nil || !bytes.Equal(tamperedLeaf, expectedLeaf.Bytes()) {
		t.Fatal("manifest corruption fixture did not retain a valid signed leaf")
	}
	// Manifest mismatch is invalid even with a valid receipt leaf and Class C
	// linkage, rather than merely because unsigned intent differs from its node.
	assure(1, 0, 0, 2, 3)
	legacy := stageReceipt(func(content map[string]json.RawMessage) {
		delete(content, "span_manifest_version")
		delete(content, "span_manifest_sha256")
	})
	assure(1, 1, 0, 2, 3)
	if n, err := publisher.RunOnce(f.ctx); err != nil || n != 1 {
		t.Fatalf("historical-format fixture receipt publication: %d %v", n, err)
	}
	waitWorker(t, f, "SELECT count(*) FROM public.audit_log_chain", 4)
	readLegacy := func() (string, []byte, []byte, []byte) {
		t.Helper()
		var payload string
		var leaf, chain, head []byte
		if err := f.admin.QueryRow(f.ctx, `SELECT l.payload,c.leaf_hash,c.chain_hash,h.chain_hash
FROM public.audit_log_chain c JOIN public.mvp_audit_logs l ON l.seq=c.seq
CROSS JOIN public.audit_log_head h WHERE c.event_id=$1 AND h.singleton`, legacy.EventID).Scan(&payload, &leaf, &chain, &head); err != nil {
			t.Fatal(err)
		}
		return payload, leaf, chain, head
	}
	legacyPayload, legacyLeaf, legacyChain, legacyHead := readLegacy()
	expectedLeaf, err = audit.LeafAudit(legacy.AuditRecord())
	if err != nil || legacyPayload != legacy.Payload || !bytes.Equal(legacyLeaf, expectedLeaf.Bytes()) {
		t.Fatal("historical-format receipt fixture bytes do not match their signed leaf")
	}
	assure(1, 1, 0, 2, 4)
	// Delivery cleanup cannot upgrade the retained historical receipt into a
	// manifest-bound one. The reader must classify its retained body alone.
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.event_outbox WHERE id=$1", legacy.EventID)
	assure(1, 1, 0, 2, 4)
	// Explicit owner-driven corruption removes retained material but never chain
	// nodes, heads or erasure annotations, and never disables evidence guards.
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.mvp_audit_logs WHERE event_type=$1", audit.EventLegalLedgerPurgeSkipped)
	assure(0, 1, 1, 2, 4) // Chained held-only body absent, durable intent retained.
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.mvp_audit_logs WHERE seq=$1", receiptSeq)
	workerExec(t, f.ctx, f.admin, "DELETE FROM public.event_outbox WHERE id=$1", original.EventID)
	assure(0, 1, 2, 1, 4) // Both bodies absent; erasure operation still discoverable.
	payloadAfter, leafAfter, chainAfter, headAfter := readLegacy()
	if payloadAfter != legacyPayload || !bytes.Equal(leafAfter, legacyLeaf) ||
		!bytes.Equal(chainAfter, legacyChain) || !bytes.Equal(headAfter, legacyHead) {
		t.Fatal("read-only reconciliation rewrote historical payload, leaf, chain or head")
	}
}

func TestWorkerCutoffHighwaterIndependentHoldsAndHeldDryRun(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	cutoff := audit.NormalizeChainTime(time.Now())
	seeded := f.seed(t, workerLedgerRecord(account, cutoff.Add(-time.Microsecond)), workerLedgerRecord(account, cutoff))
	b := Boundary{Cutoff: cutoff, ThroughSeq: seeded[1].Seq}
	f.seed(t, workerLedgerRecord(account, cutoff.Add(-time.Hour))) // Late/backdated beyond fixed highwater.
	first, second := f.hold(t, f.admin, account), f.hold(t, f.admin, account)
	workerExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false,released_at=statement_timestamp(),released_by=$2 WHERE id=$1", first, uuid.New())
	result, err := f.store.Purge(f.ctx, b, []Candidate{seeded[0].Candidate}, true)
	if err != nil || result.Held != 1 || result.Deleted != 0 {
		t.Fatalf("independent hold dry-run: %+v %v", result, err)
	}
	f.assertState(t, 3, 0, 0)
	workerExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false,released_at=statement_timestamp(),released_by=$2 WHERE id=$1", second, uuid.New())
	candidates, err := f.store.Candidates(f.ctx, b, Candidate{}, 10)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("strict cutoff/highwater: %d %v", len(candidates), err)
	}
	result, err = f.store.Purge(f.ctx, b, candidates, false)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("purge exact bound: %+v %v", result, err)
	}
	f.assertState(t, 2, 1, 1)
}

func TestWorkerHoldLockWaitRechecksFreshSnapshot(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	seeded := f.seed(t, expired(t, account, 400*24*time.Hour))
	b := f.boundary(t)
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := pglock.LockAccount(f.ctx, tx, account); err != nil {
		t.Fatal(err)
	}
	f.hold(t, tx, account)
	type outcome struct {
		result BatchResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := f.store.Purge(f.ctx, b, []Candidate{seeded[0].Candidate}, false)
		done <- outcome{result, err}
	}()
	waitWorker(t, f, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, 1, f.appName)
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.err != nil || result.result.Held != 1 || result.result.Deleted != 0 {
			t.Fatalf("post-wait stale hold snapshot: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("purge did not resume")
	}
	f.assertState(t, 1, 0, 1)
}

func TestWorkerCorruptCandidateAndReceiptInsertRollback(t *testing.T) {
	for _, phase := range []string{"corrupt", "erasure", "outbox"} {
		t.Run(phase, func(t *testing.T) {
			f := newWorkerFixture(t)
			account := uuid.New()
			rec := expired(t, account, 400*24*time.Hour)
			seeded := f.seed(t, rec)
			b := f.boundary(t)
			if phase == "corrupt" {
				// Simulate pre-existing corruption using ordinary owner DELETE/INSERT,
				// without disarming immutable or append-only guards.
				workerExec(t, f.ctx, f.admin, "DELETE FROM public.security_event_ledger WHERE seq=$1", seeded[0].Seq)
				workerExec(t, f.ctx, f.admin, `INSERT INTO public.security_event_ledger(seq,account_ref,blind_index_version,event_type,timestamp,retain_until)
VALUES($1,$2,$3,'corrupted',$4,$5)`, seeded[0].Seq, account, rec.BlindIndexVersion, rec.Timestamp, rec.RetainUntil)
			} else {
				table := "security_ledger_erasures"
				if phase == "outbox" {
					table = "event_outbox"
				}
				workerExec(t, f.ctx, f.admin, `CREATE FUNCTION public.retention_fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rejected'; END $$`)
				workerExec(t, f.ctx, f.admin, "CREATE TRIGGER retention_fixture_reject BEFORE INSERT ON public."+table+" FOR EACH ROW EXECUTE FUNCTION public.retention_fixture_reject()")
			}
			if _, err := f.store.Purge(f.ctx, b, []Candidate{seeded[0].Candidate}, false); err == nil {
				t.Fatal("invalid batch committed")
			}
			f.assertState(t, 1, 0, 0)
		})
	}
}

func TestWorkerPurgeThenHoldObservedLockWait(t *testing.T) {
	f := newWorkerFixture(t)
	account := uuid.New()
	seeded := f.seed(t, expired(t, account, 400*24*time.Hour))
	b := f.boundary(t)
	blocker, err := f.admin.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	const pauseKey int64 = 5299981
	workerExec(t, f.ctx, blocker, "SELECT pg_advisory_lock($1)", pauseKey)
	defer func() { _, _ = blocker.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", pauseKey) }()
	// Pause AFTER DELETE under the account lock without bypassing evidence guards.
	workerExec(t, f.ctx, f.admin, `CREATE FUNCTION public.retention_fixture_pause() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock(5299981); RETURN NEW; END $$`)
	workerExec(t, f.ctx, f.admin, "CREATE TRIGGER retention_fixture_pause BEFORE INSERT ON public.security_ledger_erasures FOR EACH ROW EXECUTE FUNCTION public.retention_fixture_pause()")
	purged := make(chan error, 1)
	go func() { _, err := f.store.Purge(f.ctx, b, []Candidate{seeded[0].Candidate}, false); purged <- err }()
	waitWorker(t, f, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, 1, f.appName)
	holdTx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holdTx.Rollback(context.Background()) }()
	workerExec(t, f.ctx, holdTx, "SET LOCAL application_name='retention-hold-order-observation'")
	held := make(chan error, 1)
	go func() { held <- pglock.LockAccount(f.ctx, holdTx, account) }()
	waitWorker(t, f, `SELECT count(*) FROM pg_stat_activity WHERE application_name='retention-hold-order-observation' AND wait_event_type='Lock'`, 1)
	workerExec(t, f.ctx, blocker, "SELECT pg_advisory_unlock($1)", pauseKey)
	select {
	case err := <-purged:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("purge did not commit")
	}
	select {
	case err := <-held:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hold did not acquire after purge")
	}
	f.hold(t, holdTx, account)
	if err := holdTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.assertState(t, 0, 1, 1)
}

func TestWorkerSimultaneousBatchesEraseOnce(t *testing.T) {
	f := newWorkerFixture(t)
	seeded := f.seed(t, expired(t, uuid.New(), 400*24*time.Hour))
	b := f.boundary(t)
	type outcome struct {
		result BatchResult
		err    error
	}
	done := make(chan outcome, 2)
	for range 2 {
		go func() {
			result, err := f.store.Purge(f.ctx, b, []Candidate{seeded[0].Candidate}, false)
			done <- outcome{result, err}
		}()
	}
	deleted := 0
	for range 2 {
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatal(got.err)
			}
			deleted += got.result.Deleted
		case <-time.After(5 * time.Second):
			t.Fatal("simultaneous purge did not finish")
		}
	}
	if deleted != 1 {
		t.Fatalf("simultaneous deleted=%d", deleted)
	}
	f.assertState(t, 0, 1, 1)
}

type lostCommitAckPool struct {
	*pgxpool.Pool
	commits int
}

func (p *lostCommitAckPool) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return lostCommitAckTx{Tx: tx, pool: p}, nil
}

type lostCommitAckTx struct {
	pgx.Tx
	pool *lostCommitAckPool
}

func (t lostCommitAckTx) Commit(ctx context.Context) error {
	if err := t.Tx.Commit(ctx); err != nil {
		return err
	}
	t.pool.commits++
	// Real PostgreSQL committed durably. Simulate loss of its reply at the client
	// boundary; this is not an actual socket fault or a fabricated database write.
	return errors.New("fixture: COMMIT acknowledgment transport lost")
}

func TestWorkerRealUncertainCommitReceiptReconciliation(t *testing.T) {
	f := newWorkerFixture(t)
	f.seed(t, expired(t, uuid.New(), 400*24*time.Hour))
	workerExec(t, f.ctx, f.admin, "INSERT INTO public.audit_log_head VALUES(true,0,$1)", audit.Genesis().Bytes())
	wrapped := &lostCommitAckPool{Pool: f.worker}
	f.store.pool = wrapped
	locker, err := pglock.NewPgAdvisoryLocker(f.worker, pglock.SecurityLedgerPurgeKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Config{BatchSize: 1, MaxRows: 10, Timeout: 15 * time.Second}, f.store, locker, nil)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := service.RunOnce(f.ctx)
	if !errors.Is(err, ErrUncertain) || stats.Deleted != 0 || stats.Uncertain != 1 || stats.Failed != 0 || wrapped.commits != 1 {
		t.Fatalf("lost ack was counted/retried: %+v %v commits=%d", stats, err, wrapped.commits)
	}
	// Separate credentials/snapshot resolve the durable evidence, rather than
	// retrying the ambiguous purge or trusting a success count from the client.
	f.assertState(t, 0, 1, 1)
	reader := f.login(t, "reconcile")
	if err := receiptreconcile.ProbePrivileges(f.ctx, reader); err != nil {
		t.Fatal(err)
	}
	// Unrelated unparseable megabyte TEXT must be skipped before JSON parsing.
	workerExec(t, f.ctx, f.admin, `INSERT INTO public.event_outbox(id,subject,payload,admin_action)
VALUES($1,$2,$3,true)`, uuid.New(), f.subject, strings.Repeat("x", 1024*1024))
	summary, err := receiptreconcile.ReconcileSnapshot(f.ctx, reader, receiptreconcile.Options{Limit: 10, ProofLimit: 100})
	if err != nil || summary.Inspected != 1 || summary.RecordedPending != 1 || summary.Chained != 0 || summary.Invalid != 0 || summary.Incomplete != 0 || !summary.InventoryComplete || !summary.ProofComplete {
		t.Fatalf("committed ambiguous intent not reconciled: %+v %v", summary, err)
	}
	if wrapped.commits != 1 {
		t.Fatal("reconciliation repeated a purge transaction")
	}
}
