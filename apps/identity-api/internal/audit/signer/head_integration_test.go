//go:build integration

package signer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Startup verifies the entire ledger, so signer tests cannot share historical
// rows intentionally corrupted by other integration suites. Only a disposable
// integration DATABASE_URL with CREATE DATABASE authority may run this fixture.
func isolatedSignerDatabase(t *testing.T, dsn string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	name := "signer_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create disposable signer database: %v", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		conn, err := pgx.Connect(cleanup, dsn)
		if err != nil {
			t.Errorf("connect for disposable database cleanup: %v", err)
			return
		}
		defer func() { _ = conn.Close(cleanup) }()
		if _, err := conn.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop disposable signer database: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		parsed.Path = "/" + name
		params := parsed.Query()
		params.Del("dbname")
		parsed.RawQuery = params.Encode()
		return parsed.String()
	}
	return dsn + " dbname=" + name
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func provisionSignerFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	// v2 bootstrap is just the two heads and the receipt subject. There is no
	// maintenance-owner role to create and no SECURITY DEFINER routine to re-own,
	// because erasure is an ordinary DELETE controlled by table privilege.
	//
	// Both heads are seeded with their derived genesis digest. The CHECK
	// constraints reject anything else at seq 0, so this is also an assertion that
	// the migration and internal/audit agree about the canonical format.
	// One statement per Exec: pgx prepares any statement carrying parameters, and
	// a prepared statement cannot hold multiple commands.
	if _, err := pool.Exec(ctx,
		"INSERT INTO public.security_ledger_head(singleton,seq,chain_hash) VALUES (true,0,$1)",
		audit.LedgerGenesis().Bytes()); err != nil {
		t.Fatalf("explicit ledger head bootstrap: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"INSERT INTO public.audit_log_head(singleton,seq,chain_hash) VALUES (true,0,$1)",
		audit.AuditGenesis().Bytes()); err != nil {
		t.Fatalf("explicit audit head bootstrap: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"INSERT INTO public.security_ledger_retention_settings(singleton,audit_subject) VALUES (true,'identity.audit.logs')"); err != nil {
		t.Fatalf("retention subject provisioning: %v", err)
	}
}

func signerFixture(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" || os.Getenv("REQUIRE_RETENTION_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required")
		}
		t.Skip("DATABASE_URL is not set")
	}
	dsn = isolatedSignerDatabase(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	migrationDB, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migrationDB.Close() }()
	if err := migrate.Up(ctx, migrationDB); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	provisionSignerFixture(t, ctx, pool)
	return ctx, pool
}

type integrationSignerMessage struct {
	jetstream.Msg
	body                     []byte
	acked, naked, terminated bool
}

func (m *integrationSignerMessage) Data() []byte { return m.body }
func (m *integrationSignerMessage) Metadata() (*jetstream.MsgMetadata, error) {
	return nil, errors.New("no metadata")
}
func (m *integrationSignerMessage) Ack() error                       { m.acked = true; return nil }
func (m *integrationSignerMessage) NakWithDelay(time.Duration) error { m.naked = true; return nil }

// TermWithReason is how an undecodable message is settled: the quarantine record
// is durable, so redelivering the message forever would only re-quarantine it.
// The fixture has to implement it, or a quarantine path reaches the embedded nil
// interface instead of being observed.
func (m *integrationSignerMessage) TermWithReason(string) error { m.terminated = true; return nil }

type integrationSignerBatch struct{ messages chan jetstream.Msg }

func (b integrationSignerBatch) Messages() <-chan jetstream.Msg { return b.messages }
func (b integrationSignerBatch) Error() error                   { return nil }

type integrationSignerFetcher struct {
	msgs   []*integrationSignerMessage
	cancel context.CancelFunc
}

func (f *integrationSignerFetcher) Fetch(_ int, _ ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	ch := make(chan jetstream.Msg, len(f.msgs))
	if len(f.msgs) == 0 {
		f.cancel()
	}
	for _, msg := range f.msgs {
		ch <- msg
	}
	f.msgs = nil
	close(ch)
	return integrationSignerBatch{messages: ch}, nil
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func runSignerFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, envs ...audit.Envelope) error {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fetcher := &integrationSignerFetcher{cancel: cancel}
	var messages []*integrationSignerMessage
	for _, env := range envs {
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		msg := &integrationSignerMessage{body: raw}
		fetcher.msgs = append(fetcher.msgs, msg)
		messages = append(messages, msg)
	}
	store, err := signer.NewPoolStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := signer.NewPgBatchTxOpener(pool)
	if err != nil {
		t.Fatal(err)
	}
	locker, err := pglock.NewPgAdvisoryLocker(pool, pglock.AuditSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.New(signer.Config{BatchSize: 10, FlushInterval: time.Millisecond, LedgerRetention: 365 * 24 * time.Hour}, store, opener, fetcher, signer.WithAdvisoryLocker(locker))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RunUntilDone(ctx); err != nil {
		return err
	}
	for _, msg := range messages {
		// A committed batch settles every message, either by acking a signed event
		// or by terminating an undecodable one. A nak means the batch did not commit.
		if msg.naked || (!msg.acked && !msg.terminated) {
			return errors.New("batch did not commit and settle every message")
		}
	}
	return nil
}

func signerLedgerEnvelope() audit.Envelope {
	return audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.Nil.String(),
		OccurredAt: time.Now().UTC().Add(-2 * 365 * 24 * time.Hour), EventType: audit.EventLoginSucceeded,
		ActionStatus: audit.StatusSuccess, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}}
}

// purgeSignerFixture erases the payloads at the given sequences exactly as the
// retention worker does: delete the payload, record the span, leave the chain
// node and the head untouched.
//
//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func purgeSignerFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, seqs []int64) {
	t.Helper()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout='15s'"); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockLedger(ctx, tx); err != nil {
		t.Fatal(err)
	}
	tag, err := tx.Exec(ctx, "DELETE FROM public.security_event_ledger WHERE seq = ANY($1::bigint[])", seqs)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != int64(len(seqs)) {
		t.Fatalf("erased %d payloads, want %d", tag.RowsAffected(), len(seqs))
	}
	operation := uuid.New()
	for _, seq := range seqs {
		if _, err := tx.Exec(ctx, `INSERT INTO public.security_ledger_erasures
(first_seq,last_seq,operation_id,erased_at) VALUES($1,$1,$2,statement_timestamp())`, seq, operation); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestSignerAppendsAfterRetentionIntegration is the interaction the whole split
// exists to make safe: the signer keeps appending to a chain whose payloads have
// been erased, and the chain stays verifiable from genesis throughout.
//
// Under v1 this was the hardest case in the system. Erasure removed chain links,
// so the signer had to reconstruct its tip from a mixture of surviving rows and
// checkpoint terminal digests, and "all payloads erased" was a distinct state
// that needed compaction to stay appendable. None of that applies now: the chain
// table is untouched by retention, so the signer's tip is simply the head.
func TestSignerAppendsAfterRetentionIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	first, second, third := signerLedgerEnvelope(), signerLedgerEnvelope(), signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, first, second, third); err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)

	headBefore, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := q.ListSecurityLedgerChainForVerification(ctx, db.ListSecurityLedgerChainForVerificationParams{
		ThroughSeq: headBefore.Seq, PageLimit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("chain nodes = %d, want 3", len(nodes))
	}

	// Erase the middle payload, then append again.
	purgeSignerFixture(t, ctx, pool, []int64{nodes[1].Seq})
	assertLedgerChainVerifies(t, ctx, pool)

	fourth := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, fourth); err != nil {
		t.Fatalf("signer refused to append over an erased span: %v", err)
	}
	assertLedgerChainVerifies(t, ctx, pool)

	// Now erase every remaining payload. The head must not move, and the signer
	// must still be able to append.
	headMid, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := pool.Query(ctx, "SELECT seq FROM public.security_event_ledger ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int64
	for remaining.Next() {
		var seq int64
		if err := remaining.Scan(&seq); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	remaining.Close()
	purgeSignerFixture(t, ctx, pool, seqs)

	headAfter, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if headAfter.Seq != headMid.Seq || !bytes.Equal(headAfter.ChainHash, headMid.ChainHash) {
		t.Fatal("erasing every payload moved the chain head")
	}
	if !headAfter.StateValid {
		t.Fatal("a fully erased ledger reports an invalid head; the signer could never append again")
	}
	assertLedgerChainVerifies(t, ctx, pool)

	// Replay of an already-signed event must still be suppressed, even though its
	// payload is gone. This is exactly why the dedupe key lives on the chain node.
	if err := runSignerFixture(t, ctx, pool, third); err != nil {
		t.Fatal(err)
	}
	if got := countSigner(t, ctx, pool, "SELECT count(*) FROM public.security_event_ledger"); got != 0 {
		t.Fatalf("a redelivered message resurrected an erased payload: %d rows", got)
	}

	// And a genuinely new event still appends on top.
	fifth := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, fifth); err != nil {
		t.Fatal(err)
	}
	final, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !final.StateValid || final.Seq <= headAfter.Seq {
		t.Fatalf("append after a full erasure did not advance the head: %+v", final)
	}
	assertLedgerChainVerifies(t, ctx, pool)

	// Restart must accept the resulting state.
	if err := runSignerFixture(t, ctx, pool); err != nil {
		t.Fatalf("restart over an erased chain: %v", err)
	}
}

// TestSignerStartupRejectsMissingStateIntegration keeps startup failing closed.
func TestSignerStartupRejectsMissingStateIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	if err := runSignerFixture(t, ctx, pool, signerLedgerEnvelope(), signerLedgerEnvelope()); err != nil {
		t.Fatal(err)
	}

	// An erased payload with no erasure record is indistinguishable from a
	// deletion, so the signer must refuse to extend the chain.
	if _, err := pool.Exec(ctx, "DELETE FROM public.security_event_ledger WHERE seq=(SELECT min(seq) FROM public.security_event_ledger)"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool); !errors.Is(err, signer.ErrLedgerStateInvalid) {
		t.Fatalf("unexplained missing payload accepted at startup: %v", err)
	}

	// A missing head must never be treated as genesis.
	if _, err := pool.Exec(ctx, "DELETE FROM public.security_ledger_head"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool); !errors.Is(err, signer.ErrLedgerStateInvalid) {
		t.Fatalf("missing head restarted at genesis: %v", err)
	}
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func countSigner(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// assertLedgerChainVerifies replays the whole ledger chain through the production
// verifier, so these tests assert the same property an operator's
// GET /admin/ledger/verify would report.
//
//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func assertLedgerChainVerifies(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	params := ledgerproof.Params{Chain: ledgerproof.ChainLedger, Limit: 100}
	for {
		result, err := ledgerproof.VerifySnapshot(ctx, pool, params)
		if err != nil {
			t.Fatalf("verify ledger chain: %v", err)
		}
		if !result.Verified {
			reason := "<nil>"
			if result.FailureReason != nil {
				reason = *result.FailureReason
			}
			t.Fatalf("ledger chain failed verification at seq %v: %s", result.BrokenAtSeq, reason)
		}
		next, ok := result.NextParams(params)
		if !ok {
			if !result.Complete {
				t.Fatal("verification stopped before completing")
			}
			return
		}
		params = next
	}
}

// TestSignerSequenceResetCannotCommitBelowHeadIntegration covers an operator or
// restore mistake that rewinds the chain sequence. The signer allocates positions
// from that sequence, so a rewind would make it try to write nodes at positions
// the head has already passed — producing a fork that nothing could repair,
// because the chain table forbids UPDATE and DELETE outright.
//
// advance_chain_head's expected-seq check is what stops it.
func TestSignerSequenceResetCannotCommitBelowHeadIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	// Consume unused values first, so a rewind lands in an allocation gap and
	// cannot rely on a duplicate-key error to protect the chain.
	if _, err := pool.Exec(ctx, "SELECT nextval('public.security_ledger_chain_seq'), nextval('public.security_ledger_chain_seq')"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool, signerLedgerEnvelope()); err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	head, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != 3 {
		t.Fatalf("gap fixture: head seq = %d, want 3", head.Seq)
	}

	if _, err := pool.Exec(ctx, "SELECT setval('public.security_ledger_chain_seq',1,false)"); err != nil {
		t.Fatal(err)
	}
	bad := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, bad); err == nil {
		t.Fatal("a batch allocated below the head was acknowledged")
	}

	after, err := q.GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Seq != head.Seq || !bytes.Equal(after.ChainHash, head.ChainHash) {
		t.Fatalf("sequence reset changed the logical head: %+v -> %+v", head, after)
	}

	// Neither chain may contain the rejected event: the batch is one transaction,
	// so a partial commit would leave the audit chain counting an event the ledger
	// chain never recorded.
	var leaked bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM public.security_ledger_chain WHERE event_id=$1)
		     OR EXISTS(SELECT 1 FROM public.audit_log_chain WHERE event_id=$1)`, bad.EventID).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("a failed head advancement still committed one of the chains")
	}
	assertLedgerChainVerifies(t, ctx, pool)
}

func TestSignerLedgerWaitUsesFreshReadCommittedHeadIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	blocker, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if err := pglock.LockLedger(ctx, blocker); err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	opener, err := signer.NewPgBatchTxOpener(conn)
	if err != nil {
		t.Fatal(err)
	}
	type opened struct {
		batch signer.BatchTx
		err   error
	}
	ready := make(chan opened, 1)
	go func() { batch, err := opener.BeginBatch(ctx); ready <- opened{batch, err} }()
	pid := int64(conn.Conn().PgConn().PID())
	waitCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(waitCtx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
			t.Fatal("signer did not wait on observed ledger lock")
		case <-ticker.C:
		}
	}
	// A cooperating writer commits while BeginBatch is waiting. The next statement
	// must see it even though this connection defaults to REPEATABLE READ.
	rec := audit.LedgerRecord{
		ID: uuid.NewString(), AccountRef: uuid.NewString(), BlindIndexVersion: 0,
		EventType: audit.EventLoginSucceeded,
		Timestamp: audit.NormalizeChainTime(time.Now()), RetainUntil: audit.NormalizeChainTime(time.Now().Add(time.Hour)),
	}
	leaf, err := audit.LeafLedger(rec)
	if err != nil {
		t.Fatal(err)
	}
	chainDigest := audit.ChainLedger(audit.LedgerGenesis(), leaf)
	seq, err := db.New(blocker).InsertSecurityEventWithChain(ctx, db.InsertSecurityEventWithChainParams{
		EventID: uuid.MustParse(rec.ID), LeafHash: leaf.Bytes(), ChainHash: chainDigest.Bytes(),
		AccountRef: uuid.MustParse(rec.AccountRef), BlindIndexVersion: rec.BlindIndexVersion,
		EventType:   rec.EventType,
		Timestamp:   pgtype.Timestamptz{Time: rec.Timestamp, Valid: true},
		RetainUntil: pgtype.Timestamptz{Time: rec.RetainUntil, Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.New(blocker).AdvanceChainHead(ctx, db.AdvanceChainHeadParams{
		Which: "ledger", ExpectedSeq: 0, FirstSeq: seq, LastSeq: seq, NodeCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-ready
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer func() { _ = result.batch.Rollback(context.Background()) }()
	head, err := result.batch.Store().GetSecurityLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head.Seq != seq || !bytes.Equal(head.ChainHash, chainDigest.Bytes()) || !head.StateValid {
		t.Fatalf("stale head after ledger lock: %+v, want seq %d / %s", head, seq, chainDigest.Hex())
	}
	var isolation string
	if err := conn.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "read committed" {
		t.Fatalf("isolation=%s err=%v", isolation, err)
	}
}

// TestSignerQuarantinesV1EnvelopeIntegration covers the schema-version gate
// against a real database.
//
// A v1 envelope cannot state which pepper generation produced its blind index,
// so the signer must not sign it: defaulting the generation would record a claim
// the producer never made, and because the ledger body is hashed with that
// generation inside it, the wrong value would be unfixable afterwards. The event
// is quarantined instead — a Class C audit record is written describing the
// rejection, and no ledger row is produced.
func TestSignerQuarantinesV1EnvelopeIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)

	legacy := signerLedgerEnvelope()
	legacy.SchemaVersion = 1
	if err := runSignerFixture(t, ctx, pool, legacy); err != nil {
		t.Fatalf("a quarantined envelope must still commit and settle: %v", err)
	}

	// The event's own id must not appear in either chain.
	var present bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM public.audit_log_chain WHERE event_id=$1)
		     OR EXISTS(SELECT 1 FROM public.security_ledger_chain WHERE event_id=$1)`,
		legacy.EventID).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("a v1 envelope was signed into a chain")
	}

	// A quarantine record was written to Class C, and nothing to Class B: the
	// rejection is itself auditable, but it is not a security event about a
	// subject.
	if got := countSigner(t, ctx, pool, "SELECT count(*) FROM public.audit_log_chain"); got == 0 {
		t.Fatal("no quarantine audit record was written")
	}
	if got := countSigner(t, ctx, pool, "SELECT count(*) FROM public.security_ledger_chain"); got != 0 {
		t.Fatalf("a quarantined envelope produced %d ledger nodes", got)
	}
	assertLedgerChainVerifies(t, ctx, pool)
}
