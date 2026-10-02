//go:build integration

package signer_test

import (
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
	_, err := pool.Exec(ctx, `
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='identity_ledger_maintenance_owner') THEN
        CREATE ROLE identity_ledger_maintenance_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT USAGE ON SCHEMA public TO identity_ledger_maintenance_owner;
GRANT SELECT, DELETE, UPDATE(seq) ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT SELECT, UPDATE ON public.security_ledger_head TO identity_ledger_maintenance_owner;
GRANT SELECT, INSERT, DELETE ON public.security_ledger_checkpoints TO identity_ledger_maintenance_owner;
GRANT SELECT ON public.legal_holds, public.security_ledger_retention_settings TO identity_ledger_maintenance_owner;
GRANT INSERT ON public.event_outbox TO identity_ledger_maintenance_owner;
GRANT EXECUTE ON FUNCTION public.security_ledger_require_owner(),
    public.security_ledger_chain_time(timestamptz),
    public.security_ledger_canonical_body(public.security_event_ledger),
    public.security_ledger_account_lock_key(uuid),
    public.security_ledger_predecessor(bigint) TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.advance_security_ledger_head(bigint,uuid) OWNER TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) OWNER TO identity_ledger_maintenance_owner;
INSERT INTO public.security_ledger_head(singleton,seq,chain_hash) VALUES (true,0,repeat('0',64));
INSERT INTO public.security_ledger_retention_settings(singleton,audit_subject) VALUES (true,'identity.audit.logs');`)
	if err != nil {
		t.Fatalf("explicit signer fixture provisioning/bootstrap: %v", err)
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
	body         []byte
	acked, naked bool
}

func (m *integrationSignerMessage) Data() []byte { return m.body }
func (m *integrationSignerMessage) Metadata() (*jetstream.MsgMetadata, error) {
	return nil, errors.New("no metadata")
}
func (m *integrationSignerMessage) Ack() error                       { m.acked = true; return nil }
func (m *integrationSignerMessage) NakWithDelay(time.Duration) error { m.naked = true; return nil }

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
		if !msg.acked || msg.naked {
			return errors.New("batch did not commit and acknowledge")
		}
	}
	return nil
}

func signerLedgerEnvelope() audit.Envelope {
	return audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), ActorID: uuid.Nil.String(),
		OccurredAt: time.Now().UTC().Add(-2 * 365 * 24 * time.Hour), EventType: audit.EventLoginSucceeded,
		ActionStatus: audit.StatusSuccess, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}}
}

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
	queries := db.New(tx)
	head, err := queries.GetSignerLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := queries.ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{ThroughSeq: head.Seq, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var hashes []string
	var bodies [][]byte
	for _, seq := range seqs {
		found := false
		for _, row := range rows {
			if row.Seq == seq {
				hashes = append(hashes, row.ChainHash)
				bodies = append(bodies, audit.SerializeLedger(ledgerproof.Record(row)))
				found = true
			}
		}
		if !found {
			t.Fatalf("missing selected fixture seq %d", seq)
		}
	}
	var deleted, held int64
	// The production worker captures database time too. Host/VM clock skew must
	// not accidentally exercise the routine's future-cutoff rejection here.
	var cutoff time.Time
	if err := tx.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT deleted_count,held_count FROM public.purge_security_ledger_batch($1,$2,$3,$4,$5,$6,$7)",
		cutoff, head.Seq, seqs, hashes, bodies, uuid.New(), "identity.audit.logs").Scan(&deleted, &held); err != nil {
		t.Fatal(err)
	}
	if deleted != int64(len(seqs)) || held != 0 {
		t.Fatalf("purge counts deleted=%d held=%d", deleted, held)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSignerAppendRestartAfterRetentionIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	first, second, third := signerLedgerEnvelope(), signerLedgerEnvelope(), signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, first, second, third); err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	head, err := q.GetSignerLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{ThroughSeq: head.Seq, PageLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	purgeSignerFixture(t, ctx, pool, []int64{rows[2].Seq})
	fourth := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, fourth); err != nil {
		t.Fatal(err)
	}
	head, err = q.GetSignerLedgerHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = q.ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{ThroughSeq: head.Seq, PageLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	seqs := make([]int64, len(rows))
	for i, row := range rows {
		seqs[i] = row.Seq
	}
	purgeSignerFixture(t, ctx, pool, seqs)
	afterPurge, err := q.GetSignerLedgerHead(ctx)
	if err != nil || afterPurge != head {
		t.Fatalf("purge moved head: %v %v", afterPurge, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM public.security_ledger_checkpoints").Scan(&count); err != nil || count != 1 {
		t.Fatalf("all-purged proof not compact: %d %v", count, err)
	}
	// Replay is still suppressed by Class C after all Class B payloads disappear.
	if err := runSignerFixture(t, ctx, pool, third); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "SELECT nextval(pg_get_serial_sequence('security_event_ledger','seq'))"); err != nil {
		t.Fatal(err)
	}
	fifth := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, fifth); err != nil {
		t.Fatal(err)
	}
	final, err := q.GetSignerLedgerHead(ctx)
	if err != nil || !final.StateValid || final.Seq <= head.Seq+1 {
		t.Fatalf("append after gap/all purge: %v %v", final, err)
	}
	rows, err = q.ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{ThroughSeq: final.Seq, PageLimit: 10})
	if err != nil || len(rows) != 1 || rows[0].ID != fifth.EventID {
		t.Fatalf("duplicate replay resurrected erased payload: %v %v", rows, err)
	}
	if _, err := ledgerproof.VerifyRecord(head.ChainHash, ledgerproof.Record(rows[0]), rows[0].ChainHash); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool); err != nil {
		t.Fatalf("restart: %v", err)
	}
}

func TestSignerStartupRejectsMissingProofIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	if err := runSignerFixture(t, ctx, pool, signerLedgerEnvelope(), signerLedgerEnvelope(), signerLedgerEnvelope()); err != nil {
		t.Fatal(err)
	}
	purgeSignerFixture(t, ctx, pool, []int64{2})
	if _, err := pool.Exec(ctx, "DELETE FROM public.security_ledger_checkpoints"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool); !errors.Is(err, signer.ErrLedgerStateInvalid) {
		t.Fatalf("missing interior checkpoint accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM public.security_ledger_head"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool); !errors.Is(err, signer.ErrLedgerStateInvalid) {
		t.Fatalf("missing head restarted at genesis: %v", err)
	}
}

func TestSignerSequenceResetCannotCommitBelowHeadIntegration(t *testing.T) {
	ctx, pool := signerFixture(t)
	// Consume unused values so resetting into an allocation gap cannot rely on a
	// duplicate-key error to protect the chain.
	if _, err := pool.Exec(ctx, "SELECT nextval(pg_get_serial_sequence('security_event_ledger','seq')), nextval(pg_get_serial_sequence('security_event_ledger','seq'))"); err != nil {
		t.Fatal(err)
	}
	if err := runSignerFixture(t, ctx, pool, signerLedgerEnvelope()); err != nil {
		t.Fatal(err)
	}
	head, err := db.New(pool).GetSignerLedgerHead(ctx)
	if err != nil || head.Seq != 3 {
		t.Fatalf("gap fixture: %v %v", head, err)
	}
	if _, err := pool.Exec(ctx, "SELECT setval(pg_get_serial_sequence('security_event_ledger','seq'),1,false)"); err != nil {
		t.Fatal(err)
	}
	bad := signerLedgerEnvelope()
	if err := runSignerFixture(t, ctx, pool, bad); err == nil {
		t.Fatal("sequence-reset batch acknowledged")
	}
	after, err := db.New(pool).GetSignerLedgerHead(ctx)
	if err != nil || after != head {
		t.Fatalf("sequence reset changed logical head: %v %v", after, err)
	}
	var leaked bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM public.security_event_ledger WHERE id=$1) OR EXISTS(SELECT 1 FROM public.mvp_audit_logs WHERE id=$1)", bad.EventID).Scan(&leaked); err != nil || leaked {
		t.Fatalf("failed advancement committed one chain: %v %v", leaked, err)
	}
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
	rec := audit.LedgerRecord{ID: uuid.NewString(), AccountRef: uuid.NewString(), EventType: audit.EventLoginSucceeded, Timestamp: time.Now().UTC().Truncate(time.Microsecond), RetainUntil: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
	hash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(rec))
	if _, err := blocker.Exec(ctx, "INSERT INTO public.security_event_ledger(id,account_ref,event_type,timestamp,retain_until,chain_hash) VALUES($1,$2,$3,$4,$5,$6)", rec.ID, rec.AccountRef, rec.EventType, rec.Timestamp, rec.RetainUntil, hash); err != nil {
		t.Fatal(err)
	}
	if err := db.New(blocker).AdvanceSecurityLedgerHead(ctx, db.AdvanceSecurityLedgerHeadParams{TerminalID: uuid.MustParse(rec.ID)}); err != nil {
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
	head, err := result.batch.Store().GetSignerLedgerHead(ctx)
	if err != nil || head.Seq != 1 || head.ChainHash != hash || !head.StateValid {
		t.Fatalf("stale head after ledger lock: %v %v", head, err)
	}
	var isolation string
	if err := conn.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "read committed" {
		t.Fatalf("isolation=%s err=%v", isolation, err)
	}
}
