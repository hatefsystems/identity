//go:build integration

package retention

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type workerFixture struct {
	ctx     context.Context
	admin   *pgxpool.Pool
	worker  *pgxpool.Pool
	store   *PgStore
	js      jetstream.JetStream
	subject string
	appName string
}

// The database is disposable and separate from the migration/reset suites. The
// database-local session lock also serializes separate invocations of this suite.
// Shared cluster roles are created only, never altered or dropped by these tests.
func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	for _, key := range []string{"DATABASE_URL", "REDIS_URL", "NATS_URL"} {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			if os.Getenv("REQUIRE_RETENTION_INTEGRATION") == "1" {
				t.Fatalf("%s required by mandatory retention integration gate", key)
			}
			t.Skipf("%s not configured", key)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	redisOptions, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(redisOptions)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("configured Redis unavailable: %v", err)
	}
	nc, js, err := natsjs.Connect(ctx, os.Getenv("NATS_URL"), "retention-worker-integration", nil)
	if err != nil {
		t.Fatalf("configured NATS unavailable: %v", err)
	}
	t.Cleanup(nc.Close)
	if _, err := js.AccountInfo(ctx); err != nil {
		t.Fatalf("configured JetStream unavailable: %v", err)
	}
	rootConfig, err := pgx.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	rootConfig.Database = "postgres"
	root, err := pgx.ConnectConfig(ctx, rootConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close(context.Background()) })
	workerExec(t, ctx, root, "SELECT pg_advisory_lock(5299999)")
	// v2 needs only the purge login. The non-login maintenance owner existed
	// solely to own the SECURITY DEFINER purge routine, which no longer exists:
	// erasure is now an ordinary DELETE controlled by table privilege.
	workerExec(t, ctx, root, `DO $$ BEGIN
 CREATE ROLE identity_ledger_purge LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'retention-worker-integration-only';
 EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;`)
	var exists bool
	if err := root.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname='worker_integration_agent')").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		workerExec(t, ctx, root, "CREATE DATABASE worker_integration_agent")
	}
	workerExec(t, ctx, root, "SELECT pg_advisory_unlock(5299999)")
	dsn, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	dsn.Path = "/worker_integration_agent"
	admin, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	guard, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = guard.Exec(context.Background(), "SELECT pg_advisory_unlock(5299998)")
		guard.Release()
	})
	workerExec(t, ctx, guard, "SELECT pg_advisory_lock(5299998)")
	workerExec(t, ctx, admin, "DROP SCHEMA public CASCADE; CREATE SCHEMA public; REVOKE CREATE ON SCHEMA public FROM PUBLIC")
	sqldb, err := migrate.Open(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatal(err)
	}
	_ = sqldb.Close()
	// Exactly the v2 erasure privileges, and nothing more. Notably absent: any
	// right on the chain tables, which is what keeps a retention purge from being
	// able to remove a chain node, and EXECUTE on advance_chain_head, which is the
	// signer's alone.
	workerExec(t, ctx, admin, `GRANT USAGE ON SCHEMA public TO identity_ledger_purge;
GRANT SELECT,DELETE ON public.security_event_ledger TO identity_ledger_purge;
GRANT SELECT,INSERT ON public.security_ledger_erasures TO identity_ledger_purge;
GRANT SELECT ON public.security_ledger_chain,public.security_ledger_head,
 public.legal_holds,public.security_ledger_retention_settings TO identity_ledger_purge;
GRANT INSERT ON public.event_outbox TO identity_ledger_purge;
REVOKE CREATE ON DATABASE worker_integration_agent FROM identity_ledger_purge;`)
	// Separate statement: a parameterized query cannot share an Exec with a
	// multi-command string, because pgx prepares it.
	workerExec(t, ctx, admin, "INSERT INTO public.security_ledger_head VALUES(true,0,$1)", audit.LedgerGenesis().Bytes())
	subject := "identity.audit.retention." + strings.ReplaceAll(uuid.NewString(), "-", "")
	workerExec(t, ctx, admin, "INSERT INTO public.security_ledger_retention_settings VALUES(true,$1)", subject)
	config, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.User = "identity_ledger_purge"
	config.ConnConfig.Password = "retention-worker-integration-only"
	config.MaxConns = 4
	appName := "retention-worker-" + uuid.NewString()
	config.ConnConfig.RuntimeParams["application_name"] = appName
	// Every test runs against a hostile session default. Writes must explicitly
	// override it, including the statement after an account-lock wait.
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	config.ConnConfig.RuntimeParams["timezone"] = "Pacific/Honolulu"
	worker, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	store, err := NewPgStore(worker, subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Probe(ctx); err != nil {
		t.Fatalf("correctly provisioned real worker login failed startup: %v", err)
	}
	return &workerFixture{ctx: ctx, admin: admin, worker: worker, store: store, js: js, subject: subject, appName: appName}
}

type workerExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func workerExec(t *testing.T, ctx context.Context, conn workerExecutor, query string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, query, args...); err != nil {
		t.Fatalf("fixture SQL: %v", err)
	}
}

type workerRecord struct {
	Candidate
	record audit.LedgerRecord
	leaf   audit.Digest
	chain  audit.Digest
}

func workerLedgerRecord(account uuid.UUID, expires time.Time) audit.LedgerRecord {
	return audit.LedgerRecord{ID: uuid.NewString(), AccountRef: account.String(), EventType: "auth.login",
		BlindIndexVersion: 1,
		Timestamp:         audit.NormalizeChainTime(expires.Add(-365 * 24 * time.Hour)),
		RetainUntil:       audit.NormalizeChainTime(expires)}
}

// seed inserts signed fixtures without disabling any guard, writing both the
// chain node and its payload exactly as the signer would. Explicit sequence gaps
// make numeric adjacency an invalid shortcut: the chain defines adjacency, never
// seq-1.
func (f *workerFixture) seed(t *testing.T, records ...audit.LedgerRecord) []workerRecord {
	t.Helper()
	tx, err := f.admin.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	workerExec(t, f.ctx, tx, "SELECT pg_advisory_xact_lock($1)", pglock.LedgerCoordinationKey)
	var seq int64
	var previousRaw []byte
	if err := tx.QueryRow(f.ctx, "SELECT seq,chain_hash FROM public.security_ledger_head WHERE singleton").Scan(&seq, &previousRaw); err != nil {
		t.Fatal(err)
	}
	previous, err := audit.DecodeDigest(previousRaw)
	if err != nil {
		t.Fatal(err)
	}
	expected := seq
	first := seq + 3
	result := make([]workerRecord, 0, len(records))
	for _, rec := range records {
		leaf, err := audit.LeafLedger(rec)
		if err != nil {
			t.Fatal(err)
		}
		seq += 3
		previous = audit.ChainLedger(previous, leaf)
		workerExec(t, f.ctx, tx, `INSERT INTO public.security_ledger_chain(seq,event_id,leaf_hash,chain_hash)
 VALUES($1,$2,$3,$4)`, seq, rec.ID, leaf.Bytes(), previous.Bytes())
		workerExec(t, f.ctx, tx, `INSERT INTO public.security_event_ledger
 (seq,account_ref,identity_blind_index,blind_index_version,event_type,client_ip,ip_subnet,user_agent,device_fingerprint,client_id,scope,timestamp,retain_until)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, seq, rec.AccountRef, rec.IdentityBlindIndex,
			rec.BlindIndexVersion, rec.EventType, rec.ClientIP, rec.IPSubnet, rec.UserAgent,
			rec.DeviceFingerprint, rec.ClientID, rec.Scope, rec.Timestamp, rec.RetainUntil)
		result = append(result, workerRecord{Candidate{seq, uuid.MustParse(rec.AccountRef), rec.RetainUntil}, rec, leaf, previous})
	}
	if len(records) > 0 {
		workerExec(t, f.ctx, tx, "SELECT public.advance_chain_head('ledger',$1,$2,$3,$4)",
			expected, first, seq, int64(len(records)))
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *workerFixture) boundary(t *testing.T) Boundary {
	t.Helper()
	b, err := f.store.Capture(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *workerFixture) run(t *testing.T, batchSize, maxRows int, dry bool) Stats {
	t.Helper()
	locker, err := pglock.NewPgAdvisoryLocker(f.worker, pglock.SecurityLedgerPurgeKey)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{BatchSize: batchSize, MaxRows: maxRows, Timeout: 20 * time.Second, DryRun: dry}, f.store, locker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := svc.RunOnce(f.ctx)
	if err != nil {
		t.Fatalf("worker run: %+v, %v", stats, err)
	}
	return stats
}

func (f *workerFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.admin.QueryRow(f.ctx, query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *workerFixture) assertState(t *testing.T, ledger, erasures, receipts int) {
	t.Helper()
	for _, check := range []struct {
		table string
		want  int
	}{{"security_event_ledger", ledger}, {"security_ledger_erasures", erasures}, {"event_outbox", receipts}} {
		if got := f.count(t, "SELECT count(*) FROM public."+check.table); got != check.want {
			t.Errorf("%s rows=%d, want %d", check.table, got, check.want)
		}
	}
}

func (f *workerFixture) hold(t *testing.T, conn workerExecutor, account uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	workerExec(t, f.ctx, conn, `INSERT INTO public.legal_holds
 (id,account_ref,reason,requesting_authority,legal_basis,applied_by,review_at)
 VALUES($1,$2,'private case narrative','fixture authority','legal obligation',$3,now()-interval '10 years')`, id, account, uuid.New())
	return id
}

type workerPurgeResult struct {
	batch BatchResult
	err   error
}

func (f *workerFixture) purgeAsync(b Boundary, candidates []Candidate) <-chan workerPurgeResult {
	done := make(chan workerPurgeResult, 1)
	go func() {
		result, err := f.store.Purge(f.ctx, b, candidates, false)
		done <- workerPurgeResult{result, err}
	}()
	return done
}

func awaitWorkerPurge(t *testing.T, done <-chan workerPurgeResult) workerPurgeResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not finish after lock release")
		return workerPurgeResult{}
	}
}

// pg_blocking_pids identifies the exact blocker, while pg_locks proves there is
// a real ungranted lock request. The ticker only bounds observation frequency;
// elapsed time is never used as evidence that a race reached its synchronization point.
func (f *workerFixture) waitBlocked(t *testing.T, blocker uint32, waiterApp string) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 1500*time.Millisecond)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var pid uint32
		err := f.admin.QueryRow(ctx, `SELECT a.pid FROM pg_stat_activity a
 WHERE a.datname=current_database() AND a.application_name=$1
 AND $2::integer=ANY(pg_blocking_pids(a.pid))
 AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted) LIMIT 1`, waiterApp, blocker).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("observe PostgreSQL lock wait: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected PostgreSQL lock wait was not observed")
		case <-tick.C:
		}
	}
}

// chainHead reads the durable ledger head digest.
func (f *workerFixture) chainHead(t *testing.T) audit.Digest {
	t.Helper()
	var raw []byte
	if err := f.admin.QueryRow(f.ctx, "SELECT chain_hash FROM public.security_ledger_head WHERE singleton").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	head, err := audit.DecodeDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// assertChainVerifies walks every chain node from genesis and confirms it still
// reproduces the recorded head, and that each retained payload still reproduces
// its own leaf.
//
// This is the assertion the v1 design could not make after an erasure: the chain
// had a hole, so a verifier had to bridge it with stored checkpoint digests and
// take the erased span's contents on trust.
func (f *workerFixture) assertChainVerifies(t *testing.T) {
	t.Helper()
	rows, err := f.admin.Query(f.ctx, `SELECT c.seq, c.event_id, c.leaf_hash, c.chain_hash,
 l.seq IS NOT NULL,
 l.account_ref, l.identity_blind_index, l.blind_index_version, l.event_type,
 l.client_ip, l.ip_subnet, l.user_agent, l.device_fingerprint, l.client_id, l.scope,
 l.timestamp, l.retain_until,
 EXISTS (SELECT 1 FROM public.security_ledger_erasures e WHERE c.seq BETWEEN e.first_seq AND e.last_seq)
FROM public.security_ledger_chain c
LEFT JOIN public.security_event_ledger l ON l.seq = c.seq
ORDER BY c.seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	previous := audit.LedgerGenesis()
	var lastSeq int64
	nodes := 0
	for rows.Next() {
		var (
			seq                                     int64
			eventID                                 uuid.UUID
			leafRaw, chainRaw                       []byte
			present, erasureRecorded                bool
			accountRef                              uuid.NullUUID
			blindIndex, eventType, clientIP, subnet *string
			userAgent, fingerprint, clientID, scope *string
			blindVersion                            *int16
			timestamp, retainUntil                  *time.Time
		)
		if err := rows.Scan(&seq, &eventID, &leafRaw, &chainRaw, &present,
			&accountRef, &blindIndex, &blindVersion, &eventType,
			&clientIP, &subnet, &userAgent, &fingerprint, &clientID, &scope,
			&timestamp, &retainUntil, &erasureRecorded); err != nil {
			t.Fatal(err)
		}
		leaf, err := audit.DecodeDigest(leafRaw)
		if err != nil {
			t.Fatalf("seq %d: leaf digest: %v", seq, err)
		}
		stored, err := audit.DecodeDigest(chainRaw)
		if err != nil {
			t.Fatalf("seq %d: chain digest: %v", seq, err)
		}
		if seq <= lastSeq {
			t.Fatalf("chain is not ordered: %d after %d", seq, lastSeq)
		}
		if got := audit.ChainLedger(previous, leaf); got != stored {
			t.Fatalf("chain broken at seq %d: computed %s, stored %s", seq, got.Hex(), stored.Hex())
		}
		switch {
		case present:
			rec := audit.LedgerRecord{
				ID: eventID.String(), IdentityBlindIndex: blindIndex, ClientIP: clientIP,
				IPSubnet: subnet, UserAgent: userAgent, DeviceFingerprint: fingerprint,
				ClientID: clientID, Scope: scope,
			}
			if accountRef.Valid {
				rec.AccountRef = accountRef.UUID.String()
			}
			if blindVersion != nil {
				rec.BlindIndexVersion = *blindVersion
			}
			if eventType != nil {
				rec.EventType = *eventType
			}
			if timestamp != nil {
				rec.Timestamp = *timestamp
			}
			if retainUntil != nil {
				rec.RetainUntil = *retainUntil
			}
			recomputed, err := audit.LeafLedger(rec)
			if err != nil {
				t.Fatalf("seq %d: serialize retained payload: %v", seq, err)
			}
			if recomputed != leaf {
				t.Fatalf("seq %d: retained payload does not reproduce its leaf: %s vs %s", seq, recomputed.Hex(), leaf.Hex())
			}
		case !erasureRecorded:
			t.Fatalf("seq %d: payload absent with no erasure record; indistinguishable from a deletion", seq)
		}
		previous, lastSeq = stored, seq
		nodes++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if head := f.chainHead(t); nodes > 0 && previous != head {
		t.Fatalf("replayed chain tip %s does not match the recorded head %s", previous.Hex(), head.Hex())
	}
}
