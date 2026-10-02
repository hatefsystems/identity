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

const integrationPurgeRoutine = "public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text)"

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
	workerExec(t, ctx, root, `DO $$ BEGIN
 CREATE ROLE identity_ledger_maintenance_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$;
DO $$ BEGIN
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
	// Keep in sync with retentiondbintegration's real-role grants. No runtime
	// role owns a table, inherits another role, or receives arbitrary outbox writes.
	workerExec(t, ctx, admin, `GRANT USAGE ON SCHEMA public TO identity_ledger_maintenance_owner,identity_ledger_purge;
GRANT SELECT,DELETE ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT UPDATE(seq) ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT SELECT,UPDATE ON public.security_ledger_head TO identity_ledger_maintenance_owner;
GRANT SELECT,INSERT,DELETE ON public.security_ledger_checkpoints TO identity_ledger_maintenance_owner;
GRANT SELECT ON public.legal_holds,public.security_ledger_retention_settings TO identity_ledger_maintenance_owner;
GRANT INSERT ON public.event_outbox TO identity_ledger_maintenance_owner;
GRANT EXECUTE ON FUNCTION public.security_ledger_require_owner(),public.security_ledger_chain_time(timestamptz),
 public.security_ledger_canonical_body(public.security_event_ledger),public.security_ledger_account_lock_key(uuid),
 public.security_ledger_predecessor(bigint) TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.advance_security_ledger_head(bigint,uuid) OWNER TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) OWNER TO identity_ledger_maintenance_owner;
GRANT SELECT ON public.security_event_ledger,public.security_ledger_head,public.security_ledger_checkpoints,
 public.legal_holds,public.security_ledger_retention_settings TO identity_ledger_purge;
GRANT EXECUTE ON FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) TO identity_ledger_purge;
REVOKE CREATE ON DATABASE worker_integration_agent FROM identity_ledger_purge;
INSERT INTO public.security_ledger_head VALUES(true,0,repeat('0',64));`)
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
	hash   string
}

func workerLedgerRecord(account uuid.UUID, expires time.Time) audit.LedgerRecord {
	return audit.LedgerRecord{ID: uuid.NewString(), AccountRef: account.String(), EventType: "auth.login",
		Timestamp: audit.NormalizeChainTime(expires.Add(-365 * 24 * time.Hour)), RetainUntil: audit.NormalizeChainTime(expires)}
}

// Inserts signed fixtures without disabling guards. Explicit sequence gaps make
// numeric adjacency an invalid shortcut in both preflight and compaction tests.
func (f *workerFixture) seed(t *testing.T, records ...audit.LedgerRecord) []workerRecord {
	t.Helper()
	tx, err := f.admin.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	workerExec(t, f.ctx, tx, "SELECT pg_advisory_xact_lock($1)", pglock.LedgerCoordinationKey)
	var seq int64
	var previous string
	if err := tx.QueryRow(f.ctx, "SELECT seq,chain_hash FROM public.security_ledger_head WHERE singleton").Scan(&seq, &previous); err != nil {
		t.Fatal(err)
	}
	expected := seq
	result := make([]workerRecord, 0, len(records))
	for _, rec := range records {
		prev, err := audit.DecodeChainHash(previous)
		if err != nil {
			t.Fatal(err)
		}
		seq += 3
		previous = audit.ChainHash(prev, audit.SerializeLedger(rec))
		workerExec(t, f.ctx, tx, `INSERT INTO public.security_event_ledger
 (seq,id,account_ref,identity_blind_index,event_type,client_ip,ip_subnet,user_agent,device_fingerprint,client_id,scope,timestamp,retain_until,chain_hash)
 OVERRIDING SYSTEM VALUE
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, seq, rec.ID, rec.AccountRef, rec.IdentityBlindIndex,
			rec.EventType, rec.ClientIP, rec.IPSubnet, rec.UserAgent, rec.DeviceFingerprint, rec.ClientID, rec.Scope, rec.Timestamp, rec.RetainUntil, previous)
		result = append(result, workerRecord{Candidate{seq, uuid.MustParse(rec.AccountRef), rec.RetainUntil}, rec, previous})
	}
	if len(records) > 0 {
		workerExec(t, f.ctx, tx, "SELECT public.advance_security_ledger_head($1,$2)", expected, records[len(records)-1].ID)
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

func (f *workerFixture) assertState(t *testing.T, ledger, checkpoints, receipts int) {
	t.Helper()
	for _, check := range []struct {
		table string
		want  int
	}{{"security_event_ledger", ledger}, {"security_ledger_checkpoints", checkpoints}, {"event_outbox", receipts}} {
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
