//go:build integration

// Package retentiondbintegration exercises the destructive maintenance boundary
// using actual non-owner logins. Every test creates a disposable database; the
// supplied DATABASE_URL must identify a disposable, role-provisioning cluster.
//
// # What canonical format v2 changed here
//
// v1 routed erasure through a SECURITY DEFINER routine owned by a non-login
// maintenance role, so this suite spent most of its effort proving that routine
// could not be hijacked: function ownership, EXECUTE ACLs, search_path pinning,
// SECURITY INVOKER downgrades, and the checkpoint table's exclusion constraints.
// None of that exists now. Erasure is an ordinary DELETE on the payload table,
// authorized by a plain GRANT, and the chain table is append-only for everyone
// with no maintenance exemption at all.
//
// So this suite now proves the boundary that remains, which is a privilege
// boundary rather than a routine boundary:
//
//   - no runtime role can mutate or erase anything it should not, including via
//     trigger bypasses, role escalation, or search_path shadowing;
//   - PUBLIC holds EXECUTE on none of the protected functions;
//   - the destructive down-migration is still refused.
//
// The behavioural half of retention — spans, receipts, holds, dry run, and
// chain-verifiability after an erasure — lives in internal/audit/retention's
// worker integration suite, which runs as the real identity_ledger_purge login.
package retentiondbintegration

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

const (
	purgeRole    = "identity_ledger_purge"
	auditSubject = "identity.audit.logs"
)

type fixture struct {
	ctx         context.Context
	databaseURL string
	admin       *pgx.Conn
	purge       *pgx.Conn
	signer      *pgx.Conn
	api         *pgx.Conn
	cleaner     *pgx.Conn
	names       map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DATABASE_URL is required for real-role retention integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	root, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	database := "retention_db_" + suffix
	mustExec(t, ctx, root, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize())
	conns := []*pgx.Conn{}
	names := map[string]string{}
	t.Cleanup(func() {
		// DROP DATABASE waits for a cluster checkpoint; concurrent isolated suites
		// can make Docker's fsync considerably slower than business transactions.
		cleanup, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		for _, conn := range conns {
			_ = conn.Close(cleanup)
		}
		if _, err := root.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated database: %v", err)
		}
		for _, name := range names {
			if _, err := root.Exec(cleanup, "DROP ROLE "+pgx.Identifier{name}.Sanitize()); err != nil {
				t.Errorf("drop isolated role: %v", err)
			}
		}
		_ = root.Close(cleanup)
	})
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = database
	// ConnString must be rebuilt after changing Database for database/sql goose.
	dbURL, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	dbURL.Path = "/" + database
	sqldb, err := migrate.Open(ctx, dbURL.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatal(err)
	}
	_ = sqldb.Close()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	conns = append(conns, admin)
	f := &fixture{ctx: ctx, databaseURL: dbURL.String(), admin: admin, names: names}

	// A migration must never bootstrap a head: an uninitialized head and an empty
	// chain are different states, and only an operator may assert which one this is.
	assertCount(t, f, "public.security_ledger_head", 0)
	assertCount(t, f, "public.audit_log_head", 0)
	assertCount(t, f, "public.security_ledger_retention_settings", 0)
	// advance_chain_head must be SECURITY DEFINER with a pinned search_path and no
	// PUBLIC EXECUTE. SECURITY DEFINER is what forces the signer to move a head
	// *through* linkage verification: the signer deliberately holds no direct
	// UPDATE on the head tables, so this function is its only path, and it cannot
	// set a head to an arbitrary value.
	//
	// The function's owner — the role that ran the migration, i.e. the schema owner
	// — does retain EXECUTE, which is unavoidable and harmless: that role already
	// owns the tables and triggers. Narrowing it to a dedicated non-login owner is
	// an operator-runbook hardening step, not something a migration may do, since a
	// migration must never create or empower a role. The boundary this suite
	// enforces is that no *runtime* login can execute it.
	var secdef, pinned bool
	if err := admin.QueryRow(ctx, `SELECT p.prosecdef,
 EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig,'{}')) c WHERE c LIKE 'search_path=%')
FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND p.proname='advance_chain_head'`).Scan(&secdef, &pinned); err != nil {
		t.Fatal(err)
	}
	if !secdef {
		t.Fatal("advance_chain_head is SECURITY INVOKER; the signer could then move a head without verification")
	}
	if !pinned {
		t.Fatal("advance_chain_head has no pinned search_path; a caller could shadow the objects it reads")
	}

	for _, kind := range []string{"purge", "signer", "api", "cleaner"} {
		name := "retention_" + kind + "_" + suffix
		password := uuid.NewString()
		quoted := pgx.Identifier{name}.Sanitize()
		mustExec(t, ctx, admin, "CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
		names[kind] = name
		mustExec(t, ctx, admin, "GRANT USAGE ON SCHEMA public TO "+quoted)
		mustExec(t, ctx, admin, "GRANT SELECT ON public.security_event_ledger,public.security_ledger_chain,"+
			"public.security_ledger_head,public.security_ledger_erasures,public.legal_holds,"+
			"public.security_ledger_retention_settings TO "+quoted)
		switch kind {
		case "purge":
			// Exactly the v2 erasure privileges. No rights on the chain at all.
			mustExec(t, ctx, admin, "GRANT DELETE ON public.security_event_ledger TO "+quoted)
			mustExec(t, ctx, admin, "GRANT INSERT ON public.security_ledger_erasures TO "+quoted)
			mustExec(t, ctx, admin, "GRANT INSERT ON public.event_outbox TO "+quoted)
		case "signer":
			mustExec(t, ctx, admin, "GRANT INSERT ON public.security_event_ledger,public.security_ledger_chain TO "+quoted)
			mustExec(t, ctx, admin, "GRANT USAGE ON SEQUENCE public.security_ledger_chain_seq TO "+quoted)
			mustExec(t, ctx, admin, "GRANT EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) TO "+quoted)
		case "api":
			mustExec(t, ctx, admin, "GRANT INSERT,UPDATE ON public.legal_holds TO "+quoted)
		}
		roleConfig := config.Copy()
		roleConfig.User, roleConfig.Password = name, password
		conn, err := pgx.ConnectConfig(ctx, roleConfig)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		mustExec(t, ctx, conn, "SET statement_timeout='15s'")
		switch kind {
		case "purge":
			f.purge = conn
		case "signer":
			f.signer = conn
		case "api":
			f.api = conn
		case "cleaner":
			f.cleaner = conn
		}
	}

	// Only this fixture knows that the newly created database has no history.
	mustExec(t, ctx, admin, "INSERT INTO public.security_ledger_head VALUES (true,0,$1)", audit.LedgerGenesis().Bytes())
	mustExec(t, ctx, admin, "INSERT INTO public.audit_log_head VALUES (true,0,$1)", audit.AuditGenesis().Bytes())
	mustExec(t, ctx, admin, "INSERT INTO public.security_ledger_retention_settings VALUES (true,$1)", auditSubject)
	return f
}

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

//nolint:revive // Testing helpers conventionally take testing.T before operation arguments.
func mustExec(t *testing.T, ctx context.Context, conn executor, sql string, args ...any) {
	t.Helper()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("fixture SQL %q: %v", sql, err)
	}
}

func assertSQLState(t *testing.T, err error, state string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != state {
		t.Fatalf("error = %v, want SQLSTATE %s", err, state)
	}
}

// assertRefused requires the statement to have been rejected, and reports which
// statement slipped through rather than only the SQLSTATE.
//
// Two codes count as a refusal. 42501 is the privilege or trigger rejection.
// 0A000 is PostgreSQL refusing to TRUNCATE a table that an enabled foreign key
// references, which it checks before firing any trigger — a different mechanism
// reaching the same outcome, and one the chain tables get for free from the
// payload tables' ON DELETE RESTRICT reference.
func assertRefused(t *testing.T, sql string, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("statement was not refused: %q (err = %v)", sql, err)
	}
	if pgErr.Code != "42501" && pgErr.Code != "0A000" {
		t.Fatalf("statement %q refused with SQLSTATE %s, want 42501 or 0A000", sql, pgErr.Code)
	}
}

func assertCount(t *testing.T, f *fixture, table string, want int64) {
	t.Helper()
	var got int64
	if err := f.admin.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}

// seedLedger appends one well-formed chain node and payload as the signer login,
// so the row under test was produced through the same privileges production uses.
func (f *fixture) seedLedger(t *testing.T, expires time.Time) int64 {
	t.Helper()
	eventID := uuid.New()
	timestamp := audit.NormalizeChainTime(expires.Add(-365 * 24 * time.Hour))
	retainUntil := audit.NormalizeChainTime(expires)
	account := uuid.New()
	leaf, err := audit.LeafLedger(audit.LedgerRecord{
		ID: eventID.String(), AccountRef: account.String(), BlindIndexVersion: 0,
		EventType: "auth.login", Timestamp: timestamp, RetainUntil: retainUntil,
	})
	if err != nil {
		t.Fatal(err)
	}
	chain := audit.ChainLedger(audit.LedgerGenesis(), leaf)

	tx, err := f.signer.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var seq int64
	if err := tx.QueryRow(f.ctx, `INSERT INTO public.security_ledger_chain(event_id,leaf_hash,chain_hash)
VALUES($1,$2,$3) RETURNING seq`, eventID, leaf.Bytes(), chain.Bytes()).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.ctx, tx, `INSERT INTO public.security_event_ledger
(seq,account_ref,blind_index_version,event_type,timestamp,retain_until) VALUES($1,$2,0,'auth.login',$3,$4)`,
		seq, account, timestamp, retainUntil)
	mustExec(t, f.ctx, tx, "SELECT public.advance_chain_head('ledger',0,$1,$1,1)", seq)
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return seq
}

// TestNoRuntimeRoleCanMutateTheLedger is the privilege matrix. Every runtime
// login is tried against every destructive statement, including the ones that
// would disarm the guards rather than defeat them directly.
func TestNoRuntimeRoleCanMutateTheLedger(t *testing.T) {
	f := newFixture(t)
	seq := f.seedLedger(t, time.Now().Add(-time.Hour))

	for name, conn := range map[string]*pgx.Conn{
		"purge": f.purge, "signer": f.signer, "api": f.api, "cleaner": f.cleaner,
	} {
		t.Run(name, func(t *testing.T) {
			statements := []string{
				// The chain is the tamper-evidence. Nothing may touch it.
				"UPDATE public.security_ledger_chain SET chain_hash=leaf_hash",
				"DELETE FROM public.security_ledger_chain",
				"TRUNCATE public.security_ledger_chain",
				"UPDATE public.audit_log_chain SET chain_hash=leaf_hash",
				"DELETE FROM public.audit_log_chain",
				// Payload is immutable for everyone; erasable only by the purge role.
				"UPDATE public.security_event_ledger SET event_type='changed'",
				"TRUNCATE public.security_event_ledger",
				// The heads are the signer's alone.
				"UPDATE public.security_ledger_head SET seq=0",
				"TRUNCATE public.security_ledger_head",
				"UPDATE public.audit_log_head SET seq=0",
				// Erasure records must not be removable: deleting one turns a lawful
				// erasure back into an unexplained gap.
				"UPDATE public.security_ledger_erasures SET operation_id=gen_random_uuid()",
				"DELETE FROM public.security_ledger_erasures",
				// Disarming or bypassing the guards.
				"ALTER TABLE public.security_event_ledger DISABLE TRIGGER ALL",
				"ALTER TABLE public.security_ledger_chain DISABLE TRIGGER ALL",
				"SET session_replication_role='replica'",
				"CREATE ROLE retention_escalation SUPERUSER",
			}
			// Escalating into another runtime login. The target must not be the
			// current role: SET ROLE to yourself is always permitted and would make
			// this case vacuous for whichever role it named.
			for kind, target := range f.names {
				if kind == name {
					continue
				}
				statements = append(statements, "SET ROLE "+pgx.Identifier{target}.Sanitize())
			}
			if name != "purge" {
				statements = append(statements,
					"DELETE FROM public.security_event_ledger",
					"INSERT INTO public.security_ledger_erasures(first_seq,last_seq,operation_id) VALUES(1,1,gen_random_uuid())",
					"INSERT INTO public.event_outbox(subject,payload) VALUES('identity.audit.logs','{}')")
			}
			if name != "signer" {
				statements = append(statements,
					"INSERT INTO public.security_ledger_chain(seq,event_id,leaf_hash,chain_hash) VALUES(999,gen_random_uuid(),sha256('a'),sha256('b'))",
					"SELECT public.advance_chain_head('ledger',0,1,1,1)")
			}
			for _, sql := range statements {
				_, err := conn.Exec(f.ctx, sql)
				assertRefused(t, sql, err)
			}
		})
	}

	// The seeded row and its chain node must still be intact and verifiable after
	// every attempt above.
	assertCount(t, f, "public.security_event_ledger", 1)
	assertCount(t, f, "public.security_ledger_chain", 1)
	var storedSeq int64
	if err := f.admin.QueryRow(f.ctx, "SELECT seq FROM public.security_ledger_chain").Scan(&storedSeq); err != nil {
		t.Fatal(err)
	}
	if storedSeq != seq {
		t.Fatalf("chain node seq = %d, want %d", storedSeq, seq)
	}
}

// TestTableGrantsCannotBypassTheGuards covers the operator-error case: even an
// accidental UPDATE/TRUNCATE grant must not get past the triggers, because a
// GRANT is a privilege decision and immutability is an integrity decision.
func TestTableGrantsCannotBypassTheGuards(t *testing.T) {
	f := newFixture(t)
	f.seedLedger(t, time.Now().Add(-time.Hour))
	quoted := pgx.Identifier{f.names["cleaner"]}.Sanitize()

	mustExec(t, f.ctx, f.admin, "GRANT UPDATE,TRUNCATE ON public.security_event_ledger TO "+quoted)
	mustExec(t, f.ctx, f.admin, "GRANT UPDATE,DELETE,TRUNCATE ON public.security_ledger_chain TO "+quoted)
	// Session GUCs that a v1-style trigger might have consulted.
	mustExec(t, f.ctx, f.cleaner, "SET app.ledger_maintenance='true'")
	mustExec(t, f.ctx, f.cleaner, "SET security_ledger.purge='on'")

	for _, sql := range []string{
		"UPDATE public.security_event_ledger SET event_type='changed'",
		"TRUNCATE public.security_event_ledger",
		"UPDATE public.security_ledger_chain SET chain_hash=leaf_hash",
		"DELETE FROM public.security_ledger_chain",
		"TRUNCATE public.security_ledger_chain",
	} {
		_, err := f.cleaner.Exec(f.ctx, sql)
		assertRefused(t, sql, err)
	}
	assertCount(t, f, "public.security_event_ledger", 1)
	assertCount(t, f, "public.security_ledger_chain", 1)
}

// TestSearchPathShadowingCannotDeceiveTheGuards covers the temp-table attack:
// every guard and every query must name its objects schema-qualified, or a role
// that can create temp tables could substitute its own legal_holds and make a
// held subject look unheld.
func TestSearchPathShadowingCannotDeceiveTheGuards(t *testing.T) {
	f := newFixture(t)
	seq := f.seedLedger(t, time.Now().Add(-time.Hour))

	// A hold that must be honoured regardless of what search_path says.
	var account uuid.UUID
	if err := f.admin.QueryRow(f.ctx, "SELECT account_ref FROM public.security_event_ledger WHERE seq=$1", seq).Scan(&account); err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.ctx, f.admin, `INSERT INTO public.legal_holds(account_ref,reason,requesting_authority,legal_basis,applied_by)
VALUES($1,'shadowing','court','legal claims',$2)`, account, uuid.New())

	mustExec(t, f.ctx, f.purge, "CREATE TEMP TABLE legal_holds(account_ref uuid, is_active boolean)")
	mustExec(t, f.ctx, f.purge, "CREATE TEMP TABLE security_ledger_head(singleton boolean, seq bigint, chain_hash bytea)")
	mustExec(t, f.ctx, f.purge, "SET search_path=pg_temp")

	// The schema-qualified DELETE still sees the real hold and erases nothing.
	tag, err := f.purge.Exec(f.ctx, `DELETE FROM public.security_event_ledger l
WHERE l.seq=$1 AND l.retain_until < now()
  AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref=l.account_ref AND h.is_active)`, seq)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatal("a shadowed legal_holds let a held payload be erased")
	}
	assertCount(t, f, "public.security_event_ledger", 1)
}

// TestPublicHoldsNoExecuteOnProtectedFunctions keeps the function surface closed
// by default. A PUBLIC EXECUTE grant on any of these would make every one of the
// privilege tests above meaningless.
func TestPublicHoldsNoExecuteOnProtectedFunctions(t *testing.T) {
	f := newFixture(t)
	var exposed int64
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace,
LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
WHERE n.nspname='public'
  AND p.proname IN ('advance_chain_head','chain_table_guard',
                    'security_event_ledger_guard','mvp_audit_logs_guard')
  AND acl.grantee=0 AND acl.privilege_type='EXECUTE'`).Scan(&exposed); err != nil {
		t.Fatal(err)
	}
	if exposed != 0 {
		t.Fatalf("PUBLIC can execute %d protected functions", exposed)
	}

	// And the v1 routines must be gone rather than merely unreachable: a surviving
	// SECURITY DEFINER purge routine would be an erasure path outside the model.
	var leftovers int64
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND p.proname IN
 ('purge_security_ledger_batch','security_ledger_canonical_body','security_ledger_predecessor',
  'security_ledger_require_owner','security_ledger_account_lock_key','security_ledger_chain_time',
  'advance_security_ledger_head')`).Scan(&leftovers); err != nil {
		t.Fatal(err)
	}
	if leftovers != 0 {
		t.Fatalf("%d v1 maintenance routines survived migration 00015", leftovers)
	}

	var checkpoints int64
	if err := f.admin.QueryRow(f.ctx,
		"SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='security_ledger_checkpoints'").Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 0 {
		t.Fatal("the v1 checkpoint table survived migration 00015")
	}
}

// TestForwardOnlyMigrationIsRefused keeps the escape hatch closed. Reverting
// would reinstate a format whose digests nothing can recompute, and would drop
// the chain and erasure tables that are the only surviving record of what was
// erased.
func TestForwardOnlyMigrationIsRefused(t *testing.T) {
	f := newFixture(t)
	f.seedLedger(t, time.Now().Add(-time.Hour))

	sqldb, err := migrate.Open(f.ctx, f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqldb.Close() }()

	if err := migrate.Down(f.ctx, sqldb); err == nil {
		t.Fatal("the destructive down migration was not refused")
	} else if !strings.Contains(strings.ToLower(err.Error()), "forward-only") {
		t.Fatalf("down migration failed for the wrong reason: %v", err)
	}
	// Forward recovery must still work after the refusal, and must not have lost
	// anything.
	if err := migrate.Up(f.ctx, sqldb); err != nil {
		t.Fatalf("forward recovery after a refused downgrade: %v", err)
	}
	assertCount(t, f, "public.security_ledger_head", 1)
	assertCount(t, f, "public.audit_log_head", 1)
	assertCount(t, f, "public.security_ledger_chain", 1)
	assertCount(t, f, "public.security_event_ledger", 1)
}
