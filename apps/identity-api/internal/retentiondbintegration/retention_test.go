//go:build integration

// Package retentiondbintegration exercises the destructive maintenance boundary
// using actual non-owner logins. Every test creates a disposable database; the
// supplied DATABASE_URL must identify a disposable, role-provisioning cluster.
package retentiondbintegration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
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
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

const (
	owner        = "identity_ledger_maintenance_owner"
	auditSubject = "identity.audit.logs"
	purgeSQL     = `SELECT deleted_count,held_count FROM public.purge_security_ledger_batch($1,$2,$3,$4,$5,$6,$7)`
)

type fixture struct {
	ctx         context.Context
	databaseURL string
	admin       *pgx.Conn
	worker      *pgx.Conn
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
	assertCount(t, f, "public.security_ledger_head", 0)
	assertCount(t, f, "public.security_ledger_retention_settings", 0)
	_, err = admin.Exec(ctx, "SELECT public.advance_security_ledger_head(0,$1)", uuid.New())
	assertSQLState(t, err, "42501")
	// A deployment operator provisions this role, never a migration/runtime.
	mustExec(t, ctx, admin, `DO $$ BEGIN CREATE ROLE identity_ledger_maintenance_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; EXCEPTION WHEN duplicate_object THEN NULL; END $$`)
	mustExec(t, ctx, admin, `GRANT USAGE ON SCHEMA public TO identity_ledger_maintenance_owner;
GRANT SELECT,DELETE ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT UPDATE(seq) ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT SELECT,UPDATE ON public.security_ledger_head TO identity_ledger_maintenance_owner;
GRANT SELECT,INSERT,DELETE ON public.security_ledger_checkpoints TO identity_ledger_maintenance_owner;
GRANT SELECT ON public.legal_holds,public.security_ledger_retention_settings TO identity_ledger_maintenance_owner;
GRANT INSERT ON public.event_outbox TO identity_ledger_maintenance_owner;
GRANT EXECUTE ON FUNCTION public.security_ledger_require_owner(), public.security_ledger_chain_time(timestamptz),
public.security_ledger_canonical_body(public.security_event_ledger), public.security_ledger_account_lock_key(uuid),
public.security_ledger_predecessor(bigint) TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.advance_security_ledger_head(bigint,uuid) OWNER TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) OWNER TO identity_ledger_maintenance_owner;`)
	for _, kind := range []string{"worker", "signer", "api", "cleaner"} {
		name := "retention_" + kind + "_" + suffix
		password := uuid.NewString()
		quoted := pgx.Identifier{name}.Sanitize()
		mustExec(t, ctx, admin, "CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
		names[kind] = name
		mustExec(t, ctx, admin, "GRANT USAGE ON SCHEMA public TO "+quoted)
		mustExec(t, ctx, admin, "GRANT SELECT ON public.security_event_ledger,public.security_ledger_head,public.security_ledger_checkpoints,public.legal_holds,public.security_ledger_retention_settings TO "+quoted)
		switch kind {
		case "worker":
			mustExec(t, ctx, admin, "GRANT EXECUTE ON FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) TO "+quoted)
		case "signer":
			mustExec(t, ctx, admin, "GRANT INSERT ON public.security_event_ledger TO "+quoted)
			mustExec(t, ctx, admin, "GRANT USAGE ON SEQUENCE public.security_event_ledger_seq_seq TO "+quoted)
			mustExec(t, ctx, admin, "GRANT EXECUTE ON FUNCTION public.advance_security_ledger_head(bigint,uuid) TO "+quoted)
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
		case "worker":
			f.worker = conn
		case "signer":
			f.signer = conn
		case "api":
			f.api = conn
		case "cleaner":
			f.cleaner = conn
		}
	}
	// Only this fixture knows that the newly created database has no history.
	mustExec(t, ctx, admin, "INSERT INTO public.security_ledger_head VALUES (true,0,repeat('0',64))")
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
		t.Fatalf("SQL operation: %v", err)
	}
}

func assertSQLState(t *testing.T, err error, state string) {
	t.Helper()
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != state {
		t.Fatalf("expected SQLSTATE %s, got %v", state, err)
	}
}

func assertCount(t *testing.T, f *fixture, table string, want int64) {
	t.Helper()
	var got int64
	if err := f.admin.QueryRow(f.ctx, "SELECT count(*) FROM "+table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count=%d, want %d", table, got, want)
	}
}

type ledgerRow struct {
	record audit.LedgerRecord
	seq    int64
	hash   string
}

func (f *fixture) append(t *testing.T, records ...audit.LedgerRecord) []ledgerRow {
	t.Helper()
	tx, err := f.signer.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	mustExec(t, f.ctx, tx, "SELECT pg_advisory_xact_lock(5200002::bigint)")
	var head int64
	var hash string
	if err := tx.QueryRow(f.ctx, "SELECT seq,chain_hash FROM public.security_ledger_head WHERE singleton").Scan(&head, &hash); err != nil {
		t.Fatal(err)
	}
	rows := make([]ledgerRow, 0, len(records))
	for _, record := range records {
		previous, err := audit.DecodeChainHash(hash)
		if err != nil {
			t.Fatal(err)
		}
		hash = audit.ChainHash(previous, audit.SerializeLedger(record))
		row := ledgerRow{record: record, hash: hash}
		if err := tx.QueryRow(f.ctx, `INSERT INTO public.security_event_ledger
(id,account_ref,identity_blind_index,event_type,client_ip,ip_subnet,user_agent,device_fingerprint,client_id,scope,timestamp,retain_until,chain_hash)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING seq`,
			record.ID, record.AccountRef, record.IdentityBlindIndex, record.EventType, record.ClientIP,
			record.IPSubnet, record.UserAgent, record.DeviceFingerprint, record.ClientID, record.Scope,
			record.Timestamp, record.RetainUntil, hash).Scan(&row.seq); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	mustExec(t, f.ctx, tx, "SELECT public.advance_security_ledger_head($1,$2)", head, records[len(records)-1].ID)
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return rows
}

func record(expiry time.Time) audit.LedgerRecord {
	return audit.LedgerRecord{ID: uuid.NewString(), AccountRef: uuid.NewString(), EventType: "auth.login",
		Timestamp: audit.NormalizeChainTime(expiry.Add(-365 * 24 * time.Hour)), RetainUntil: audit.NormalizeChainTime(expiry)}
}

func batchArgs(rows []ledgerRow, cutoff time.Time, highwater int64, operation uuid.UUID) []any {
	seqs := make([]int64, len(rows))
	hashes := make([]string, len(rows))
	bodies := make([][]byte, len(rows))
	for i, row := range rows {
		seqs[i], hashes[i], bodies[i] = row.seq, row.hash, audit.SerializeLedger(row.record)
	}
	return []any{cutoff, highwater, seqs, hashes, bodies, operation, auditSubject}
}

func (f *fixture) purge(t *testing.T, rows []ledgerRow, cutoff time.Time, highwater int64, commit bool) (int64, int64, uuid.UUID) {
	t.Helper()
	tx, err := f.worker.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	operation := uuid.New()
	var deleted, held int64
	if err := tx.QueryRow(f.ctx, purgeSQL, batchArgs(rows, cutoff, highwater, operation)...).Scan(&deleted, &held); err != nil {
		t.Fatal(err)
	}
	if commit {
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	return deleted, held, operation
}

func TestCanonicalAndAccountLockParity(t *testing.T) {
	f := newFixture(t)
	values := []string{"", "agent\n\"quoted\"", "\u062f\u0631\u0648\u062f \U0001f512", "a\\b\t"}
	for i, fraction := range []int{0, 100000000, 123400000, 1000, 999999000} {
		timestamp := time.Date(2025, 3, 7, 8, 9, 10, fraction, time.FixedZone("offset", -7*3600))
		r := record(timestamp.Add(365 * 24 * time.Hour))
		r.Timestamp = timestamp
		if i > 0 {
			r.IdentityBlindIndex = &values[0]
			r.ClientIP, r.IPSubnet, r.UserAgent = &values[0], &values[1], &values[2]
			r.DeviceFingerprint, r.ClientID, r.Scope = &values[3], &values[0], &values[2]
		}
		row := f.append(t, r)[0]
		var body []byte
		if err := f.admin.QueryRow(f.ctx, "SELECT public.security_ledger_canonical_body(l) FROM public.security_event_ledger l WHERE seq=$1", row.seq).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, audit.SerializeLedger(r)) {
			t.Fatalf("canonical bytes differ for fraction %d", fraction)
		}
	}
	for _, text := range []string{"00000000-0000-0000-0000-000000000001", "ffffffff-ffff-ffff-ffff-ffffffffffff", "12345678-1234-5678-9abc-def012345678"} {
		id := uuid.MustParse(text)
		sum := sha256.Sum256(append([]byte("identity:account-lock:v1:"), id[:]...))
		want := -int64(binary.BigEndian.Uint64(sum[:8])&0x7fffffffffffffff) - 1
		keyBits := ^(binary.BigEndian.Uint64(sum[:8]) & 0x7fffffffffffffff)
		var got int64
		if err := f.admin.QueryRow(f.ctx, "SELECT public.security_ledger_account_lock_key($1)", id).Scan(&got); err != nil || got != want || got >= 0 {
			t.Fatalf("account lock parity: got %d want %d: %v", got, want, err)
		}
		tx, err := f.api.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := pglock.LockAccount(f.ctx, tx, id); err != nil {
			t.Fatal(err)
		}
		var observed bool
		if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory'
AND classid::bigint=$2 AND objid::bigint=$3 AND objsubid=1 AND granted)`, f.api.PgConn().PID(), int64(keyBits>>32), int64(keyBits&0xffffffff)).Scan(&observed); err != nil || !observed {
			t.Fatalf("Go did not hold the SQL-derived advisory lock: %v", err)
		}
		_ = tx.Rollback(f.ctx)
	}
}

func TestRealRolesAndSpoofedBypasses(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	row := f.append(t, record(cutoff.Add(-time.Hour)))[0]
	for name, conn := range map[string]*pgx.Conn{"worker": f.worker, "signer": f.signer, "api": f.api, "cleaner": f.cleaner} {
		t.Run(name, func(t *testing.T) {
			for _, sql := range []string{
				"DELETE FROM public.security_event_ledger", "UPDATE public.security_event_ledger SET event_type='changed'",
				"TRUNCATE public.security_event_ledger", "UPDATE public.security_ledger_head SET seq=0",
				"DELETE FROM public.security_ledger_checkpoints", "TRUNCATE public.security_ledger_head",
				"ALTER TABLE public.security_event_ledger DISABLE TRIGGER ALL", "SET ROLE " + owner,
				"SET session_replication_role='replica'", "CREATE ROLE retention_escalation SUPERUSER",
				"INSERT INTO public.event_outbox(subject,payload) VALUES('identity.audit.logs','{}')",
			} {
				_, err := conn.Exec(f.ctx, sql)
				assertSQLState(t, err, "42501")
			}
			if name != "worker" {
				_, err := conn.Exec(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...)
				assertSQLState(t, err, "42501")
			}
		})
	}
	// Even accidental table DELETE/UPDATE/TRUNCATE grants cannot bypass triggers.
	mustExec(t, f.ctx, f.admin, "GRANT DELETE,UPDATE,TRUNCATE ON public.security_event_ledger TO "+pgx.Identifier{f.names["worker"]}.Sanitize())
	mustExec(t, f.ctx, f.worker, "SET app.ledger_maintenance='true'; SET security_ledger.purge='on'")
	for _, sql := range []string{"DELETE FROM public.security_event_ledger", "UPDATE public.security_event_ledger SET event_type='changed'", "TRUNCATE public.security_event_ledger"} {
		_, err := f.worker.Exec(f.ctx, sql)
		assertSQLState(t, err, "42501")
	}
	mustExec(t, f.ctx, f.worker, "CREATE TEMP TABLE legal_holds(account_ref uuid,is_active boolean); CREATE TEMP TABLE security_ledger_head(singleton boolean,seq bigint,chain_hash text); SET search_path=pg_temp")
	deleted, _, _ := f.purge(t, []ledgerRow{row}, cutoff, row.seq, true)
	if deleted != 1 {
		t.Fatal("qualified maintenance objects were shadowed")
	}
}

func TestPurgeBoundsAndDryRun(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	rows := f.append(t, record(cutoff.Add(-time.Hour)), record(cutoff), record(cutoff.Add(time.Hour)))
	highwater := rows[len(rows)-1].seq
	for name, mutate := range map[string]func([]any){
		"future_cutoff":    func(a []any) { a[0] = time.Now().Add(time.Hour) },
		"future_highwater": func(a []any) { a[1] = highwater + 1 },
		"empty":            func(a []any) { a[2], a[3], a[4] = []int64{}, []string{}, [][]byte{} },
		"duplicate":        func(a []any) { a[2] = []int64{rows[0].seq, rows[0].seq, rows[2].seq} },
		"unbounded":        func(a []any) { a[2] = make([]int64, 5001) },
		"missing":          func(a []any) { a[2] = []int64{highwater + 100} },
		"uppercase_hash":   func(a []any) { a[3] = []string{strings.ToUpper(rows[0].hash), rows[1].hash, rows[2].hash} },
		"wrong_body":       func(a []any) { a[4].([][]byte)[0] = []byte("fabricated") },
		"null_body":        func(a []any) { a[4].([][]byte)[0] = nil },
		"subject":          func(a []any) { a[6] = "identity.user.deleted" },
		"zero_operation":   func(a []any) { a[5] = uuid.Nil },
	} {
		t.Run(name, func(t *testing.T) {
			args := batchArgs(rows, cutoff, highwater, uuid.New())
			mutate(args)
			if _, err := f.worker.Exec(f.ctx, purgeSQL, args...); err == nil {
				t.Fatal("unsafe arguments accepted")
			}
			assertCount(t, f, "public.security_event_ledger", 3)
			assertCount(t, f, "public.security_ledger_checkpoints", 0)
			assertCount(t, f, "public.event_outbox", 0)
		})
	}
	mustExec(t, f.ctx, f.worker, "SET statement_timeout=0")
	_, err := f.worker.Exec(f.ctx, purgeSQL, batchArgs(rows, cutoff, highwater, uuid.New())...)
	assertSQLState(t, err, "22023")
	mustExec(t, f.ctx, f.worker, "SET statement_timeout='15s'")
	tx, err := f.worker.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(f.ctx, purgeSQL, batchArgs(rows, cutoff, highwater, uuid.New())...)
	assertSQLState(t, err, "25001")
	_ = tx.Rollback(f.ctx)
	deleted, held, _ := f.purge(t, rows, cutoff, highwater, false)
	if deleted != 1 || held != 0 {
		t.Fatalf("strict boundary dry-run: deleted=%d held=%d", deleted, held)
	}
	assertCount(t, f, "public.security_event_ledger", 3)
	assertCount(t, f, "public.security_ledger_checkpoints", 0)
	assertCount(t, f, "public.event_outbox", 0)
	deleted, _, _ = f.purge(t, rows, cutoff, highwater, true)
	if deleted != 1 {
		t.Fatal("strict cutoff did not preserve equality/future rows")
	}
}

func TestSpansGapsHoldsReceiptsAndAppendAfterTailErasure(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	var rows []ledgerRow
	for i := 0; i < 7; i++ {
		// Simulate nontransactional sequence allocation gaps without overriding seq.
		mustExec(t, f.ctx, f.admin, "SELECT nextval('public.security_event_ledger_seq_seq')")
		rows = append(rows, f.append(t, record(cutoff.Add(-time.Hour)))...)
	}
	// Ledger eligibility is independent of live/deleted Class A subjects. Keep
	// another Class C row with the same event ID to prove erasure leaves it alone.
	mustExec(t, f.ctx, f.admin, "INSERT INTO public.users(id,email) VALUES($1,'live@retention.test'),($2,'deleted@retention.test')", rows[0].record.AccountRef, rows[1].record.AccountRef)
	mustExec(t, f.ctx, f.admin, "DELETE FROM public.users WHERE id=$1", rows[1].record.AccountRef)
	mustExec(t, f.ctx, f.admin, `INSERT INTO public.mvp_audit_logs(id,actor_id,actor_spiffe_id,event_type,action_status,client_ip,user_agent,payload,chain_hash)
VALUES($1,$2,'system://identity/fixture','auth.login','success','','','{}',repeat('0',64))`, rows[0].record.ID, uuid.Nil)
	highwater := rows[6].seq
	for _, i := range []int{1, 5} {
		mustExec(t, f.ctx, f.admin, `INSERT INTO public.legal_holds(account_ref,applied_by,reason,requesting_authority,legal_basis,review_at)
VALUES($1,$2,'fixture','fixture','fixture',now()-interval '1 year')`, rows[i].record.AccountRef, uuid.New())
	}
	deleted, held, operation := f.purge(t, []ledgerRow{rows[0], rows[1], rows[2], rows[3], rows[5], rows[6]}, cutoff, highwater, true)
	if deleted != 4 || held != 2 {
		t.Fatalf("deleted=%d held=%d", deleted, held)
	}
	assertCount(t, f, "public.security_ledger_checkpoints", 3)
	var overlap bool
	if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM public.security_ledger_checkpoints c
JOIN public.security_event_ledger l ON l.seq BETWEEN c.first_seq AND c.last_seq)`).Scan(&overlap); err != nil || overlap {
		t.Fatalf("checkpoint covered a retained island: %v", err)
	}
	var raw string
	if err := f.admin.QueryRow(f.ctx, "SELECT payload FROM public.event_outbox WHERE id=$1 AND admin_action", operation).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var env audit.Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil || env.Security != nil || env.SubjectID != "" || env.EventID != operation || env.EventType != "legal.ledger.purged" {
		t.Fatalf("invalid Class C receipt: %v", err)
	}
	for _, row := range rows {
		if strings.Contains(raw, row.record.ID) || strings.Contains(raw, row.record.AccountRef) || strings.Contains(raw, row.hash) {
			t.Fatal("receipt contains erased evidence identifiers/proof history")
		}
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(env.Payload), &payload); err != nil || payload["deleted_count"] != float64(4) || payload["held_count"] != float64(2) {
		t.Fatalf("receipt counts do not match deletion: %v", err)
	}
	mustExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false")
	deleted, _, _ = f.purge(t, []ledgerRow{rows[1], rows[4], rows[5]}, cutoff, highwater, true)
	if deleted != 3 {
		t.Fatal("released hold restarted signed retention")
	}
	assertCount(t, f, "public.security_event_ledger", 0)
	assertCount(t, f, "public.security_ledger_checkpoints", 1)
	var first, last, predecessor, count, head int64
	var predecessorHash, terminal, headHash string
	if err := f.admin.QueryRow(f.ctx, "SELECT first_seq,last_seq,predecessor_seq,predecessor_hash,terminal_hash,erased_count FROM public.security_ledger_checkpoints").Scan(&first, &last, &predecessor, &predecessorHash, &terminal, &count); err != nil {
		t.Fatal(err)
	}
	if first != rows[0].seq || last != highwater || predecessor != 0 || predecessorHash != strings.Repeat("0", 64) || terminal != rows[6].hash || count != 7 {
		t.Fatal("all-erased proof was not maximally compact or lost its true boundary")
	}
	if err := f.admin.QueryRow(f.ctx, "SELECT seq,chain_hash FROM public.security_ledger_head WHERE singleton").Scan(&head, &headHash); err != nil || head != highwater || headHash != terminal {
		t.Fatalf("erasure changed durable head: %v", err)
	}
	newRows := f.append(t, record(cutoff.Add(-time.Hour)))
	if newRows[0].seq <= highwater {
		t.Fatal("signer restarted erased history")
	}
	f.purge(t, newRows, cutoff, newRows[0].seq, true)
	assertCount(t, f, "public.security_ledger_checkpoints", 1)
	assertCount(t, f, "public.users", 1)
	assertCount(t, f, "public.mvp_audit_logs", 1)
}

func TestOutboxAndCompactionFailureRollback(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	rows := f.append(t, record(cutoff.Add(-time.Hour)), record(cutoff.Add(-time.Hour)), record(cutoff.Add(-time.Hour)))
	f.purge(t, rows[:1], cutoff, rows[2].seq, true)
	operation := uuid.New()
	mustExec(t, f.ctx, f.admin, "INSERT INTO public.event_outbox(id,subject,payload) VALUES($1,$2,'{}')", operation, auditSubject)
	_, err := f.worker.Exec(f.ctx, purgeSQL, batchArgs(rows[1:], cutoff, rows[2].seq, operation)...)
	assertSQLState(t, err, "23505")
	assertCount(t, f, "public.security_event_ledger", 2)
	assertCount(t, f, "public.security_ledger_checkpoints", 1)
	var last int64
	if err := f.admin.QueryRow(f.ctx, "SELECT last_seq FROM public.security_ledger_checkpoints").Scan(&last); err != nil || last != rows[0].seq {
		t.Fatalf("failed receipt committed compaction: %v", err)
	}
	// Failure injection adds a rejecting trigger; no production trigger is disabled.
	mustExec(t, f.ctx, f.admin, `CREATE FUNCTION public.reject_checkpoint_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'checkpoint fixture failure'; END $$;
CREATE TRIGGER reject_checkpoint_fixture BEFORE INSERT ON public.security_ledger_checkpoints FOR EACH ROW EXECUTE FUNCTION public.reject_checkpoint_fixture()`)
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs(rows[1:], cutoff, rows[2].seq, uuid.New())...)
	assertSQLState(t, err, "P0001")
	assertCount(t, f, "public.security_event_ledger", 2)
	assertCount(t, f, "public.security_ledger_checkpoints", 1)
}

func waitForBlock(t *testing.T, f *fixture, waiter, blocker uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := f.admin.QueryRow(ctx, "SELECT $2::bigint = ANY(pg_blocking_pids($1))", waiter, int64(blocker)).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("did not observe required PostgreSQL lock wait")
		}
	}
}

func TestHoldWinsAfterObservedWaitAndPurgeWinsReverseOrder(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	row := f.append(t, record(cutoff.Add(-time.Hour)))[0]
	account := uuid.MustParse(row.record.AccountRef)
	holdTx, err := f.api.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holdTx.Rollback(context.Background()) }()
	if err := pglock.LockAccount(f.ctx, holdTx, account); err != nil {
		t.Fatal(err)
	}
	type result struct {
		deleted, held int64
		err           error
	}
	results := make(chan result, 1)
	go func() {
		var r result
		r.err = f.worker.QueryRow(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...).Scan(&r.deleted, &r.held)
		results <- r
	}()
	waitForBlock(t, f, f.worker.PgConn().PID(), f.api.PgConn().PID())
	for i := 0; i < 2; i++ {
		mustExec(t, f.ctx, holdTx, `INSERT INTO public.legal_holds(account_ref,applied_by,reason,requesting_authority,legal_basis,review_at)
VALUES($1,$2,'fixture','fixture','fixture',now()-interval '1 year')`, account, uuid.New())
	}
	if err := holdTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	r := <-results
	if r.err != nil || r.deleted != 0 || r.held != 1 {
		t.Fatalf("post-lock READ COMMITTED snapshot missed hold: %+v", r)
	}
	assertCount(t, f, "public.security_ledger_checkpoints", 0)
	mustExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false WHERE id=(SELECT id FROM public.legal_holds LIMIT 1)")
	deleted, held, _ := f.purge(t, []ledgerRow{row}, cutoff, row.seq, true)
	if deleted != 0 || held != 1 {
		t.Fatal("one independent hold release erased another hold")
	}
	mustExec(t, f.ctx, f.admin, "UPDATE public.legal_holds SET is_active=false")
	purgeTx, err := f.worker.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = purgeTx.Rollback(context.Background()) }()
	if err := purgeTx.QueryRow(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...).Scan(&deleted, &held); err != nil || deleted != 1 {
		t.Fatalf("pre-hold purge: %v", err)
	}
	holdTx, err = f.api.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holdTx.Rollback(context.Background()) }()
	waitResult := make(chan error, 1)
	go func() { waitResult <- pglock.LockAccount(f.ctx, holdTx, account) }()
	waitForBlock(t, f, f.api.PgConn().PID(), f.worker.PgConn().PID())
	if err := purgeTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-waitResult; err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err := holdTx.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM public.security_event_ledger WHERE account_ref=$1)", account).Scan(&remains); err != nil || remains {
		t.Fatalf("post-purge hold pretended erased payload survived: %v", err)
	}
}

func TestHeadAdvancementAndCorruptionFailClosed(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	row := f.append(t, record(cutoff.Add(-time.Hour)))[0]
	for _, args := range [][]any{{int64(0), row.record.ID}, {row.seq, row.record.ID}, {row.seq, uuid.New()}} {
		_, err := f.signer.Exec(f.ctx, "SELECT public.advance_security_ledger_head($1,$2)", args...)
		assertSQLState(t, err, "23000")
	}
	// An old signer can leave a committed row without advancing head. Even if an
	// operator supplied its digest, the advancement routine must refuse adoption.
	bad := record(cutoff.Add(-time.Hour))
	var badSeq int64
	if err := f.admin.QueryRow(f.ctx, `INSERT INTO public.security_event_ledger(id,account_ref,event_type,timestamp,retain_until,chain_hash)
VALUES($1,$2,$3,$4,$5,$6) RETURNING seq`, bad.ID, bad.AccountRef, bad.EventType, bad.Timestamp, bad.RetainUntil, strings.Repeat("f", 64)).Scan(&badSeq); err != nil {
		t.Fatal(err)
	}
	_, err := f.signer.Exec(f.ctx, "SELECT public.advance_security_ledger_head($1,$2)", row.seq, bad.ID)
	assertSQLState(t, err, "23000")
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...)
	assertSQLState(t, err, "23000")
	// Simulate incorrectly initialized historical state without mutating bodies or
	// disabling guards. A matching head does not launder a bad canonical hash.
	mustExec(t, f.ctx, f.admin, "UPDATE public.security_ledger_head SET seq=$1,chain_hash=$2", badSeq, strings.Repeat("f", 64))
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs([]ledgerRow{{record: bad, seq: badSeq, hash: strings.Repeat("f", 64)}}, cutoff, badSeq, uuid.New())...)
	assertSQLState(t, err, "23000")
	assertCount(t, f, "public.security_event_ledger", 2)
	assertCount(t, f, "public.security_ledger_checkpoints", 0)
	assertCount(t, f, "public.event_outbox", 0)
	mustExec(t, f.ctx, f.admin, "DELETE FROM public.security_ledger_head")
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...)
	assertSQLState(t, err, "P0002")
}

func TestProtectedFunctionACLsProvisioningAndForwardOnlyMigration(t *testing.T) {
	f := newFixture(t)
	var exposed int64
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_proc p
JOIN pg_namespace n ON n.oid=p.pronamespace,
LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl
WHERE n.nspname='public' AND (p.proname LIKE 'security_ledger_%'
 OR p.proname IN ('security_event_ledger_guard','advance_security_ledger_head','purge_security_ledger_batch'))
AND acl.grantee=0 AND acl.privilege_type='EXECUTE'`).Scan(&exposed); err != nil || exposed != 0 {
		t.Fatalf("PUBLIC can execute %d protected functions: %v", exposed, err)
	}
	for _, sql := range []string{
		"SELECT public.security_ledger_require_owner()",
		"SELECT public.security_ledger_predecessor(1)",
		"SELECT public.security_ledger_account_lock_key('00000000-0000-0000-0000-000000000001')",
		"SELECT public.advance_security_ledger_head(0,'00000000-0000-0000-0000-000000000001')",
	} {
		_, err := f.worker.Exec(f.ctx, sql)
		assertSQLState(t, err, "42501")
	}
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	row := f.append(t, record(cutoff.Add(-time.Hour)))[0]
	mustExec(t, f.ctx, f.admin, "ALTER FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) OWNER TO "+pgx.Identifier{f.names["api"]}.Sanitize())
	_, err := f.worker.Exec(f.ctx, purgeSQL, batchArgs([]ledgerRow{row}, cutoff, row.seq, uuid.New())...)
	assertSQLState(t, err, "42501")
	assertCount(t, f, "public.security_event_ledger", 1)
	mustExec(t, f.ctx, f.admin, "ALTER FUNCTION public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text) OWNER TO identity_ledger_maintenance_owner")
	f.purge(t, []ledgerRow{row}, cutoff, row.seq, true)
	sqldb, err := migrate.Open(f.ctx, f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqldb.Close() }()
	if err := migrate.Down(f.ctx, sqldb); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatalf("destructive down migration was not refused: %v", err)
	}
	if err := migrate.Up(f.ctx, sqldb); err != nil {
		t.Fatalf("forward recovery after refused downgrade: %v", err)
	}
	assertCount(t, f, "public.security_ledger_head", 1)
	assertCount(t, f, "public.security_ledger_checkpoints", 1)
	assertCount(t, f, "public.event_outbox", 1)
}

func TestCheckpointConstraintsAndTamperingAreNotLaundered(t *testing.T) {
	f := newFixture(t)
	cutoff := audit.NormalizeChainTime(time.Now().Add(-time.Minute))
	rows := f.append(t, record(cutoff.Add(-time.Hour)), record(cutoff.Add(-time.Hour)), record(cutoff.Add(-time.Hour)))
	f.purge(t, rows[1:2], cutoff, rows[2].seq, true)
	_, err := f.admin.Exec(f.ctx, `INSERT INTO public.security_ledger_checkpoints VALUES($1,$2,0,repeat('0',64),$3,3)`, rows[0].seq, rows[2].seq, rows[2].hash)
	assertSQLState(t, err, "23P01")
	_, err = f.admin.Exec(f.ctx, `INSERT INTO public.security_ledger_checkpoints VALUES(100,101,$1,$2,$3,2)`, rows[0].seq, rows[0].hash, rows[2].hash)
	assertSQLState(t, err, "23505")
	for _, sql := range []string{
		"UPDATE public.security_ledger_checkpoints SET terminal_hash='malformed'",
		"UPDATE public.security_ledger_checkpoints SET predecessor_seq=first_seq",
		"UPDATE public.security_ledger_checkpoints SET erased_count=0",
		"UPDATE public.security_ledger_checkpoints SET erased_count=last_seq-first_seq+2",
		"UPDATE public.security_ledger_head SET singleton=false",
		"UPDATE public.security_ledger_head SET seq=-1",
		"UPDATE public.security_ledger_head SET chain_hash=repeat('A',64)",
	} {
		_, err := f.admin.Exec(f.ctx, sql)
		assertSQLState(t, err, "23514")
	}
	// A database owner can still tamper with valid-looking proof. The routine must
	// detect local broken linkage instead of laundering it into a new certificate.
	mustExec(t, f.ctx, f.admin, "UPDATE public.security_ledger_checkpoints SET terminal_hash=repeat('f',64)")
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs(rows[2:], cutoff, rows[2].seq, uuid.New())...)
	assertSQLState(t, err, "23000")
	assertCount(t, f, "public.security_event_ledger", 2)
	mustExec(t, f.ctx, f.admin, "DELETE FROM public.security_ledger_checkpoints")
	_, err = f.worker.Exec(f.ctx, purgeSQL, batchArgs(rows[2:], cutoff, rows[2].seq, uuid.New())...)
	assertSQLState(t, err, "23000")
	assertCount(t, f, "public.security_event_ledger", 2)
	assertCount(t, f, "public.event_outbox", 1)
}
