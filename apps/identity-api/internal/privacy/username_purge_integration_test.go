//go:build integration

package privacy

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type usernamePurgeDatabase struct {
	ctx       context.Context
	owner     *pgxpool.Pool
	worker    *pgxpool.Pool
	role      string
	namespace *username.Store
	opener    *PgSubjectTxOpener
	now       time.Time
	trace     *usernamePurgeTrace
}

type usernamePurgeTrace struct{ accountStarted chan struct{} }

func (trace *usernamePurgeTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "pg_advisory_xact_lock") {
		select {
		case trace.accountStarted <- struct{}{}:
		default:
		}
	}
	return ctx
}

func (*usernamePurgeTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Do not reuse openTestPool: it migrates the supplied DATABASE_URL itself.
func newUsernamePurgeDatabase(t *testing.T) usernamePurgeDatabase {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL provisioning access is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	parent, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid provisioning configuration")
	}
	t.Cleanup(parent.Close)
	const inventory = `SELECT COALESCE(jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner) ORDER BY oid)::text,'[]') FROM pg_class WHERE relnamespace='public'::regnamespace`
	var before string
	if err := parent.QueryRow(ctx, inventory).Scan(&before); err != nil {
		t.Fatal("cannot inventory provisioning schema")
	}
	name := "username_purge_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := parent.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Logf("run-owned username purge database: %s", name)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := parent.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("run-owned database cleanup failed", err)
		}
		var exists bool
		if err := parent.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("run-owned database removal not confirmed", err)
		}
		var after string
		if err := parent.QueryRow(cleanup, inventory).Scan(&after); err != nil || after != before {
			t.Error("provisioning schema changed", err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 8
	owner, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	var actual string
	if err := sqlDB.QueryRowContext(ctx, "SELECT current_database()").Scan(&actual); err != nil || actual != name {
		_ = sqlDB.Close()
		t.Fatal("migration target is not the run-owned child")
	}
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	policy := username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1,
		Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}
	const admission = `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`
	normalizer, err := username.New(policy, admission, bytes.Repeat([]byte{0x59}, 32), "purge-fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x43}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := username.NewStore(owner, cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	f := usernamePurgeDatabase{ctx: ctx, owner: owner, namespace: namespace, now: time.Now().UTC().Truncate(time.Microsecond), trace: &usernamePurgeTrace{accountStarted: make(chan struct{}, 1)}}
	// Explicit owner-only fixture activation, never a production installation path.
	a := normalizer.Authority()
	f.exec(t, `INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact())
	f.exec(t, `INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, a.KeyID, a.KeyVerifier[:])
	f.exec(t, `UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:])
	if err := namespace.CheckReady(ctx); err != nil {
		t.Fatal("fixture namespace is not ready", err)
	}
	roleName, password := "username_purger_"+strings.ReplaceAll(uuid.NewString(), "-", ""), uuid.NewString()
	f.role = pgx.Identifier{roleName}.Sanitize()
	f.exec(t, "CREATE ROLE "+f.role+" LOGIN NOINHERIT PASSWORD '"+password+"'")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := owner.Exec(cleanup, "DROP OWNED BY "+f.role); err != nil {
			t.Error(err)
		}
		if _, err := owner.Exec(cleanup, "DROP ROLE "+f.role); err != nil {
			t.Error(err)
		}
	})
	f.exec(t, "GRANT CONNECT ON DATABASE "+quoted+" TO "+f.role)
	f.exec(t, "GRANT USAGE ON SCHEMA public TO "+f.role)
	f.exec(t, "GRANT SELECT,DELETE ON users TO "+f.role)
	// PostgreSQL row locks need one UPDATE column, not username mutation rights.
	f.exec(t, "GRANT UPDATE(id) ON users TO "+f.role)
	f.exec(t, "GRANT SELECT ON legal_holds,username_active_policy TO "+f.role)
	f.exec(t, "GRANT UPDATE(guard) ON username_active_policy TO "+f.role)
	f.exec(t, "GRANT INSERT ON event_outbox TO "+f.role)
	workerConfig := owner.Config().Copy()
	workerConfig.ConnConfig.User, workerConfig.ConnConfig.Password = roleName, password
	workerConfig.ConnConfig.Tracer = f.trace
	f.worker, err = pgxpool.NewWithConfig(ctx, workerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.worker.Close)
	var login, current string
	if err := f.worker.QueryRow(ctx, "SELECT session_user,current_user").Scan(&login, &current); err != nil || login != roleName || current != roleName {
		t.Fatal("worker is not an actual restricted login", err)
	}
	if err := dbprivilege.Check(ctx, f.worker, usernamePurgePrivileges()); err != nil {
		t.Fatal("restricted purger privileges unproven", err)
	}
	f.opener, err = NewPgSubjectTxOpener(f.worker)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"USERNAME_LOOKUP_KEY", "USERNAME_LOOKUP_KEY_ID", "USERNAME_POLICY_JSON", "USERNAME_REGEX", "USERNAME_REVIEW_KEY", "ENVELOPE_MASTER_KEK", "ENVELOPE_MASTER_KEK_VERSION"} {
		t.Setenv(key, "")
	}
	return f
}

func usernamePurgePrivileges() dbprivilege.Contract {
	return dbprivilege.Contract{Tables: []dbprivilege.Table{
		{Name: "public.users", Select: true, Delete: true, UpdateColumns: []string{"id"}},
		{Name: "public.legal_holds", Select: true},
		{Name: "public.username_active_policy", Select: true, UpdateColumns: []string{"guard"}},
		{Name: "public.event_outbox", Insert: true},
	}, Guards: []dbprivilege.Guard{
		{Table: "public.users", Name: "users_username_immutable", Function: "public.username_ownership_guard()", Type: 31},
		{Table: "public.username_active_policy", Name: "username_active_no_delete", Function: "public.username_registry_immutable()", Type: 11},
	}}
}

func (f usernamePurgeDatabase) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.owner.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func (f usernamePurgeDatabase) user(t *testing.T, input string) db.User {
	t.Helper()
	u, err := db.New(f.owner).CreateUser(f.ctx, db.CreateUserParams{Email: uuid.NewString() + "@username-purge.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.namespace.Normalizer().Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := f.namespace.Assign(f.ctx, tx, u.ID, u.AuthVersion, v); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f usernamePurgeDatabase) purger(t *testing.T) *Purger {
	t.Helper()
	p, err := NewPurger(PurgeConfig{GracePeriod: testGracePeriod, BatchSize: 10}, db.New(f.worker), f.opener, &fakeRecorder{}, WithPurgeLogger(discardLogger()), WithPurgeClock(func() time.Time { return f.now }))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f usernamePurgeDatabase) reserved(t *testing.T, input string, id uuid.UUID) {
	t.Helper()
	if owner, err := f.namespace.Lookup(f.ctx, input); err != nil || owner != id {
		t.Fatal("username ownership was not retained", err)
	}
}

func TestUsernamePurgeAdapterRestrictedPrivilegesIntegration(t *testing.T) {
	f := newUsernamePurgeDatabase(t)
	u := f.user(t, "\u0633")
	for _, query := range []string{
		`UPDATE username_active_policy SET admission_state='closed'`,
		`UPDATE users SET username_key=NULL`,
		`SELECT * FROM username_lookup_keys`,
		`SELECT * FROM username_policy_artifacts`,
	} {
		_, err := f.worker.Exec(f.ctx, query)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("purger acquired namespace secrets or mutation authority", err)
		}
	}
	f.exec(t, "REVOKE UPDATE(guard) ON username_active_policy FROM "+f.role)
	if err := dbprivilege.Check(f.ctx, f.worker, usernamePurgePrivileges()); !errors.Is(err, dbprivilege.ErrUnsafe) {
		t.Fatal("missing narrow guard grant accepted", err)
	}
	tx, err := f.opener.BeginSubject(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := tx.LockAccount(f.ctx, u.ID); !errors.Is(err, username.ErrUnavailable) {
		t.Fatal("adapter acquired account authority without policy-row privilege", err)
	}
	_ = tx.Rollback(f.ctx)
	f.exec(t, "GRANT UPDATE(guard) ON username_active_policy TO "+f.role)
	f.exec(t, "GRANT UPDATE ON username_active_policy TO "+f.role)
	if err := dbprivilege.Check(f.ctx, f.worker, usernamePurgePrivileges()); !errors.Is(err, dbprivilege.ErrUnsafe) {
		t.Fatal("broad policy authority grant accepted", err)
	}
	f.exec(t, "REVOKE UPDATE ON username_active_policy FROM "+f.role)
	f.exec(t, "GRANT UPDATE(guard) ON username_active_policy TO "+f.role)
	if err := dbprivilege.Check(f.ctx, f.worker, usernamePurgePrivileges()); err != nil {
		t.Fatal("restored narrow grants rejected", err)
	}
}

func TestUsernamePurgeAdapterPolicyBeforeAccountIntegration(t *testing.T) {
	f := newUsernamePurgeDatabase(t)
	u := f.user(t, "\u0633")
	blocker, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if err := pglock.LockAccount(f.ctx, blocker, u.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.opener.BeginSubject(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	lockCtx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- tx.LockAccount(lockCtx, u.ID) }()
	select {
	case <-f.trace.accountStarted:
	case <-lockCtx.Done():
		t.Fatal("adapter did not reach the account lock")
	}
	// The real adapter is waiting on the account lock. Its earlier policy guard
	// must already prevent an exclusive cutover, not merely be acquired later.
	observer, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Rollback(context.Background())
	if _, err := observer.Exec(f.ctx, "SET LOCAL lock_timeout='150ms'"); err != nil {
		t.Fatal(err)
	}
	_, err = observer.Exec(f.ctx, `UPDATE username_active_policy SET admission_state='closed' WHERE singleton`)
	var blocked *pgconn.PgError
	guardHeld := errors.As(err, &blocked) && blocked.Code == "55P03"
	_ = observer.Rollback(f.ctx)
	if err := blocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	lockErr := <-result
	_ = tx.Rollback(f.ctx)
	if !guardHeld || lockErr != nil {
		t.Fatal("adapter did not hold policy authority before waiting for the account", err, lockErr)
	}
}

func TestUsernamePurgeAdapterClosedGateIntegration(t *testing.T) {
	f := newUsernamePurgeDatabase(t)
	u := f.user(t, "\u0633")
	f.exec(t, `UPDATE users SET status='pending_deletion',deleted_at=$2 WHERE id=$1`, u.ID, f.now.Add(-2*testGracePeriod))
	f.exec(t, `UPDATE username_active_policy SET admission_state='closed' WHERE singleton`)
	tx, err := f.opener.BeginSubject(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := tx.LockAccount(f.ctx, u.ID); !errors.Is(err, username.ErrUnavailable) {
		t.Fatal("adapter ignored the closed ownership gate", err)
	}
	select {
	case <-f.trace.accountStarted:
		t.Fatal("adapter attempted the account lock after gate refusal")
	default:
	}
	_ = tx.Rollback(f.ctx)
	stats, err := f.purger(t).RunOnce(f.ctx)
	if err != nil || stats != (PurgeStats{Considered: 1, Failed: 1}) {
		t.Fatal("real purger did not fail closed", stats, err)
	}
	f.exec(t, `UPDATE username_active_policy SET admission_state='open' WHERE singleton`)
	f.reserved(t, "\u0633", u.ID)
}

func TestUsernamePurgeAdapterRollbackAndCommitIntegration(t *testing.T) {
	f := newUsernamePurgeDatabase(t)
	u := f.user(t, "\u0633")
	f.exec(t, `UPDATE users SET status='pending_deletion',deleted_at=$2 WHERE id=$1`, u.ID, f.now.Add(-2*testGracePeriod))
	tx, err := f.opener.BeginSubject(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := tx.LockAccount(f.ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	user, err := tx.Store().GetUserForUpdateIncludingDeleted(f.ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	count, err := tx.Store().HardDeleteUser(f.ctx, db.HardDeleteUserParams{ID: u.ID, DeletedAt: pgtype.Timestamptz{Time: f.now.Add(-testGracePeriod), Valid: true}})
	if err != nil || count != 1 {
		t.Fatal("real adapter could not delete under narrow grants", count, err)
	}
	if err := lifecycle.EnqueueDeletion(f.ctx, tx.Store(), u.ID, user.LifecycleRevision); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.reserved(t, "\u0633", u.ID)
	var events int
	if err := f.owner.QueryRow(f.ctx, "SELECT count(*) FROM event_outbox").Scan(&events); err != nil || events != 0 {
		t.Fatal("rolled-back deletion retained its intent", events, err)
	}
	stats, err := f.purger(t).RunOnce(f.ctx)
	if err != nil || stats != (PurgeStats{Considered: 1, Purged: 1}) {
		t.Fatal("secret-free restricted purger did not commit physical deletion", stats, err)
	}
	if _, err := f.namespace.Lookup(f.ctx, "\u0633"); !errors.Is(err, username.ErrNotFound) {
		t.Fatal("committed purge retained the reservation", err)
	}
	if err := f.owner.QueryRow(f.ctx, "SELECT count(*) FROM event_outbox WHERE subject=$1 AND lifecycle_user_id=$2", lifecycle.SubjectDeleted, u.ID).Scan(&events); err != nil || events != 1 {
		t.Fatal("physical deletion and its intent did not commit together", events, err)
	}
}

func TestUsernamePurgeAdapterHoldAndReclaimIntegration(t *testing.T) {
	f := newUsernamePurgeDatabase(t)
	env := newIntegrationEnv(t, f.owner)
	reclaimed := f.user(t, "\u0633")
	if _, err := env.svc.RequestDeletion(f.ctx, reclaimed.ID, reclaimed.AuthVersion, "", "en"); err != nil {
		t.Fatal(err)
	}
	notice := env.deliveredNotice(f.ctx, t)
	if err := env.svc.Reclaim(f.ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatal(err)
	}
	f.reserved(t, "\u0633", reclaimed.ID)
	held := f.user(t, "\u0635")
	f.exec(t, `UPDATE users SET status='pending_deletion',deleted_at=$2 WHERE id=$1`, held.ID, f.now.Add(-2*testGracePeriod))
	hold, err := db.New(f.owner).CreateEncryptedLegalHold(f.ctx, db.CreateEncryptedLegalHoldParams{ID: uuid.New(), RequestKind: "legal_hold", DetailsEncrypted: []byte("fixture ciphertext"), AccountRef: held.ID, AppliedBy: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	stats, err := f.purger(t).RunOnce(f.ctx)
	if err != nil || stats != (PurgeStats{Considered: 1, SkippedLegalHold: 1}) {
		t.Fatal("restricted purger did not retain a held account", stats, err)
	}
	f.reserved(t, "\u0635", held.ID)
	f.reserved(t, "\u0633", reclaimed.ID)
	if _, err := db.New(f.owner).ReleaseLegalHold(f.ctx, db.ReleaseLegalHoldParams{ID: hold.ID, ReleasedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	stats, err = f.purger(t).RunOnce(f.ctx)
	if err != nil || stats != (PurgeStats{Considered: 1, Purged: 1}) {
		t.Fatal("released hold did not permit actual purge", stats, err)
	}
	if _, err := f.namespace.Lookup(f.ctx, "\u0635"); !errors.Is(err, username.ErrNotFound) {
		t.Fatal("released held account retained its reservation", err)
	}
	f.reserved(t, "\u0633", reclaimed.ID)
}
