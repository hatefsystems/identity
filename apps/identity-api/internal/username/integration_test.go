//go:build integration

package username

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type usernameDatabase struct {
	ctx        context.Context
	pool       *pgxpool.Pool
	normalizer *Normalizer
	cipher     Cipher
	store      *Store
}

// Like registration/profile integration harnesses, migrate ONLY a verified,
// unique run-owned child database. Never adopt the supplied provisioning data.
func usernameFixture(t *testing.T) usernameDatabase {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL provisioning access is required")
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid provisioning configuration")
	}
	t.Cleanup(admin.Close)
	const inventory = `SELECT COALESCE(jsonb_agg(jsonb_build_array(oid,relname,relkind,relowner) ORDER BY oid)::text,'[]') FROM pg_class WHERE relnamespace='public'::regnamespace`
	var before string
	if err := admin.QueryRow(ctx, inventory).Scan(&before); err != nil {
		t.Fatal("cannot inventory provisioning schema")
	}
	name := "username_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Logf("run-owned username fixture database: %s", name)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("fixture cleanup failed", err)
		}
		var exists bool
		if err := admin.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("fixture cleanup not confirmed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	var actual string
	if err := sqlDB.QueryRowContext(ctx, `SELECT current_database()`).Scan(&actual); err != nil || actual != name {
		_ = sqlDB.Close()
		t.Fatal("migration target is not run-owned")
	}
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	var after string
	if err := admin.QueryRow(ctx, inventory).Scan(&after); err != nil || after != before {
		t.Fatal("provisioning schema changed")
	}
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x43}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	n := fixtureNormalizer(t)
	store, err := NewStore(pool, cipher, n)
	if err != nil {
		t.Fatal(err)
	}
	f := usernameDatabase{ctx: ctx, pool: pool, normalizer: n, cipher: cipher, store: store}
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatal("migrated username schema failed readiness", err)
	}
	return f
}

func usernameExec(t *testing.T, f usernameDatabase, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

// Explicit owner-only fixture seeding is NOT an executable production activation.
func usernameActivateFixture(t *testing.T, f usernameDatabase) {
	t.Helper()
	a := f.normalizer.Authority()
	usernameExec(t, f, `INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, a.PolicyID, a.Fingerprint[:], f.normalizer.CanonicalArtifact())
	usernameExec(t, f, `INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, a.KeyID, a.KeyVerifier[:])
	usernameExec(t, f, `UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:])
}

func usernameUser(t *testing.T, f usernameDatabase) db.User {
	t.Helper()
	user, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: uuid.NewString() + "@username.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func usernameChosen(t *testing.T, n *Normalizer, input string) Value {
	t.Helper()
	value, err := n.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func usernameAssign(f usernameDatabase, store *Store, id uuid.UUID, version int64, value Value) error {
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer rollbackUsername(tx)
	if err := store.Assign(f.ctx, tx, id, version, value); err != nil {
		return err
	}
	return tx.Commit(f.ctx)
}

func usernameRole(t *testing.T, f usernameDatabase, kind string) *pgxpool.Pool {
	t.Helper()
	name := "username_" + kind + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	password := uuid.NewString()
	usernameExec(t, f, "CREATE ROLE "+quoted+" LOGIN NOINHERIT PASSWORD '"+password+"'")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, "DROP OWNED BY "+quoted); err != nil {
			t.Error(err)
		}
		if _, err := f.pool.Exec(ctx, "DROP ROLE "+quoted); err != nil {
			t.Error(err)
		}
	})
	usernameExec(t, f, "GRANT CONNECT ON DATABASE "+pgx.Identifier{f.pool.Config().ConnConfig.Database}.Sanitize()+" TO "+quoted)
	usernameExec(t, f, "GRANT USAGE ON SCHEMA public TO "+quoted)
	switch kind {
	case "installer":
		usernameExec(t, f, "GRANT SELECT,INSERT ON username_policy_artifacts,username_lookup_keys TO "+quoted)
	case "reader":
		usernameExec(t, f, "GRANT SELECT ON users,username_policy_artifacts,username_lookup_keys,username_active_policy TO "+quoted)
	case "api":
		usernameExec(t, f, "GRANT SELECT,INSERT,UPDATE,DELETE ON users TO "+quoted)
		usernameExec(t, f, "GRANT SELECT ON username_policy_artifacts,username_lookup_keys,username_active_policy TO "+quoted)
		usernameExec(t, f, "GRANT UPDATE(guard) ON username_active_policy TO "+quoted)
	default:
		t.Fatal("unknown fixture role")
	}
	cfg := f.pool.Config().Copy()
	cfg.ConnConfig.User = name
	cfg.ConnConfig.Password = password
	cfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var current, login string
	if err := pool.QueryRow(f.ctx, `SELECT current_user,session_user`).Scan(&current, &login); err != nil || current != name || login != name {
		t.Fatal("fixture is not actual restricted login")
	}
	return pool
}

func TestUsernameGlobalReservationsAndOrdinaryImmutabilityIntegration(t *testing.T) {
	f := usernameFixture(t)
	first, second := usernameUser(t, f), usernameUser(t, f)
	if result, err := f.store.Get(f.ctx, first.ID, first.AuthVersion); !errors.Is(err, ErrUnavailable) || result != nil {
		t.Fatal("uninstalled namespace falsely available")
	}
	usernameActivateFixture(t, f)
	api := usernameRole(t, f, "api")
	store, err := NewStore(api, f.cipher, f.normalizer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReady(f.ctx); err != nil {
		t.Fatal("restricted API shared guard failed", err)
	}
	if result, err := store.Get(f.ctx, first.ID, first.AuthVersion); err != nil || result != nil {
		t.Fatal("legacy null username fabricated")
	}
	chosen := usernameChosen(t, f.normalizer, "\u0639\u0644\u06cc.\u0645\u0624\u0645\u0646\u06cc")
	if err := usernameAssign(f, store, first.ID, first.AuthVersion, chosen); err != nil {
		t.Fatal(err)
	}
	result, err := store.Get(f.ctx, first.ID, first.AuthVersion)
	if err != nil || result == nil || result.Display != chosen.Display() {
		t.Fatal("NFC original display lost", err)
	}
	alias := usernameChosen(t, f.normalizer, "\u0639\u0644\u064a.\u0645\u0648\u0645\u0646\u064a")
	if err := usernameAssign(f, store, first.ID, first.AuthVersion, alias); !errors.Is(err, ErrConflict) {
		t.Fatal("equivalent display rename permitted")
	}
	for _, status := range []string{"active", "suspended", "banned", "pending_verification", "pending_deletion"} {
		usernameExec(t, f, `UPDATE users SET status=$2,deleted_at=now() WHERE id=$1`, first.ID, status)
		if available, err := store.Available(f.ctx, alias); err != nil || available {
			t.Fatalf("status released reservation: %s %v", status, err)
		}
		if id, err := store.Lookup(f.ctx, alias.Display()); err != nil || id != first.ID {
			t.Fatal("lookup applied account policy or lost alias", err)
		}
		if err := usernameAssign(f, store, second.ID, second.AuthVersion, alias); !errors.Is(err, ErrConflict) {
			t.Fatal("surviving owner lost global uniqueness", err)
		}
	}
	usernameExec(t, f, `UPDATE users SET status='active',deleted_at=NULL WHERE id=$1`, first.ID)
	for _, sql := range []string{
		`UPDATE users SET username_key=NULL,username_details_encrypted=NULL,username_policy_id=NULL,username_policy_fingerprint=NULL,username_policy_epoch=NULL,username_lookup_key_id=NULL WHERE id=$1`,
		`UPDATE users SET username_details_encrypted=decode(repeat('00',100),'hex') WHERE id=$1`,
		`UPDATE users SET username_key=sha256('different') WHERE id=$1`,
		`UPDATE users SET username_policy_epoch=username_policy_epoch+1 WHERE id=$1`,
		`UPDATE users SET id=gen_random_uuid() WHERE id=$1`,
	} {
		if _, err := api.Exec(f.ctx, sql, first.ID); err == nil {
			t.Fatal("ordinary tuple rename/clear permitted")
		}
	}
	// Caller-settable state cannot create a maintenance bypass.
	tx, err := api.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `SELECT set_config('username.maintenance','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE users SET username_details_encrypted=decode(repeat('00',100),'hex') WHERE id=$1`, first.ID); err == nil {
		t.Fatal("caller-settable bypass succeeded")
	}
	rollbackUsername(tx)
	for _, sql := range []string{`ALTER TABLE users DISABLE TRIGGER users_username_immutable`, `SET session_replication_role=replica`, `UPDATE username_active_policy SET admission_state='closed'`, `DELETE FROM username_active_policy`, `TRUNCATE users`} {
		if _, err := api.Exec(f.ctx, sql); err == nil {
			t.Fatal("ordinary guard bypass authority permitted")
		}
	}
	// Partial tuples and non-32-byte keys are refused at the SQL boundary.
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET username_details_encrypted=decode(repeat('00',100),'hex') WHERE id=$1`, second.ID); err == nil {
		t.Fatal("partial tuple accepted")
	}
	a := f.normalizer.Authority()
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET username_key=$2,username_details_encrypted=$3,username_policy_id=$4,username_policy_fingerprint=$5,username_policy_epoch=1,username_lookup_key_id=$6 WHERE id=$1`, second.ID, []byte{1}, bytes.Repeat([]byte{1}, 100), a.PolicyID, a.Fingerprint[:], a.KeyID); err == nil {
		t.Fatal("wrong-length key accepted")
	}
}

func TestUsernameAssignmentRacesAndLockedAuthorizationIntegration(t *testing.T) {
	f := usernameFixture(t)
	usernameActivateFixture(t, f)
	value := usernameChosen(t, f.normalizer, "\u0643\u06cc\u0648\u0627\u0646")
	alias := usernameChosen(t, f.normalizer, "\u06a9\u06cc\u0648\u0627\u0646")
	users := []db.User{usernameUser(t, f), usernameUser(t, f)}
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	var wait sync.WaitGroup
	for i := range 2 {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			<-start
			v := value
			if i == 1 {
				v = alias
			}
			outcomes <- usernameAssign(f, f.store, users[i].ID, users[i].AuthVersion, v)
		}(i)
	}
	close(start)
	wait.Wait()
	close(outcomes)
	wins, conflicts := 0, 0
	for err := range outcomes {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("equivalent names did not have one owner")
	}
	account := usernameUser(t, f)
	start = make(chan struct{})
	outcomes = make(chan error, 2)
	for _, input := range []string{"\u0633", "\u0635"} {
		v := usernameChosen(t, f.normalizer, input)
		go func() { <-start; outcomes <- usernameAssign(f, f.store, account.ID, account.AuthVersion, v) }()
	}
	close(start)
	wins, conflicts = 0, 0
	for range 2 {
		err := <-outcomes
		if err == nil {
			wins++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("competing initial assignments overwrote account")
	}
	for _, status := range []string{"suspended", "banned", "pending_verification", "pending_deletion"} {
		user := usernameUser(t, f)
		usernameExec(t, f, `UPDATE users SET status=$2 WHERE id=$1`, user.ID, status)
		if err := usernameAssign(f, f.store, user.ID, user.AuthVersion, value); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("inactive assignment admitted", err)
		}
	}
	for _, sql := range []string{`UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, `UPDATE users SET deleted_at=now() WHERE id=$1`} {
		user := usernameUser(t, f)
		usernameExec(t, f, sql, user.ID)
		if err := usernameAssign(f, f.store, user.ID, user.AuthVersion, value); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("stale/deleted authority admitted", err)
		}
	}
	// A blocked waiter must decide from a fresh statement after moderation.
	user := usernameUser(t, f)
	blocker, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackUsername(blocker)
	if err := f.store.Guard(f.ctx, blocker); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, blocker, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(f.ctx, `UPDATE users SET auth_version=auth_version+1,status='suspended' WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- usernameAssign(f, f.store, user.ID, user.AuthVersion, usernameChosen(t, f.normalizer, "\u062b"))
	}()
	if err := blocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrUnauthorized) {
		t.Fatal("deciding read used pre-lock authority", err)
	}
}

func TestUsernamePolicyFencesWrongKeyAndPhysicalReleaseIntegration(t *testing.T) {
	f := usernameFixture(t)
	usernameActivateFixture(t, f)
	value := usernameChosen(t, f.normalizer, "\u0628")
	user := usernameUser(t, f)
	if err := usernameAssign(f, f.store, user.ID, user.AuthVersion, value); err != nil {
		t.Fatal(err)
	}
	wrong, err := New(f.normalizer.Policy(), fixtureRegex, bytes.Repeat([]byte{0x99}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := NewStore(f.pool, f.cipher, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if available, err := wrongStore.Available(f.ctx, usernameChosen(t, wrong, "\u062a")); !errors.Is(err, ErrPolicyMismatch) || available {
		t.Fatal("wrong actual key returned availability")
	}
	if _, err := wrongStore.Lookup(f.ctx, "\u062a"); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatal("wrong actual key returned not-found")
	}
	policy := f.normalizer.Policy()
	policy.ID = uuid.New()
	stale, err := New(policy, fixtureRegex, bytes.Repeat([]byte{0x59}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	staleStore, _ := NewStore(f.pool, f.cipher, stale)
	if available, err := staleStore.Available(f.ctx, usernameChosen(t, stale, "\u062a")); !errors.Is(err, ErrPolicyMismatch) || available {
		t.Fatal("stale artifact returned availability")
	}
	guard, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcquireOwnershipGuard(f.ctx, guard); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(f.ctx, 150*time.Millisecond)
	_, err = f.pool.Exec(bounded, `UPDATE username_active_policy SET admission_state='closed'`)
	cancel()
	if err == nil {
		t.Fatal("exclusive policy transition did not wait for shared guard")
	}
	rollbackUsername(guard)
	usernameExec(t, f, `UPDATE username_active_policy SET admission_state='closed'`)
	guard, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcquireOwnershipGuard(f.ctx, guard); !errors.Is(err, ErrUnavailable) {
		t.Fatal("purge admitted while writer gate closed")
	}
	rollbackUsername(guard)
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM users WHERE id=$1`, user.ID); err == nil {
		t.Fatal("direct SQL release ignored closed gate")
	}
	usernameExec(t, f, `UPDATE username_active_policy SET admission_state='open'`)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcquireOwnershipGuard(f.ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, tx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `DELETE FROM users WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	rollbackUsername(tx)
	if available, err := f.store.Available(f.ctx, value); err != nil || available {
		t.Fatal("rolled-back purge released reservation")
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := AcquireOwnershipGuard(f.ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, tx, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `DELETE FROM users WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if available, err := f.store.Available(f.ctx, value); err != nil || !available {
		t.Fatal("physical deletion did not release key")
	}
}

func preflightOptions() PreflightOptions {
	return PreflightOptions{PageSize: 1, MaxRows: 100, MaxIssues: 10, Timeout: 30 * time.Second, ReviewKey: bytes.Repeat([]byte{0x66}, 32)}
}

func TestUsernameOperatorInactiveIdentityAndCompletePreflightIntegration(t *testing.T) {
	f := usernameFixture(t)
	installer := usernameRole(t, f, "installer")
	reader := usernameRole(t, f, "reader")
	if err := InstallInactive(f.ctx, f.pool, f.normalizer); err == nil {
		t.Fatal("database owner admitted as installer")
	}
	if err := InstallInactive(f.ctx, installer, f.normalizer); err != nil {
		t.Fatal("actual insert-only installation refused", err)
	}
	if err := InstallInactive(f.ctx, installer, f.normalizer); err != nil {
		t.Fatal("exact immutable replay failed", err)
	}
	active, err := db.New(f.pool).GetUsernamePolicy(f.ctx)
	if err != nil || active.AdmissionState != "uninstalled" || active.Epoch != 0 {
		t.Fatal("inactive installation activated namespace")
	}
	changed, err := New(f.normalizer.Policy(), `\x{0628}+`, bytes.Repeat([]byte{0x59}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallInactive(f.ctx, installer, changed); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatal("same ID changed artifact accepted", err)
	}
	p := f.normalizer.Policy()
	p.ID = uuid.New()
	changedKey, err := New(p, fixtureRegex, bytes.Repeat([]byte{0x77}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallInactive(f.ctx, installer, changedKey); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatal("same key ID changed secret accepted", err)
	}
	if _, err := db.New(f.pool).GetUsernameArtifact(f.ctx, p.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("failed key binding leaked partial artifact")
	}
	for _, pool := range []*pgxpool.Pool{installer, reader} {
		for _, sql := range []string{`UPDATE username_policy_artifacts SET artifact=artifact`, `DELETE FROM username_lookup_keys`, `UPDATE username_active_policy SET admission_state='open'`, `UPDATE users SET display_name='leak'`} {
			if _, err := pool.Exec(f.ctx, sql); err == nil {
				t.Fatal("operator grants permit mutation outside contract")
			}
		}
	}
	for _, sql := range []string{`UPDATE username_policy_artifacts SET artifact=artifact`, `DELETE FROM username_lookup_keys`, `TRUNCATE username_policy_artifacts`, `DELETE FROM username_active_policy`} {
		if _, err := f.pool.Exec(f.ctx, sql); err == nil {
			t.Fatal("immutable registry accepts ordinary SQL")
		}
	}
	usernameUser(t, f)
	usernameUser(t, f)
	usernameUser(t, f)
	report, err := Preflight(f.ctx, reader, f.cipher, f.normalizer, f.normalizer, preflightOptions())
	if err != nil || !report.Complete || !report.Clean || report.Scanned != 3 || report.Unclaimed != 3 || report.Claimed != 0 {
		t.Fatal("full baseline inventory incorrectly counted", report, err)
	}
	options := preflightOptions()
	options.MaxRows = 2
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, f.normalizer, options)
	if !errors.Is(err, ErrIncomplete) || report.Complete || report.Clean || report.Scanned != 2 || report.Reason != "row_limit" {
		t.Fatal("capped scan treated as clearance", report, err)
	}
	options.MaxRows = 3
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, f.normalizer, options)
	if err != nil || !report.Complete || !report.Clean {
		t.Fatal("exact-cap complete scan classified incomplete", report, err)
	}
	report, err = Preflight(f.ctx, f.pool, f.cipher, f.normalizer, f.normalizer, options)
	if !errors.Is(err, ErrIncomplete) || report.Reason != "privileges_unproven" || report.Complete {
		t.Fatal("owner scan claimed operator privilege evidence")
	}
}

func TestUsernamePreflightCrossPageReservedCollisionsAndUnreadableRowsIntegration(t *testing.T) {
	f := usernameFixture(t)
	usernameActivateFixture(t, f)
	names := []string{"\u0633", "\u0635"}
	users := make([]db.User, 0, 2)
	for _, name := range names {
		user := usernameUser(t, f)
		users = append(users, user)
		if err := usernameAssign(f, f.store, user.ID, user.AuthVersion, usernameChosen(t, f.normalizer, name)); err != nil {
			t.Fatal(err)
		}
		usernameExec(t, f, `UPDATE users SET status='banned',deleted_at=now() WHERE id=$1`, user.ID)
	}
	usernameUser(t, f)
	policy := f.normalizer.Policy()
	policy.ID = uuid.New()
	policy.ReservedNames = names
	candidate, err := New(policy, fixtureRegex, bytes.Repeat([]byte{0x59}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	installer := usernameRole(t, f, "installer")
	if err := InstallInactive(f.ctx, installer, candidate); err != nil {
		t.Fatal(err)
	}
	reader := usernameRole(t, f, "reader")
	report, err := Preflight(f.ctx, reader, f.cipher, f.normalizer, candidate, preflightOptions())
	if err != nil || !report.Complete || report.Clean || report.Collisions != 2 || report.Claimed != 2 || report.Unclaimed != 1 || report.ReservedNames != 2 {
		t.Fatal("cross-page inactive-owner/reserved collisions missed", report, err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range append(names, users[0].ID.String(), users[1].ID.String()) {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private collision material leaked in report")
		}
	}
	options := preflightOptions()
	options.MaxIssues = 1
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, candidate, options)
	if err != nil || !report.Complete || report.Clean || !report.IssuesTruncated || report.Collisions != 2 {
		t.Fatal("bounded report lost collision counts")
	}
	// Owner-only corrupt fixture construction tests fail-closed read checks.
	// The ordinary role cannot invoke this DDL or a maintenance bypass.
	usernameExec(t, f, `ALTER TABLE users DISABLE TRIGGER users_username_immutable`)
	usernameExec(t, f, `UPDATE users SET username_details_encrypted=decode(repeat('00',100),'hex') WHERE id=$1`, users[0].ID)
	usernameExec(t, f, `ALTER TABLE users ENABLE TRIGGER users_username_immutable`)
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, candidate, preflightOptions())
	if err != nil || !report.Complete || report.Clean || report.Unreadable != 1 {
		t.Fatal("unreadable owner treated as absent/clean", report, err)
	}
	wrong, err := New(f.normalizer.Policy(), fixtureRegex, bytes.Repeat([]byte{0x90}, 32), f.normalizer.Authority().KeyID)
	if err != nil {
		t.Fatal(err)
	}
	report, err = Preflight(f.ctx, reader, f.cipher, wrong, candidate, preflightOptions())
	if !errors.Is(err, ErrIncomplete) || report.Complete || report.Reason != "current_authority_mismatch" {
		t.Fatal("wrong current key allowed scan clearance")
	}
	// SQL errors must not expose raw identity/key/ciphertext diagnostics.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		t.Fatal("raw PostgreSQL diagnostics leaked")
	}
	// A failed page after a snapshot began is not clearance, even when the
	// previously visited prefix contained no new collision.
	canceled, stop := context.WithCancel(f.ctx)
	cipher := &cancelingInventoryCipher{Cipher: f.cipher, cancel: stop}
	report, err = Preflight(canceled, reader, cipher, f.normalizer, candidate, preflightOptions())
	stop()
	if !errors.Is(err, ErrIncomplete) || report.Complete || report.Clean || report.Reason != "account_scan_failed" {
		t.Fatal("failed midscan treated as clearance", report, err)
	}
	// A row referring to an unreadable installed artifact is explicitly unknown,
	// not converted into an unclaimed account or normalized with a fallback.
	badPolicy := uuid.New()
	badArtifact := []byte("unreviewed artifact")
	badFingerprint := bytes.Repeat([]byte{0x80}, 32)
	usernameExec(t, f, `INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, badPolicy, badFingerprint, badArtifact)
	usernameExec(t, f, `ALTER TABLE users DISABLE TRIGGER users_username_immutable`)
	usernameExec(t, f, `UPDATE users SET username_policy_id=$2,username_policy_fingerprint=$3 WHERE id=$1`, users[0].ID, badPolicy, badFingerprint)
	usernameExec(t, f, `ALTER TABLE users ENABLE TRIGGER users_username_immutable`)
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, candidate, preflightOptions())
	unknown := false
	for _, issue := range report.Issues {
		if issue.Kind == "unknown_policy" {
			unknown = true
		}
	}
	if err != nil || !report.Complete || report.Clean || report.PolicyErrors < 2 || !unknown {
		t.Fatal("unknown policy owner treated as clear", report, err)
	}
	usernameExec(t, f, `UPDATE username_active_policy SET admission_state='uninstalled',policy_id=NULL,fingerprint=NULL,key_id=NULL,key_verifier=NULL,epoch=0`)
	report, err = Preflight(f.ctx, reader, f.cipher, f.normalizer, candidate, preflightOptions())
	if err != nil || !report.Complete || report.Clean || report.Inconsistent < 1 {
		t.Fatal("claimed row without authority treated as unclaimed", report, err)
	}
}

type cancelingInventoryCipher struct {
	Cipher
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelingInventoryCipher) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	c.once.Do(c.cancel)
	return c.Cipher.Decrypt(ctx, blob)
}

func TestUsernameStoredCiphertextAccountPurposePolicyEpochBindingsIntegration(t *testing.T) {
	f := usernameFixture(t)
	usernameActivateFixture(t, f)
	value := usernameChosen(t, f.normalizer, "\u062a")
	user := usernameUser(t, f)
	if err := usernameAssign(f, f.store, user.ID, user.AuthVersion, value); err != nil {
		t.Fatal(err)
	}
	row, err := db.New(f.pool).ReadUsername(f.ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	a := GuardAuthority{Authority: f.normalizer.Authority(), Epoch: 1}
	original, err := f.cipher.Decrypt(f.ctx, row.UsernameDetailsEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	for _, kind := range []string{"account", "purpose", "policy", "epoch", "security", "display"} {
		var details storageDetails
		if json.Unmarshal(original, &details) != nil {
			t.Fatal("fixture payload malformed")
		}
		switch kind {
		case "account":
			details.AccountID = uuid.New()
		case "purpose":
			details.Purpose = "registration"
		case "policy":
			details.Authority.PolicyID = uuid.New()
		case "epoch":
			details.Authority.Epoch++
		case "security":
			details.SecurityName = "\u0628"
		case "display":
			details.Display = "\u0628"
		}
		raw, err := json.Marshal(details)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := f.cipher.Encrypt(f.ctx, raw)
		clear(raw)
		if err != nil {
			t.Fatal(err)
		}
		changed := row
		changed.UsernameDetailsEncrypted = blob
		if _, err := f.store.openStorage(f.ctx, changed, a); !errors.Is(err, ErrUnavailable) {
			t.Fatal("ciphertext binding substitution admitted", kind, err)
		}
	}
}

func TestUsernameWeakenedSchemaFailsReadinessIntegration(t *testing.T) {
	for name, sql := range map[string]string{
		"tuple":                 `ALTER TABLE users DROP CONSTRAINT users_username_tuple; ALTER TABLE users ADD CONSTRAINT users_username_tuple CHECK(TRUE)`,
		"nullable":              `ALTER TABLE users ALTER COLUMN username_policy_epoch SET NOT NULL`,
		"unique":                `ALTER TABLE users DROP CONSTRAINT users_username_key_unique; CREATE UNIQUE INDEX users_username_key_unique ON users(username_key) WHERE deleted_at IS NULL`,
		"deferred_unique":       `ALTER TABLE users DROP CONSTRAINT users_username_key_unique; ALTER TABLE users ADD CONSTRAINT users_username_key_unique UNIQUE(username_key) DEFERRABLE INITIALLY DEFERRED`,
		"null_unique":           `ALTER TABLE users DROP CONSTRAINT users_username_key_unique; ALTER TABLE users ADD CONSTRAINT users_username_key_unique UNIQUE NULLS NOT DISTINCT(username_key)`,
		"unknown_legacy_source": `ALTER TABLE users ADD COLUMN username TEXT`,
		"guard_disabled":        `ALTER TABLE users DISABLE TRIGGER users_username_immutable`,
		"guard_body":            `CREATE OR REPLACE FUNCTION public.username_ownership_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$`,
		"guard_columns":         `DROP TRIGGER users_username_immutable ON users; CREATE TRIGGER users_username_immutable BEFORE INSERT OR UPDATE OF username_key OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION username_ownership_guard()`,
	} {
		t.Run(name, func(t *testing.T) {
			f := usernameFixture(t)
			usernameExec(t, f, sql)
			if err := CheckSchema(f.ctx, f.pool); !errors.Is(err, ErrUnavailable) {
				t.Fatal("weakened storage boundary admitted", err)
			}
		})
	}
}
