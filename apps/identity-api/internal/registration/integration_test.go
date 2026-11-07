//go:build integration

package registration

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only this helper's unique child database is migrated. DATABASE_URL supplies
// provisioning access, never an application dataset to adopt, clean or migrate.
func registrationDatabase(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for registration integration tests")
	}
	admin, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error("registration provisioning close failed")
		}
	})
	name := "registration_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Logf("run-owned registration fixture database: %s", name)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Errorf("registration fixture drop failed: %v", err)
		}
		var exists bool
		if err := admin.QueryRowContext(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Error("registration fixture cleanup not confirmed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB, err := migrate.Open(ctx, cfg.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(ctx, pool); err != nil {
		t.Fatal("new migration schema readiness failed", err)
	}
	return ctx, pool
}

func registrationExec(t *testing.T, ctx context.Context, q db.DBTX, sql string, args ...any) {
	t.Helper()
	if _, err := q.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func registrationRole(t *testing.T, ctx context.Context, root *pgxpool.Pool, kind string) (*pgxpool.Pool, string) {
	t.Helper()
	name := "registration_" + kind + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	password := uuid.NewString()
	registrationExec(t, ctx, root, "CREATE ROLE "+quoted+" LOGIN NOINHERIT PASSWORD '"+password+"'")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		registrationExec(t, cleanup, root, "DROP OWNED BY "+quoted)
		registrationExec(t, cleanup, root, "DROP ROLE "+quoted)
	})
	registrationExec(t, ctx, root, "GRANT CONNECT ON DATABASE "+pgx.Identifier{root.Config().ConnConfig.Database}.Sanitize()+" TO "+quoted)
	registrationExec(t, ctx, root, "GRANT USAGE ON SCHEMA public TO "+quoted)
	if kind == "cleanup" {
		registrationExec(t, ctx, root, "GRANT SELECT, DELETE ON public.registration_attempts TO "+quoted)
		registrationExec(t, ctx, root, "GRANT SELECT ON public.legal_holds TO "+quoted)
	} else {
		registrationExec(t, ctx, root, "GRANT SELECT, INSERT ON public.registration_attempts TO "+quoted)
		columns := make([]string, 0)
		for _, column := range APIUpdateColumns() {
			columns = append(columns, pgx.Identifier{column}.Sanitize())
		}
		registrationExec(t, ctx, root, "GRANT UPDATE ("+strings.Join(columns, ",")+") ON public.registration_attempts TO "+quoted)
	}
	cfg := root.Config().Copy()
	cfg.ConnConfig.User = name
	cfg.ConnConfig.Password = password
	cfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var current, login string
	if err := pool.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&current, &login); err != nil || current != name || login != name {
		t.Fatal("fixture is not actual restricted login")
	}
	return pool, quoted
}

func TestRegistrationRealRolePrivilegesAndSchemaReadiness(t *testing.T) {
	ctx, root := registrationDatabase(t)
	cleaner, cleanupRole := registrationRole(t, ctx, root, "cleanup")
	api, apiRole := registrationRole(t, ctx, root, "api")
	if err := CheckCleanupReady(ctx, cleaner); err != nil {
		t.Fatal("least-privilege actual cleanup login refused", err)
	}
	if err := CheckCleanupReady(ctx, root); err != dbprivilege.ErrUnsafe {
		t.Fatal("owner/superuser cleanup admitted")
	}
	for name, sql := range map[string]string{
		"insert":      `INSERT INTO public.registration_attempts(id) VALUES(gen_random_uuid())`,
		"update":      `UPDATE public.registration_attempts SET state='failed'`,
		"delete user": `DELETE FROM public.users`, "read user": `SELECT * FROM public.users`,
		"hold mutation": `DELETE FROM public.legal_holds`, "create": `CREATE TABLE public.privilege_leak(id integer)`,
		"set role": "SET ROLE " + apiRole,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := cleaner.Exec(ctx, sql)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("cleanup grant denial failed: %v", err)
			}
		})
	}
	for _, sql := range []string{`DELETE FROM public.registration_attempts`, `UPDATE public.registration_attempts SET expires_at=expires_at+interval '1 minute'`, `UPDATE public.registration_attempts SET jkt='changed'`, `UPDATE public.registration_attempts SET capability_hash=sha256('changed')`} {
		_, err := api.Exec(ctx, sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("API frozen authority/delete grant widened: %v", err)
		}
	}
	registrationExec(t, ctx, root, "GRANT UPDATE ON public.registration_attempts TO "+cleanupRole)
	if err := CheckCleanupReady(ctx, cleaner); err != dbprivilege.ErrUnsafe {
		t.Fatal("overgranted cleanup login admitted")
	}
	registrationExec(t, ctx, root, "REVOKE UPDATE ON public.registration_attempts FROM "+cleanupRole)
	registrationExec(t, ctx, root, "GRANT "+apiRole+" TO "+cleanupRole)
	if err := CheckCleanupReady(ctx, cleaner); err != dbprivilege.ErrUnsafe {
		t.Fatal("NOINHERIT role membership admitted")
	}
	registrationExec(t, ctx, root, "REVOKE "+apiRole+" FROM "+cleanupRole)
	if err := CheckCleanupReady(ctx, cleaner); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(api, testCipher(t), 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckReady(ctx); err != nil {
		t.Fatal("API schema/envelope readiness failed", err)
	}
	a, secret, err := s.Create(ctx, "person@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal("narrow API admission failed", err)
	}
	defer clear(secret)
	tx, err := api.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	locked, err := s.Lock(ctx, tx, a.Record.ID, secret, a.Record.Jkt)
	if err != nil {
		t.Fatal("narrow API row lock failed", err)
	}
	locked.Record.EmailTokenHash = bytes.Repeat([]byte{6}, 32)
	locked.Record.EmailTokenIssuedAt = timestamp(time.Now())
	locked.Record.EmailTokenExpiresAt = timestamp(locked.Record.EmailTokenIssuedAt.Time.Add(EmailLifetime))
	if _, err := s.Save(ctx, tx, locked); err != nil {
		t.Fatal("narrow API proof save failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationSharedCapacityExpiredPendingAndRestart(t *testing.T) {
	ctx, root := registrationDatabase(t)
	api, _ := registrationRole(t, ctx, root, "api")
	cleaner, _ := registrationRole(t, ctx, root, "cleanup")
	stores := make([]*Store, 2)
	for i := range stores {
		s, err := NewStore(api, testCipher(t), 1)
		if err != nil {
			t.Fatal(err)
		}
		s.now = func() time.Time { return time.Now().Add(-16 * time.Minute) }
		stores[i] = s
	}
	var wait sync.WaitGroup
	results := make(chan error, 8)
	for i := range 8 {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			_, secret, err := stores[i%2].Create(ctx, "person@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			clear(secret)
			results <- err
		}(i)
	}
	wait.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if err != ErrCapacity {
			t.Fatalf("unexpected capacity outcome: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("replicas admitted %d attempts through capacity 1", wins)
	}
	var users, attempts int
	if err := root.QueryRow(ctx, `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM registration_attempts)`).Scan(&users, &attempts); err != nil || users != 0 || attempts != 1 {
		t.Fatal("pending authority created an account or overflowed")
	}
	stats, err := Cleanup(ctx, cleaner, 10)
	if err != nil || stats.Deleted != 1 {
		t.Fatalf("expired pending cleanup failed: %+v %v", stats, err)
	}
	restarted, err := NewStore(api, testCipher(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, secret, err := restarted.Create(ctx, "person@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal("cleanup capacity not restored on reconstructed store", err)
	} else {
		clear(secret)
	}
}

func completedRegistration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, start time.Time) (Attempt, []byte) {
	t.Helper()
	s, err := NewStore(pool, testCipher(t), 100)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return start }
	email := "registration-" + uuid.NewString() + "@example.com"
	a, secret, err := s.Create(ctx, email, "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	a, err = s.Lock(ctx, tx, a.Record.ID, secret, a.Record.Jkt)
	if err != nil {
		t.Fatal(err)
	}
	a.Record.EmailTokenIssuedAt = timestamp(start)
	a.Record.EmailTokenExpiresAt = timestamp(start.Add(EmailLifetime))
	a.Record.EmailVerifiedAt = timestamp(start.Add(time.Second))
	a.Record.SmsVerificationRef = uuid.NullUUID{UUID: uuid.New(), Valid: true}
	a.Record.PhoneVerifiedAt = timestamp(start.Add(2 * time.Second))
	a.Record.ChallengeRevision = 1
	a.Record.PasskeyCreatedAt = timestamp(start.Add(3 * time.Second))
	a.Record.PasskeyExpiresAt = timestamp(start.Add(3*time.Second + PasskeyLifetime))
	a.Details.Ceremony = []byte(`{"challenge":"fixture-server-ceremony"}`)
	a.Details.CeremonyRevision = 1
	s.now = func() time.Time { return start.Add(4 * time.Second) }
	a, err = s.Save(ctx, tx, a)
	if err != nil {
		t.Fatal(err)
	}
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO public.users(email) VALUES($1) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	complete, err := s.Complete(ctx, tx, a, userID, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return complete, secret
}

func TestRegistrationReceiptCleanupHoldContentionFailureAndPurge(t *testing.T) {
	ctx, root := registrationDatabase(t)
	cleaner, _ := registrationRole(t, ctx, root, "cleanup")
	held, secret := completedRegistration(t, ctx, root, time.Now().Add(-80*time.Minute))
	defer clear(secret)
	contended, key := completedRegistration(t, ctx, root, time.Now().Add(-79*time.Minute))
	defer clear(key)
	free, freeKey := completedRegistration(t, ctx, root, time.Now().Add(-78*time.Minute))
	defer clear(freeKey)
	registrationExec(t, ctx, root, `INSERT INTO public.legal_holds(account_ref,applied_by,details_encrypted) VALUES($1,gen_random_uuid(),'\x01')`, held.Record.ResultUserID.UUID)
	blocker, err := root.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(blocker)
	if err := pglock.LockAccount(ctx, blocker, contended.Record.ResultUserID.UUID); err != nil {
		t.Fatal(err)
	}
	stats, err := Cleanup(ctx, cleaner, 10)
	if err != nil || stats.Deleted != 1 || stats.Contended != 1 {
		t.Fatalf("held/contention blocked unrelated progress: %+v %v", stats, err)
	}
	var exists bool
	if err := root.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM registration_attempts WHERE id=$1)`, free.Record.ID).Scan(&exists); err != nil || exists {
		t.Fatal("free receipt not deleted")
	}
	rollback(blocker)
	registrationExec(t, ctx, root, `UPDATE legal_holds SET is_active=false,released_at=now() WHERE account_ref=$1`, held.Record.ResultUserID.UUID)
	restarted, err := NewStore(root, testCipher(t), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Get(ctx, held.Record.ID, secret, held.Record.Jkt); err != ErrExpired {
		t.Fatal("hold release reactivated expired receipt")
	}
	stats, err = Cleanup(ctx, cleaner, 10)
	if err != nil || stats.Deleted != 2 {
		t.Fatalf("restart cleanup did not resume deferred rows: %+v %v", stats, err)
	}
	pending, capability, err := restarted.Create(ctx, "pending@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(capability)
	if _, err := restarted.Get(ctx, pending.Record.ID, capability, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"); err != ErrUnauthorized {
		t.Fatal("foreign JKT authorized")
	}
	registrationExec(t, ctx, root, `UPDATE registration_attempts SET details_encrypted=set_byte(details_encrypted,octet_length(details_encrypted)-1,$2) WHERE id=$1`, pending.Record.ID, int(pending.Record.DetailsEncrypted[len(pending.Record.DetailsEncrypted)-1]^1))
	if _, err := restarted.Get(ctx, pending.Record.ID, capability, pending.Record.Jkt); err != ErrInvalid {
		t.Fatal("corrupt pending envelope accepted")
	}
	receipt, receiptKey := completedRegistration(t, ctx, root, time.Now().Add(-time.Minute))
	defer clear(receiptKey)
	got, err := restarted.Get(ctx, receipt.Record.ID, receiptKey, receipt.Record.Jkt)
	if err != nil {
		t.Fatal(err)
	}
	if _, replay, err := CheckReplay(got, bytes.Repeat([]byte{7}, 32)); err != nil || !replay {
		t.Fatal("lost-response replay receipt unavailable")
	}
	registrationExec(t, ctx, root, `DELETE FROM users WHERE id=$1`, receipt.Record.ResultUserID.UUID)
	if err := root.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM registration_attempts WHERE id=$1)`, receipt.Record.ID).Scan(&exists); err != nil || exists {
		t.Fatal("receipt FK prevented lawful account purge")
	}
}

func TestRegistrationSQLConstraintsAndCleanupFailureResume(t *testing.T) {
	ctx, root := registrationDatabase(t)
	cleaner, _ := registrationRole(t, ctx, root, "cleanup")
	// Every mutation is in this unique fixture, never in the provisioning DB.
	s, err := NewStore(root, testCipher(t), 100)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(-16 * time.Minute) }
	a, key, err := s.Create(ctx, "first@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	b, key2, err := s.Create(ctx, "second@example.com", "+989123456789", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key2)
	for name, sql := range map[string]string{
		"state":           `UPDATE registration_attempts SET state='verified' WHERE id=$1`,
		"hash":            `UPDATE registration_attempts SET capability_hash='\x01' WHERE id=$1`,
		"jkt":             `UPDATE registration_attempts SET jkt='short' WHERE id=$1`,
		"expiry":          `UPDATE registration_attempts SET expires_at=expires_at+interval '1 second' WHERE id=$1`,
		"infinity":        `UPDATE registration_attempts SET created_at='infinity' WHERE id=$1`,
		"pending account": `UPDATE registration_attempts SET result_user_id=gen_random_uuid() WHERE id=$1`,
		"proof":           `UPDATE registration_attempts SET email_verified_at=created_at WHERE id=$1`,
		"email ttl":       `UPDATE registration_attempts SET email_token_issued_at=created_at,email_token_expires_at=created_at+interval '11 minutes' WHERE id=$1`,
		"ceremony":        `UPDATE registration_attempts SET passkey_created_at=created_at,passkey_expires_at=created_at+interval '6 minutes' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := root.Exec(ctx, sql, a.Record.ID)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || (pgErr.Code != "23514" && pgErr.Code != "23503") {
				t.Fatalf("invalid SQL state accepted: %v", err)
			}
		})
	}
	function := `CREATE FUNCTION public.registration_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id='` + b.Record.ID.String() + `'::uuid THEN RAISE EXCEPTION 'fixture delete failure'; END IF; RETURN OLD; END $$`
	registrationExec(t, ctx, root, function)
	registrationExec(t, ctx, root, `CREATE TRIGGER registration_fixture_failure BEFORE DELETE ON registration_attempts FOR EACH ROW EXECUTE FUNCTION registration_fixture_failure()`)
	stats, err := Cleanup(ctx, cleaner, 10)
	if err != ErrUnavailable || stats.Deleted != 1 {
		t.Fatalf("later delete failure rolled back prior candidate: %+v %v", stats, err)
	}
	registrationExec(t, ctx, root, `DROP TRIGGER registration_fixture_failure ON registration_attempts`)
	stats, err = Cleanup(ctx, cleaner, 10)
	if err != nil || stats.Deleted != 1 {
		t.Fatalf("failed candidate did not resume: %+v %v", stats, err)
	}
}

func TestRegistrationReadinessRejectsMalformedSchema(t *testing.T) {
	ctx, root := registrationDatabase(t)
	for name, ddl := range map[string]string{
		"extra column":           `ALTER TABLE registration_attempts ADD COLUMN raw_email text`,
		"wrong type":             `ALTER TABLE registration_attempts ALTER COLUMN jkt TYPE varchar(43)`,
		"nullable authority":     `ALTER TABLE registration_attempts ALTER COLUMN capability_hash DROP NOT NULL`,
		"missing time check":     `ALTER TABLE registration_attempts DROP CONSTRAINT registration_attempt_times`,
		"weakened time check":    `ALTER TABLE registration_attempts DROP CONSTRAINT registration_attempt_times; ALTER TABLE registration_attempts ADD CONSTRAINT registration_attempt_times CHECK(true)`,
		"unvalidated time check": `ALTER TABLE registration_attempts DROP CONSTRAINT registration_attempt_times; ALTER TABLE registration_attempts ADD CONSTRAINT registration_attempt_times CHECK(expires_at > created_at) NOT VALID`,
		"missing FK":             `ALTER TABLE registration_attempts DROP CONSTRAINT registration_attempts_result_user_id_fkey`,
		"wrong cascade":          `ALTER TABLE registration_attempts DROP CONSTRAINT registration_attempts_result_user_id_fkey; ALTER TABLE registration_attempts ADD FOREIGN KEY(result_user_id) REFERENCES users(id) ON DELETE RESTRICT`,
		"wrong index":            `DROP INDEX idx_registration_pending_expiry; CREATE INDEX idx_registration_pending_expiry ON registration_attempts(created_at,id) WHERE state='pending'`,
		"wrong predicate":        `DROP INDEX idx_registration_receipt_expiry; CREATE INDEX idx_registration_receipt_expiry ON registration_attempts(receipt_expires_at,id) WHERE state='failed'`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := root.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer rollback(tx)
			registrationExec(t, ctx, tx, ddl)
			if err := CheckSchema(ctx, tx); err != ErrUnavailable {
				t.Fatal("malformed signup storage admitted", err)
			}
		})
	}
	if err := CheckSchema(ctx, root); err != nil {
		t.Fatal("schema refusal mutated valid fixture", err)
	}
}
