//go:build integration

package actionproof

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

// Rewrite only the owned client's script keys. Production Lua/budgets remain
// unchanged and cleanup never flushes or enumerates another fixture's keys.
type ownedScriptKeys struct{ prefix string }

func (h ownedScriptKeys) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h ownedScriptKeys) rewrite(cmd redis.Cmder) {
	if cmd.Name() != "eval" && cmd.Name() != "evalsha" {
		return
	}
	args := cmd.Args()
	count, ok := args[2].(int)
	if !ok {
		return
	}
	for i := range count {
		key := args[3+i].(string)
		// Session Lua derives related keys internally. Its independently random
		// account/session IDs already isolate those records from other fixtures.
		if !strings.HasPrefix(key, "identity:session:v1:") {
			args[3+i] = h.prefix + key
		}
	}
}

func (h ownedScriptKeys) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.rewrite(cmd)
		return next(ctx, cmd)
	}
}

func (h ownedScriptKeys) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			h.rewrite(cmd)
		}
		return next(ctx, cmds)
	}
}

type realProofFixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	runtime  *pgxpool.Pool
	service  *Service
	sessions *session.Manager
	delivery *captureDelivery
	sess     session.Session
	user     db.User
}

func newRealProofFixture(t *testing.T) realProofFixture {
	return newRealProofFixtureFor(t, contactcode.PurposeAccountDeletion)
}

func newRealPasswordChangeFixture(t *testing.T) realProofFixture {
	return newRealProofFixtureFor(t, contactcode.PurposePasswordChange)
}

func newRealProofFixtureFor(t *testing.T, purpose string) realProofFixture {
	t.Helper()
	dsn, redisURL := strings.TrimSpace(os.Getenv("DATABASE_URL")), strings.TrimSpace(os.Getenv("REDIS_URL"))
	if dsn == "" || redisURL == "" {
		if os.Getenv("REQUIRE_ACTIONPROOF_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" {
			t.Fatal("run-owned PostgreSQL and Redis required by mandatory actionproof integration")
		}
		t.Skip("run-owned PostgreSQL and Redis not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid fixture PostgreSQL configuration")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal("configured fixture PostgreSQL unavailable")
	}
	name := "actionproof_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	role := "actionproof_role_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal("create run-owned actionproof database failed")
	}
	t.Logf("run-owned actionproof database: %s", name)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("run-owned actionproof database teardown failed")
		}
		if _, err := admin.Exec(cleanup, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Error("run-owned actionproof role teardown failed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid fixture PostgreSQL configuration")
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("run-owned actionproof database connection failed")
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned actionproof migrations failed", err)
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid fixture Redis configuration")
	}
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("configured fixture Redis unavailable")
	}
	prefix := "actionproof_test:" + uuid.NewString() + ":"
	client.AddHook(ownedScriptKeys{prefix})
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		var cursor uint64
		for {
			keys, next, err := client.Scan(cleanup, cursor, prefix+"*", 100).Result()
			if err != nil {
				t.Error("run-owned actionproof Redis scan failed")
				return
			}
			if len(keys) > 0 {
				if err := client.Del(cleanup, keys...).Err(); err != nil {
					t.Error("run-owned actionproof Redis teardown failed")
					return
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		keys, _, err := client.Scan(cleanup, 0, prefix+"*", 100).Result()
		if err != nil || len(keys) != 0 {
			t.Error("run-owned actionproof Redis teardown incomplete")
		}
	})
	delivery := &captureDelivery{}
	codes := purposeCodes(t, client, delivery, true, true, purpose)
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		t.Fatal(err)
	}
	q, cipher := db.New(pool), testCipher(t)
	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: new(uuid.NewString() + "@actionproof.invalid"), PasswordHash: new(credentialHash(t)), Status: "active"})
	if err != nil {
		t.Fatal("create actionproof fixture user failed")
	}
	now := time.Now().UTC()
	sess := session.Session{ID: uuid.NewString(), UserID: u.ID.String(), Kind: session.KindAuthenticated, AuthVersion: u.AuthVersion, AuthVersionSet: true, DPoPJKT: testCapability(1), CreatedAt: now, LastSeenAt: now, AbsoluteExpiry: now.Add(time.Hour), IdleExpiry: now.Add(time.Hour)}
	sessionStore, err := session.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	_, tokenHash, err := session.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := sessionStore.Create(ctx, tokenHash, sess); err != nil {
		t.Fatal("persist real fixture session failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := sessionStore.DeleteAllForUser(cleanup, sess.UserID); err != nil {
			t.Error("revoke run-owned fixture session failed")
		}
		user := strconv.Itoa(len(sess.UserID)) + ":" + sess.UserID
		if err := client.Del(cleanup, "identity:session:v1:token:"+tokenHash, "identity:session:v1:user:"+user, "identity:session:v1:id:"+user+":"+sess.ID).Err(); err != nil {
			t.Error("run-owned session marker cleanup failed")
		}
	})
	cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(sessionStore, cookie, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := contactproof.Seal(ctx, cipher, u.ID, contactproof.Email, *u.Email, contactproof.EmailLink, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.PutContactVerificationEvidence(ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Email, EvidenceEncrypted: blob}); err != nil {
		t.Fatal("persist fixture contact evidence failed")
	}
	phone, err := cipher.Encrypt(ctx, []byte("+989123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.SetUserPhone(ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: phone, PhoneBlindIndex: new(uuid.NewString())}); err != nil {
		t.Fatal("persist fixture phone failed")
	}
	phoneProof, err := contactproof.Seal(ctx, cipher, u.ID, contactproof.Phone, "+989123456789", contactproof.SMSOTP, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.PutContactVerificationEvidence(ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Phone, EvidenceEncrypted: phoneProof}); err != nil {
		t.Fatal("persist fixture phone evidence failed")
	}
	if _, err := pool.Exec(ctx, "CREATE TABLE public.proof_test_actions (id BIGSERIAL PRIMARY KEY, user_id UUID NOT NULL)"); err != nil {
		t.Fatal("create test-only action table failed")
	}
	roleSQL := pgx.Identifier{role}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+roleSQL+" NOLOGIN"); err != nil {
		t.Fatal("create run-owned proof runtime role failed")
	}
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA public TO ",
		"GRANT SELECT ON public.users,public.webauthn_credentials,public.user_roles,public.contact_verification_evidence TO ",
		"GRANT UPDATE(id) ON public.users TO ", // Required by SELECT ... FOR UPDATE, not proof mutation.
		"GRANT SELECT,INSERT,DELETE ON public.account_deletion_action_proofs,public.password_change_action_proofs,public.first_passkey_enrollment_action_proofs,public.mfa_enrollment_action_proofs TO ",
		"GRANT INSERT ON public.proof_test_actions TO ",
		"GRANT USAGE ON SEQUENCE public.proof_test_actions_id_seq TO ",
	} {
		if _, err := pool.Exec(ctx, grant+roleSQL); err != nil {
			t.Fatal("install least-privilege fixture runtime grants failed")
		}
	}
	runtimeConfig := cfg.Copy()
	runtimeConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+roleSQL)
		return err
	}
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal("connect restricted fixture runtime failed")
	}
	t.Cleanup(runtimePool.Close)
	deps := Deps{DB: runtimePool, Queries: db.New(runtimePool), Codes: codes, Cipher: cipher, Limiter: limiter, Sessions: sessions}
	var svc *Service
	switch purpose {
	case contactcode.PurposeMFAEnrollment:
		svc, err = NewMFAEnrollment(Config{BindingKey: bytes.Repeat([]byte{4}, 32)}, deps)
	case contactcode.PurposeFirstPasskey:
		svc, err = NewFirstPasskey(Config{BindingKey: bytes.Repeat([]byte{4}, 32)}, deps)
	case contactcode.PurposePasswordChange:
		svc, err = NewPasswordChange(Config{BindingKey: bytes.Repeat([]byte{4}, 32)}, deps)
	default:
		svc, err = New(Config{BindingKey: bytes.Repeat([]byte{4}, 32)}, deps)
	}
	if err != nil {
		t.Fatal(err)
	}
	return realProofFixture{ctx: ctx, pool: pool, runtime: runtimePool, service: svc, sessions: sessions, delivery: delivery, sess: sess, user: u}
}

func (f realProofFixture) challenge(t *testing.T) (string, time.Time) {
	t.Helper()
	handle, expires, err := f.service.Challenge(f.ctx, f.sess, testSecret, "email", "203.0.113.8")
	if err != nil || !capability(handle) {
		t.Fatal("real deletion challenge failed", err)
	}
	return handle, expires
}

func (f realProofFixture) issue(t *testing.T) string {
	t.Helper()
	handle, deadline := f.challenge(t)
	proof, expires, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("real deletion proof issuance failed", err)
	}
	return proof
}

func (f realProofFixture) counts(t *testing.T) (int, int) {
	t.Helper()
	var proofs, actions int
	if err := f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM account_deletion_action_proofs), (SELECT count(*) FROM proof_test_actions)").Scan(&proofs, &actions); err != nil {
		t.Fatal("read test-only proof/action counts failed")
	}
	return proofs, actions
}

func TestCommittedPhoneRepairRejectsEarlierDeletionProofIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	proof := f.issue(t)
	cipher := f.service.deps.Cipher
	const destination = "+989123456789"
	encrypted, err := cipher.Encrypt(f.ctx, []byte(destination))
	if err != nil {
		t.Fatal("encrypt repaired contact failed")
	}
	evidence, err := contactproof.Seal(f.ctx, cipher, f.user.ID, contactproof.Phone, destination, contactproof.SMSOTP, time.Now().UTC())
	if err != nil {
		t.Fatal("seal repaired contact failed")
	}
	users, err := smsotp.NewUserStore(f.pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.SetPhoneIfCurrent(f.ctx, f.user.ID, f.sess.AuthVersion, encrypted, "owned-repair-index", evidence); err != nil {
		t.Fatal("verified contact repair failed", err)
	}
	current, err := db.New(f.pool).GetUserByID(f.ctx, f.user.ID)
	if err != nil || current.AuthVersion != f.sess.AuthVersion+1 {
		t.Fatal("contact repair did not commit exactly one authority change")
	}
	if err := session.ValidateAuthority(f.ctx, session.NewDBAccountState(f.pool), f.sess.UserID, f.sess.AuthVersion, f.sess.Kind, f.sess.Evidence); !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatal("earlier session survived verified contact change")
	}
	tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != ErrUnauthorized {
		t.Fatal("earlier eligible deletion proof survived actual contact change", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if proofs, actions := f.counts(t); proofs != 1 || actions != 0 {
		t.Fatal("rejected earlier proof partially consumed or performed an action")
	}
}

func TestAccountDeletionProofRollbackAndConcurrentConsumersIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	proof := f.issue(t)
	tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != nil {
		t.Fatal("rollback transaction failed to consume", err)
	}
	if _, err := tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES ($1)", f.user.ID); err != nil {
		t.Fatal("test-only action failed")
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal("forced rollback failed")
	}
	if proofs, actions := f.counts(t); proofs != 1 || actions != 0 {
		t.Fatal("rollback failed to restore consumption and discard action")
	}
	start, results := make(chan struct{}), make(chan error, 12)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			<-start
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != nil {
				results <- err
				return
			}
			if _, err := tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES ($1)", f.user.ID); err != nil {
				results <- err
				return
			}
			results <- tx.Commit(f.ctx)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrInvalid {
			t.Fatal("real concurrent consumer failed unexpectedly", err)
		}
	}
	if proofs, actions := f.counts(t); winners != 1 || proofs != 0 || actions != 1 {
		t.Fatal("concurrent consumers did not commit exactly one action after rollback")
	}
}

func TestAccountDeletionRealRedisOTPConcurrentIssuanceIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	handle, deadline := f.challenge(t)
	code := f.delivery.lastCode()
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			proof, expires, err := f.service.Verify(f.ctx, f.sess, handle, code)
			if err == nil && (!capability(proof) || !expires.Equal(deadline)) {
				err = ErrInvalid
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != contactcode.ErrNoActiveCode {
			t.Fatal("real concurrent OTP verification failed unexpectedly", err)
		}
	}
	if proofs, actions := f.counts(t); winners != 1 || proofs != 1 || actions != 0 {
		t.Fatal("real Redis OTP issued more than one PostgreSQL proof")
	}
}

func TestAccountDeletionEmailSMSFlowIntegration(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newRealProofFixture(t)
			before, err := f.sessions.LookupByID(f.ctx, f.sess.UserID, f.sess.ID)
			if err != nil {
				t.Fatal("read original fixture session failed")
			}
			handle, deadline, err := f.service.Challenge(f.ctx, f.sess, testSecret, channel, "203.0.113.8")
			if err != nil || !capability(handle) || deadline.After(time.Now().Add(3*time.Minute)) {
				t.Fatal("real channel challenge failed", err)
			}
			proof, expires, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode())
			if err != nil || !capability(proof) || !expires.Equal(deadline) {
				t.Fatal("real channel proof issuance failed", err)
			}
			var storedChannel string
			var storedDeadline time.Time
			if err := f.pool.QueryRow(f.ctx, "SELECT channel,expires_at FROM account_deletion_action_proofs").Scan(&storedChannel, &storedDeadline); err != nil || storedChannel != channel || !storedDeadline.Equal(deadline) {
				t.Fatal("real proof restamped deadline/channel")
			}
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != nil {
				t.Fatal("real channel proof consumption failed", err)
			}
			if _, err := tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES ($1)", f.user.ID); err != nil {
				t.Fatal("test-only channel action failed")
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			after, err := f.sessions.LookupByID(f.ctx, f.sess.UserID, f.sess.ID)
			if err != nil || before != after {
				t.Fatal("deletion proof granted or renewed session evidence")
			}
			if proofs, actions := f.counts(t); proofs != 0 || actions != 1 {
				t.Fatal("channel proof did not commit exactly one test action")
			}
		})
	}
}

func TestAccountDeletionChallengeEligibilityIntegration(t *testing.T) {
	for _, scenario := range []string{"wrong-password", "unverified", "replaced", "passkey", "mfa", "role", "version", "password-absent", "suspended", "revoked", "recovery"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealProofFixture(t)
			secret, sess := testSecret, f.sess
			var err error
			switch scenario {
			case "wrong-password":
				secret = "wrong"
			case "unverified":
				_, err = f.pool.Exec(f.ctx, "DELETE FROM contact_verification_evidence WHERE user_id=$1", f.user.ID)
			case "replaced":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET email=$2 WHERE id=$1", f.user.ID, "replacement@actionproof.invalid")
			case "passkey":
				_, err = f.pool.Exec(f.ctx, "INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES ($1,$2,$3,'none',$4)", []byte("test-proof-credential"), f.user.ID, []byte("test-key"), uuid.Nil)
			case "mfa":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", f.user.ID)
			case "role":
				_, err = db.New(f.pool).CreateRole(f.ctx, db.CreateRoleParams{ID: "test-proof-operator"})
				if err == nil {
					err = db.New(f.pool).AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: f.user.ID, RoleID: "test-proof-operator"})
				}
			case "version":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
			case "password-absent":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET password_hash=NULL WHERE id=$1", f.user.ID)
			case "suspended":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET status='suspended' WHERE id=$1", f.user.ID)
			case "revoked":
				_, err = f.sessions.RevokeByID(f.ctx, sess.UserID, sess.ID)
			case "recovery":
				sess.Kind = session.KindRecoveryEnrollment
			}
			if err != nil {
				t.Fatal("eligibility fixture transition failed")
			}
			if handle, expires, err := f.service.Challenge(f.ctx, sess, secret, "email", "203.0.113.8"); handle != "" || !expires.IsZero() || err != ErrUnauthorized || f.delivery.calls != 0 {
				t.Fatal("ineligible real account dispatched deletion challenge", err)
			}
			if proofs, actions := f.counts(t); proofs != 0 || actions != 0 {
				t.Fatal("ineligible challenge created proof/action")
			}
		})
	}
}

func TestAccountDeletionIssuanceRechecksAfterLockWaitIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	handle, _ := f.challenge(t)
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if err := pglock.LockAccount(f.ctx, tx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		proof, _, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode())
		if proof != "" {
			err = ErrInvalid
		}
		result <- err
	}()
	select {
	case err := <-result:
		t.Fatal("issuance did not wait for account advisory lock", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := tx.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != ErrUnauthorized {
		t.Fatal("issuance read a pre-lock authentication snapshot", err)
	}
	if proof, _, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode()); proof != "" || err != contactcode.ErrNoActiveCode {
		t.Fatal("failed post-lock issuance restored or retried consumed OTP")
	}
	if proofs, actions := f.counts(t); proofs != 0 || actions != 0 {
		t.Fatal("revoked post-lock issuance persisted authority")
	}
}

func TestAccountDeletionDatabaseDeadlineNotTransactionStartIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	proof := f.issue(t)
	if _, err := f.pool.Exec(f.ctx, "UPDATE account_deletion_action_proofs SET expires_at=clock_timestamp()+interval '150 milliseconds'"); err != nil {
		t.Fatal(err)
	}
	tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	if _, err := tx.Exec(f.ctx, "SELECT CURRENT_TIMESTAMP"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != ErrInvalid {
		t.Fatal("transaction start time extended expired proof", err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if proofs, actions := f.counts(t); proofs != 1 || actions != 0 {
		t.Fatal("expired proof changed consumption/action")
	}
}

func TestAccountDeletionProofRevocationAndIsolationIntegration(t *testing.T) {
	for _, scenario := range []string{"contact-time", "destination", "version", "session", "passkey", "mfa", "operator-role", "repeatable read", "serializable"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealProofFixture(t)
			proof := f.issue(t)
			iso, want := pgx.ReadCommitted, ErrUnauthorized
			switch scenario {
			case "repeatable read", "serializable":
				iso, want = pgx.TxIsoLevel(scenario), ErrTransaction
			case "session":
				if revoked, err := f.sessions.RevokeByID(f.ctx, f.sess.UserID, f.sess.ID); err != nil || !revoked {
					t.Fatal("real session revocation failed")
				}
			default:
				tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(f.ctx) }()
				if err := pglock.LockAccount(f.ctx, tx, f.user.ID); err != nil {
					t.Fatal(err)
				}
				q := db.New(tx)
				if _, err := q.GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "contact-time":
					blob, err := contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, contactproof.Email, *f.user.Email, contactproof.EmailLink, time.Now().UTC().Add(-20*time.Second))
					if err != nil {
						t.Fatal(err)
					}
					if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: contactproof.Email, EvidenceEncrypted: blob}); err != nil {
						t.Fatal(err)
					}
				case "destination":
					_, err = tx.Exec(f.ctx, "UPDATE users SET email=$2 WHERE id=$1", f.user.ID, "replacement@actionproof.invalid")
				case "version":
					_, err = tx.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
				case "passkey":
					_, err = tx.Exec(f.ctx, "INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES ($1,$2,$3,'none',$4)", []byte("test-proof-credential"), f.user.ID, []byte("test-key"), uuid.Nil)
				case "mfa":
					_, err = tx.Exec(f.ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", f.user.ID)
				case "operator-role":
					_, err = q.CreateRole(f.ctx, db.CreateRoleParams{ID: "test-proof-operator"})
					if err == nil {
						err = q.AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: f.user.ID, RoleID: "test-proof-operator"})
					}
				}
				if err != nil {
					t.Fatal("locked fixture transition failed")
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: iso})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != want {
				t.Fatal("revoked/stale-snapshot proof authorized", err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if proofs, actions := f.counts(t); proofs != 1 || actions != 0 {
				t.Fatal("rejected proof changed consumption/action")
			}
		})
	}
}

type commitUnknownDB struct{ pool *pgxpool.Pool }
type commitUnknownTx struct{ pgx.Tx }

func (d commitUnknownDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return commitUnknownTx{tx}, nil
}

func (tx commitUnknownTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return errors.New("synthetic unknown commit outcome")
}

func TestAccountDeletionIssuanceFailureAndUnknownCommitIntegration(t *testing.T) {
	for _, scenario := range []string{"insert", "commit"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealProofFixture(t)
			handle, _ := f.challenge(t)
			if scenario == "insert" {
				if _, err := f.pool.Exec(f.ctx, "ALTER TABLE account_deletion_action_proofs ADD CONSTRAINT test_no_issue CHECK (false)"); err != nil {
					t.Fatal(err)
				}
			} else {
				f.service.deps.DB = commitUnknownDB{f.runtime}
			}
			if proof, deadline, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode()); proof != "" || !deadline.IsZero() || err != ErrOutcomeUnknown {
				t.Fatal("failed/unknown real issuance exposed authority")
			}
			if proof, _, err := f.service.Verify(f.ctx, f.sess, handle, f.delivery.lastCode()); proof != "" || err != contactcode.ErrNoActiveCode {
				t.Fatal("failed/unknown real issuance retried consumed OTP")
			}
			wantRows := 0
			if scenario == "commit" {
				wantRows = 1 // Orphaned digest cannot be redeemed without its unreturned handle.
			}
			if proofs, actions := f.counts(t); proofs != wantRows || actions != 0 || f.delivery.calls != 1 {
				t.Fatal("unknown issuance retried, dispatched, or committed an action")
			}
		})
	}
}

func TestAccountDeletionProofSchemaCleanupAndForwardOnlyIntegration(t *testing.T) {
	f := newRealProofFixture(t)
	proof := f.issue(t)
	var selectAllowed, insertAllowed, deleteAllowed, updateAllowed, truncateAllowed bool
	if err := f.runtime.QueryRow(f.ctx, "SELECT has_table_privilege(current_user,'account_deletion_action_proofs','SELECT'),has_table_privilege(current_user,'account_deletion_action_proofs','INSERT'),has_table_privilege(current_user,'account_deletion_action_proofs','DELETE'),has_any_column_privilege(current_user,'account_deletion_action_proofs','UPDATE'),has_table_privilege(current_user,'account_deletion_action_proofs','TRUNCATE')").Scan(&selectAllowed, &insertAllowed, &deleteAllowed, &updateAllowed, &truncateAllowed); err != nil || !selectAllowed || !insertAllowed || !deleteAllowed || updateAllowed || truncateAllowed {
		t.Fatal("runtime proof privileges exceed SELECT/INSERT/DELETE")
	}
	if _, err := f.runtime.Exec(f.ctx, "UPDATE account_deletion_action_proofs SET expires_at=expires_at"); err == nil {
		t.Fatal("runtime role can restamp proof rows")
	}
	var rawStored, publicGrants bool
	if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM account_deletion_action_proofs WHERE proof_digest=convert_to($1,'UTF8')), EXISTS(SELECT 1 FROM information_schema.table_privileges WHERE table_name='account_deletion_action_proofs' AND grantee='PUBLIC')", proof).Scan(&rawStored, &publicGrants); err != nil || rawStored || publicGrants {
		t.Fatal("schema persisted raw proof or granted PUBLIC capability")
	}
	// Explicit test-only backdating preserves schema's <=5-minute invariant.
	if _, err := f.pool.Exec(f.ctx, "UPDATE account_deletion_action_proofs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO account_deletion_action_proofs SELECT sha256(proof_digest),user_id,session_id,jkt,auth_version,action,channel,contact_binding,created_at,expires_at FROM account_deletion_action_proofs"); err != nil {
		t.Fatal(err)
	}
	if rows, err := f.service.CleanupExpired(f.ctx, 1); err != nil || rows != 1 {
		t.Fatal("cleanup did not respect bounded batch", err)
	}
	if proofs, _ := f.counts(t); proofs != 1 {
		t.Fatal("bounded cleanup erased more than one proof")
	}
	if rows, err := f.service.CleanupExpired(f.ctx, 1000); err != nil || rows != 1 {
		t.Fatal("cleanup failed to reclaim remaining expired proof", err)
	}
	cfg := *f.pool.Config().ConnConfig
	sqlDB := stdlib.OpenDB(cfg)
	defer func() { _ = sqlDB.Close() }()
	provider, err := migrate.NewProvider(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ApplyVersion(f.ctx, 7, false); err == nil {
		t.Fatal("forward-only proof migration allowed rollback")
	}
	if version, err := provider.GetDBVersion(f.ctx); err != nil || version != 9 {
		t.Fatal("forward-only refusal changed final lineage")
	}
}
