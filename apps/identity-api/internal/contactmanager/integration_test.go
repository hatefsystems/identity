//go:build integration

package contactmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Only EVAL keys belonging to this fixture are rewritten. Production scripts,
// quotas, capacity and single-use decisions are unchanged; no Redis flush occurs.
type ownedKeys struct{ prefix string }

func (h ownedKeys) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}
func (h ownedKeys) rewrite(cmd redis.Cmder) {
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
		if !strings.HasPrefix(key, "identity:session:v1:") {
			args[3+i] = h.prefix + key
		}
	}
}
func (h ownedKeys) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error { h.rewrite(cmd); return next(ctx, cmd) }
}
func (h ownedKeys) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			h.rewrite(cmd)
		}
		return next(ctx, cmds)
	}
}

type delivery struct {
	mu    sync.Mutex
	codes map[string]string
	calls int
	hook  func(context.Context) error
	err   error
}

func (d *delivery) send(ctx context.Context, destination, code string) error {
	d.mu.Lock()
	d.calls++
	d.codes[destination] = code
	hook, err := d.hook, d.err
	d.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return err
}
func (d *delivery) SendCode(ctx context.Context, destination, code string, _ time.Time) error {
	return d.send(ctx, destination, code)
}
func (d *delivery) code(destination string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.codes[destination]
}
func (d *delivery) count() int { d.mu.Lock(); defer d.mu.Unlock(); return d.calls }

type smsDelivery struct{ d *delivery }

func (s smsDelivery) SendCode(ctx context.Context, phone, code string) error {
	return s.d.send(ctx, phone, code)
}

type managerFixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	redis    *redis.Client
	prefix   string
	service  *Service
	store    *contactcode.RedisStore
	sessions *session.RedisStore
	manager  *session.Manager
	delivery *delivery
	user     db.User
	sess     session.Session
}

func realManager(t *testing.T, emailPresent bool) managerFixture {
	t.Helper()
	dsn, redisURL := strings.TrimSpace(os.Getenv("DATABASE_URL")), strings.TrimSpace(os.Getenv("REDIS_URL"))
	if dsn == "" || redisURL == "" {
		if os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_CONTACTMANAGER_INTEGRATION") == "1" {
			t.Fatal("run-owned PostgreSQL and Redis required by mandatory contactmanager integration")
		}
		t.Skip("run-owned PostgreSQL and Redis not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid fixture PostgreSQL configuration")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal("configured fixture PostgreSQL unavailable")
	}
	name := "contactmanager_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal("create run-owned contactmanager database failed")
	}
	t.Logf("run-owned contactmanager database: %s", name)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("run-owned contactmanager database teardown failed")
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned contactmanager migration failed", err)
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
	prefix := "contactmanager_test:" + uuid.NewString() + ":"
	client.AddHook(ownedKeys{prefix})
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		var cursor uint64
		for {
			keys, next, err := client.Scan(cleanup, cursor, prefix+"*", 100).Result()
			if err != nil {
				t.Error("run-owned Redis scan failed")
				return
			}
			if len(keys) > 0 {
				if err := client.Del(cleanup, keys...).Err(); err != nil {
					t.Error("run-owned Redis cleanup failed")
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
			t.Error("run-owned Redis teardown incomplete")
		}
	})
	cipher := testCipher(t)
	indexer, err := blindindex.New(bytes.Repeat([]byte{8}, 32), 0)
	if err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	var email *string
	if emailPresent {
		email = new(uuid.NewString() + "@contactmanager.invalid")
	}
	u, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)", []byte(uuid.NewString()), u.ID, []byte("fixture-public-key"), uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if email != nil {
		proof, err := contactproof.Seal(ctx, cipher, u.ID, "email", *email, contactproof.EmailLink, time.Now().Add(-time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := q.PutContactVerificationEvidence(ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: "email", EvidenceEncrypted: proof}); err != nil {
			t.Fatal(err)
		}
	}
	stores, err := session.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewManager(stores, cookie, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(pool)})
	if err != nil {
		t.Fatal(err)
	}
	d := &delivery{codes: map[string]string{}}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		t.Fatal(err)
	}
	otps, err := smsotp.NewRedisOTPStore(client)
	if err != nil {
		t.Fatal(err)
	}
	users, err := smsotp.NewUserStore(pool, cipher)
	if err != nil {
		t.Fatal(err)
	}
	sms, err := smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{9}, 32), GlobalPerDay: 10000}, users, cipher, indexer, limiter, otps, smsDelivery{d})
	if err != nil {
		t.Fatal(err)
	}
	store, err := contactcode.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{10}, 32), ContactOwnershipEmail: d}, store, sms, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Deps{DB: pool, Queries: q, Sessions: sessions, Cipher: cipher, Indexer: indexer, Codes: codes})
	if err != nil {
		t.Fatal(err)
	}
	f := managerFixture{ctx: ctx, pool: pool, redis: client, prefix: prefix, service: svc, store: store, sessions: stores, manager: sessions, delivery: d, user: u}
	f.sess = f.freshSession(t)
	return f
}
func (f managerFixture) freshSession(t *testing.T) session.Session {
	t.Helper()
	u := f.load(t)
	now := time.Now().UTC()
	sess := session.Session{UserID: u.ID.String(), ID: uuid.NewString(), DPoPJKT: capability(1), AuthVersion: u.AuthVersion, AuthVersionSet: true, Kind: session.KindAuthenticated, CreatedAt: now, LastSeenAt: now, IdleExpiry: now.Add(time.Hour), AbsoluteExpiry: now.Add(time.Hour)}
	_, hash, err := session.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sessions.Create(f.ctx, hash, sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := f.sessions.DeleteAllForUser(cleanup, sess.UserID); err != nil {
			t.Error("run-owned session cleanup failed")
		}
		user := fmt.Sprintf("%d:%s", len(sess.UserID), sess.UserID)
		if err := f.redis.Del(cleanup, "identity:session:v1:token:"+hash, "identity:session:v1:user:"+user, "identity:session:v1:id:"+user+":"+sess.ID).Err(); err != nil {
			t.Error("run-owned session marker cleanup failed")
		}
	})
	return sess
}
func (f managerFixture) load(t *testing.T) db.User {
	t.Helper()
	u, err := db.New(f.pool).GetUserByID(f.ctx, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func (f managerFixture) grant(sess session.Session) Authorization {
	return Authorization{Grant: &StrongAuthorization{UserID: sess.UserID, SessionID: sess.ID, DPoPJKT: sess.DPoPJKT, AuthVersion: sess.AuthVersion, Method: "webauthn_uv", ExpiresAt: time.Now().UTC().Add(2 * time.Minute)}}
}
func randomPhone() string {
	raw := uuid.New()
	return fmt.Sprintf("+989%09d", binary.BigEndian.Uint32(raw[:4])%1000000000)
}
func (f managerFixture) start(t *testing.T, target, destination string) StartResult {
	t.Helper()
	result, err := f.service.Start(f.ctx, f.sess, target, destination, f.grant(f.sess), "203.0.113.8")
	if err != nil || !validHandle(result.VerificationID) {
		t.Fatal("real manager start failed", err)
	}
	return result
}
func (f managerFixture) intentCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1", f.user.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestContactManagerRealOwnershipSnapshotAndOneWinnerIntegration(t *testing.T) {
	for _, target := range []string{"email", "phone"} {
		t.Run(target, func(t *testing.T) {
			f := realManager(t, true)
			destination := uuid.NewString() + "@new-contact.invalid"
			if target == "phone" {
				destination = randomPhone()
			}
			before := f.load(t)
			started := f.start(t, target, destination)
			if after := f.load(t); !reflect.DeepEqual(before, after) || f.intentCount(t) != 0 {
				t.Fatal("pending start mutated contact/security/lifecycle")
			}
			for _, foreign := range []session.Session{func() session.Session { v := f.sess; v.ID = "foreign"; return v }(), func() session.Session { v := f.sess; v.DPoPJKT = capability(8); return v }(), func() session.Session { v := f.sess; v.UserID = uuid.NewString(); return v }()} {
				if _, err := f.service.Finish(f.ctx, foreign, target, started.VerificationID, f.delivery.code(destination)); err == nil {
					t.Fatal("foreign ownership binding admitted")
				}
			}
			if n, err := f.redis.HGet(f.ctx, f.prefix+"contact:login:challenge:"+started.VerificationID, "attempts").Result(); err != nil || n != "0" {
				t.Fatal("foreign request burned legitimate attempts")
			}
			if payload, err := f.redis.HGet(f.ctx, f.prefix+"contact:login:challenge:"+started.VerificationID, "payload").Result(); err != nil || strings.Contains(payload, destination) || strings.Contains(payload, f.delivery.code(destination)) {
				t.Fatal("ownership record leaked pending destination/code")
			}
			begin, results := make(chan struct{}), make(chan error, 2)
			for range 2 {
				go func() {
					<-begin
					_, err := f.service.Finish(f.ctx, f.sess, target, started.VerificationID, f.delivery.code(destination))
					results <- err
				}()
			}
			close(begin)
			wins := 0
			for range 2 {
				err := <-results
				if err == nil {
					wins++
				} else if !errors.Is(err, ErrExpired) && !errors.Is(err, ErrUnauthorized) {
					t.Fatal("unexpected concurrent finish result", err)
				}
			}
			if wins != 1 {
				t.Fatal("ownership completion did not have exactly one winner")
			}
			after := f.load(t)
			if after.AuthVersion != before.AuthVersion+1 || after.AuthEpoch <= before.AuthEpoch {
				t.Fatal("security version/epoch did not advance exactly once")
			}
			proof, err := contactproof.Read(f.ctx, db.New(f.pool), f.service.deps.Cipher, f.user.ID, target)
			if err != nil || proof == nil || proof.Destination != destination || proof.VerifiedAt.Before(started.ExpiresAt.Add(-3*time.Minute)) || proof.VerifiedAt.After(time.Now()) {
				t.Fatal("exact truthful ownership evidence missing")
			}
			wantMethod := contactproof.EmailOTP
			if target == "phone" {
				wantMethod = contactproof.SMSOTP
				plain, err := f.service.deps.Cipher.Decrypt(f.ctx, after.PhoneEncrypted)
				if err != nil || string(plain) != destination || after.PhoneBlindIndex == nil || *after.PhoneBlindIndex != f.service.deps.Indexer.Compute(destination) {
					t.Fatal("canonical encrypted phone and index differ")
				}
				clear(plain)
			}
			if proof.Method != wantMethod {
				t.Fatal("ownership method relabelled")
			}
			wantRevision, wantEvents := before.LifecycleRevision, 0
			if target == "email" {
				wantRevision++
				wantEvents++
			}
			if after.LifecycleRevision != wantRevision || f.intentCount(t) != wantEvents {
				t.Fatal("contact changed unrelated lifecycle metadata")
			}
			if _, err := f.service.Read(f.ctx, f.sess); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("old session survived contact version change")
			}
			current, err := f.service.Read(f.ctx, f.freshSession(t))
			if err != nil {
				t.Fatal(err)
			}
			value := current.Email
			if target == "phone" {
				value = current.Phone
			}
			if value == nil || value.Value != destination || !value.Verified || value.VerifiedAt == nil || !value.VerifiedAt.Equal(proof.VerifiedAt) {
				t.Fatal("current snapshot lost exact proof")
			}
			if target == "email" {
				var payload string
				if err := f.pool.QueryRow(f.ctx, "SELECT payload FROM event_outbox WHERE lifecycle_user_id=$1", f.user.ID).Scan(&payload); err != nil {
					t.Fatal(err)
				}
				event, err := lifecycle.UnmarshalEvent([]byte(payload))
				if err != nil || event.SchemaVersion != 1 || len(event.ChangedFields) != 1 || event.ChangedFields[0] != "email" || strings.Contains(payload, destination) || strings.Contains(payload, *before.Email) {
					t.Fatal("email intent includes PII or changed contract")
				}
			}
		})
	}
}

// Faults execute the real write first, then deny its acknowledgement. Rollback is
// PostgreSQL's actual transaction rollback, not a fake restoration implementation.
type faultDB struct {
	pool       *pgxpool.Pool
	statement  string
	commitLost bool
}

func (d faultDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return faultTx{Tx: tx, statement: d.statement, commitLost: d.commitLost}, nil
}

type faultTx struct {
	pgx.Tx
	statement  string
	commitLost bool
}

func (tx faultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil && tx.statement != "" && strings.Contains(sql, tx.statement) {
		return tag, errors.New("private destination in lost write acknowledgement")
	}
	return tag, err
}
func (tx faultTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	if tx.commitLost {
		return errors.New("private commit acknowledgement lost after actual commit")
	}
	return nil
}

func TestContactManagerRealRollbackAfterEveryWriteAndSpentOwnershipIntegration(t *testing.T) {
	for _, statement := range []string{"SetUserEmailIfAuthorized", "PutContactVerificationEvidence", "RevokeUserCredentials", "InsertLifecycleEvent", "ConsumeContactChangeAttempt"} {
		t.Run(statement, func(t *testing.T) {
			f := realManager(t, true)
			destination := uuid.NewString() + "@rollback.invalid"
			before := f.load(t)
			started := f.start(t, "email", destination)
			proofBefore, err := contactproof.Read(f.ctx, db.New(f.pool), f.service.deps.Cipher, f.user.ID, "email")
			if err != nil {
				t.Fatal(err)
			}
			f.service.deps.DB = faultDB{pool: f.pool, statement: statement}
			if changed, err := f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(destination)); changed || !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed SQL write claimed success", err)
			}
			if after := f.load(t); !reflect.DeepEqual(before, after) || f.intentCount(t) != 0 {
				t.Fatal("failed write did not restore user timestamps/versions/lifecycle")
			}
			proofAfter, err := contactproof.Read(f.ctx, db.New(f.pool), f.service.deps.Cipher, f.user.ID, "email")
			if err != nil || !reflect.DeepEqual(proofBefore, proofAfter) {
				t.Fatal("rollback lost old exact evidence")
			}
			if _, err := db.New(f.pool).GetContactChangeAttempt(f.ctx, attemptParams(f.sess, "email", started.VerificationID)); err != nil {
				t.Fatal("rollback lost pending SQL authority")
			}
			if _, err := f.store.Get(f.ctx, started.VerificationID); !errors.Is(err, contactcode.ErrNoActiveCode) {
				t.Fatal("rollback refunded consumed Redis ownership")
			}
		})
	}
}

func TestContactManagerActualCommittedLostAcknowledgementIntegration(t *testing.T) {
	for _, phase := range []string{"start", "finish", "remove", "noop"} {
		t.Run(phase, func(t *testing.T) {
			f := realManager(t, true)
			destination := uuid.NewString() + "@lost-ack.invalid"
			before := f.load(t)
			if phase == "remove" {
				destination = randomPhone()
				started := f.start(t, "phone", destination)
				if _, err := f.service.Finish(f.ctx, f.sess, "phone", started.VerificationID, f.delivery.code(destination)); err != nil {
					t.Fatal(err)
				}
				f.sess = f.freshSession(t)
				before = f.load(t)
			}
			var started StartResult
			if phase == "finish" {
				started = f.start(t, "email", destination)
			}
			f.service.deps.DB = faultDB{pool: f.pool, commitLost: true}
			if phase == "start" {
				result, err := f.service.Start(f.ctx, f.sess, "email", destination, f.grant(f.sess), "203.0.113.8")
				if result != (StartResult{}) || !errors.Is(err, ErrOutcomeUnknown) || f.delivery.count() != 0 {
					t.Fatal("unknown committed start leaked handle/submitted code")
				}
				var n int
				if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_change_attempts WHERE user_id=$1", f.user.ID).Scan(&n); err != nil || n != 1 {
					t.Fatal("commit-lost wrapper did not actually persist pending")
				}
				if !reflect.DeepEqual(before, f.load(t)) {
					t.Fatal("start changed contact")
				}
				return
			}
			var changed bool
			var err error
			if phase == "finish" {
				changed, err = f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(destination))
			} else {
				changed, err = f.service.Remove(f.ctx, f.sess, "phone", f.grant(f.sess))
			}
			if changed || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("unknown commit claimed successful outcome")
			}
			after := f.load(t)
			if phase == "noop" {
				if !reflect.DeepEqual(before, after) || f.intentCount(t) != 0 {
					t.Fatal("actual no-op commit changed state")
				}
				return
			}
			if after.AuthVersion != before.AuthVersion+1 {
				t.Fatal("commit-lost wrapper did not actually persist exactly one security change")
			}
			if phase == "finish" {
				if after.Email == nil || *after.Email != destination || after.LifecycleRevision != before.LifecycleRevision+1 || f.intentCount(t) != 1 {
					t.Fatal("actual commit did not atomically persist email and lifecycle")
				}
				if _, err := db.New(f.pool).GetContactChangeAttempt(f.ctx, attemptParams(f.sess, "email", started.VerificationID)); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("actual finish commit retained pending")
				}
			} else if len(after.PhoneEncrypted) != 0 || after.LifecycleRevision != before.LifecycleRevision {
				t.Fatal("actual remove changed wrong state")
			}
		})
	}
}

type admissionStore struct {
	contactcode.Store
	afterReserve func(context.Context) error
	afterConsume func()
}

func (s *admissionStore) Reserve(ctx context.Context, rec contactcode.Record, budgets []contactcode.Budget, key string, capacity int) error {
	if err := s.Store.Reserve(ctx, rec, budgets, key, capacity); err != nil {
		return err
	}
	if s.afterReserve != nil {
		return s.afterReserve(ctx)
	}
	return nil
}
func (s *admissionStore) Consume(ctx context.Context, rec contactcode.Record, hash, key string) error {
	err := s.Store.Consume(ctx, rec, hash, key)
	if err == nil && s.afterConsume != nil {
		s.afterConsume()
	}
	return err
}
func (f managerFixture) codesWithStore(t *testing.T, store contactcode.Store) *contactcode.Service {
	t.Helper()
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{10}, 32), ContactOwnershipEmail: f.delivery}, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

func TestContactManagerPostQuotaRevocationAndReplacementSubmitNothingIntegration(t *testing.T) {
	for _, mode := range []string{"revoke", "replace"} {
		t.Run(mode, func(t *testing.T) {
			f := realManager(t, true)
			original := uuid.NewString() + "@not-submitted.invalid"
			replacement := uuid.NewString() + "@replacement.invalid"
			store := &admissionStore{Store: f.store}
			f.service.deps.Codes = f.codesWithStore(t, store)
			store.afterReserve = func(ctx context.Context) error {
				store.afterReserve = nil
				if mode == "replace" {
					result, err := f.service.Start(ctx, f.sess, "email", replacement, f.grant(f.sess), "203.0.113.8")
					if err != nil || !validHandle(result.VerificationID) {
						return ErrUnavailable
					}
					return nil
				}
				tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					return err
				}
				defer rollback(ctx, tx)
				if err := pglock.LockAccount(ctx, tx, f.user.ID); err != nil {
					return err
				}
				if _, err := db.New(tx).GetUserByIDForUpdate(ctx, f.user.ID); err != nil {
					return err
				}
				if err := db.New(tx).RevokeUserCredentials(ctx, f.user.ID); err != nil {
					return err
				}
				return tx.Commit(ctx)
			}
			result, err := f.service.Start(f.ctx, f.sess, "email", original, f.grant(f.sess), "203.0.113.8")
			if result != (StartResult{}) || err == nil || f.delivery.code(original) != "" {
				t.Fatal("failed final pending/live check submitted original code or exposed handle")
			}
			want := 0
			if mode == "replace" {
				want = 1
				if f.delivery.code(replacement) == "" {
					t.Fatal("fresh authorized replacement did not send")
				}
			}
			if f.delivery.count() != want {
				t.Fatal("unexpected provider submissions after quota barrier")
			}
		})
	}
}

func TestContactManagerNoProviderLockAndExpiredLockWaitIntegration(t *testing.T) {
	f := realManager(t, true)
	destination := uuid.NewString() + "@lock.invalid"
	f.delivery.hook = func(ctx context.Context) error {
		ctx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		defer rollback(ctx, tx)
		if err := pglock.LockAccount(ctx, tx, f.user.ID); err != nil {
			return err
		}
		_, err = db.New(tx).GetUserByIDForUpdate(ctx, f.user.ID)
		return err
	}
	auth := f.grant(f.sess)
	auth.Grant.ExpiresAt = time.Now().Add(600 * time.Millisecond)
	started, err := f.service.Start(f.ctx, f.sess, "email", destination, auth, "203.0.113.8")
	if err != nil {
		t.Fatal("provider I/O retained an account lock", err)
	}
	held, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(f.ctx, held)
	if err := pglock.LockAccount(f.ctx, held, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(held).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	consumed := make(chan struct{})
	store := &admissionStore{Store: f.store, afterConsume: func() { close(consumed) }}
	f.service.deps.Codes = f.codesWithStore(t, store)
	before := f.load(t)
	result := make(chan error, 1)
	go func() {
		_, err := f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(destination))
		result <- err
	}()
	select {
	case <-consumed:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership consume was nested behind SQL lock")
	}
	<-time.After(time.Until(started.ExpiresAt) + 20*time.Millisecond)
	if err := held.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrExpired) {
		t.Fatal("expiry crossed during lock wait was accepted", err)
	}
	if !reflect.DeepEqual(before, f.load(t)) || f.intentCount(t) != 0 {
		t.Fatal("expired lock wait changed contact/security/lifecycle")
	}
	if _, err := f.store.Get(f.ctx, started.VerificationID); !errors.Is(err, contactcode.ErrNoActiveCode) {
		t.Fatal("expired finalization refunded ownership")
	}
}

func TestContactManagerAbsentContactsGatesRepairAndReaderShutdownIntegration(t *testing.T) {
	f := realManager(t, false)
	before := f.load(t)
	for _, target := range []string{"email", "phone"} {
		changed, err := f.service.Remove(f.ctx, f.sess, target, f.grant(f.sess))
		if err != nil || changed {
			t.Fatal("authorized absent contact removal was not a no-op", err)
		}
	}
	if !reflect.DeepEqual(before, f.load(t)) || f.intentCount(t) != 0 {
		t.Fatal("absent no-op changed metadata")
	}
	phone := randomPhone()
	started := f.start(t, "phone", phone)
	if _, err := f.service.Finish(f.ctx, f.sess, "phone", started.VerificationID, f.delivery.code(phone)); err != nil {
		t.Fatal(err)
	}
	f.sess = f.freshSession(t)
	if _, err := f.service.Remove(f.ctx, f.sess, "phone", f.grant(f.sess)); !errors.Is(err, accountpolicy.ErrLastVerifiedContact) {
		t.Fatal("last evidenced primary contact removed")
	}
	email := uuid.NewString() + "@added.invalid"
	started = f.start(t, "email", email)
	// Reader shutdown does not change captured code policy or require a provider.
	f.service.deps.Codes = f.codesWithStore(t, f.store)
	reader, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{10}, 32)}, f.store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.service.deps.Codes = reader
	if _, err := f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(email)); err != nil {
		t.Fatal("disabled provider prevented bounded ownership finish", err)
	}
	f.sess = f.freshSession(t)
	if _, err := f.service.Remove(f.ctx, f.sess, "email", f.grant(f.sess)); !errors.Is(err, ErrEmailRemovalUnavailable) {
		t.Fatal("present email removal gate bypassed by verified phone")
	}
	if n, err := f.service.CleanupExpired(f.ctx, 1000); err != nil || n != 0 {
		t.Fatal("cleanup deleted nonexpired state")
	}
	proof, err := contactproof.Read(f.ctx, db.New(f.pool), f.service.deps.Cipher, f.user.ID, "email")
	if err != nil || proof == nil || proof.Method != contactproof.EmailOTP {
		t.Fatal("durable email OTP reader lost method after sending disabled")
	}
	changed, err := f.service.Remove(f.ctx, f.sess, "phone", f.grant(f.sess))
	if err != nil || !changed {
		t.Fatal("provider-free evidenced phone removal failed", err)
	}
}

func TestContactManagerPendingConstraintsPrivilegesAndBoundedCleanupIntegration(t *testing.T) {
	f := realManager(t, true)
	role := "contactmanager_role_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := f.pool.Exec(f.ctx, "CREATE ROLE "+quoted+" NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if _, err := f.pool.Exec(cleanup, "DROP OWNED BY "+quoted); err != nil {
			t.Error("run-owned restricted grants teardown failed")
		}
		if _, err := f.pool.Exec(cleanup, "DROP ROLE "+quoted); err != nil {
			t.Error("run-owned restricted role teardown failed")
		}
	})
	if _, err := f.pool.Exec(f.ctx, "GRANT USAGE ON SCHEMA public TO "+quoted+"; GRANT SELECT,INSERT,DELETE ON contact_management_action_proofs,contact_change_attempts TO "+quoted); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"contact_management_action_proofs", "contact_change_attempts"} {
		for _, privilege := range []string{"SELECT", "INSERT", "DELETE", "UPDATE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			var got bool
			if err := f.pool.QueryRow(f.ctx, "SELECT has_table_privilege($1,$2,$3)", role, table, privilege).Scan(&got); err != nil {
				t.Fatal(err)
			}
			want := privilege == "SELECT" || privilege == "INSERT" || privilege == "DELETE"
			if got != want {
				t.Fatal("restricted authority privilege inventory differs", table, privilege)
			}
		}
	}
	destination := uuid.NewString() + "@constraints.invalid"
	started := f.start(t, "email", destination)
	params := attemptParams(f.sess, "email", started.VerificationID)
	row, err := db.New(f.pool).GetContactChangeAttempt(f.ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	for name, sql := range map[string]string{"invalid method": "UPDATE contact_change_attempts SET authorization_method='password' WHERE user_id=$1", "missing proof evidence": "UPDATE contact_change_attempts SET authorization_method='password_contact' WHERE user_id=$1", "strong with evidence": "UPDATE contact_change_attempts SET channel='email',contact_mac=decode(repeat('01',32),'hex') WHERE user_id=$1", "unbounded expiry": "UPDATE contact_change_attempts SET expires_at=created_at+interval '4 minutes' WHERE user_id=$1", "infinite expiry": "UPDATE contact_change_attempts SET authorization_expires_at='infinity' WHERE user_id=$1"} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.pool.Exec(f.ctx, sql, f.user.ID); err == nil {
				t.Fatal("incomplete or unbounded pending record accepted")
			}
		})
	}
	duplicate := bytes.Repeat([]byte{12}, 32)
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO contact_change_attempts SELECT $1,user_id,session_id,dpop_jkt,auth_version,target,authorization_method,authorization_expires_at,channel,contact_mac,original_state_digest,destination_encrypted,created_at,expires_at FROM contact_change_attempts WHERE digest=$2", duplicate, row.Digest); err == nil {
		t.Fatal("two current attempts per account/target admitted")
	}
	// SQL expiry must be reclaimed explicitly; native Redis TTL is not evidence.
	if _, err := f.pool.Exec(f.ctx, "UPDATE contact_change_attempts SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute',authorization_expires_at=clock_timestamp()-interval '30 seconds' WHERE digest=$1", row.Digest); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(f.ctx, tx)
	if _, err := tx.Exec(f.ctx, "SET LOCAL ROLE "+quoted); err != nil {
		t.Fatal(err)
	}
	n, err := db.New(tx).CleanupExpiredContactChangeAttempts(f.ctx, 1)
	if err != nil || n != 1 {
		t.Fatal("restricted bounded cleanup needs generic UPDATE privilege", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := f.service.CleanupExpired(f.ctx, 1); err != nil || n != 0 {
		t.Fatal("cleanup was not finite/idempotent")
	}
	if _, err := f.service.CleanupExpired(f.ctx, 1001); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded cleanup accepted")
	}
	digest := sha256.Sum256([]byte("fixture-proof"))
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO contact_management_action_proofs(digest,user_id,session_id,dpop_jkt,auth_version,action,target,channel,contact_mac,expires_at) VALUES($1,$2,$3,$4,$5,'contact_change','backup','email',$6,clock_timestamp()+interval '1 minute')", digest[:], f.user.ID, f.sess.ID, f.sess.DPoPJKT, f.sess.AuthVersion, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("generic proof target admitted")
	}
}

func TestContactManagerDecidingEnvelopeRejectsSQLReinsertionIntegration(t *testing.T) {
	for _, field := range []string{"expires_at", "authorization_expires_at", "original_state_digest"} {
		t.Run(field, func(t *testing.T) {
			f := realManager(t, true)
			destination := uuid.NewString() + "@substitution.invalid"
			before := f.load(t)
			started := f.start(t, "email", destination)
			store := &admissionStore{Store: f.store}
			store.afterConsume = func() {
				tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					t.Error(err)
					return
				}
				defer rollback(f.ctx, tx)
				q := db.New(tx)
				row, err := q.GetContactChangeAttempt(f.ctx, attemptParams(f.sess, "email", started.VerificationID))
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := q.DeleteCurrentContactChangeAttempt(f.ctx, db.DeleteCurrentContactChangeAttemptParams{UserID: row.UserID, Target: row.Target}); err != nil {
					t.Error(err)
					return
				}
				switch field {
				case "expires_at":
					row.ExpiresAt.Time = row.ExpiresAt.Time.Add(time.Second)
					row.AuthorizationExpiresAt.Time = row.AuthorizationExpiresAt.Time.Add(time.Second)
				case "authorization_expires_at":
					row.AuthorizationExpiresAt.Time = row.AuthorizationExpiresAt.Time.Add(time.Second)
				case "original_state_digest":
					row.OriginalStateDigest = bytes.Repeat([]byte{77}, 32)
				}
				n, err := q.CreateContactChangeAttempt(f.ctx, db.CreateContactChangeAttemptParams{Digest: row.Digest, UserID: row.UserID, SessionID: row.SessionID, DpopJkt: row.DpopJkt, AuthVersion: row.AuthVersion, Target: row.Target, AuthorizationMethod: row.AuthorizationMethod, AuthorizationExpiresAt: row.AuthorizationExpiresAt, Channel: row.Channel, ContactMac: row.ContactMac, OriginalStateDigest: row.OriginalStateDigest, DestinationEncrypted: row.DestinationEncrypted, ExpiresAt: row.ExpiresAt})
				if err != nil || n != 1 {
					t.Error("permitted DELETE/INSERT substitution fixture failed", err)
					return
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Error(err)
				}
			}
			f.service.deps.Codes = f.codesWithStore(t, store)
			if changed, err := f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(destination)); changed || !errors.Is(err, ErrUnauthorized) {
				t.Fatal("deciding transaction trusted substituted frozen columns", err)
			}
			if !reflect.DeepEqual(before, f.load(t)) || f.intentCount(t) != 0 {
				t.Fatal("substituted authority changed contacts/security/lifecycle")
			}
			if _, err := f.store.Get(f.ctx, started.VerificationID); !errors.Is(err, contactcode.ErrNoActiveCode) {
				t.Fatal("substitution rejection refunded Redis ownership")
			}
		})
	}
}

type delayedCipher struct {
	contactproof.Cipher
	beforeDecrypt func()
}

func (c delayedCipher) Decrypt(ctx context.Context, blob []byte) ([]byte, error) {
	if c.beforeDecrypt != nil {
		c.beforeDecrypt()
	}
	return c.Cipher.Decrypt(ctx, blob)
}

func TestContactManagerRemoveCannotOutliveSessionDuringEvidenceWorkIntegration(t *testing.T) {
	f := realManager(t, true)
	phone := randomPhone()
	started := f.start(t, "phone", phone)
	if _, err := f.service.Finish(f.ctx, f.sess, "phone", started.VerificationID, f.delivery.code(phone)); err != nil {
		t.Fatal(err)
	}
	sess := f.freshSession(t)
	sess.ID = uuid.NewString()
	sess.CreatedAt = time.Now().UTC()
	sess.LastSeenAt = sess.CreatedAt
	sess.IdleExpiry = sess.CreatedAt.Add(250 * time.Millisecond)
	_, hash, err := session.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sessions.Create(f.ctx, hash, sess); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = f.sessions.DeleteAllForUser(cleanup, sess.UserID)
		user := fmt.Sprintf("%d:%s", len(sess.UserID), sess.UserID)
		if err := f.redis.Del(cleanup, "identity:session:v1:token:"+hash, "identity:session:v1:user:"+user, "identity:session:v1:id:"+user+":"+sess.ID).Err(); err != nil {
			t.Error("expired session marker teardown failed")
		}
	})
	before := f.load(t)
	baseCipher := f.service.deps.Cipher
	once := sync.Once{}
	f.service.deps.Cipher = delayedCipher{Cipher: baseCipher, beforeDecrypt: func() { once.Do(func() { <-time.After(time.Until(sess.IdleExpiry) + 20*time.Millisecond) }) }}
	changed, err := f.service.Remove(f.ctx, sess, "phone", f.grant(sess))
	if changed || !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrExpired) {
		t.Fatal("contact removal outlived earning session", err)
	}
	if !reflect.DeepEqual(before, f.load(t)) || f.intentCount(t) != 0 {
		t.Fatal("expired session removal changed contact/security/lifecycle")
	}
}

func TestContactManagerStrongRepairAndReverificationAreSecurityChangesIntegration(t *testing.T) {
	f := realManager(t, true)
	original := *f.user.Email
	// Deliberate corruption cannot become authorization or survivor evidence, but
	// an independently strong grant plus fresh ownership can repair this target.
	if _, err := f.pool.Exec(f.ctx, "UPDATE contact_verification_evidence SET evidence_encrypted=$2 WHERE user_id=$1 AND channel='email'", f.user.ID, bytes.Repeat([]byte{6}, 100)); err != nil {
		t.Fatal(err)
	}
	before := f.load(t)
	started := f.start(t, "email", original)
	if _, err := f.service.Finish(f.ctx, f.sess, "email", started.VerificationID, f.delivery.code(original)); err != nil {
		t.Fatal("independent exact-target repair failed", err)
	}
	after := f.load(t)
	proof, err := contactproof.Read(f.ctx, db.New(f.pool), f.service.deps.Cipher, f.user.ID, "email")
	if err != nil || proof == nil || proof.Method != contactproof.EmailOTP || proof.Destination != original || after.AuthVersion != before.AuthVersion+1 || after.LifecycleRevision != before.LifecycleRevision || f.intentCount(t) != 0 {
		t.Fatal("same-value repair invented lifecycle event or lost fresh evidence")
	}
}

func TestContactManagerCompetingRemovalAndVersionRevocationIntegration(t *testing.T) {
	for _, competitor := range []string{"remove", "revoke", "role"} {
		t.Run(competitor, func(t *testing.T) {
			f := realManager(t, true)
			original := randomPhone()
			first := f.start(t, "phone", original)
			if _, err := f.service.Finish(f.ctx, f.sess, "phone", first.VerificationID, f.delivery.code(original)); err != nil {
				t.Fatal(err)
			}
			f.sess = f.freshSession(t)
			replacement := randomPhone()
			started := f.start(t, "phone", replacement)
			before := f.load(t)
			begin, results := make(chan struct{}), make(chan error, 2)
			go func() {
				<-begin
				_, err := f.service.Finish(f.ctx, f.sess, "phone", started.VerificationID, f.delivery.code(replacement))
				results <- err
			}()
			go func() {
				<-begin
				if competitor == "remove" {
					_, err := f.service.Remove(f.ctx, f.sess, "phone", f.grant(f.sess))
					results <- err
					return
				}
				tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					results <- ErrUnavailable
					return
				}
				defer rollback(f.ctx, tx)
				if err := pglock.LockAccount(f.ctx, tx, f.user.ID); err != nil {
					results <- ErrUnavailable
					return
				}
				q := db.New(tx)
				u, err := q.GetUserByIDForUpdate(f.ctx, f.user.ID)
				if err != nil {
					results <- ErrUnavailable
					return
				}
				if u.AuthVersion != before.AuthVersion {
					results <- ErrUnauthorized
					return
				}
				if competitor == "role" {
					if _, err := tx.Exec(f.ctx, "INSERT INTO user_roles(user_id,role_id) VALUES($1,'support')", f.user.ID); err != nil {
						results <- ErrUnavailable
						return
					}
				}
				if err := q.RevokeUserCredentials(f.ctx, f.user.ID); err != nil {
					results <- ErrUnavailable
					return
				}
				results <- tx.Commit(f.ctx)
			}()
			close(begin)
			wins := 0
			for range 2 {
				err := <-results
				if err == nil {
					wins++
				} else if !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrExpired) {
					t.Fatal("unexpected account-lock competitor result", err)
				}
			}
			if wins != 1 || f.load(t).AuthVersion != before.AuthVersion+1 || f.intentCount(t) != 0 {
				t.Fatal("contact/factor-authority competitors did not serialize exactly once")
			}
		})
	}
}

func (f managerFixture) passwordProofs(t *testing.T) *actionproof.Service {
	t.Helper()
	secret := "Correct contact password 27!"
	hash, err := password.HashContext(f.ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM webauthn_credentials WHERE user_id=$1", f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE users SET password_hash=$2 WHERE id=$1", f.user.ID, hash); err != nil {
		t.Fatal(err)
	}
	normalizer, err := username.New(username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1, Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}, `[\x{0621}-\x{06CC}]+`, bytes.Repeat([]byte{0x71}, 32), "contactmanager-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	a := normalizer.Authority()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{{"INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)", []any{a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact()}}, {"INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)", []any{a.KeyID, a.KeyVerifier[:]}}, {"UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton", []any{a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:]}}} {
		if _, err := f.pool.Exec(f.ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	names, err := username.NewStore(f.pool, f.service.deps.Cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	value, err := normalizer.Normalize("\u0645\u0627\u0644\u06a9")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(f.ctx, tx)
	if err := names.Assign(f.ctx, tx, f.user.ID, f.sess.AuthVersion, value); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: names}
	f.service.deps.Policy = policy
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{10}, 32), ContactChangeEmail: f.delivery, ContactRemovalEmail: f.delivery, ContactOwnershipEmail: f.delivery}, f.store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.service.deps.Codes = codes
	limiter, err := ratelimit.NewRedisLimiter(f.redis)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := actionproof.NewContacts(actionproof.Config{BindingKey: bytes.Repeat([]byte{11}, 32), ContactIssuanceEnabled: true}, actionproof.Deps{DB: f.pool, Queries: db.New(f.pool), Cipher: f.service.deps.Cipher, Sessions: f.manager, Codes: codes, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	proofs.SetAccountPolicy(policy)
	f.service.deps.Proofs = proofs
	return proofs
}

func TestContactManagerSingleUseSQLProofRollbackStartAndFrozenFinishIntegration(t *testing.T) {
	for _, fault := range []string{"none", "CreateContactChangeAttempt", "commitLost", "concurrent"} {
		t.Run(fault, func(t *testing.T) {
			f := realManager(t, true)
			proofs := f.passwordProofs(t)
			secret := "Correct contact password 27!"
			destination := uuid.NewString() + "@proof-owned.invalid"
			challenge, deadline, err := proofs.ContactChallenge(f.ctx, f.sess, secret, "email", "contact_change", "email", "203.0.113.8")
			if err != nil {
				t.Fatal("actual password/contact challenge failed", err)
			}
			proof, expires, err := proofs.ContactVerify(f.ctx, f.sess, challenge, f.delivery.code(*f.user.Email), "contact_change")
			if err != nil || !expires.Equal(deadline) {
				t.Fatal("actual contact proof failed", err)
			}
			digest := sha256.Sum256([]byte(proof))
			before := f.load(t)
			if fault == "concurrent" {
				begin, results := make(chan struct{}), make(chan error, 2)
				for _, value := range []string{destination, uuid.NewString() + "@other-proof-owned.invalid"} {
					go func(value string) {
						<-begin
						_, err := f.service.Start(f.ctx, f.sess, "email", value, Authorization{Proof: proof}, "203.0.113.8")
						results <- err
					}(value)
				}
				close(begin)
				wins := 0
				for range 2 {
					err := <-results
					if err == nil {
						wins++
					} else if !errors.Is(err, ErrUnauthorized) {
						t.Fatal("unexpected concurrent proof consumer result", err)
					}
				}
				var unused, pending int
				if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_management_action_proofs WHERE digest=$1", digest[:]).Scan(&unused); err != nil {
					t.Fatal(err)
				}
				if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_change_attempts WHERE user_id=$1", f.user.ID).Scan(&pending); err != nil {
					t.Fatal(err)
				}
				if wins != 1 || unused != 0 || pending != 1 || !reflect.DeepEqual(before, f.load(t)) || f.delivery.count() != 2 {
					t.Fatal("same proof start did not have one SQL+delivery winner")
				}
				return
			}
			if fault != "none" {
				f.service.deps.DB = faultDB{pool: f.pool, statement: map[string]string{"CreateContactChangeAttempt": "CreateContactChangeAttempt"}[fault], commitLost: fault == "commitLost"}
			}
			result, err := f.service.Start(f.ctx, f.sess, "email", destination, Authorization{Proof: proof}, "203.0.113.8")
			var unused int
			if scanErr := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_management_action_proofs WHERE digest=$1", digest[:]).Scan(&unused); scanErr != nil {
				t.Fatal(scanErr)
			}
			if fault == "CreateContactChangeAttempt" {
				if result != (StartResult{}) || !errors.Is(err, ErrUnavailable) || unused != 1 || !reflect.DeepEqual(before, f.load(t)) {
					t.Fatal("SQL rollback did not restore start proof/account")
				}
				return
			}
			if fault == "commitLost" {
				if result != (StartResult{}) || !errors.Is(err, ErrOutcomeUnknown) || unused != 0 || f.delivery.code(destination) != "" {
					t.Fatal("actual committed start proof was refunded or uncertain handle escaped")
				}
				return
			}
			if err != nil || unused != 0 || !result.ExpiresAt.Equal(expires) {
				t.Fatal("start did not freeze/spend exact original proof", err)
			}
			if _, err := f.service.Start(f.ctx, f.sess, "email", uuid.NewString()+"@replay.invalid", Authorization{Proof: proof}, "203.0.113.8"); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("spent start proof replayed", err)
			}
			if changed, err := f.service.Finish(f.ctx, f.sess, "email", result.VerificationID, f.delivery.code(destination)); err != nil || !changed {
				t.Fatal("finish replayed spent start proof instead of read-only authorization", err)
			}
			if f.load(t).AuthVersion != before.AuthVersion+1 || f.intentCount(t) != 1 {
				t.Fatal("proof-authorized contact changed auth/lifecycle more than once")
			}
		})
	}
}
