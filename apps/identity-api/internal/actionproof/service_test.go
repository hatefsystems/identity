package actionproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

const testSecret = " short\x00 " // An existing credential, not new-password policy.

var hashOnce sync.Once
var existingHash string
var existingHashErr error

func credentialHash(t *testing.T) string {
	t.Helper()
	hashOnce.Do(func() { existingHash, existingHashErr = password.RehashContext(context.Background(), testSecret) })
	if existingHashErr != nil {
		t.Fatal("test credential computation failed")
	}
	return existingHash
}

func testCipher(t *testing.T) contactproof.Cipher {
	t.Helper()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{9}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func testCapability(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32))
}

type liveSessions struct {
	mu    sync.Mutex
	sess  session.Session
	err   error
	reads int
}

func (s *liveSessions) LookupByID(context.Context, string, string) (session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.sess, s.err
}

func (s *liveSessions) revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = session.ErrSessionNotFound
}

type passwordLimiter struct {
	keys  []string
	deny  int
	err   error
	db    *proofDB
	limit []int
}

func (l *passwordLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	l.limit = append(l.limit, limit)
	if l.db != nil {
		l.db.events = append(l.db.events, "limit")
	}
	return len(l.keys) != l.deny && window == time.Minute, l.err
}

type captureDelivery struct {
	mu       sync.Mutex
	code     string
	calls    int
	err      error
	database *proofDB
}

func (d *captureDelivery) SendCode(_ context.Context, _, code string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.code, d.calls = code, d.calls+1
	if d.database != nil && d.database.inTx {
		return errors.New("test transport invoked under account transaction")
	}
	return d.err
}

func (d *captureDelivery) lastCode() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.code
}

type unusedSMSUsers struct{ smsotp.UserStore }
type unusedSMSEncryptor struct{ smsotp.Encryptor }
type unusedSMSIndexer struct{ smsotp.BlindIndexer }
type deletionSMSSender struct{ delivery *captureDelivery }

func (s deletionSMSSender) SendCode(ctx context.Context, destination, code string) error {
	return s.delivery.SendCode(ctx, destination, code, time.Time{})
}

func deletionCodes(t *testing.T, client *redis.Client, delivery *captureDelivery, emailEnabled, smsEnabled bool) *contactcode.Service {
	t.Helper()
	store, err := contactcode.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	var phones *smsotp.Service
	if smsEnabled {
		otpStore, err := smsotp.NewRedisOTPStore(client)
		if err != nil {
			t.Fatal(err)
		}
		limiter, err := ratelimit.NewRedisLimiter(client)
		if err != nil {
			t.Fatal(err)
		}
		sender := deletionSMSSender{delivery}
		phones, err = smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{5}, 32), DeletionSender: sender}, unusedSMSUsers{}, unusedSMSEncryptor{}, unusedSMSIndexer{}, limiter, otpStore, sender)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := contactcode.Config{HashKey: bytes.Repeat([]byte{3}, 32)}
	if emailEnabled {
		cfg.DeletionEmail = delivery
	}
	codes, err := contactcode.New(cfg, store, phones, nil)
	if err != nil {
		t.Fatal(err)
	}
	return codes
}

type proofRow struct {
	values []any
	err    error
}

func (r proofRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("fixture row shape mismatch")
	}
	for i, value := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

// Only SQL execution is faked. Production crypto, password verifier and Redis
// scripts run unchanged; real PostgreSQL semantics are tested separately.
type proofDB struct {
	pgx.Tx
	user        db.User
	evidence    map[string][]byte
	passkeys    int64
	privileged  bool
	events      []string
	inTx        bool
	beginErr    error
	commitErr   error
	createErr   error
	createZero  bool
	deleteZero  bool
	onLock      func()
	saved       *db.CreateAccountDeletionActionProofParams
	pending     *db.CreateAccountDeletionActionProofParams
	deleted     bool
	commits     int
	rollbacks   int
	beginCalls  int
	deleteCalls int
	createCalls int
	isolation   string
}

func (f *proofDB) BeginTx(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	f.events = append(f.events, "begin")
	f.beginCalls++
	if opts.IsoLevel != pgx.ReadCommitted {
		return nil, ErrTransaction
	}
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	f.inTx = true
	return f, nil
}

func (f *proofDB) Commit(context.Context) error {
	f.commits++
	f.inTx = false
	if f.commitErr != nil {
		return f.commitErr
	}
	if f.pending != nil {
		f.saved = f.pending
		f.pending = nil
	}
	if f.deleted {
		f.saved = nil
	}
	return nil
}

func (f *proofDB) Rollback(context.Context) error {
	f.rollbacks++
	f.inTx = false
	f.pending = nil
	f.deleted = false
	return nil
}

func (f *proofDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.HasPrefix(sql, "SHOW transaction_isolation"):
		return proofRow{values: []any{f.isolation}}
	case strings.Contains(sql, "-- name: GetUserByID"):
		if strings.Contains(sql, "FOR UPDATE") {
			f.events = append(f.events, "row")
		} else {
			f.events = append(f.events, "user")
		}
		value := reflect.ValueOf(f.user)
		fields := make([]any, value.NumField())
		for i := range fields {
			fields[i] = value.Field(i).Interface()
		}
		return proofRow{values: fields}
	case strings.Contains(sql, "-- name: CountWebauthnCredentialsByUser"):
		f.events = append(f.events, "passkeys")
		return proofRow{values: []any{f.passkeys}}
	case strings.Contains(sql, "-- name: UserHasPrivilegedRole"):
		f.events = append(f.events, "roles")
		return proofRow{values: []any{f.privileged}}
	case strings.Contains(sql, "-- name: GetCurrentContactEvidence"):
		f.events = append(f.events, "contact")
		return proofRow{values: []any{f.user.ID, f.user.Email, f.user.PhoneEncrypted, f.evidence[args[0].(string)]}}
	case strings.Contains(sql, "-- name: GetAccountDeletionActionProofBinding"):
		if f.saved == nil || !bytes.Equal(args[0].([]byte), f.saved.ProofDigest) || args[1] != f.saved.UserID || args[2] != f.saved.SessionID || args[3] != f.saved.Jkt || args[4] != f.saved.AuthVersion || !time.Now().Before(f.saved.ExpiresAt.Time) {
			return proofRow{err: pgx.ErrNoRows}
		}
		return proofRow{values: []any{f.saved.Channel, f.saved.ContactBinding}}
	default:
		return proofRow{err: errors.New("unexpected fixture query")}
	}
}

func (f *proofDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		f.events = append(f.events, "advisory")
		if f.onLock != nil {
			f.onLock()
		}
		return pgconn.NewCommandTag("SELECT 1"), nil
	case strings.Contains(sql, "-- name: CreateAccountDeletionActionProof"):
		f.createCalls++
		if f.createErr != nil {
			return pgconn.CommandTag{}, f.createErr
		}
		if f.createZero {
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		}
		f.pending = &db.CreateAccountDeletionActionProofParams{ProofDigest: args[0].([]byte), UserID: args[1].(uuid.UUID), SessionID: args[2].(string), Jkt: args[3].(string), AuthVersion: args[4].(int64), Channel: args[5].(string), ContactBinding: args[6].([]byte), ExpiresAt: args[7].(pgtype.Timestamptz)}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case strings.Contains(sql, "-- name: ConsumeAccountDeletionActionProof"):
		f.deleteCalls++
		if f.deleteZero {
			return pgconn.NewCommandTag("DELETE 0"), nil
		}
		f.deleted = true
		return pgconn.NewCommandTag("DELETE 1"), nil
	case strings.Contains(sql, "-- name: CleanupExpiredAccountDeletionActionProofs"):
		return pgconn.NewCommandTag("DELETE 2"), nil
	default:
		return pgconn.CommandTag{}, errors.New("unexpected fixture execution")
	}
}

type proofFixture struct {
	service  *Service
	database *proofDB
	sessions *liveSessions
	limiter  *passwordLimiter
	delivery *captureDelivery
	sess     session.Session
	cipher   contactproof.Cipher
	client   *redis.Client
}

func newProofFixture(t *testing.T) proofFixture {
	t.Helper()
	id, now := uuid.New(), time.Now().UTC()
	sess := session.Session{ID: uuid.NewString(), UserID: id.String(), Kind: session.KindAuthenticated, AuthVersion: 3, AuthVersionSet: true, DPoPJKT: testCapability(1), CreatedAt: now, LastSeenAt: now, AbsoluteExpiry: now.Add(time.Hour), IdleExpiry: now.Add(time.Hour)}
	f := proofFixture{sess: sess, cipher: testCipher(t)}
	f.database = &proofDB{user: db.User{ID: id, Email: new("owner@example.test"), PasswordHash: new(credentialHash(t)), Status: "active", AuthVersion: 3}, evidence: make(map[string][]byte), isolation: "read committed"}
	f.sessions = &liveSessions{sess: sess}
	f.limiter = &passwordLimiter{db: f.database}
	f.delivery = &captureDelivery{database: f.database}
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	f.client = client
	t.Cleanup(func() { _ = client.Close() })
	codes := deletionCodes(t, client, f.delivery, true, true)
	var err error
	f.service, err = New(Config{BindingKey: bytes.Repeat([]byte{2}, 32)}, Deps{DB: f.database, Queries: db.New(f.database), Codes: codes, Cipher: f.cipher, Limiter: f.limiter, Sessions: f.sessions})
	if err != nil {
		t.Fatal(err)
	}
	f.seal(t, time.Now().UTC().Add(-time.Minute))
	phone, err := f.cipher.Encrypt(t.Context(), []byte("+989123456789"))
	if err != nil {
		t.Fatal(err)
	}
	f.database.user.PhoneEncrypted = phone
	f.database.evidence[contactproof.Phone], err = contactproof.Seal(t.Context(), f.cipher, id, contactproof.Phone, "+989123456789", contactproof.SMSOTP, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f proofFixture) seal(t *testing.T, at time.Time) {
	t.Helper()
	blob, err := contactproof.Seal(t.Context(), f.cipher, f.database.user.ID, contactproof.Email, *f.database.user.Email, contactproof.EmailLink, at)
	if err != nil {
		t.Fatal(err)
	}
	f.database.evidence[contactproof.Email] = blob
}

func (f proofFixture) challenge(t *testing.T) (string, time.Time) {
	t.Helper()
	handle, deadline, err := f.service.Challenge(t.Context(), f.sess, testSecret, contactcode.ChannelEmail, "203.0.113.8")
	if err != nil || !capability(handle) || deadline.IsZero() {
		t.Fatal("eligible deletion challenge failed", err)
	}
	return handle, deadline
}

func (f proofFixture) issue(t *testing.T) string {
	t.Helper()
	handle, deadline := f.challenge(t)
	proof, expires, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("eligible deletion proof issuance failed", err)
	}
	return proof
}

func TestPasswordLimitsBeforeWorkAndExactBytes(t *testing.T) {
	for _, deny := range []int{1, 2} {
		f := newProofFixture(t)
		f.limiter.deny = deny
		f.database.user.PasswordHash = new("malformed")
		if handle, _, err := f.service.Challenge(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); handle != "" || err != ErrRateLimited || f.database.beginCalls != 0 || f.delivery.calls != 0 {
			t.Fatal("rate denial reached password/transaction/provider work")
		}
	}
	f := newProofFixture(t)
	if handle, _, err := f.service.Challenge(t.Context(), f.sess, strings.TrimSpace(testSecret), "email", "203.0.113.8"); handle != "" || err != ErrUnauthorized || f.delivery.calls != 0 || f.database.beginCalls != 0 {
		t.Fatal("altered password dispatched or opened a transaction")
	}
	f.challenge(t)
	if len(f.limiter.keys) != 4 || f.limiter.limit[0] != 5 || f.limiter.limit[1] != 20 || strings.Contains(f.limiter.keys[0], f.sess.UserID) || strings.Contains(f.limiter.keys[1], "203.0.113") {
		t.Fatal("password budgets not bounded/keyed by account and source")
	}
	order := strings.Join(f.database.events, ",")
	if !strings.Contains(order, "limit,limit,user,begin,advisory,row,passkeys,roles,user,contact") || f.database.inTx {
		t.Fatal("password verification/contact dispatch violated account lock order")
	}
}

func TestEmailSMSOperateIndependently(t *testing.T) {
	for _, tc := range []struct {
		channel    string
		email, sms bool
	}{{"email", true, false}, {"sms", false, true}, {"email", true, true}, {"sms", true, true}} {
		t.Run(tc.channel+"-"+strings.Join([]string{testEnabled(tc.email), testEnabled(tc.sms)}, "-"), func(t *testing.T) {
			f := newProofFixture(t)
			f.service.deps.Codes = deletionCodes(t, f.client, f.delivery, tc.email, tc.sms)
			handle, deadline, err := f.service.Challenge(t.Context(), f.sess, testSecret, tc.channel, "203.0.113.8")
			if err != nil || handle == "" {
				t.Fatal("independently enabled channel challenge failed", err)
			}
			proof, expires, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode())
			if err != nil || !capability(proof) || !expires.Equal(deadline) || f.database.saved.Channel != tc.channel {
				t.Fatal("independently enabled channel proof failed", err)
			}
			if err := f.service.ConsumeTx(t.Context(), f.database, f.sess, proof); err != nil {
				t.Fatal("channel-specific proof consumption failed", err)
			}
		})
	}
}

func testEnabled(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func TestChallengeLockedEligibilityAndCapturedVersion(t *testing.T) {
	for _, scenario := range []string{"version", "password", "passkey", "mfa", "role", "status", "contact", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProofFixture(t)
			f.database.onLock = func() {
				switch scenario {
				case "version":
					f.database.user.AuthVersion++
				case "password":
					f.database.user.PasswordHash = new("changed-hash")
				case "passkey":
					f.database.passkeys = 1
				case "mfa":
					f.database.user.IsMfaEnabled = true
				case "role":
					f.database.privileged = true
				case "status":
					f.database.user.Status = "suspended"
				case "contact":
					delete(f.database.evidence, contactproof.Email)
				case "revoked":
					f.sessions.revoke()
				}
			}
			if handle, _, err := f.service.Challenge(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); handle != "" || err != ErrUnauthorized || f.delivery.calls != 0 {
				t.Fatal("locked authority transition dispatched a deletion code")
			}
		})
	}
}

func TestSessionRejectionsDoNotConsumeOTP(t *testing.T) {
	for _, scenario := range []string{"recovery", "version", "jkt", "session", "expired", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProofFixture(t)
			handle, _ := f.challenge(t)
			bad := f.sess
			switch scenario {
			case "recovery":
				bad.Kind = session.KindRecoveryEnrollment
			case "version":
				bad.AuthVersion++
			case "jkt":
				bad.DPoPJKT = testCapability(2)
			case "session":
				bad.ID = uuid.NewString()
			case "expired":
				f.sessions.sess.IdleExpiry = time.Now()
			case "revoked":
				f.sessions.revoke()
			}
			if proof, _, err := f.service.Verify(t.Context(), bad, handle, f.delivery.lastCode()); proof != "" || err != ErrUnauthorized || f.database.createCalls != 0 {
				t.Fatal("foreign/dead session consumed authority")
			}
			f.sessions.err, f.sessions.sess = nil, f.sess
			if proof, _, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode()); err != nil || proof == "" {
				t.Fatal("preconsumption session rejection burned valid OTP")
			}
		})
	}
}

func TestIssuanceBindingIncludesOriginalVerifiedTime(t *testing.T) {
	f := newProofFixture(t)
	handle, _ := f.challenge(t)
	f.seal(t, time.Now().UTC().Add(-30*time.Second))
	if proof, _, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || err != ErrUnauthorized || f.database.saved != nil {
		t.Fatal("replacement evidence for identical contact retained challenge authority")
	}
	if proof, _, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || err != contactcode.ErrNoActiveCode {
		t.Fatal("failed issuance reused a consumed OTP")
	}
}

func TestConsumedOTPFailedIssuanceReturnsNoProofAndNeverRetries(t *testing.T) {
	for _, failure := range []string{"begin", "insert", "deadline", "commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newProofFixture(t)
			handle, _ := f.challenge(t)
			switch failure {
			case "begin":
				f.database.beginErr = errors.New("private database diagnostic")
			case "insert":
				f.database.createErr = errors.New("private database diagnostic")
			case "deadline":
				f.database.createZero = true
			case "commit":
				f.database.commitErr = errors.New("private database diagnostic")
			}
			if proof, expires, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || !expires.IsZero() || err != ErrOutcomeUnknown || f.database.saved != nil || f.database.createCalls > 1 || f.database.beginCalls != 2 {
				t.Fatal("failed/unknown issuance exposed a proof or retried work")
			}
			if proof, _, err := f.service.Verify(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || err != contactcode.ErrNoActiveCode || f.delivery.calls != 1 {
				t.Fatal("consumed OTP failed issuance replayed or resent")
			}
		})
	}
}

func TestProofDigestFrozenDeadlineAndTransactionOwnership(t *testing.T) {
	f := newProofFixture(t)
	proof := f.issue(t)
	digest := sha256.Sum256([]byte(proof))
	if !bytes.Equal(f.database.saved.ProofDigest, digest[:]) || bytes.Contains(f.database.saved.ContactBinding, []byte(*f.database.user.Email)) || len(f.database.saved.ContactBinding) != 32 {
		t.Fatal("proof storage did not retain only digest/keyed evidence")
	}
	commits, rollbacks, begins := f.database.commits, f.database.rollbacks, f.database.beginCalls
	if err := f.service.ConsumeTx(t.Context(), f.database, f.sess, proof); err != nil {
		t.Fatal("valid transaction-bound proof rejected", err)
	}
	if f.database.commits != commits || f.database.rollbacks != rollbacks || f.database.beginCalls != begins || f.database.deleteCalls != 1 {
		t.Fatal("consumer began or finalized caller transaction")
	}
}

func TestConsumerIsolationExactDeleteAndEvidenceRevocation(t *testing.T) {
	for _, scenario := range []string{"repeatable read", "serializable", "contact", "version", "revoked", "zero rows", "expired", "invalid proof"} {
		t.Run(scenario, func(t *testing.T) {
			f := newProofFixture(t)
			proof := f.issue(t)
			want := ErrUnauthorized
			switch scenario {
			case "repeatable read", "serializable":
				f.database.isolation = scenario
				want = ErrTransaction
			case "contact":
				f.seal(t, time.Now().UTC().Add(-20*time.Second))
			case "version":
				f.database.user.AuthVersion++
			case "revoked":
				f.sessions.revoke()
			case "zero rows":
				f.database.deleteZero = true
				want = ErrInvalid
			case "expired":
				f.database.saved.ExpiresAt.Time = time.Now()
				want = ErrInvalid
			case "invalid proof":
				proof = "not-a-proof"
				want = ErrInvalid
			}
			commits := f.database.commits
			if err := f.service.ConsumeTx(t.Context(), f.database, f.sess, proof); err != want || f.database.commits != commits {
				t.Fatal("invalid consumer authorized an action or committed")
			}
		})
	}
}

func TestEvidenceBindingCoversEveryFieldAndContext(t *testing.T) {
	f := newProofFixture(t)
	binding, err := f.service.live(t.Context(), f.sess)
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.service.contact(t.Context(), db.New(f.database), binding, "email")
	if err != nil {
		t.Fatal(err)
	}
	original := f.service.contactBinding(binding, "email", *e)
	for _, field := range []string{"purpose", "account", "channel", "destination", "method", "time", "session", "jkt", "version", "delivery"} {
		b, evidence, channel := binding, *e, "email"
		switch field {
		case "purpose":
			evidence.Purpose += "x"
		case "account":
			evidence.AccountID = uuid.New()
		case "channel":
			evidence.Channel = "phone"
		case "destination":
			evidence.Destination += "x"
		case "method":
			evidence.Method = "sms_otp"
		case "time":
			evidence.VerifiedAt = evidence.VerifiedAt.Add(time.Microsecond)
		case "session":
			b.SessionID = uuid.NewString()
		case "jkt":
			b.JKT = testCapability(2)
		case "version":
			b.AuthVersion++
		case "delivery":
			channel = "sms"
		}
		if bytes.Equal(original, f.service.contactBinding(b, channel, evidence)) {
			t.Fatal("binding omitted evidence/context field", field)
		}
	}
}

func TestCleanupIsBoundedAndConstructionFailsClosed(t *testing.T) {
	f := newProofFixture(t)
	for _, batch := range []int32{0, -1, 1001} {
		if count, err := f.service.CleanupExpired(t.Context(), batch); count != 0 || err != ErrInvalid {
			t.Fatal("cleanup accepted unbounded batch")
		}
	}
	if count, err := f.service.CleanupExpired(t.Context(), 2); count != 2 || err != nil {
		t.Fatal("bounded cleanup failed")
	}
	if _, err := New(Config{BindingKey: bytes.Repeat([]byte{1}, 31)}, f.service.deps); err != ErrInvalid {
		t.Fatal("weak binding key accepted")
	}
	deps := f.service.deps
	deps.Sessions = (*liveSessions)(nil)
	if _, err := New(Config{BindingKey: bytes.Repeat([]byte{1}, 32)}, deps); err != ErrUnavailable {
		t.Fatal("missing live session authority accepted")
	}
}
