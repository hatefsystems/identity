package smsotp

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// --- Fakes -----------------------------------------------------------------

// fakeUserStore records the last SetUserPhone call so a test can assert the
// verified phone was persisted with its blind index.
type fakeUserStore struct {
	users  map[uuid.UUID]bool
	status string

	setCalled       bool
	setEncrypted    []byte
	setBlindIndex   *string
	setUserID       uuid.UUID
	setUserPhoneErr error

	removeCalled       bool
	removeUserID       uuid.UUID
	removeAffected     *int64
	removeUserPhoneErr error
}

func newFakeUserStore(ids ...uuid.UUID) *fakeUserStore {
	m := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return &fakeUserStore{users: m}
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if !f.users[id] {
		return db.User{}, pgx.ErrNoRows
	}
	status := f.status
	if status == "" {
		status = "active"
	}
	return db.User{ID: id, Status: status}, nil
}

func (f *fakeUserStore) SetUserPhone(_ context.Context, arg db.SetUserPhoneParams) (int64, error) {
	if f.setUserPhoneErr != nil {
		return 0, f.setUserPhoneErr
	}
	f.setCalled = true
	f.setUserID = arg.ID
	f.setEncrypted = arg.PhoneEncrypted
	f.setBlindIndex = arg.PhoneBlindIndex
	return 1, nil
}

func (f *fakeUserStore) RemoveUserPhone(_ context.Context, id uuid.UUID) (int64, error) {
	if f.removeUserPhoneErr != nil {
		return 0, f.removeUserPhoneErr
	}
	f.removeCalled = true
	f.removeUserID = id
	if f.removeAffected != nil {
		return *f.removeAffected, nil
	}
	return 1, nil
}

// fakeEncryptor prefixes plaintext so a test can confirm encryption ran without
// pulling in the real AES-GCM module.
type fakeEncryptor struct{ err error }

func (f *fakeEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte("enc_"), plaintext...), nil
}

// fakeIndexer returns a deterministic, prefixed index so a test can assert the
// normalized phone was the value indexed.
type fakeIndexer struct{}

func (f *fakeIndexer) Compute(pii string) string { return "idx_" + pii }

// fakeSender records what was dispatched (or fails on demand).
type fakeSender struct {
	mu      sync.Mutex
	calls   int
	lastTo  string
	failErr error
}

func (f *fakeSender) Send(_ context.Context, phone, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failErr != nil {
		return f.failErr
	}
	f.calls++
	f.lastTo = phone
	return nil
}

// fakeLimiter admits a fixed number of calls per key, then rejects. A per-key
// budget lets a test target a single dimension (phone-minute, phone-hour,
// subnet) independently.
type fakeLimiter struct {
	budget map[string]int
	calls  map[string]int
	err    error
}

func newFakeLimiter() *fakeLimiter {
	return &fakeLimiter{budget: make(map[string]int), calls: make(map[string]int)}
}

func (f *fakeLimiter) allowAll() *fakeLimiter {
	f.budget = nil // nil budget => unlimited
	return f
}

// denyAll saturates every window, so a test can assert an operation is (or is
// not) subject to rate limiting.
func (f *fakeLimiter) denyAll() *fakeLimiter {
	f.budget = make(map[string]int) // every key has a zero budget
	return f
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.calls[key]++
	if f.budget == nil {
		return true, nil
	}
	return f.calls[key] <= f.budget[key], nil
}

// fakeOTPStore is an in-memory OTPStore for the service tests.
type fakeOTPStore struct {
	records  map[string]*OTPRecord
	lockouts map[string]bool

	storeErr error
	getErr   error
}

func newFakeOTPStore() *fakeOTPStore {
	return &fakeOTPStore{
		records:  make(map[string]*OTPRecord),
		lockouts: make(map[string]bool),
	}
}

func (f *fakeOTPStore) Store(_ context.Context, verificationID string, record OTPRecord, _ time.Duration) error {
	if f.storeErr != nil {
		return f.storeErr
	}
	record.Attempts = 0
	f.records[verificationID] = &record
	return nil
}

func (f *fakeOTPStore) Get(_ context.Context, verificationID string) (OTPRecord, error) {
	if f.getErr != nil {
		return OTPRecord{}, f.getErr
	}
	rec, ok := f.records[verificationID]
	if !ok {
		return OTPRecord{}, ErrNoActiveCode
	}
	return *rec, nil
}

func (f *fakeOTPStore) IncrementAttempts(_ context.Context, verificationID string) (int, error) {
	rec, ok := f.records[verificationID]
	if !ok {
		return 0, ErrNoActiveCode
	}
	rec.Attempts++
	return rec.Attempts, nil
}

func (f *fakeOTPStore) Delete(_ context.Context, verificationID string) error {
	delete(f.records, verificationID)
	return nil
}

func (f *fakeOTPStore) Lockout(_ context.Context, phone string, _ time.Duration) error {
	f.lockouts[phone] = true
	return nil
}

func (f *fakeOTPStore) IsLockedOut(_ context.Context, phone string) (bool, error) {
	return f.lockouts[phone], nil
}

// setStoredCode injects a fully bound record so a Verify test can supply the
// matching plaintext code. It mirrors what SendCode would have stored.
func (f *fakeOTPStore) setStoredCode(s *Service, verificationID string, userID uuid.UUID, sessionID, phone, code string) {
	f.records[verificationID] = &OTPRecord{
		UserID:    userID.String(),
		SessionID: sessionID,
		Phone:     phone,
		CodeHash:  s.hashCode(phone, code),
	}
}

// --- Test builder ----------------------------------------------------------

type serviceFixture struct {
	svc       *Service
	users     *fakeUserStore
	limiter   *fakeLimiter
	otps      *fakeOTPStore
	sender    *fakeSender
	userID    uuid.UUID
	sessionID string
}

func testVerificationID(seed byte) string {
	raw := make([]byte, verificationIDBytes)
	for i := range raw {
		raw[i] = seed
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func newServiceFixture(t *testing.T, cfg Config) *serviceFixture {
	t.Helper()

	userID := uuid.New()
	users := newFakeUserStore(userID)
	limiter := newFakeLimiter().allowAll()
	otps := newFakeOTPStore()
	sender := &fakeSender{}

	svc, err := New(cfg, users, &fakeEncryptor{}, &fakeIndexer{}, limiter, otps, sender)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &serviceFixture{
		svc:       svc,
		users:     users,
		limiter:   limiter,
		otps:      otps,
		sender:    sender,
		userID:    userID,
		sessionID: "session-a",
	}
}

// --- New validation --------------------------------------------------------

func TestNewRequiresCollaborators(t *testing.T) {
	users := newFakeUserStore()
	enc := &fakeEncryptor{}
	idx := &fakeIndexer{}
	lim := newFakeLimiter()
	otps := newFakeOTPStore()
	snd := &fakeSender{}

	cases := []struct {
		name  string
		users UserStore
		enc   Encryptor
		idx   BlindIndexer
		lim   ratelimit.Limiter

		otps OTPStore
		snd  Sender
	}{
		{"nil users", nil, enc, idx, lim, otps, snd},
		{"nil encryptor", users, nil, idx, lim, otps, snd},
		{"nil indexer", users, enc, nil, lim, otps, snd},
		{"nil limiter", users, enc, idx, nil, otps, snd},
		{"nil otps", users, enc, idx, lim, nil, snd},
		{"nil sender", users, enc, idx, lim, otps, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(Config{}, tc.users, tc.enc, tc.idx, tc.lim, tc.otps, tc.snd); err == nil {
				t.Error("expected error for missing collaborator, got nil")
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	s := fx.svc
	if s.codeTTL != defaultCodeTTL {
		t.Errorf("codeTTL = %v, want %v", s.codeTTL, defaultCodeTTL)
	}
	if s.maxAttempts != defaultMaxAttempts {
		t.Errorf("maxAttempts = %d, want %d", s.maxAttempts, defaultMaxAttempts)
	}
	if s.lockoutTTL != defaultLockoutTTL {
		t.Errorf("lockoutTTL = %v, want %v", s.lockoutTTL, defaultLockoutTTL)
	}
	if s.perPhonePerMinute != defaultPerPhonePerMinute {
		t.Errorf("perPhonePerMinute = %d, want %d", s.perPhonePerMinute, defaultPerPhonePerMinute)
	}
	if s.perPhonePerHour != defaultPerPhonePerHour {
		t.Errorf("perPhonePerHour = %d, want %d", s.perPhonePerHour, defaultPerPhonePerHour)
	}
	if s.perSubnetPerHour != defaultPerSubnetPerHour {
		t.Errorf("perSubnetPerHour = %d, want %d", s.perSubnetPerHour, defaultPerSubnetPerHour)
	}
	if s.messageTemplate != defaultMessageTemplate {
		t.Errorf("messageTemplate = %q, want %q", s.messageTemplate, defaultMessageTemplate)
	}
}

// --- SendCode --------------------------------------------------------------

func TestSendCodeHappyPath(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	ctx := context.Background()

	verificationID, err := fx.svc.SendCode(ctx, fx.userID, fx.sessionID, "+1 555 010 2020", "203.0.113.9:5555")
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	rawID, err := base64.RawURLEncoding.DecodeString(verificationID)
	if err != nil || len(rawID) != verificationIDBytes {
		t.Fatalf("verification ID = %q, want %d bytes of base64url entropy (decode error: %v)", verificationID, verificationIDBytes, err)
	}
	if fx.sender.calls != 1 {
		t.Errorf("sender calls = %d, want 1", fx.sender.calls)
	}
	if fx.sender.lastTo != "+15550102020" {
		t.Errorf("sender delivered to %q, want normalized +15550102020", fx.sender.lastTo)
	}
	record, ok := fx.otps.records[verificationID]
	if !ok {
		t.Fatal("expected a pending code stored under the verification ID")
	}
	if record.UserID != fx.userID.String() || record.SessionID != fx.sessionID || record.Phone != "+15550102020" {
		t.Errorf("stored binding = %+v, want user %s, session %q, normalized phone", record, fx.userID, fx.sessionID)
	}
	if _, phoneKeyed := fx.otps.records["+15550102020"]; phoneKeyed {
		t.Error("pending challenge must not be keyed by phone")
	}
}

func TestSendCodeReturnsUniqueVerificationIDs(t *testing.T) {
	fx := newServiceFixture(t, Config{})

	first, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9")
	if err != nil {
		t.Fatalf("first SendCode: %v", err)
	}
	second, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9")
	if err != nil {
		t.Fatalf("second SendCode: %v", err)
	}
	if first == second {
		t.Fatal("two sends returned the same verification ID")
	}
}

func TestSendCodeUnknownUser(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	if _, err := fx.svc.SendCode(context.Background(), uuid.New(), fx.sessionID, "+15550102020", "203.0.113.9"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("SendCode unknown user: error = %v, want ErrUserNotFound", err)
	}
}

func TestPhoneOperationsRejectNonActiveAccount(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.users.status = "suspended"
	verificationID := testVerificationID(42)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, "+15550102020", "123456")

	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9"); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("SendCode = %v, want ErrAccountNotActive", err)
	}
	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "123456"); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("Verify = %v, want ErrAccountNotActive", err)
	}
	if err := fx.svc.RemovePhone(context.Background(), fx.userID); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("RemovePhone = %v, want ErrAccountNotActive", err)
	}
	if fx.sender.calls != 0 || fx.users.setCalled || fx.users.removeCalled {
		t.Fatal("a non-active account caused phone side effects")
	}
}

func TestSendCodeInvalidPhone(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "not-a-phone", "203.0.113.9"); !errors.Is(err, ErrInvalidPhone) {
		t.Errorf("SendCode invalid phone: error = %v, want ErrInvalidPhone", err)
	}
}

func TestSendCodeRejectedWhenLockedOut(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.otps.lockouts["+15550102020"] = true
	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9"); !errors.Is(err, ErrLockedOut) {
		t.Errorf("SendCode while locked out: error = %v, want ErrLockedOut", err)
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be sent while locked out")
	}
}

func TestSendCodePerMinuteLimit(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	// Budget the minute window to zero; other windows unlimited.
	fx.limiter.budget = map[string]int{
		phoneRateKey("+15550102020", "1m"): 0,
	}
	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("SendCode over minute limit: error = %v, want ErrRateLimited", err)
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be sent when rate limited")
	}
}

func TestSendCodePerSubnetLimit(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	// Allow both phone windows but saturate the subnet window.
	fx.limiter.budget = map[string]int{
		phoneRateKey("+15550102020", "1m"): 5,
		phoneRateKey("+15550102020", "1h"): 5,
		subnetRateKey("203.0.113.0/24"):    0,
	}
	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9:1234"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("SendCode over subnet limit: error = %v, want ErrRateLimited", err)
	}
	// Verify subnet check runs first so phone rate limits are not consumed on subnet rejection.
	if phoneCalls := fx.limiter.calls[phoneRateKey("+15550102020", "1m")]; phoneCalls != 0 {
		t.Errorf("phone 1m limit calls = %d, want 0 when subnet limit is rejected first", phoneCalls)
	}
}

func TestSendCodePerHourPhoneLimit(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.limiter.budget = map[string]int{
		subnetRateKey("203.0.113.0/24"):    5,
		phoneRateKey("+15550102020", "1m"): 5,
		phoneRateKey("+15550102020", "1h"): 0,
	}
	if _, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9:1234"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("SendCode over 1h phone limit: error = %v, want ErrRateLimited", err)
	}
}

func TestSendCodeSendFailureCleansUp(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.sender.failErr = errors.New("gateway down")
	_, err := fx.svc.SendCode(context.Background(), fx.userID, fx.sessionID, "+15550102020", "203.0.113.9")
	if !errors.Is(err, ErrSendFailed) {
		t.Fatalf("SendCode with failing gateway: error = %v, want ErrSendFailed", err)
	}
	if len(fx.otps.records) != 0 {
		t.Error("a failed delivery must purge the pending code so the slot is not wasted")
	}
}

// --- Verify ----------------------------------------------------------------

func TestVerifyHappyPathPersistsPhone(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	const phone = "+15550102020"
	verificationID := testVerificationID(1)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "123456"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !fx.users.setCalled {
		t.Fatal("expected the verified phone to be persisted")
	}
	if fx.users.setUserID != fx.userID {
		t.Errorf("persisted for user %v, want %v", fx.users.setUserID, fx.userID)
	}
	if string(fx.users.setEncrypted) != "enc_"+phone {
		t.Errorf("stored ciphertext = %q, want enc_%s", fx.users.setEncrypted, phone)
	}
	if fx.users.setBlindIndex == nil || *fx.users.setBlindIndex != "idx_"+phone {
		t.Errorf("stored blind index = %v, want idx_%s", fx.users.setBlindIndex, phone)
	}
	// The code must be consumed on success.
	if _, ok := fx.otps.records[verificationID]; ok {
		t.Error("expected the code to be purged after a successful verify")
	}
}

func TestVerifyWrongCodeIncrementsAttempts(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	const phone = "+15550102020"
	verificationID := testVerificationID(2)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Verify wrong code: error = %v, want ErrInvalidCode", err)
	}
	rec := fx.otps.records[verificationID]
	if rec == nil || rec.Attempts != 1 {
		t.Errorf("expected one failed attempt recorded, got %+v", rec)
	}
	if fx.users.setCalled {
		t.Error("phone must not be persisted on a wrong code")
	}
}

func TestVerifyLocksOutAfterMaxAttempts(t *testing.T) {
	fx := newServiceFixture(t, Config{MaxAttempts: 3})
	const phone = "+15550102020"
	verificationID := testVerificationID(3)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")

	// Two wrong guesses return ErrInvalidCode.
	for i := 0; i < 2; i++ {
		if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "000000"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("attempt %d: error = %v, want ErrInvalidCode", i+1, err)
		}
	}
	// The third wrong guess trips the lockout.
	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "000000"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("third wrong guess: error = %v, want ErrLockedOut", err)
	}
	if !fx.otps.lockouts[phone] {
		t.Error("expected the phone to be locked out after MaxAttempts failures")
	}
	if _, ok := fx.otps.records[verificationID]; ok {
		t.Error("expected the code purged when the lockout trips")
	}
}

func TestVerifyRejectedWhenLockedOut(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	const phone = "+15550102020"
	fx.otps.lockouts[phone] = true
	verificationID := testVerificationID(4)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "123456"); !errors.Is(err, ErrLockedOut) {
		t.Errorf("Verify while locked out: error = %v, want ErrLockedOut", err)
	}
	if fx.users.setCalled {
		t.Error("a locked-out phone must not be verifiable even with the right code")
	}
}

func TestVerifyNoActiveCode(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, testVerificationID(5), "123456"); !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Verify with no pending code: error = %v, want ErrNoActiveCode", err)
	}
}

func TestVerifyUnknownUser(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	if err := fx.svc.Verify(context.Background(), uuid.New(), fx.sessionID, testVerificationID(6), "123456"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Verify unknown user: error = %v, want ErrUserNotFound", err)
	}
}

func TestVerifyForeignSessionDoesNotConsumeChallenge(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	const phone = "+15550102020"
	verificationID := testVerificationID(7)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")

	err := fx.svc.Verify(context.Background(), fx.userID, "foreign-session", verificationID, "123456")
	if !errors.Is(err, ErrNoActiveCode) {
		t.Fatalf("foreign session: error = %v, want ErrNoActiveCode", err)
	}
	record := fx.otps.records[verificationID]
	if record == nil || record.Attempts != 0 {
		t.Fatalf("foreign session consumed or mutated the challenge: %+v", record)
	}

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "123456"); err != nil {
		t.Fatalf("initiating session could not use its untouched challenge: %v", err)
	}
}

func TestVerifyForeignUserDoesNotConsumeChallenge(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	const phone = "+15550102020"
	verificationID := testVerificationID(8)
	fx.otps.setStoredCode(fx.svc, verificationID, fx.userID, fx.sessionID, phone, "123456")
	foreignUser := uuid.New()
	fx.users.users[foreignUser] = true

	err := fx.svc.Verify(context.Background(), foreignUser, fx.sessionID, verificationID, "123456")
	if !errors.Is(err, ErrNoActiveCode) {
		t.Fatalf("foreign user: error = %v, want ErrNoActiveCode", err)
	}
	record := fx.otps.records[verificationID]
	if record == nil || record.Attempts != 0 {
		t.Fatalf("foreign user consumed or mutated the challenge: %+v", record)
	}

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, verificationID, "123456"); err != nil {
		t.Fatalf("owning user could not use the untouched challenge: %v", err)
	}
}

func TestVerifyRejectsMalformedVerificationIDWithoutStoreLookup(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.otps.getErr = errors.New("store should not be called")

	if err := fx.svc.Verify(context.Background(), fx.userID, fx.sessionID, "not-a-256-bit-id", "123456"); !errors.Is(err, ErrNoActiveCode) {
		t.Fatalf("malformed verification ID: error = %v, want ErrNoActiveCode", err)
	}
}

// TestHashCodeBindsPhone confirms a code hashed for one phone does not validate
// against another, so a leaked hash cannot be replayed onto a different number.
func TestHashCodeBindsPhone(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	h1 := fx.svc.hashCode("+15550102020", "123456")
	h2 := fx.svc.hashCode("+15550109999", "123456")
	if h1 == h2 {
		t.Error("hashCode must bind the phone so identical codes hash differently per number")
	}
}

// --- RemovePhone ------------------------------------------------------------

// TestRemovePhoneClearsTheAccount covers the happy path. The encrypted payload
// and its blind index are cleared by a single statement, so they cannot drift
// apart — the same invariant persistPhone maintains on the way in.
func TestRemovePhoneClearsTheAccount(t *testing.T) {
	fx := newServiceFixture(t, Config{})

	if err := fx.svc.RemovePhone(context.Background(), fx.userID); err != nil {
		t.Fatalf("RemovePhone: %v", err)
	}
	if !fx.users.removeCalled {
		t.Fatal("expected the phone to be cleared")
	}
	if fx.users.removeUserID != fx.userID {
		t.Fatalf("cleared %s, want %s", fx.users.removeUserID, fx.userID)
	}
}

// TestRemovePhoneIsNotRateLimited records a deliberate asymmetry: sending codes is
// throttled because it costs money and can be used to harass a number, whereas
// clearing one's own phone is already gated by step-up authentication at the HTTP
// layer and has no such abuse potential.
func TestRemovePhoneIsNotRateLimited(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.limiter.denyAll()

	if err := fx.svc.RemovePhone(context.Background(), fx.userID); err != nil {
		t.Fatalf("RemovePhone with a saturated limiter: %v", err)
	}
}

func TestRemovePhoneRejectsAnUnknownAccount(t *testing.T) {
	fx := newServiceFixture(t, Config{})

	if err := fx.svc.RemovePhone(context.Background(), uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
	if fx.users.removeCalled {
		t.Error("an unknown account triggered a write")
	}
}

// TestRemovePhoneReportsAVanishedAccount covers the row-count check: the account
// disappeared between the lookup and the update, so the caller's session has
// outlived its account.
func TestRemovePhoneReportsAVanishedAccount(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	zero := int64(0)
	fx.users.removeAffected = &zero

	if err := fx.svc.RemovePhone(context.Background(), fx.userID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestRemovePhonePropagatesStoreFailures(t *testing.T) {
	fx := newServiceFixture(t, Config{})
	fx.users.removeUserPhoneErr = errors.New("database on fire")

	err := fx.svc.RemovePhone(context.Background(), fx.userID)
	if err == nil {
		t.Fatal("expected the store failure to propagate")
	}
	// An infrastructure fault must not be flattened into a domain sentinel, or a
	// database outage would surface to the user as "no such account".
	if errors.Is(err, ErrUserNotFound) {
		t.Fatal("a store failure was reported as ErrUserNotFound")
	}
}
