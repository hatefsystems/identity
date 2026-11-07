package smsotp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

const testPhone = "+989123456789"

var errPrivate = errors.New("private-key private-phone private-code private-db")

type fakeUserStore struct {
	mu         sync.Mutex
	id         uuid.UUID
	version    int64
	status     string
	phone      []byte
	index      string
	writes     int
	err        error
	lockChange func(*fakeUserStore)
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != f.id {
		return db.User{}, pgx.ErrNoRows
	}
	return db.User{ID: id, Status: f.status, AuthVersion: f.version}, f.err
}
func (f *fakeUserStore) mutate(id uuid.UUID, version int64, phone []byte, index string, remove bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lockChange != nil {
		f.lockChange(f)
		f.lockChange = nil
	}
	if f.err != nil {
		return false, f.err
	}
	if id != f.id {
		return false, ErrUserNotFound
	}
	if f.status != "active" {
		return false, ErrAccountNotActive
	}
	if f.version != version {
		return false, ErrStaleSession
	}
	changed := !remove || len(f.phone) > 0 || f.index != ""
	if changed {
		f.writes++
		f.phone = phone
		f.index = index
	}
	return changed, nil
}
func (f *fakeUserStore) SetPhoneIfCurrent(_ context.Context, id uuid.UUID, v int64, p []byte, i string) error {
	_, err := f.mutate(id, v, p, i, false)
	return err
}
func (f *fakeUserStore) RemovePhoneIfCurrent(_ context.Context, id uuid.UUID, v int64) (bool, error) {
	return f.mutate(id, v, nil, "", true)
}

type fakeEncryptor struct{ err error }

func (e *fakeEncryptor) Encrypt(_ context.Context, p []byte) ([]byte, error) {
	return append([]byte("enc_"), p...), e.err
}

type fakeIndexer struct{}

func (*fakeIndexer) Compute(p string) string { return "idx_" + p }

type fakeSender struct {
	calls       int
	phone, code string
	err         error
}

func (f *fakeSender) SendCode(_ context.Context, p, c string) error {
	f.calls++
	f.phone = p
	f.code = c
	return f.err
}

type fakeLimiter struct {
	calls map[string]int
	deny  string
	err   error
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	f.calls[key]++
	return key != f.deny, f.err
}

type serviceFixture struct {
	svc     *Service
	users   *fakeUserStore
	sender  *fakeSender
	limiter *fakeLimiter
	otps    *RedisOTPStore
	enc     *fakeEncryptor
}

func testVerificationID(seed byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed}), 32)))
}
func fixture(t *testing.T, cfg Config) *serviceFixture {
	t.Helper()
	users := &fakeUserStore{id: uuid.New(), version: 7, status: "active"}
	store, _ := newTestOTPStore(t)
	sender := &fakeSender{}
	lim := &fakeLimiter{calls: map[string]int{}}
	enc := &fakeEncryptor{}
	if cfg.HashPepper == nil {
		cfg.HashPepper = []byte(strings.Repeat("p", 32))
	}
	svc, err := New(cfg, users, enc, &fakeIndexer{}, lim, store, sender)
	if err != nil {
		t.Fatal(err)
	}
	return &serviceFixture{svc, users, sender, lim, store, enc}
}
func (f *serviceFixture) send(t *testing.T) string {
	t.Helper()
	id, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *serviceFixture) verify(id, code string) error {
	return f.svc.Verify(context.Background(), f.users.id, 7, "session-a", id, code)
}
func TestSMSServiceDefaultsAndBoundedConstruction(t *testing.T) {
	f := fixture(t, Config{})
	c := f.svc.cfg
	if c.CodeTTL != 3*time.Minute || c.MaxAttempts != 3 || c.LockoutTTL != 15*time.Minute || c.PerPhonePerMinute != 1 || c.PerPhonePerHour != 5 || c.PerSubnetPerHour != 10 {
		t.Fatal("default policy changed")
	}
	for _, cfg := range []Config{{MaxAttempts: 4}, {CodeTTL: 4 * time.Minute}, {LockoutTTL: time.Minute}, {PerPhonePerMinute: 6}, {PerPhonePerHour: 21}, {PerSubnetPerHour: 101}, {GlobalPerDay: 100001}, {MaxPendingSignup: 10001}, {SignupEnabled: true}, {HashPepper: []byte("short")}} {
		if cfg.HashPepper == nil {
			cfg.HashPepper = c.HashPepper
		}
		if _, err := New(cfg, f.users, f.enc, &fakeIndexer{}, f.limiter, f.otps, f.sender); err == nil {
			t.Fatal("unbounded construction accepted")
		}
	}
	if _, err := New(Config{}, f.users, f.enc, &fakeIndexer{}, f.limiter, f.otps, f.sender); err == nil {
		t.Fatal("missing pepper accepted")
	}
	if _, err := New(c, nil, f.enc, &fakeIndexer{}, f.limiter, f.otps, f.sender); err == nil {
		t.Fatal("missing DB accepted")
	}
	if _, err := New(c, f.users, nil, &fakeIndexer{}, f.limiter, f.otps, f.sender); err == nil {
		t.Fatal("missing encryption accepted")
	}
	if _, err := New(c, f.users, f.enc, nil, f.limiter, f.otps, f.sender); err == nil {
		t.Fatal("missing indexer accepted")
	}
	if _, err := New(c, f.users, f.enc, &fakeIndexer{}, nil, f.otps, f.sender); err == nil {
		t.Fatal("missing limiter accepted")
	}
	if _, err := New(c, f.users, f.enc, &fakeIndexer{}, f.limiter, nil, f.sender); err == nil {
		t.Fatal("missing OTP store accepted")
	}
	if _, err := New(c, f.users, f.enc, &fakeIndexer{}, f.limiter, f.otps, nil); err == nil {
		t.Fatal("missing sender accepted")
	}
}
func TestSMSServiceSendVerifyAndSingleUse(t *testing.T) {
	f := fixture(t, Config{})
	id := f.send(t)
	if !validVerificationID(id) || f.sender.calls != 1 || f.sender.phone != testPhone || len(f.sender.code) != 6 {
		t.Fatal("invalid send contract")
	}
	if err := f.verify(id, f.sender.code); err != nil {
		t.Fatal(err)
	}
	if string(f.users.phone) != "enc_"+testPhone || f.users.index != "idx_"+testPhone || f.users.writes != 1 {
		t.Fatal("phone not encrypted/indexed")
	}
	if err := f.verify(id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("OTP replay accepted")
	}
}

func TestSMSServiceIssuesIndependentVerificationIDs(t *testing.T) {
	f := fixture(t, Config{})
	first := f.send(t)
	second := f.send(t)
	if first == second || !validVerificationID(first) || !validVerificationID(second) {
		t.Fatal("send authorities are not independent 256-bit IDs")
	}
}
func TestSMSServiceForeignAuthorityDoesNotBurn(t *testing.T) {
	f := fixture(t, Config{})
	id := f.send(t)
	if err := f.svc.Verify(context.Background(), f.users.id, 7, "foreign", id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal(err)
	}
	rec, err := f.otps.Get(context.Background(), id)
	if err != nil || rec.Attempts != 0 {
		t.Fatal("foreign owner burned state")
	}
	if err := f.verify(id, f.sender.code); err != nil {
		t.Fatal(err)
	}
}
func TestSMSServiceAttemptsLockoutAndSharedLimits(t *testing.T) {
	for _, key := range []string{subnetRateKey("203.0.113.0/24"), phoneRateKey(testPhone, "1m"), phoneRateKey(testPhone, "1h")} {
		f := fixture(t, Config{})
		f.limiter.deny = key
		_, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9")
		if !errors.Is(err, ErrRateLimited) || f.sender.calls != 0 {
			t.Fatal("rate limit bypassed")
		}
		if key == subnetRateKey("203.0.113.0/24") && f.limiter.calls[phoneRateKey(testPhone, "1m")] != 0 {
			t.Fatal("subnet reject burned phone budget")
		}
	}
	f := fixture(t, Config{})
	id := f.send(t)
	for i := 0; i < 3; i++ {
		err := f.verify(id, "invalid")
		want := ErrInvalidCode
		if i == 2 {
			want = ErrLockedOut
		}
		if !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9"); !errors.Is(err, ErrLockedOut) {
		t.Fatal("lockout bypassed")
	}
}
func TestSMSServiceFailuresAreRedactedAndProofNeverResurrects(t *testing.T) {
	f := fixture(t, Config{})
	f.sender.err = errPrivate
	if id, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9"); id != "" || err != ErrSendFailed {
		t.Fatal("delivery failure disclosed or accepted")
	}
	for _, failure := range []string{"encrypt", "db", "revoked"} {
		t.Run(failure, func(t *testing.T) {
			f := fixture(t, Config{})
			id := f.send(t)
			if failure == "encrypt" {
				f.enc.err = errPrivate
			} else {
				f.users.lockChange = func(u *fakeUserStore) {
					if failure == "revoked" {
						u.version++
					} else {
						u.err = errPrivate
					}
				}
			}
			err := f.verify(id, f.sender.code)
			if failure == "revoked" {
				if !errors.Is(err, ErrStaleSession) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrRestartRequired) {
				t.Fatal(err)
			}
			if strings.Contains(err.Error(), "private") || f.users.writes != 0 {
				t.Fatal("failed mutation leaked/wrote")
			}
			if _, err := f.otps.Get(context.Background(), id); !errors.Is(err, ErrNoActiveCode) {
				t.Fatal("consumed OTP resurrected")
			}
		})
	}
}
func TestSMSServiceNonActiveAndStaleAdmission(t *testing.T) {
	for _, state := range []string{"suspended", "stale", "missing"} {
		f := fixture(t, Config{})
		id := f.send(t)
		user := f.users.id
		want := ErrAccountNotActive
		switch state {
		case "suspended":
			f.users.status = "suspended"
		case "stale":
			f.users.version++
			want = ErrStaleSession
		case "missing":
			user = uuid.New()
			want = ErrUserNotFound
		}
		if _, err := f.svc.SendCode(context.Background(), user, 7, "session-a", testPhone, "203.0.113.9"); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if err := f.svc.Verify(context.Background(), user, 7, "session-a", id, f.sender.code); !errors.Is(err, want) {
			t.Fatal(err)
		}
		if f.users.writes != 0 {
			t.Fatal("unauthorized write")
		}
	}
}
func TestSMSDisabledRemovalIsFencedAndChangeCountAtomic(t *testing.T) {
	f := fixture(t, Config{})
	s, err := NewDisabled(f.users)
	if err != nil {
		t.Fatal(err)
	}
	if s.DeliveryEnabled() {
		t.Fatal("disabled service delivers")
	}
	if _, err := s.SendCode(context.Background(), f.users.id, 7, "", testPhone, ""); err != ErrDisabled {
		t.Fatal(err)
	}
	if err := s.Verify(context.Background(), f.users.id, 7, "", "", ""); err != ErrDisabled {
		t.Fatal(err)
	}
	f.users.phone = []byte("encrypted")
	var wg sync.WaitGroup
	changes := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			changed, err := s.RemovePhone(context.Background(), f.users.id, 7)
			if err != nil {
				t.Error(err)
			}
			changes <- changed
		}()
	}
	wg.Wait()
	close(changes)
	winners := 0
	for changed := range changes {
		if changed {
			winners++
		}
	}
	if winners != 1 || f.users.writes != 1 {
		t.Fatal("duplicate removal change event")
	}
	f.users.phone = []byte("encrypted")
	f.users.lockChange = func(u *fakeUserStore) { u.version++ }
	if changed, err := s.RemovePhone(context.Background(), f.users.id, 7); changed || !errors.Is(err, ErrStaleSession) {
		t.Fatal("stale removal accepted")
	}
}
func TestSMSSignupPurposeSharesBudgetsAndDoesNotCreateUser(t *testing.T) {
	f := fixture(t, Config{SignupEnabled: true, GlobalPerDay: 10, MaxPendingSignup: 2})
	attempt := uuid.New()
	jkt := testVerificationID(44)
	id, err := f.svc.SendSignupCode(context.Background(), attempt, jkt, testPhone, "203.0.113.9", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Verify(context.Background(), f.users.id, 7, "session-a", id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("signup usable as enrollment")
	}
	if err := f.svc.ConsumeSignupCode(context.Background(), attempt, testVerificationID(45), testPhone, id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("foreign JKT accepted")
	}
	if err := f.svc.ConsumeSignupCode(context.Background(), attempt, jkt, "+989123456780", id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("foreign phone accepted")
	}
	if err := f.svc.ConsumeSignupCode(context.Background(), attempt, jkt, testPhone, id, f.sender.code); err != nil {
		t.Fatal(err)
	}
	if f.users.writes != 0 || f.limiter.calls[phoneRateKey(testPhone, "1m")] != 1 || f.limiter.calls[subnetRateKey("203.0.113.0/24")] != 1 || f.limiter.calls["rate:otp:global:1d"] != 1 {
		t.Fatal("signup used fake account or different budgets")
	}
	if err := f.svc.ConsumeSignupCode(context.Background(), attempt, jkt, testPhone, id, f.sender.code); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("signup replay")
	}
}
func TestSMSHashBindsPhoneAndPepper(t *testing.T) {
	f := fixture(t, Config{})
	if f.svc.hashCode(testPhone, "000042") == f.svc.hashCode("+989123456780", "000042") {
		t.Fatal("unbound hash")
	}
}

func TestSMSServiceInvalidBindingsPhonesAndStorageFailuresAreSafe(t *testing.T) {
	for _, tc := range []struct {
		session, phone string
		want           error
	}{
		{"", testPhone, ErrNoActiveCode}, {"private\nsession", testPhone, ErrNoActiveCode}, {"session-a", "not-phone", ErrInvalidPhone},
	} {
		f := fixture(t, Config{})
		if _, err := f.svc.SendCode(context.Background(), f.users.id, 7, tc.session, tc.phone, "203.0.113.9"); err != tc.want || f.sender.calls != 0 {
			t.Fatal("invalid send produced side effects")
		}
	}
	f := fixture(t, Config{})
	f.limiter.err = errPrivate
	if _, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9"); err != ErrUnavailable || f.sender.calls != 0 {
		t.Fatal("limiter error leaked or sent")
	}
	f = fixture(t, Config{})
	f.sender.err = errPrivate
	if id, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9"); err != ErrSendFailed || id != "" {
		t.Fatal("failed send exposed authority")
	}
	keys, err := f.otps.client.Keys(context.Background(), otpKeyPrefix+"*").Result()
	if err != nil || len(keys) != 0 {
		t.Fatal("failed delivery retained usable challenge")
	}
	f = fixture(t, Config{})
	if err := f.verify("malformed-key", "000042"); err != ErrNoActiveCode {
		t.Fatal("invalid verification id accepted")
	}
}

func TestSMSSignupExplicitBudgetsExpiryAndFailureNeverVerify(t *testing.T) {
	f := fixture(t, Config{})
	if _, err := f.svc.SendSignupCode(context.Background(), uuid.New(), testVerificationID(50), testPhone, "203.0.113.9", time.Now().Add(time.Minute)); err != ErrDisabled {
		t.Fatal("signup without explicit limits enabled")
	}
	f = fixture(t, Config{SignupEnabled: true, GlobalPerDay: 10, MaxPendingSignup: 1})
	if _, err := f.svc.SendSignupCode(context.Background(), uuid.New(), testVerificationID(50), testPhone, "203.0.113.9", time.Now().Add(-time.Second)); err != ErrNoActiveCode || f.sender.calls != 0 {
		t.Fatal("expired signup sent")
	}
	f.limiter.deny = "rate:otp:global:1d"
	if _, err := f.svc.SendSignupCode(context.Background(), uuid.New(), testVerificationID(50), testPhone, "203.0.113.9", time.Now().Add(time.Minute)); err != ErrRateLimited || f.sender.calls != 0 {
		t.Fatal("global signup cap bypassed")
	}
	f = fixture(t, Config{SignupEnabled: true, GlobalPerDay: 10, MaxPendingSignup: 1})
	f.sender.err = errPrivate
	if id, err := f.svc.SendSignupCode(context.Background(), uuid.New(), testVerificationID(50), testPhone, "203.0.113.9", time.Now().Add(time.Minute)); id != "" || err != ErrSendFailed || f.users.writes != 0 {
		t.Fatal("failed signup delivery claimed proof")
	}
}

func TestSMSRealLimiterSharesPhoneAndSubnetBudgetsAcrossPurposes(t *testing.T) {
	for _, subnet := range []bool{false, true} {
		f := fixture(t, Config{SignupEnabled: true, GlobalPerDay: 10, MaxPendingSignup: 2})
		limiter, err := ratelimit.NewRedisLimiter(f.otps.client.(*redis.Client))
		if err != nil {
			t.Fatal(err)
		}
		f.svc.limiter = limiter
		if subnet {
			f.svc.cfg.PerSubnetPerHour = 1
		}
		id, err := f.svc.SendSignupCode(context.Background(), uuid.New(), testVerificationID(60), testPhone, "203.0.113.9", time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if !validVerificationID(id) {
			t.Fatal("signup did not receive independent authority")
		}
		phone := testPhone
		if subnet {
			phone = "+989123456780"
		}
		if _, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", phone, "203.0.113.10"); err != ErrRateLimited || f.sender.calls != 1 {
			t.Fatal("purposes used independent abuse budgets")
		}
	}
}

type deliveryReasonError string

func (deliveryReasonError) Error() string            { return "private-key private-phone private-provider-body" }
func (e deliveryReasonError) DeliveryReason() string { return string(e) }
func TestSMSSafeProviderClassificationIsNotUserRateLimit(t *testing.T) {
	for _, reason := range []string{"credentials", "account", "egress", "template", "parameters", "credit", "throttle", "recipient", "unavailable", "rejected", "private-key"} {
		f := fixture(t, Config{})
		f.sender.err = deliveryReasonError(reason)
		_, err := f.svc.SendCode(context.Background(), f.users.id, 7, "session-a", testPhone, "203.0.113.9")
		if !errors.Is(err, ErrSendFailed) || errors.Is(err, ErrRateLimited) || strings.Contains(err.Error(), "private") {
			t.Fatal("unsafe provider reason or local-rate-limit misclassification")
		}
		want := reason
		if reason == "private-key" {
			want = "unavailable"
		}
		if SendFailureReason(err) != want {
			t.Fatal("provider reason lost or untrusted reason forwarded")
		}
	}
}
