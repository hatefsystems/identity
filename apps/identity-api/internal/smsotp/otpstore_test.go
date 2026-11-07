package smsotp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func newTestOTPStore(t *testing.T) (*RedisOTPStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	s, err := NewRedisOTPStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return s, mr
}
func boundOTPRecord() OTPRecord {
	return OTPRecord{OTPBinding: OTPBinding{PurposeEnrollment, uuid.New().String(), "session-a"}, Phone: testPhone, CodeHash: strings.Repeat("a", 64)}
}
func storeRecord(t *testing.T, s *RedisOTPStore, id string, rec OTPRecord) {
	t.Helper()
	if err := s.Store(context.Background(), id, rec, 3*time.Minute, 10); err != nil {
		t.Fatal(err)
	}
}
func consumeRecord(s *RedisOTPStore, id string, rec OTPRecord, hash string) error {
	return s.Consume(context.Background(), id, rec, hash, 3, 15*time.Minute)
}
func TestOTPStoreAtomicConsumeHasOneWinner(t *testing.T) {
	s, _ := newTestOTPStore(t)
	id := testVerificationID(10)
	rec := boundOTPRecord()
	storeRecord(t, s, id, rec)
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- consumeRecord(s, id, rec, rec.CodeHash) }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrNoActiveCode) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("consume winners=%d", winners)
	}
}
func TestOTPStoreWrongBindingDoesNotBurnOrExtend(t *testing.T) {
	s, mr := newTestOTPStore(t)
	id := testVerificationID(11)
	rec := boundOTPRecord()
	storeRecord(t, s, id, rec)
	for _, field := range []string{"purpose", "owner", "binding", "phone", "hash"} {
		foreign := rec
		switch field {
		case "purpose":
			foreign.Purpose = PurposeSignup
			foreign.BindingID = testVerificationID(12)
		case "owner":
			foreign.OwnerID = uuid.New().String()
		case "binding":
			foreign.BindingID = "foreign"
		case "phone":
			foreign.Phone = "+989123456780"
		case "hash":
			foreign.CodeHash = strings.Repeat("b", 64)
		}
		if err := consumeRecord(s, id, foreign, rec.CodeHash); !errors.Is(err, ErrNoActiveCode) {
			t.Fatal(err)
		}
	}
	if got, err := s.Get(context.Background(), id); err != nil || got.Attempts != 0 || mr.TTL(otpKey(id)) != 3*time.Minute {
		t.Fatal("foreign request burned/extended")
	}
	mr.FastForward(time.Minute)
	if err := consumeRecord(s, id, rec, strings.Repeat("b", 64)); !errors.Is(err, ErrInvalidCode) {
		t.Fatal(err)
	}
	if mr.TTL(otpKey(id)) != 2*time.Minute {
		t.Fatal("wrong attempt extends expiry")
	}
	if err := consumeRecord(s, id, rec, rec.CodeHash); err != nil {
		t.Fatal(err)
	}
}
func TestOTPStoreAtomicAttemptsAndLockout(t *testing.T) {
	s, mr := newTestOTPStore(t)
	id := testVerificationID(13)
	rec := boundOTPRecord()
	storeRecord(t, s, id, rec)
	for i := 0; i < 3; i++ {
		want := ErrInvalidCode
		if i == 2 {
			want = ErrLockedOut
		}
		if err := consumeRecord(s, id, rec, strings.Repeat("b", 64)); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	if mr.Exists(otpKey(id)) || mr.TTL(lockoutKey(testPhone)) != 15*time.Minute {
		t.Fatal("non-atomic lockout")
	}
	mr.FastForward(16 * time.Minute)
	if locked, err := s.IsLockedOut(context.Background(), testPhone); err != nil || locked {
		t.Fatal("lockout does not expire")
	}
}
func TestOTPStoreMalformedStateFailsClosed(t *testing.T) {
	for _, tc := range []struct{ field, value string }{{"attempts", ""}, {"attempts", "-1"}, {"attempts", "1junk"}, {"attempts", "01"}, {"attempts", "1.0"}, {"attempts", "3"}, {"attempts", "99999999999999999999999"}, {"code_hash", "invalid"}, {"phone", "not-phone"}, {"purpose", "other"}, {"expires_at", "bad"}, {"expires_at", "1"}} {
		t.Run(tc.field+tc.value, func(t *testing.T) {
			s, mr := newTestOTPStore(t)
			id := testVerificationID(14)
			rec := boundOTPRecord()
			storeRecord(t, s, id, rec)
			mr.HSet(otpKey(id), tc.field, tc.value)
			if err := consumeRecord(s, id, rec, rec.CodeHash); !errors.Is(err, ErrNoActiveCode) {
				t.Fatal(err)
			}
			if _, err := s.Get(context.Background(), id); !errors.Is(err, ErrNoActiveCode) {
				t.Fatal("Get accepted malformed state")
			}
		})
	}
}
func TestOTPStoreExpiryNeverRecreatesOrRefreshesChallenge(t *testing.T) {
	s, mr := newTestOTPStore(t)
	id := testVerificationID(15)
	rec := boundOTPRecord()
	storeRecord(t, s, id, rec)
	if err := s.Store(context.Background(), id, rec, 3*time.Minute, 10); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("challenge overwrite resets attempts/deadline")
	}
	mr.FastForward(4 * time.Minute)
	if err := consumeRecord(s, id, rec, rec.CodeHash); !errors.Is(err, ErrNoActiveCode) || mr.Exists(otpKey(id)) {
		t.Fatal("expired challenge recreated")
	}
	storeRecord(t, s, id, rec)
	if err := s.client.Persist(context.Background(), otpKey(id)).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), id); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("no-expiry challenge accepted")
	}
	if err := consumeRecord(s, id, rec, rec.CodeHash); !errors.Is(err, ErrNoActiveCode) {
		t.Fatal("no-expiry consume accepted")
	}
}
func TestOTPStoreLockoutCorruptionAndCancellation(t *testing.T) {
	s, mr := newTestOTPStore(t)
	id := testVerificationID(16)
	rec := boundOTPRecord()
	storeRecord(t, s, id, rec)
	if err := mr.Set(lockoutKey(testPhone), "bad"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IsLockedOut(context.Background(), testPhone); err != ErrUnavailable {
		t.Fatal("malformed lockout accepted")
	}
	if err := consumeRecord(s, id, rec, rec.CodeHash); err != ErrUnavailable {
		t.Fatal("corrupt lockout consumed code")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Consume(ctx, id, rec, rec.CodeHash, 3, 15*time.Minute); err != ErrUnavailable {
		t.Fatal("cancelled consume accepted")
	}
	if !mr.Exists(otpKey(id)) {
		t.Fatal("failure consumed OTP")
	}
}
func TestOTPStoreSignupCapacityAndDelete(t *testing.T) {
	s, mr := newTestOTPStore(t)
	rec := boundOTPRecord()
	rec.Purpose = PurposeSignup
	rec.BindingID = testVerificationID(17)
	id := testVerificationID(18)
	if err := s.Store(context.Background(), id, rec, time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Store(context.Background(), testVerificationID(19), rec, time.Minute, 1); err != ErrRateLimited {
		t.Fatal("capacity exceeded")
	}
	if err := s.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if mr.Exists(otpKey(id)) {
		t.Fatal("delete did not remove challenge")
	}
	if err := s.Store(context.Background(), testVerificationID(19), rec, time.Minute, 1); err != nil {
		t.Fatal("capacity not released")
	}
}

func TestOTPStoreInvalidPolicyLockoutAndDeleteFailure(t *testing.T) {
	s, mr := newTestOTPStore(t)
	rec := boundOTPRecord()
	id := testVerificationID(30)
	for _, ttl := range []time.Duration{0, -1, time.Millisecond, 4 * time.Minute} {
		if err := s.Store(context.Background(), id, rec, ttl, 0); err != ErrNoActiveCode || mr.Exists(otpKey(id)) {
			t.Fatal("invalid expiry created challenge")
		}
	}
	storeRecord(t, s, id, rec)
	for _, max := range []int{0, 4, 1000000} {
		if err := s.Consume(context.Background(), id, rec, rec.CodeHash, max, 15*time.Minute); err != ErrNoActiveCode {
			t.Fatal("invalid attempt policy accepted")
		}
	}
	if err := mr.Set(signupCapacityKey, "wrong-type"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), id); err != ErrUnavailable || !mr.Exists(otpKey(id)) {
		t.Fatal("failed delete did not fail closed")
	}
	mr.Del(signupCapacityKey)
	if err := mr.Set(lockoutKey(testPhone), "1"); err != nil {
		t.Fatal(err)
	}
	mr.SetTTL(lockoutKey(testPhone), 15*time.Minute)
	if err := s.Store(context.Background(), testVerificationID(31), rec, time.Minute, 0); err != ErrLockedOut {
		t.Fatal("atomic store bypassed lockout")
	}
}
