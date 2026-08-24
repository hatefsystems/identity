package smsotp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestOTPStore(t *testing.T) (*RedisOTPStore, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store, err := NewRedisOTPStore(client)
	if err != nil {
		t.Fatalf("NewRedisOTPStore: %v", err)
	}
	return store, mr
}

func TestNewRedisOTPStoreRejectsNilClient(t *testing.T) {
	if _, err := NewRedisOTPStore(nil); err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}

func boundOTPRecord(phone, codeHash string) OTPRecord {
	return OTPRecord{
		UserID:    "f387725d-728f-4de1-8be0-519172b37cc4",
		SessionID: "session-a",
		Phone:     phone,
		CodeHash:  codeHash,
	}
}

func TestOTPStoreStoreAndGet(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(11)
	want := boundOTPRecord("+15551230000", "hash-abc")

	if err := store.Store(ctx, verificationID, want, 3*time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	rec, err := store.Get(ctx, verificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.CodeHash != "hash-abc" {
		t.Errorf("CodeHash = %q, want %q", rec.CodeHash, "hash-abc")
	}
	if rec.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0 on a fresh record", rec.Attempts)
	}
	if rec.UserID != want.UserID || rec.SessionID != want.SessionID || rec.Phone != want.Phone {
		t.Errorf("binding = %+v, want %+v", rec, want)
	}
}

func TestOTPStoreGetMissingReturnsNoActiveCode(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, testVerificationID(12))
	if !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Get on missing phone: error = %v, want ErrNoActiveCode", err)
	}
}

func TestOTPStoreStoreResetsAttempts(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(13)
	record := boundOTPRecord("+15551231111", "hash-1")

	if err := store.Store(ctx, verificationID, record, time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := store.IncrementAttempts(ctx, verificationID); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}
	if _, err := store.IncrementAttempts(ctx, verificationID); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}

	// Re-issuing a code must start a clean attempt budget.
	record.CodeHash = "hash-2"
	if err := store.Store(ctx, verificationID, record, time.Minute); err != nil {
		t.Fatalf("Store (re-issue): %v", err)
	}
	rec, err := store.Get(ctx, verificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Attempts != 0 {
		t.Errorf("Attempts = %d after re-issue, want 0", rec.Attempts)
	}
	if rec.CodeHash != "hash-2" {
		t.Errorf("CodeHash = %q after re-issue, want %q", rec.CodeHash, "hash-2")
	}
}

func TestOTPStoreIncrementAttempts(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(14)

	if err := store.Store(ctx, verificationID, boundOTPRecord("+15551232222", "hash"), time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	for want := 1; want <= 3; want++ {
		got, err := store.IncrementAttempts(ctx, verificationID)
		if err != nil {
			t.Fatalf("IncrementAttempts: %v", err)
		}
		if got != want {
			t.Errorf("IncrementAttempts returned %d, want %d", got, want)
		}
	}

	rec, err := store.Get(ctx, verificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Attempts != 3 {
		t.Errorf("persisted Attempts = %d, want 3", rec.Attempts)
	}
}

func TestOTPStoreDelete(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(15)

	if err := store.Store(ctx, verificationID, boundOTPRecord("+15551233333", "hash"), time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := store.Delete(ctx, verificationID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, verificationID); !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Get after Delete: error = %v, want ErrNoActiveCode", err)
	}
}

func TestOTPStoreLockoutLifecycle(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()
	const phone = "+15551234444"

	locked, err := store.IsLockedOut(ctx, phone)
	if err != nil {
		t.Fatalf("IsLockedOut: %v", err)
	}
	if locked {
		t.Fatal("expected not locked out initially")
	}

	if err := store.Lockout(ctx, phone, 15*time.Minute); err != nil {
		t.Fatalf("Lockout: %v", err)
	}
	locked, err = store.IsLockedOut(ctx, phone)
	if err != nil {
		t.Fatalf("IsLockedOut: %v", err)
	}
	if !locked {
		t.Fatal("expected locked out after Lockout")
	}

	// The lockout must expire with its TTL.
	mr.FastForward(16 * time.Minute)
	locked, err = store.IsLockedOut(ctx, phone)
	if err != nil {
		t.Fatalf("IsLockedOut: %v", err)
	}
	if locked {
		t.Fatal("expected lockout to expire after its TTL elapsed")
	}
}

func TestOTPStoreCodeExpires(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(16)

	if err := store.Store(ctx, verificationID, boundOTPRecord("+15551235555", "hash"), 3*time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	mr.FastForward(4 * time.Minute)

	if _, err := store.Get(ctx, verificationID); !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Get after TTL: error = %v, want ErrNoActiveCode", err)
	}
}

func TestOTPStoreRejectsIncompleteBinding(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(17)

	if err := store.Store(ctx, verificationID, OTPRecord{CodeHash: "hash"}, time.Minute); err == nil {
		t.Fatal("Store accepted a record without account/session/phone binding")
	}
	if mr.Exists(otpKey(verificationID)) {
		t.Fatal("incomplete record was written to Redis")
	}
}

func TestOTPStoreRejectsInvalidVerificationID(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()

	if err := store.Store(ctx, "phone-controlled-key", boundOTPRecord("+15551230000", "hash"), time.Minute); err == nil {
		t.Fatal("Store accepted a non-random verification ID")
	}
	if mr.Exists(otpKey("phone-controlled-key")) {
		t.Fatal("invalid verification ID was written to Redis")
	}
}

func TestOTPStoreGetMalformedBindingFailsClosed(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(18)
	mr.HSet(otpKey(verificationID), fieldCodeHash, "hash", fieldAttempts, "0")

	if _, err := store.Get(ctx, verificationID); !errors.Is(err, ErrNoActiveCode) {
		t.Fatalf("Get malformed binding: error = %v, want ErrNoActiveCode", err)
	}
}

func TestOTPStoreIncrementMissingDoesNotCreateRecord(t *testing.T) {
	store, mr := newTestOTPStore(t)
	ctx := context.Background()
	verificationID := testVerificationID(19)

	if _, err := store.IncrementAttempts(ctx, verificationID); !errors.Is(err, ErrNoActiveCode) {
		t.Fatalf("IncrementAttempts missing: error = %v, want ErrNoActiveCode", err)
	}
	if mr.Exists(otpKey(verificationID)) {
		t.Fatal("incrementing an expired challenge recreated its Redis key")
	}
}
