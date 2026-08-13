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

func TestOTPStoreStoreAndGet(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	const phone = "+15551230000"

	if err := store.Store(ctx, phone, "hash-abc", 3*time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	rec, err := store.Get(ctx, phone)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.CodeHash != "hash-abc" {
		t.Errorf("CodeHash = %q, want %q", rec.CodeHash, "hash-abc")
	}
	if rec.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0 on a fresh record", rec.Attempts)
	}
}

func TestOTPStoreGetMissingReturnsNoActiveCode(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "+15550000000")
	if !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Get on missing phone: error = %v, want ErrNoActiveCode", err)
	}
}

func TestOTPStoreStoreResetsAttempts(t *testing.T) {
	store, _ := newTestOTPStore(t)
	ctx := context.Background()
	const phone = "+15551231111"

	if err := store.Store(ctx, phone, "hash-1", time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := store.IncrementAttempts(ctx, phone); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}
	if _, err := store.IncrementAttempts(ctx, phone); err != nil {
		t.Fatalf("IncrementAttempts: %v", err)
	}

	// Re-issuing a code must start a clean attempt budget.
	if err := store.Store(ctx, phone, "hash-2", time.Minute); err != nil {
		t.Fatalf("Store (re-issue): %v", err)
	}
	rec, err := store.Get(ctx, phone)
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
	const phone = "+15551232222"

	if err := store.Store(ctx, phone, "hash", time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	for want := 1; want <= 3; want++ {
		got, err := store.IncrementAttempts(ctx, phone)
		if err != nil {
			t.Fatalf("IncrementAttempts: %v", err)
		}
		if got != want {
			t.Errorf("IncrementAttempts returned %d, want %d", got, want)
		}
	}

	rec, err := store.Get(ctx, phone)
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
	const phone = "+15551233333"

	if err := store.Store(ctx, phone, "hash", time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := store.Delete(ctx, phone); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, phone); !errors.Is(err, ErrNoActiveCode) {
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
	const phone = "+15551235555"

	if err := store.Store(ctx, phone, "hash", 3*time.Minute); err != nil {
		t.Fatalf("Store: %v", err)
	}

	mr.FastForward(4 * time.Minute)

	if _, err := store.Get(ctx, phone); !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("Get after TTL: error = %v, want ErrNoActiveCode", err)
	}
}
