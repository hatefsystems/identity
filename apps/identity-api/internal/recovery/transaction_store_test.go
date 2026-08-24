package recovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func newTestRedisTransactionStore(t *testing.T) (*RedisTransactionStore, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	store, err := NewRedisTransactionStore(client)
	if err != nil {
		t.Fatalf("NewRedisTransactionStore: %v", err)
	}
	return store, mr, client
}

func TestRedisTransactionStorePersistsOnlyHashAddressedState(t *testing.T) {
	store, mr, _ := newTestRedisTransactionStore(t)
	opaqueID := "raw-recovery-transaction-value"
	tokenHash := hashTransactionToken(opaqueID)
	userID := uuid.New()
	if err := store.Save(context.Background(), tokenHash, userID, 10*time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}

	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("Redis keys = %v, want one", keys)
	}
	if keys[0] != recoveryTransactionKeyPrefix+tokenHash || strings.Contains(keys[0], opaqueID) {
		t.Fatalf("Redis key %q is not hash-addressed", keys[0])
	}
	if got := mr.TTL(keys[0]); got != 10*time.Minute {
		t.Fatalf("TTL = %v, want 10m", got)
	}
}

func TestRedisTransactionStoreGetDelHasOneClusterWinner(t *testing.T) {
	first, mr, _ := newTestRedisTransactionStore(t)
	secondClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = secondClient.Close() })
	second, err := NewRedisTransactionStore(secondClient)
	if err != nil {
		t.Fatalf("NewRedisTransactionStore(second): %v", err)
	}
	userID := uuid.New()
	if err := first.Save(context.Background(), "contended-hash", userID, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const workers = 32
	results := make(chan error, workers)
	for i := range workers {
		candidate := first
		if i%2 == 1 {
			candidate = second
		}
		go func(store *RedisTransactionStore) {
			got, err := store.Take(context.Background(), "contended-hash")
			if err == nil && got != userID {
				err = errors.New("wrong subject returned")
			}
			results <- err
		}(candidate)
	}
	var succeeded, missing int
	for range workers {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, errTransactionNotFound):
			missing++
		default:
			t.Fatalf("Take returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 || missing != workers-1 {
		t.Fatalf("success/missing = %d/%d, want 1/%d", succeeded, missing, workers-1)
	}
}

func TestRedisTransactionStoreExpiresAndFailsClosed(t *testing.T) {
	store, mr, _ := newTestRedisTransactionStore(t)
	if err := store.Save(context.Background(), "expiring", uuid.New(), time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	mr.FastForward(time.Minute + time.Second)
	if _, err := store.Take(context.Background(), "expiring"); !errors.Is(err, errTransactionNotFound) {
		t.Fatalf("Take after expiry = %v, want not found", err)
	}

	mr.Close()
	if err := store.Save(context.Background(), "outage", uuid.New(), time.Minute); err == nil {
		t.Fatal("Save during Redis outage succeeded")
	}
	if _, err := store.Take(context.Background(), "outage"); err == nil || errors.Is(err, errTransactionNotFound) {
		t.Fatalf("Take during Redis outage = %v, want infrastructure error", err)
	}
}

func TestMemoryTransactionStoreExpiresAndConsumesOnce(t *testing.T) {
	store := NewMemoryTransactionStore()
	now := time.Now()
	store.now = func() time.Time { return now }
	userID := uuid.New()
	if err := store.Save(context.Background(), "one-shot", userID, time.Minute); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, err := store.Take(context.Background(), "one-shot"); err != nil || got != userID {
		t.Fatalf("first Take = %s/%v, want %s/nil", got, err, userID)
	}
	if _, err := store.Take(context.Background(), "one-shot"); !errors.Is(err, errTransactionNotFound) {
		t.Fatalf("second Take = %v, want not found", err)
	}

	if err := store.Save(context.Background(), "expired", userID, time.Minute); err != nil {
		t.Fatalf("Save expired fixture: %v", err)
	}
	now = now.Add(time.Minute + time.Nanosecond)
	if _, err := store.Take(context.Background(), "expired"); !errors.Is(err, errTransactionNotFound) {
		t.Fatalf("expired Take = %v, want not found", err)
	}
}
