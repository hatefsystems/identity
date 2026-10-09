//go:build integration

package session

import (
	"context"
	"errors"
	"math"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisStoreIntegration(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Fatal("REDIS_URL is required for Redis session integration tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var stores []*RedisStore
	for range 2 {
		options, err := redis.ParseURL(url)
		if err != nil {
			t.Fatal(err)
		}
		options.ContextTimeoutEnabled, options.MaxRetries = true, -1
		options.DialTimeout, options.ReadTimeout, options.WriteTimeout = time.Second, time.Second, time.Second
		client := redis.NewClient(options)
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Ping(ctx).Err(); err != nil {
			t.Fatalf("Redis is required: %v", err)
		}
		store, err := NewRedisStore(client)
		if err != nil {
			t.Fatal(err)
		}
		stores = append(stores, store)
	}
	first, second := stores[0], stores[1]
	s := liveSession(time.Now().UTC(), uuid.NewString(), uuid.NewString())
	s.Kind, s.AuthVersion, s.AuthVersionSet = KindRecoveryEnrollment, math.MaxInt64, true
	s.AbsoluteExpiry, s.IdleExpiry = s.CreatedAt.Add(30*time.Second), s.CreatedAt.Add(15*time.Second)
	hash := HashToken(uuid.NewString())
	t.Cleanup(func() { _ = first.DeleteAllForUser(context.Background(), s.UserID) })
	if err := first.Create(ctx, hash, s); err != nil {
		t.Fatal(err)
	}
	got, err := second.GetByID(ctx, s.UserID, s.ID)
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("real Redis round trip: %+v, %v", got, err)
	}
	for _, key := range []string{redisTokenKey(hash), redisIDKey(s.UserID, s.ID), redisUserKey(s.UserID)} {
		ttl, err := second.client.PTTL(ctx, key).Result()
		if err != nil || ttl <= 0 || ttl > 30*time.Second+time.Millisecond {
			t.Fatalf("unbounded Redis TTL: %v, %v", ttl, err)
		}
	}
	var wg sync.WaitGroup
	var claims atomic.Int32
	for i := range 16 {
		store := stores[i%2]
		wg.Go(func() {
			ok, err := store.ClaimRecoveryEnrollment(ctx, s.UserID, s.ID)
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			if ok {
				claims.Add(1)
			}
		})
	}
	wg.Wait()
	if claims.Load() != 1 {
		t.Fatalf("real Redis claim winners = %d, want 1", claims.Load())
	}
	if err := second.ReleaseRecoveryEnrollment(ctx, s.UserID, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := first.GetByID(ctx, "foreign", s.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("foreign lookup: %v", err)
	}
	start := make(chan struct{})
	for i := range 16 {
		store := stores[i%2]
		wg.Go(func() {
			<-start
			if err := store.Touch(ctx, hash, s.AbsoluteExpiry); err != nil && !errors.Is(err, ErrSessionNotFound) {
				t.Errorf("touch: %v", err)
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := second.DeleteAllForUser(ctx, s.UserID); err != nil {
			t.Errorf("bulk revoke: %v", err)
		}
	})
	close(start)
	wg.Wait()
	for _, store := range stores {
		if _, err := store.Get(ctx, hash); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("real Redis session resurrected: %v", err)
		}
		if err := store.Touch(ctx, hash, s.AbsoluteExpiry); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("delayed touch resurrected session: %v", err)
		}
	}
	if err := first.Create(ctx, hash, s); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("delayed creation replay: %v", err)
	}
}
