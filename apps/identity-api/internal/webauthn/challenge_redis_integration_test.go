//go:build integration

package webauthn

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func realRedisChallengeStores(t *testing.T) [2]*RedisChallengeStore {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	if url == "" {
		if os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" {
			t.Fatal("REDIS_URL is required for portal challenge integration")
		}
		t.Skip("REDIS_URL is not configured")
	}
	var stores [2]*RedisChallengeStore
	for i := range stores {
		opts, err := redis.ParseURL(url)
		if err != nil {
			t.Fatal("invalid REDIS_URL")
		}
		opts.ContextTimeoutEnabled, opts.MaxRetries = true, -1
		opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second
		client := redis.NewClient(opts)
		t.Cleanup(func() { _ = client.Close() })
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		err = client.Ping(ctx).Err()
		cancel()
		if err != nil {
			t.Fatalf("Redis is unavailable: %v", err)
		}
		stores[i], err = NewRedisChallengeStore(client)
		if err != nil {
			t.Fatal(err)
		}
	}
	return stores
}

// These tests use random ceremony keys and delete only those keys. They never
// clear a database/script cache or stop a shared service.
func TestRedisChallengeIntegrationFlows(t *testing.T) {
	exerciseRedisChallengeServiceFlows(t, realRedisChallengeStores)
}

func TestRedisChallengeIntegrationAtomicConsumption(t *testing.T) {
	stores := realRedisChallengeStores(t)
	for flow := FlowRegistration; flow <= FlowReclaim; flow++ {
		t.Run(flow.String(), func(t *testing.T) {
			pc := pendingForFlow(flow)
			key := challengeRedisKey(pc.Session.Challenge)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := stores[0].client.Del(ctx, key).Err(); err != nil {
					t.Errorf("clean up owned challenge key: %v", err)
				}
			})
			if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
				t.Fatal(err)
			}
			if ttl, err := stores[1].client.PTTL(t.Context(), key).Result(); err != nil || ttl <= 0 || ttl > time.Minute {
				t.Fatalf("bounded native TTL: %v %v", ttl, err)
			}
			if err := stores[1].Save(t.Context(), pc.Session.Challenge, pc); !errors.Is(err, ErrChallengeConflict) {
				t.Fatalf("collision overwrote another instance's challenge: %v", err)
			}
			wrong := bindingFor(pc)
			wrong.DPoPJKT = "foreign-key"
			if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, wrong); !errors.Is(err, ErrChallengeNotFound) {
				t.Fatalf("wrong-key probe: %v", err)
			}
			const workers = 16
			start := make(chan struct{})
			results := make(chan error, workers)
			var wg sync.WaitGroup
			for i := range workers {
				wg.Go(func() {
					<-start
					got, err := stores[i%2].Take(t.Context(), pc.Session.Challenge, bindingFor(pc))
					if err == nil && (got.AuthVersion != pc.AuthVersion || got.AuthEpoch != pc.AuthEpoch) {
						err = errors.New("authority integer lost precision")
					}
					results <- err
				})
			}
			close(start)
			wg.Wait()
			close(results)
			winners := 0
			for err := range results {
				if err == nil {
					winners++
				} else if !errors.Is(err, ErrChallengeNotFound) {
					t.Fatal(err)
				}
			}
			if winners != 1 {
				t.Fatalf("atomic completion winners = %d, want 1", winners)
			}
		})
	}
}

func TestRedisChallengeIntegrationExpiryAndDependencyFailure(t *testing.T) {
	stores := realRedisChallengeStores(t)
	pc := pendingForFlow(FlowLoginDiscoverable)
	key := challengeRedisKey(pc.Session.Challenge)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := stores[0].client.Del(ctx, key).Err(); err != nil {
			t.Errorf("clean up owned challenge key: %v", err)
		}
	})
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	if err := stores[1].client.PExpire(t.Context(), key, time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("native expiry used stale local authority: %v", err)
	}
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	if err := stores[0].client.Persist(t.Context(), key).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeStoreUnavailable) {
		t.Fatalf("state without TTL accepted: %v", err)
	}
	if err := stores[0].client.PExpire(t.Context(), key, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if err := stores[1].client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeStoreUnavailable) {
		t.Fatalf("disconnected replica used local fallback: %v", err)
	}
	if _, err := stores[0].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); err != nil {
		t.Fatalf("disconnected replica burned shared challenge: %v", err)
	}
}
