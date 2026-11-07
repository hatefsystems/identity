//go:build integration

package clientauth

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestIntegrationRedisClientAssertions(t *testing.T) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		if os.Getenv("REQUIRE_PHASE2_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("REDIS_URL is required for client assertion integration")
		}
		t.Skip("REDIS_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	clients := make([]*redis.Client, 2)
	guards := make([]*RedisJTIGuard, 2)
	authenticators := make([]*Authenticator, 2)
	h := newHarness(t, es256Signer(t))
	for i := range clients {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			t.Fatal("invalid REDIS_URL")
		}
		opts.ContextTimeoutEnabled, opts.MaxRetries = true, -1
		opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second
		clients[i] = redis.NewClient(opts)
		client := clients[i]
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Ping(ctx).Err(); err != nil {
			t.Fatalf("Redis unavailable: %v", err)
		}
		guards[i], err = NewRedisJTIGuard(client)
		if err != nil {
			t.Fatal(err)
		}
		authenticators[i], err = New(h.auth.registry, testAudience, guards[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	now, err := guards[0].ServerTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	jti := uuid.NewString()
	claims := standardClaims(now)
	claims["jti"], claims["exp"] = jti, now.Add(-30*time.Second).Unix()
	compact := h.sk.sign(t, h.header(), claims)
	key := replayKey(testClientID, testAudience, jti)
	keys := []string{key}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := clients[0].Del(cleanup, keys...).Err(); err != nil {
			t.Errorf("clean owned JTI keys: %v", err)
		}
	})
	start := make(chan struct{})
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(auth *Authenticator) {
			defer wg.Done()
			<-start
			_, err := auth.Authenticate(ctx, form(compact))
			results <- err
		}(authenticators[i%2])
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrReplay) {
			t.Fatalf("concurrent claim: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want 1", winners)
	}
	if ttl, err := clients[0].PTTL(ctx, key).Result(); err != nil || ttl <= 0 || ttl > 30*time.Second+time.Millisecond {
		t.Fatalf("leeway retention TTL = %s, %v", ttl, err)
	}
	// Reconstruction has no local history but must observe the same claim.
	reconstructed, _ := NewRedisJTIGuard(clients[1])
	auth, err := New(h.auth.registry, testAudience, reconstructed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Authenticate(ctx, form(compact)); !errors.Is(err, ErrReplay) {
		t.Fatalf("reconstructed replay = %v", err)
	}
	for _, scope := range [][3]string{{testClientID + ":other", testAudience, jti}, {testClientID, testAudience + "/other", jti}, {testClientID, testAudience, uuid.NewString()}} {
		keys = append(keys, replayKey(scope[0], scope[1], scope[2]))
		if fresh, err := reconstructed.Remember(ctx, scope[0], scope[1], scope[2], now.Add(time.Minute)); !fresh || err != nil {
			t.Fatalf("separate tuple = %v, %v", fresh, err)
		}
	}
	for _, state := range []string{"wrong_value", "missing_ttl", "wrong_type"} {
		t.Run(state, func(t *testing.T) {
			badJTI := uuid.NewString()
			badKey := replayKey(testClientID, testAudience, badJTI)
			keys = append(keys, badKey)
			var err error
			switch state {
			case "wrong_value":
				err = clients[0].Set(ctx, badKey, "corrupt", time.Minute).Err()
			case "missing_ttl":
				err = clients[0].Set(ctx, badKey, "1", 0).Err()
			case "wrong_type":
				err = clients[0].LPush(ctx, badKey, "1").Err()
			}
			if err != nil {
				t.Fatal(err)
			}
			if fresh, err := reconstructed.Remember(ctx, testClientID, testAudience, badJTI, now.Add(time.Minute)); fresh || !errors.Is(err, ErrReplayUnavailable) {
				t.Fatalf("malformed state = %v, %v", fresh, err)
			}
		})
	}
	t.Run("replica_clock_skew", func(t *testing.T) {
		sharedNow, err := guards[0].ServerTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// NumericDate is integral; this is Redis's current second plus three.
		deadline := time.Unix(sharedNow.Unix()+3, 0)
		skewJTI := uuid.NewString()
		skewKey := replayKey(testClientID, testAudience, skewJTI)
		keys = append(keys, skewKey)
		skewClaims := standardClaims(sharedNow)
		skewClaims["jti"], skewClaims["exp"], skewClaims["iat"] = skewJTI, deadline.Add(-clockSkewLeeway).Unix(), sharedNow.Add(-2*time.Minute).Unix()
		signed := h.sk.sign(t, h.header(), skewClaims)
		fast, err := New(h.auth.registry, testAudience, guards[0], WithClock(func() time.Time { return time.Now().Add(2 * time.Second) }))
		if err != nil {
			t.Fatal(err)
		}
		slow, err := New(h.auth.registry, testAudience, guards[1], WithClock(func() time.Time { return time.Now().Add(-2 * time.Second) }))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fast.Authenticate(ctx, form(signed)); err != nil {
			t.Fatalf("fast local replica first use = %v", err)
		}
		storedDeadline, err := clients[0].Do(ctx, "PEXPIRETIME", skewKey).Int64()
		if err != nil || storedDeadline != deadline.UnixMilli()+1 {
			t.Fatalf("absolute acceptance deadline mismatch: %v", err)
		}
		time.Sleep(1200 * time.Millisecond)
		observed, err := guards[1].ServerTime(ctx)
		if err != nil || !observed.Before(deadline) {
			t.Fatalf("regression did not remain inside acceptance window: %v", err)
		}
		for _, peer := range []*Authenticator{authenticators[1], slow} {
			if _, err := peer.Authenticate(ctx, form(signed)); !errors.Is(err, ErrReplay) {
				t.Fatalf("skewed peer reused assertion after 1.2s: %v", err)
			}
		}
		unchanged, err := clients[0].Do(ctx, "PEXPIRETIME", skewKey).Int64()
		if err != nil || unchanged != storedDeadline {
			t.Fatalf("replay changed absolute deadline: %v", err)
		}
		observed, err = guards[0].ServerTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if remaining := deadline.Sub(observed); remaining > 0 {
			time.Sleep(remaining + 2*time.Millisecond)
		}
		for _, peer := range []*Authenticator{fast, authenticators[1], slow} {
			if _, err := peer.Authenticate(ctx, form(signed)); !errors.Is(err, ErrExpired) {
				t.Fatalf("shared exclusive end = %v", err)
			}
		}
		if count, err := clients[0].Exists(ctx, skewKey).Result(); err != nil || count != 0 {
			t.Fatalf("rounded accepted-end claim retained: %v", err)
		}
	})
	expiringJTI := uuid.NewString()
	expiringKey := replayKey(testClientID, testAudience, expiringJTI)
	keys = append(keys, expiringKey)
	sharedNow, err := reconstructed.ServerTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expiry := sharedNow.Add(250 * time.Millisecond)
	if fresh, err := reconstructed.Remember(ctx, testClientID, testAudience, expiringJTI, expiry); !fresh || err != nil {
		t.Fatalf("short-lived claim = %v, %v", fresh, err)
	}
	time.Sleep(300 * time.Millisecond)
	if count, err := clients[0].Exists(ctx, expiringKey).Result(); count != 0 || err != nil {
		t.Fatalf("claim did not expire = %d, %v", count, err)
	}
	if fresh, err := reconstructed.Remember(ctx, testClientID, testAudience, expiringJTI, expiry); fresh || !errors.Is(err, ErrInvalidReplayParams) {
		t.Fatalf("expired claim accepted = %v, %v", fresh, err)
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if fresh, err := reconstructed.Remember(cancelled, testClientID, testAudience, expiringJTI, now.Add(time.Minute)); fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled claim = %v, %v", fresh, err)
	}
	if observed, err := reconstructed.ServerTime(cancelled); !observed.IsZero() || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled authoritative TIME = %v", err)
	}
	if err := clients[1].Close(); err != nil {
		t.Fatal(err)
	}
	if fresh, err := reconstructed.Remember(ctx, testClientID, testAudience, uuid.NewString(), now.Add(time.Minute)); fresh || !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("closed storage = %v, %v", fresh, err)
	}
	if result, err := auth.Authenticate(ctx, form(compact)); result.ID != "" || !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("closed temporal authority = %v", err)
	}
	unreachable := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0", MaxRetries: -1, DialTimeout: 100 * time.Millisecond, ContextTimeoutEnabled: true})
	defer func() { _ = unreachable.Close() }()
	unavailable, err := NewRedisJTIGuard(unreachable)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := unavailable.Remember(ctx, testClientID, testAudience, uuid.NewString(), now.Add(time.Minute)); fresh || !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("outage = %v, %v", fresh, err)
	}
	if observed, err := unavailable.ServerTime(ctx); !observed.IsZero() || !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("authoritative TIME outage = %v", err)
	}
}
