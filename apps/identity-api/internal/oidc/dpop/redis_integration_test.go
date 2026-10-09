//go:build integration

package dpop

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisDPoPIntegration(t *testing.T) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		if os.Getenv("REQUIRE_GRPC_INTEGRATION") == "1" {
			t.Fatal("REDIS_URL is required")
		}
		t.Skip("REDIS_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clients := make([]*redis.Client, 2)
	validators := make([]*Validator, 2)
	for i := range clients {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			t.Fatal("invalid REDIS_URL")
		}
		opts.ContextTimeoutEnabled = true
		opts.MaxRetries = -1
		opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = time.Second, time.Second, time.Second
		client := redis.NewClient(opts)
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Ping(ctx).Err(); err != nil {
			t.Fatalf("Redis is unavailable: %v", err)
		}
		guard, err := NewRedisReplayGuard(client)
		if err != nil {
			t.Fatal(err)
		}
		nonces, err := NewRedisNonceStore(client)
		if err != nil {
			t.Fatal(err)
		}
		validators[i], err = NewValidator(guard, nonces)
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
	}

	s := newES256Signer(t)
	c := defaultClaims(time.Now())
	params := VerifyParams{Realm: "rs:integration:" + randToken(), ExpectedJKT: s.thumbprint(t),
		Method: testHTM, URL: testHTU, RequireNonce: true}
	proof, err := validators[0].Validate(ctx, s.sign(t, c, TypDPoP, s.alg, nil), params)
	var challenge *NonceChallenge
	if proof != nil || !errors.As(err, &challenge) {
		t.Fatalf("nonce challenge = %v, %v", proof, err)
	}
	c.nonce, err = validators[0].IssueNonce(ctx, challenge.Realm, challenge.JKT)
	if err != nil {
		t.Fatal(err)
	}
	nonceKey := stateKey(redisNoncePrefix, params.Realm, params.ExpectedJKT, c.nonce)
	replayKey := stateKey(redisReplayPrefix, stateKey("", params.Realm, params.ExpectedJKT, c.jti))
	cleanupKeys := []string{nonceKey, replayKey}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		if err := clients[0].Del(cleanupCtx, cleanupKeys...).Err(); err != nil {
			t.Errorf("clean up DPoP test keys: %v", err)
		}
	})
	if ttl, err := clients[1].PTTL(ctx, nonceKey).Result(); err != nil || ttl <= 0 || ttl > DefaultNonceTTL {
		t.Fatalf("nonce TTL = %v, %v", ttl, err)
	}
	for _, scope := range [][2]string{{params.Realm + ":other", params.ExpectedJKT}, {params.Realm, "other-key"}} {
		if ok, err := validators[1].nonces.Validate(ctx, scope[0], scope[1], c.nonce); ok || err != nil {
			t.Fatalf("wrong nonce scope = %v, %v", ok, err)
		}
	}

	compact := s.sign(t, c, TypDPoP, s.alg, nil)
	const workers = 16
	results := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(v *Validator) {
			defer wg.Done()
			<-start
			_, err := v.Validate(ctx, compact, params)
			results <- err
		}(validators[i%len(validators)])
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrNonceRequired) {
			t.Fatalf("concurrent proof: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes = %d, want 1", successes)
	}
	if ttl, err := clients[0].PTTL(ctx, replayKey).Result(); err != nil || ttl <= 0 || ttl > DefaultProofMaxAge+clockSkewLeeway+time.Millisecond {
		t.Fatalf("replay TTL = %v, %v", ttl, err)
	}
	c.nonce, err = validators[1].IssueNonce(ctx, params.Realm, params.ExpectedJKT)
	if err != nil {
		t.Fatal(err)
	}
	nonceKey = stateKey(redisNoncePrefix, params.Realm, params.ExpectedJKT, c.nonce)
	cleanupKeys = append(cleanupKeys, nonceKey)
	if _, err := validators[0].Validate(ctx, s.sign(t, c, TypDPoP, s.alg, nil), params); err != ErrReplay {
		t.Fatalf("cross-instance replay with fresh nonce: %v", err)
	}
	if err := clients[0].Set(ctx, nonceKey, "corrupt", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if ok, err := validators[1].nonces.Validate(ctx, params.Realm, params.ExpectedJKT, c.nonce); ok || !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("corrupt nonce = %v, %v", ok, err)
	}
}
