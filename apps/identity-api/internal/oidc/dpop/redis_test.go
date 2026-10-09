package dpop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedisTestClient(t *testing.T, server *miniredis.Miniredis) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{
		Addr: server.Addr(), MaxRetries: -1,
		DialTimeout: 100 * time.Millisecond, ReadTimeout: time.Second, WriteTimeout: time.Second,
		ContextTimeoutEnabled: true,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newRedisTestValidator(t *testing.T, server *miniredis.Miniredis, now func() time.Time) *Validator {
	t.Helper()
	client := newRedisTestClient(t, server)
	guard, err := NewRedisReplayGuard(client)
	if err != nil {
		t.Fatal(err)
	}
	guard.now = now
	nonces, err := NewRedisNonceStore(client)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewValidator(guard, nonces, WithClock(now))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRedisConstructorsRejectNilClients(t *testing.T) {
	var typedNil *redis.Client
	for _, client := range []redis.UniversalClient{nil, typedNil} {
		if guard, err := NewRedisReplayGuard(client); guard != nil || err != ErrInvalidParams {
			t.Fatalf("nil replay client = %v, %v", guard, err)
		}
		if nonces, err := NewRedisNonceStore(client); nonces != nil || err != ErrInvalidParams {
			t.Fatalf("nil nonce client = %v, %v", nonces, err)
		}
	}
}

func TestRedisNonceScopeSingleUseAndExpiryAcrossInstances(t *testing.T) {
	server := miniredis.RunT(t)
	a, err := NewRedisNonceStore(newRedisTestClient(t, server))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRedisNonceStore(newRedisTestClient(t, server))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nonce, err := a.Issue(ctx, testRealm, testStoreJKT)
	if err != nil {
		t.Fatal(err)
	}
	key := stateKey(redisNoncePrefix, testRealm, testStoreJKT, nonce)
	value, err := server.Get(key)
	if err != nil || value != redisStateValue || server.TTL(key) != DefaultNonceTTL {
		t.Fatalf("nonce record = %q, %v, TTL=%v", value, err, server.TTL(key))
	}
	if strings.Contains(key, nonce) || strings.Contains(key, testRealm) || strings.Contains(key, testStoreJKT) {
		t.Fatal("nonce scope or secret leaked into a Redis key")
	}
	for _, scope := range [][2]string{{"other-realm", testStoreJKT}, {testRealm, "other-key"}} {
		if ok, err := b.Validate(ctx, scope[0], scope[1], nonce); ok || err != nil {
			t.Fatalf("wrong nonce scope = %v, %v", ok, err)
		}
	}
	server.FastForward(DefaultNonceTTL - time.Millisecond)
	if ok, err := b.Validate(ctx, testRealm, testStoreJKT, nonce); !ok || err != nil {
		t.Fatalf("cross-instance nonce consumption = %v, %v", ok, err)
	}
	if ok, err := a.Validate(ctx, testRealm, testStoreJKT, nonce); ok || err != nil {
		t.Fatalf("consumed nonce reused = %v, %v", ok, err)
	}
	nonce, err = b.Issue(ctx, testRealm, testStoreJKT)
	if err != nil {
		t.Fatal(err)
	}
	server.FastForward(DefaultNonceTTL)
	if ok, err := a.Validate(ctx, testRealm, testStoreJKT, nonce); ok || err != nil {
		t.Fatalf("expired nonce = %v, %v", ok, err)
	}
}

func TestRedisValidatorChallengeAndReplayAcrossInstances(t *testing.T) {
	server := miniredis.RunT(t)
	now := time.Now().Truncate(time.Second)
	a := newRedisTestValidator(t, server, fixedClock(now))
	b := newRedisTestValidator(t, server, fixedClock(now))
	s := newES256Signer(t)
	c := defaultClaims(now)
	params := VerifyParams{Realm: testRealm, ExpectedJKT: s.thumbprint(t), Method: testHTM, URL: testHTU, RequireNonce: true}
	proof, err := a.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params)
	var challenge *NonceChallenge
	if proof != nil || !errors.As(err, &challenge) {
		t.Fatalf("initial challenge = %v, %v", proof, err)
	}
	c.nonce, err = a.IssueNonce(context.Background(), challenge.Realm, challenge.JKT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params); err != nil {
		t.Fatalf("cross-instance proof: %v", err)
	}
	key := stateKey(redisReplayPrefix, stateKey("", params.Realm, params.ExpectedJKT, c.jti))
	value, err := server.Get(key)
	if err != nil || value != redisStateValue || server.TTL(key) != DefaultProofMaxAge+clockSkewLeeway+time.Millisecond {
		t.Fatalf("replay record = %q, %v, TTL=%v", value, err, server.TTL(key))
	}
	if strings.Contains(key, c.jti) || strings.Contains(key, params.ExpectedJKT) || strings.Contains(key, testRealm) {
		t.Fatal("proof identifiers leaked into a Redis key")
	}
	// A new nonce cannot make a previously accepted jti fresh on another node.
	c.nonce, err = b.IssueNonce(context.Background(), params.Realm, params.ExpectedJKT)
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := a.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params); proof != nil || err != ErrReplay {
		t.Fatalf("cross-instance replay = %v, %v", proof, err)
	}
}

func TestRedisValidatorConcurrentProofHasOneSuccess(t *testing.T) {
	for _, requireNonce := range []bool{false, true} {
		name := "replay only"
		if requireNonce {
			name = "nonce and replay"
		}
		t.Run(name, func(t *testing.T) {
			server := miniredis.RunT(t)
			now := time.Now().Truncate(time.Second)
			validators := []*Validator{
				newRedisTestValidator(t, server, fixedClock(now)),
				newRedisTestValidator(t, server, fixedClock(now)),
			}
			s := newES256Signer(t)
			c := defaultClaims(now)
			params := VerifyParams{Realm: testRealm, ExpectedJKT: s.thumbprint(t), Method: testHTM, URL: testHTU, RequireNonce: requireNonce}
			if requireNonce {
				var err error
				c.nonce, err = validators[0].IssueNonce(context.Background(), params.Realm, params.ExpectedJKT)
				if err != nil {
					t.Fatal(err)
				}
			}
			compact := s.sign(t, c, TypDPoP, s.alg, nil)
			const workers = 32
			type result struct {
				proof *Proof
				err   error
			}
			results := make(chan result, workers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range workers {
				wg.Add(1)
				go func(v *Validator) {
					defer wg.Done()
					<-start
					proof, err := v.Validate(context.Background(), compact, params)
					results <- result{proof, err}
				}(validators[i%len(validators)])
			}
			close(start)
			wg.Wait()
			close(results)
			successes := 0
			for got := range results {
				if got.err == nil {
					if got.proof == nil || got.proof.JKT != params.ExpectedJKT {
						t.Fatal("successful proof is missing its verified binding")
					}
					successes++
					continue
				}
				want := ErrReplay
				if requireNonce {
					want = ErrNonceRequired
				}
				if got.proof != nil || !errors.Is(got.err, want) {
					t.Fatalf("concurrent rejection = %v, %v", got.proof, got.err)
				}
			}
			if successes != 1 {
				t.Fatalf("successful concurrent submissions = %d, want 1", successes)
			}
		})
	}
}

func TestRedisRejectedBindingAndMissingJTIConsumeNothing(t *testing.T) {
	for _, missingJTI := range []bool{false, true} {
		name := "wrong binding"
		if missingJTI {
			name = "missing jti"
		}
		t.Run(name, func(t *testing.T) {
			server := miniredis.RunT(t)
			now := time.Now().Truncate(time.Second)
			a := newRedisTestValidator(t, server, fixedClock(now))
			b := newRedisTestValidator(t, server, fixedClock(now))
			s := newES256Signer(t)
			params := VerifyParams{Realm: testRealm, ExpectedJKT: s.thumbprint(t), Method: testHTM, URL: testHTU, RequireNonce: true}
			c := defaultClaims(now)
			var err error
			c.nonce, err = a.IssueNonce(context.Background(), params.Realm, params.ExpectedJKT)
			if err != nil {
				t.Fatal(err)
			}
			badClaims, badParams := c, params
			want := ErrKeyMismatch
			if missingJTI {
				badClaims.jti, want = "", ErrMissingJTI
			} else {
				badParams.ExpectedJKT = "wrong-key"
			}
			// A stateless denial must not even contact an unavailable backend.
			server.SetError("ERR backend unavailable")
			proof, err := b.Validate(context.Background(), s.sign(t, badClaims, TypDPoP, s.alg, nil), badParams)
			server.SetError("")
			if proof != nil || err != want {
				t.Fatalf("stateless denial = %v, %v", proof, err)
			}
			if _, err := a.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params); err != nil {
				t.Fatalf("stateless denial burned valid nonce or jti: %v", err)
			}
		})
	}
}

func TestRedisReplayTTLHasNoAcceptanceGap(t *testing.T) {
	for _, fraction := range []time.Duration{0, 500 * time.Microsecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			server := miniredis.RunT(t)
			iat := time.Now().Truncate(time.Second)
			now := iat.Add(-clockSkewLeeway + fraction)
			clock := func() time.Time { return now }
			a := newRedisTestValidator(t, server, clock)
			b := newRedisTestValidator(t, server, clock)
			s := newES256Signer(t)
			c := defaultClaims(iat)
			compact := s.sign(t, c, TypDPoP, s.alg, nil)
			params := VerifyParams{Realm: testRealm, ExpectedJKT: s.thumbprint(t), Method: testHTM, URL: testHTU}
			if _, err := a.Validate(context.Background(), compact, params); err != nil {
				t.Fatal(err)
			}
			key := stateKey(redisReplayPrefix, stateKey("", params.Realm, params.ExpectedJKT, c.jti))
			remaining := iat.Add(DefaultProofMaxAge + clockSkewLeeway).Sub(now)
			if ttl := server.TTL(key); ttl <= remaining || ttl > remaining+time.Millisecond {
				t.Fatalf("TTL %v does not cover inclusive window %v", ttl, remaining)
			}
			now = now.Add(remaining)
			server.FastForward(remaining)
			if _, err := b.Validate(context.Background(), compact, params); err != ErrReplay {
				t.Fatalf("replay at final acceptance instant: %v", err)
			}
			now = now.Add(time.Nanosecond)
			server.FastForward(time.Nanosecond)
			if _, err := b.Validate(context.Background(), compact, params); err != ErrStaleProof {
				t.Fatalf("proof beyond acceptance window: %v", err)
			}
			server.FastForward(time.Millisecond)
			if server.Exists(key) {
				t.Fatal("replay record outlived its finite TTL")
			}
		})
	}
}

func TestRedisStoresFailClosedOnOutage(t *testing.T) {
	for _, mode := range []string{"server error", "disconnected", "closed client"} {
		t.Run(mode, func(t *testing.T) {
			server := miniredis.RunT(t)
			client := newRedisTestClient(t, server)
			guard, err := NewRedisReplayGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			nonces, err := NewRedisNonceStore(client)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := nonces.Issue(context.Background(), testRealm, testStoreJKT)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "server error":
				server.SetError("ERR backend unavailable")
			case "disconnected":
				server.Close()
			case "closed client":
				_ = client.Close()
			}
			if value, err := nonces.Issue(context.Background(), testRealm, testStoreJKT); value != "" || !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("Issue during outage = %q, %v", value, err)
			}
			if ok, err := nonces.Validate(context.Background(), testRealm, testStoreJKT, nonce); ok || !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("Validate during outage = %v, %v", ok, err)
			}
			if ok, err := guard.Remember(context.Background(), "key", time.Now().Add(time.Minute)); ok || !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("Remember during outage = %v, %v", ok, err)
			}
		})
	}
}

func TestRedisStoresRejectCorruptState(t *testing.T) {
	for _, record := range []string{"nonce", "replay"} {
		for _, corruption := range []string{"wrong value", "wrong type", "missing TTL"} {
			t.Run(record+"/"+corruption, func(t *testing.T) {
				server := miniredis.RunT(t)
				client := newRedisTestClient(t, server)
				ctx := context.Background()
				key := stateKey(redisReplayPrefix, "key")
				if record == "nonce" {
					key = stateKey(redisNoncePrefix, testRealm, testStoreJKT, "nonce")
				}
				switch corruption {
				case "wrong value":
					if err := client.Set(ctx, key, "corrupt", time.Minute).Err(); err != nil {
						t.Fatal(err)
					}
				case "wrong type":
					if err := client.RPush(ctx, key, redisStateValue).Err(); err != nil {
						t.Fatal(err)
					}
					if err := client.Expire(ctx, key, time.Minute).Err(); err != nil {
						t.Fatal(err)
					}
				case "missing TTL":
					if err := client.Set(ctx, key, redisStateValue, 0).Err(); err != nil {
						t.Fatal(err)
					}
				}
				var ok bool
				var err error
				if record == "nonce" {
					store, constructErr := NewRedisNonceStore(client)
					if constructErr != nil {
						t.Fatal(constructErr)
					}
					ok, err = store.Validate(ctx, testRealm, testStoreJKT, "nonce")
				} else {
					guard, constructErr := NewRedisReplayGuard(client)
					if constructErr != nil {
						t.Fatal(constructErr)
					}
					ok, err = guard.Remember(ctx, "key", time.Now().Add(time.Minute))
				}
				if ok || !errors.Is(err, ErrStoreUnavailable) {
					t.Fatalf("corrupt %s = %v, %v", record, ok, err)
				}
				if !server.Exists(key) {
					t.Fatal("corrupt record was consumed or overwritten")
				}
			})
		}
	}
}

func TestRedisStoresRespectContextAndInvalidParams(t *testing.T) {
	server := miniredis.RunT(t)
	client := newRedisTestClient(t, server)
	guard, err := NewRedisReplayGuard(client)
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := NewRedisNonceStore(client)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	for _, ctx := range []context.Context{canceled, expired} {
		if value, err := nonces.Issue(ctx, testRealm, testStoreJKT); value != "" || !errors.Is(err, ctx.Err()) {
			t.Fatalf("context Issue = %q, %v", value, err)
		}
		if ok, err := nonces.Validate(ctx, testRealm, testStoreJKT, "nonce"); ok || !errors.Is(err, ctx.Err()) {
			t.Fatalf("context Validate = %v, %v", ok, err)
		}
		if ok, err := guard.Remember(ctx, "key", time.Now().Add(time.Minute)); ok || !errors.Is(err, ctx.Err()) {
			t.Fatalf("context Remember = %v, %v", ok, err)
		}
	}
	ctx := context.Background()
	for _, scope := range [][2]string{{"", testStoreJKT}, {testRealm, ""}, {" ", testStoreJKT}} {
		if _, err := nonces.Issue(ctx, scope[0], scope[1]); err != ErrInvalidParams {
			t.Fatalf("invalid issue scope: %v", err)
		}
		if _, err := nonces.Validate(ctx, scope[0], scope[1], "nonce"); err != ErrInvalidParams {
			t.Fatalf("invalid validation scope: %v", err)
		}
	}
	if _, err := guard.Remember(ctx, "", time.Now().Add(time.Minute)); err != ErrInvalidParams {
		t.Fatalf("empty replay key: %v", err)
	}
	if _, err := guard.Remember(ctx, "key", time.Time{}); err != ErrInvalidParams {
		t.Fatalf("empty replay expiry: %v", err)
	}
	if ok, err := guard.Remember(ctx, "key", time.Now().Add(-time.Second)); ok || err != nil {
		t.Fatalf("expired replay claim = %v, %v", ok, err)
	}
	if ok, err := nonces.Validate(ctx, testRealm, testStoreJKT, ""); ok || err != nil {
		t.Fatalf("empty nonce = %v, %v", ok, err)
	}
	if len(server.Keys()) != 0 {
		t.Fatal("canceled or invalid request created Redis state")
	}
}

type cancelRedisHook struct {
	entered chan struct{}
	once    sync.Once
}

func (*cancelRedisHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *cancelRedisHook) ProcessHook(_ redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, _ redis.Cmder) error {
		h.once.Do(func() { close(h.entered) })
		<-ctx.Done()
		return errors.New("backend failed after cancellation")
	}
}

func (*cancelRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestRedisStoresPreserveInFlightCancellation(t *testing.T) {
	for _, operation := range []string{"issue", "validate", "remember"} {
		t.Run(operation, func(t *testing.T) {
			server := miniredis.RunT(t)
			client := newRedisTestClient(t, server)
			hook := &cancelRedisHook{entered: make(chan struct{})}
			client.AddHook(hook)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			guard, err := NewRedisReplayGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			nonces, err := NewRedisNonceStore(client)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "issue":
					_, err = nonces.Issue(ctx, testRealm, testStoreJKT)
				case "validate":
					_, err = nonces.Validate(ctx, testRealm, testStoreJKT, "nonce")
				case "remember":
					_, err = guard.Remember(ctx, "key", time.Now().Add(time.Minute))
				}
				result <- err
			}()
			select {
			case <-hook.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("store did not forward the request context")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrStoreUnavailable) || !errors.Is(err, context.Canceled) {
					t.Fatalf("in-flight cancellation: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("store ignored cancellation")
			}
			if len(server.Keys()) != 0 {
				t.Fatal("canceled operation wrote state")
			}
		})
	}
}
