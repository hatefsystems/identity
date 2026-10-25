package webauthn

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
)

func redisChallengeStores(t *testing.T) (*miniredis.Miniredis, [2]*RedisChallengeStore) {
	t.Helper()
	mini := miniredis.RunT(t)
	var stores [2]*RedisChallengeStore
	for i := range stores {
		client := redis.NewClient(&redis.Options{
			Addr: mini.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1,
			DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
		})
		t.Cleanup(func() { _ = client.Close() })
		var err error
		stores[i], err = NewRedisChallengeStore(client)
		if err != nil {
			t.Fatal(err)
		}
	}
	return mini, stores
}

func pendingForFlow(flow Flow) PendingChallenge {
	pc := newPendingChallenge(uuid.NewString(), uuid.New(), time.Now().UTC().Add(time.Minute))
	pc.Flow, pc.DPoPJKT = flow, testBrowserJKT
	pc.AuthVersion, pc.AuthEpoch = math.MaxInt64, 9007199254740993
	if isLoginFlow(flow) {
		pc.SessionID = ""
		if flow != FlowLoginNamed {
			pc.UserRef = uuid.Nil
		}
	}
	return pc
}

func TestChallengeStoresAtomicBindingAndExactAuthority(t *testing.T) {
	_, redisStores := redisChallengeStores(t)
	memory := NewMemoryChallengeStore()
	for backend, stores := range map[string][2]ChallengeStore{
		"memory": {memory, memory}, "redis": {redisStores[0], redisStores[1]},
	} {
		for flow := FlowRegistration; flow <= FlowReclaim; flow++ {
			t.Run(backend+"/"+flow.String(), func(t *testing.T) {
				pc := pendingForFlow(flow)
				binding := bindingFor(pc)
				if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
					t.Fatal(err)
				}
				wrongFlow := ChallengeBinding{Flows: []Flow{FlowRegistration}, UserRef: uuid.New(), SessionID: "foreign", DPoPJKT: pc.DPoPJKT}
				if flow == FlowRegistration {
					wrongFlow.Flows = []Flow{FlowStepUp}
				}
				if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, wrongFlow); !errors.Is(err, ErrChallengeFlowMismatch) {
					t.Fatalf("wrong flow: %v", err)
				}
				for _, field := range []string{"user", "session", "key", "missing key"} {
					wrong := binding
					switch field {
					case "user":
						wrong.UserRef = uuid.New()
					case "session":
						wrong.SessionID = "foreign-session"
					case "key":
						wrong.DPoPJKT = "another-browser"
					case "missing key":
						wrong.DPoPJKT = ""
					}
					if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, wrong); !errors.Is(err, ErrChallengeNotFound) {
						t.Fatalf("wrong %s: %v", field, err)
					}
				}
				got, err := stores[1].Take(t.Context(), pc.Session.Challenge, binding)
				if err != nil || got.AuthVersion != pc.AuthVersion || got.AuthEpoch != pc.AuthEpoch || got.DPoPJKT != pc.DPoPJKT || !got.Expires.Equal(pc.Expires) {
					t.Fatalf("cross-instance exact round trip: %+v, %v", got, err)
				}
				if _, err := stores[0].Take(t.Context(), pc.Session.Challenge, binding); !errors.Is(err, ErrChallengeNotFound) {
					t.Fatalf("replay: %v", err)
				}
			})
		}
	}
}

func TestRedisChallengeConcurrentCompletionHasOneWinner(t *testing.T) {
	_, stores := redisChallengeStores(t)
	for flow := FlowRegistration; flow <= FlowReclaim; flow++ {
		t.Run(flow.String(), func(t *testing.T) {
			pc := pendingForFlow(flow)
			if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
				t.Fatal(err)
			}
			const workers = 24
			results := make(chan error, workers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range workers {
				wg.Go(func() {
					<-start
					_, err := stores[i%2].Take(t.Context(), pc.Session.Challenge, bindingFor(pc))
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
				t.Fatalf("successful completions = %d, want 1", winners)
			}
		})
	}
}

func TestChallengeStoresCollisionBoundsCancellationAndSnapshot(t *testing.T) {
	_, redisStores := redisChallengeStores(t)
	for backend, store := range map[string]ChallengeStore{"memory": NewMemoryChallengeStore(), "redis": redisStores[0]} {
		t.Run(backend, func(t *testing.T) {
			pc := pendingForFlow(FlowRegistration)
			pc.Name = "Original name"
			if err := store.Save(t.Context(), pc.Session.Challenge, pc); err != nil {
				t.Fatal(err)
			}
			pc.Name = "Replacement"
			pc.Session.UserID[0] = 99
			if err := store.Save(t.Context(), pc.Session.Challenge, pc); !errors.Is(err, ErrChallengeConflict) {
				t.Fatalf("collision: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := store.Take(ctx, pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled take: %v", err)
			}
			if err := store.Save(ctx, pc.Session.Challenge, pc); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled save: %v", err)
			}
			got, err := store.Take(t.Context(), pc.Session.Challenge, bindingFor(pc))
			if err != nil || got.Name != "Original name" || got.Session.UserID[0] != 1 {
				t.Fatalf("collision/canceled request mutated snapshot: %+v %v", got, err)
			}
			for _, invalid := range []string{"oversized payload", "oversized key", "oversized TTL", "expired", "wrong challenge", "unbound login"} {
				pc := pendingForFlow(FlowRegistration)
				switch invalid {
				case "oversized payload":
					pc.Session.UserID = make([]byte, maxChallengeBytes)
				case "oversized key":
					pc.Session.Challenge = strings.Repeat("a", maxChallengeKeyBytes+1)
				case "oversized TTL":
					pc.Expires = time.Now().Add(MaxChallengeTTL + time.Minute)
				case "expired":
					pc.Expires = time.Now().Add(-time.Second)
				case "wrong challenge":
					pc.Session.Challenge = ""
				case "unbound login":
					pc.Flow, pc.SessionID, pc.DPoPJKT = FlowLoginNamed, "", ""
				}
				if err := store.Save(t.Context(), pc.Session.Challenge, pc); err == nil {
					t.Fatalf("accepted %s", invalid)
				}
			}
		})
	}
}

func TestRedisChallengeExpiryRestartAndOutage(t *testing.T) {
	mini, stores := redisChallengeStores(t)
	pc := pendingForFlow(FlowLoginDiscoverable)
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	key := challengeRedisKey(pc.Session.Challenge)
	if ttl := mini.TTL(key); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("native TTL = %v", ttl)
	}
	if strings.Contains(key, pc.Session.Challenge) || !strings.HasPrefix(key, redisChallengePrefix) {
		t.Fatal("challenge key is not a versioned digest")
	}
	restarted, err := NewRedisChallengeStore(stores[1].client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); err != nil {
		t.Fatalf("API restart lost shared state: %v", err)
	}
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	mini.FastForward(2 * time.Minute)
	if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expired state: %v", err)
	}
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	mini.FlushAll()
	if _, err := stores[0].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Redis state loss used a local fallback: %v", err)
	}
	mini.Close()
	if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); !errors.Is(err, ErrChallengeStoreUnavailable) {
		t.Fatalf("save outage: %v", err)
	}
	if _, err := stores[1].Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeStoreUnavailable) {
		t.Fatalf("take outage: %v", err)
	}
}

func TestRedisChallengeCorruptionFailsClosed(t *testing.T) {
	_, stores := redisChallengeStores(t)
	for _, corruption := range []string{"wrong type", "missing TTL", "missing binding", "oversized data", "invalid JSON", "rounded authority", "payload binding mismatch"} {
		t.Run(corruption, func(t *testing.T) {
			pc := pendingForFlow(FlowRegistration)
			if err := stores[0].Save(t.Context(), pc.Session.Challenge, pc); err != nil {
				t.Fatal(err)
			}
			ctx, client, key := t.Context(), stores[0].client, challengeRedisKey(pc.Session.Challenge)
			var err error
			switch corruption {
			case "wrong type":
				err = client.Set(ctx, key, "bad", time.Minute).Err()
			case "missing TTL":
				err = client.Persist(ctx, key).Err()
			case "missing binding":
				err = client.HDel(ctx, key, "jkt").Err()
			case "oversized data":
				err = client.HSet(ctx, key, "data", strings.Repeat("x", maxChallengeBytes+1)).Err()
			case "invalid JSON":
				err = client.HSet(ctx, key, "data", "{").Err()
			case "rounded authority":
				data, _, _ := encodePendingChallenge(pc.Session.Challenge, pc, time.Now())
				bad := strings.Replace(string(data), `"auth_version":"9223372036854775807"`, `"auth_version":9223372036854775807`, 1)
				err = client.HSet(ctx, key, "data", bad).Err()
			case "payload binding mismatch":
				pc.DPoPJKT = "corrupt-key"
				data, _, _ := encodePendingChallenge(pc.Session.Challenge, pc, time.Now())
				err = client.HSet(ctx, key, "data", data).Err()
				pc.DPoPJKT = testBrowserJKT
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stores[1].Take(ctx, pc.Session.Challenge, bindingFor(pc)); !errors.Is(err, ErrChallengeStoreUnavailable) {
				t.Fatalf("corrupt authority accepted: %v", err)
			}
		})
	}
}

func TestRedisChallengeServiceCrossInstanceFlows(t *testing.T) {
	exerciseRedisChallengeServiceFlows(t, func(t *testing.T) [2]*RedisChallengeStore {
		_, stores := redisChallengeStores(t)
		return stores
	})
}

func exerciseRedisChallengeServiceFlows(t *testing.T, newStores func(*testing.T) [2]*RedisChallengeStore) {
	t.Helper()
	for flow := FlowRegistration; flow <= FlowReclaim; flow++ {
		t.Run(flow.String(), func(t *testing.T) {
			f := newFixture(t)
			f.register(t, f.auth)
			stores := newStores(t)
			for _, store := range stores {
				store.now = f.svc.now
			}
			f.svc.challenges = stores[0]
			other, err := New(testConfig(), f.users, f.creds, stores[1])
			if err != nil {
				t.Fatal(err)
			}
			other.now = f.svc.now
			ctx := f.ctx()
			var challenge string
			var finish func(context.Context) error
			switch flow {
			case FlowRegistration, FlowRecoveryRegistration:
				options, err := f.svc.beginRegistration(ctx, f.user.ID, "test-session", flow, flow == FlowRecoveryRegistration, "")
				if err != nil {
					t.Fatal(err)
				}
				challenge = challengeOf(options.Response.Challenge)
				body := newSoftAuthenticator(t).attestation(challenge)
				finish = func(ctx context.Context) error {
					_, err := other.finishRegistration(ctx, f.user.ID, "test-session", flow, flow == FlowRecoveryRegistration, body)
					return err
				}
			case FlowStepUp, FlowReclaim:
				begin := f.svc.BeginStepUp
				verify := other.FinishStepUp
				if flow == FlowReclaim {
					f.setStatus(t, "pending_deletion")
					begin, verify = f.svc.BeginReclaimAssertion, other.FinishReclaimAssertion
				}
				options, err := begin(ctx, f.user.ID, "test-session")
				if err != nil {
					t.Fatal(err)
				}
				challenge = challengeOf(options.Response.Challenge)
				body := f.auth.assertion(challenge, f.handle(t))
				finish = func(ctx context.Context) error { return verify(ctx, f.user.ID, "test-session", body) }
			default:
				user := f.users.mustGet(t, f.user.ID)
				user.AuthVersion = math.MaxInt64
				f.users.byID[user.ID] = user
				var options *protocol.CredentialAssertion
				if flow == FlowLoginDiscoverable {
					options, err = f.svc.BeginDiscoverableLogin(ctx)
				} else {
					email := f.user.Email
					if flow == FlowLoginMock {
						email = "absent@example.com"
					}
					options, err = f.svc.BeginLogin(ctx, email)
				}
				if err != nil {
					t.Fatal(err)
				}
				challenge = challengeOf(options.Response.Challenge)
				body := f.auth.assertion(challenge, f.handle(t))
				finish = func(ctx context.Context) error {
					result, err := other.FinishLoginVersioned(ctx, body)
					if err == nil && (result.ID != f.user.ID || result.AuthVersion != math.MaxInt64 || result.DPoPJKT != testBrowserJKT) {
						t.Errorf("issued authority did not capture ceremony binding: %+v", result)
					}
					return err
				}
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := stores[0].client.Del(ctx, challengeRedisKey(challenge)).Err(); err != nil {
					t.Errorf("clean up this ceremony's Redis key: %v", err)
				}
			})
			wrong := dpop.WithProof(ctx, &dpop.Proof{JKT: "foreign-browser"})
			if err := finish(wrong); !errors.Is(err, ErrChallengeNotFound) {
				t.Fatalf("foreign browser: %v", err)
			}
			if !isLoginFlow(flow) {
				if _, err := other.FinishLoginVersioned(ctx, f.auth.assertion(challenge, f.handle(t))); !errors.Is(err, ErrChallengeFlowMismatch) {
					t.Fatalf("login burned non-login ceremony: %v", err)
				}
			}
			err = finish(ctx)
			if flow == FlowLoginMock {
				if !errors.Is(err, ErrMockChallenge) {
					t.Fatalf("mock verification: %v", err)
				}
			} else if err != nil {
				t.Fatalf("cross-instance verification: %v", err)
			}
			if err := finish(ctx); !errors.Is(err, ErrChallengeNotFound) {
				t.Fatalf("cross-instance replay: %v", err)
			}
		})
	}
}

func TestLoginRequiresContextDPoPBinding(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)
	if _, err := f.svc.BeginDiscoverableLogin(t.Context()); !errors.Is(err, ErrDPoPBindingRequired) {
		t.Fatalf("unbound discoverable options: %v", err)
	}
	if _, err := f.svc.BeginLogin(t.Context(), f.user.Email); !errors.Is(err, ErrDPoPBindingRequired) {
		t.Fatalf("unbound named options: %v", err)
	}
	options, err := f.svc.BeginDiscoverableLogin(f.ctx())
	if err != nil {
		t.Fatal(err)
	}
	body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))
	if _, err := f.svc.FinishLoginVersioned(t.Context(), body); !errors.Is(err, ErrDPoPBindingRequired) {
		t.Fatalf("unbound verification: %v", err)
	}
	if _, err := f.svc.FinishLoginVersioned(f.ctx(), body); err != nil {
		t.Fatalf("missing proof burned ceremony: %v", err)
	}
}

func TestRedisChallengeStoreRequiresContextTimeouts(t *testing.T) {
	if _, err := NewRedisChallengeStore(nil); err == nil {
		t.Fatal("nil Redis client accepted")
	}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	if _, err := NewRedisChallengeStore(client); err == nil {
		t.Fatal("Redis client that ignores request deadlines accepted")
	}
}

func TestRedisChallengeStoreBoundsNetworkWait(t *testing.T) {
	for _, timeout := range []time.Duration{40 * time.Millisecond, redisChallengeTimeout} {
		t.Run(timeout.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop); _ = listener.Close() })
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				<-stop // An unavailable Redis peer accepts TCP but never answers.
			}()
			client := redis.NewClient(&redis.Options{
				Addr: listener.Addr().String(), ContextTimeoutEnabled: true, MaxRetries: -1,
				DialTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
			})
			t.Cleanup(func() { _ = client.Close() })
			store, err := NewRedisChallengeStore(client)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if timeout < redisChallengeTimeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			pc := pendingForFlow(FlowRegistration)
			start := time.Now()
			err = store.Save(ctx, pc.Session.Challenge, pc)
			if !errors.Is(err, ErrChallengeStoreUnavailable) || time.Since(start) > timeout+time.Second {
				t.Fatalf("bounded network wait = %v, %v", time.Since(start), err)
			}
		})
	}
}
