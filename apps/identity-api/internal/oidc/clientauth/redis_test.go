package clientauth

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	miniredisserver "github.com/alicebob/miniredis/v2/server"
	"github.com/redis/go-redis/v9"
)

type jtiRedisHook struct {
	result     any
	err        error
	cancel     func()
	calls      int
	timeReply  any
	timeErr    error
	timeCancel func()
	timeCalls  int
	before     func(redis.Cmder)
}

func (h *jtiRedisHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}

func (h *jtiRedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if h.before != nil {
			h.before(cmd)
			return next(ctx, cmd)
		}
		if cmd.Name() == "time" {
			h.timeCalls++
			if h.timeCancel != nil {
				h.timeCancel()
			}
			cmd.(*redis.Cmd).SetVal(h.timeReply)
			cmd.SetErr(h.timeErr)
			return h.timeErr
		}
		h.calls++
		if h.cancel != nil {
			h.cancel()
		}
		cmd.(*redis.Cmd).SetVal(h.result)
		cmd.SetErr(h.err)
		return h.err
	}
}

func (h *jtiRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestRedisJTIGuardFailsClosed(t *testing.T) {
	var typedNil *redis.Client
	for _, client := range []redis.UniversalClient{nil, typedNil} {
		if _, err := NewRedisJTIGuard(client); !errors.Is(err, ErrInvalidReplayParams) {
			t.Fatal("nil Redis client accepted")
		}
	}
	for _, tc := range []struct {
		name   string
		result any
		err    error
		cancel bool
	}{
		{"outage", nil, errors.New("storage failed"), false},
		{"malformed_response", "not-an-integer", nil, false},
		{"unexpected_integer", int64(2), nil, false},
		{"cancelled_after_claim", int64(1), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hook := &jtiRedisHook{result: tc.result, err: tc.err}
			if tc.cancel {
				hook.cancel = cancel
			}
			client := redis.NewClient(&redis.Options{Addr: "unused", MaxRetries: -1})
			defer func() { _ = client.Close() }()
			client.AddHook(hook)
			guard, err := NewRedisJTIGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			h := newHarness(t, es256Signer(t))
			hook.timeReply = []any{strconv.FormatInt(h.now.Unix(), 10), "000000"}
			h.auth.jti = guard
			clientResult, err := h.auth.Authenticate(ctx, form(h.sk.sign(t, h.header(), standardClaims(h.now))))
			want := ErrReplayUnavailable
			if tc.cancel {
				want = context.Canceled
			}
			if clientResult.ID != "" || !errors.Is(err, want) {
				t.Fatalf("authentication = %v, %v", clientResult.ID, err)
			}
			if tc.err != nil && strings.Contains(err.Error(), tc.err.Error()) {
				t.Fatal("raw storage failure was exposed")
			}
		})
	}
}

func TestRedisJTIGuardRejectsBeforeStorage(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "unused"})
	defer func() { _ = client.Close() }()
	hook := &jtiRedisHook{result: int64(1)}
	client.AddHook(hook)
	guard, _ := NewRedisJTIGuard(client)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, exp := range []time.Time{{}, time.Unix(-1, 0), time.Unix(maxUnixSeconds+61, 0)} {
		if fresh, err := guard.Remember(t.Context(), testClientID, testAudience, "test", exp); fresh || !errors.Is(err, ErrInvalidReplayParams) {
			t.Fatalf("invalid expiry = %v, %v", fresh, err)
		}
	}
	for _, scope := range [][3]string{{"", testAudience, "test"}, {testClientID, "", "test"}, {testClientID, testAudience, ""},
		{strings.Repeat("c", maxClientIDBytes+1), testAudience, "test"}, {testClientID, strings.Repeat("a", maxAudienceBytes+1), "test"},
		{testClientID, testAudience, strings.Repeat("j", maxJTIBytes+1)}, {testClientID, testAudience, "\x00"}} {
		if fresh, err := guard.Remember(t.Context(), scope[0], scope[1], scope[2], now.Add(time.Minute)); fresh || !errors.Is(err, ErrInvalidReplayParams) {
			t.Fatalf("invalid identity = %v, %v", fresh, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if fresh, err := guard.Remember(ctx, testClientID, testAudience, "test", now.Add(time.Minute)); fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v, %v", fresh, err)
	}
	if hook.calls != 0 || hook.timeCalls != 0 {
		t.Fatal("invalid claim reached storage")
	}
}

func newRedisClockGuard(t *testing.T, now time.Time) (*RedisJTIGuard, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	server := miniredis.RunT(t)
	server.SetTime(now)
	client := redis.NewClient(&redis.Options{Addr: server.Addr(), MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	guard, err := NewRedisJTIGuard(client)
	if err != nil {
		t.Fatal(err)
	}
	return guard, server, client
}

func TestRedisAssertionClockIgnoresReplicaSkew(t *testing.T) {
	for _, peerSkew := range []time.Duration{0, -2 * time.Second} {
		t.Run(strconv.FormatInt(int64(peerSkew/time.Second), 10), func(t *testing.T) {
			h := newHarness(t, es256Signer(t))
			now := h.now
			guard, server, client := newRedisClockGuard(t, now)
			other, err := NewRedisJTIGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			a, err := New(h.auth.registry, testAudience, guard, WithClock(func() time.Time { return now.Add(2 * time.Second) }))
			if err != nil {
				t.Fatal(err)
			}
			b, err := New(h.auth.registry, testAudience, other, WithClock(func() time.Time { return now.Add(peerSkew) }))
			if err != nil {
				t.Fatal(err)
			}
			claims := standardClaims(now)
			claims["exp"], claims["iat"] = now.Add(-57*time.Second).Unix(), now.Add(-2*time.Minute).Unix()
			compact := h.sk.sign(t, h.header(), claims)
			key := replayKey(testClientID, testAudience, stringClaim(claims, "jti"))
			if _, err := a.Authenticate(t.Context(), form(compact)); err != nil {
				t.Fatal(err)
			}
			if ttl := server.TTL(key); ttl != 3*time.Second+time.Millisecond {
				t.Fatalf("absolute retention = %s", ttl)
			}
			// miniredis TIME and TTL are independent: advance both, not only TTL.
			now = now.Add(1200 * time.Millisecond)
			server.SetTime(now)
			server.FastForward(1200 * time.Millisecond)
			if _, err := b.Authenticate(t.Context(), form(compact)); !errors.Is(err, ErrReplay) {
				t.Fatalf("skewed peer replay = %v", err)
			}
			if ttl := server.TTL(key); ttl != 1800*time.Millisecond+time.Millisecond {
				t.Fatalf("replay extended or shortened retention = %s", ttl)
			}
			now = now.Add(1800 * time.Millisecond)
			server.SetTime(now)
			server.FastForward(1800 * time.Millisecond)
			if _, err := b.Authenticate(t.Context(), form(compact)); !errors.Is(err, ErrExpired) {
				t.Fatalf("exclusive end = %v", err)
			}
			if ttl := server.TTL(key); ttl != time.Millisecond {
				t.Fatalf("rounded end retention = %s", ttl)
			}
			server.SetTime(now.Add(time.Millisecond))
			server.FastForward(time.Millisecond)
			if server.Exists(key) {
				t.Fatal("claim outlived rounded acceptance end")
			}
		})
	}
}

func TestRedisAtomicClaimRechecksClockAfterAdmission(t *testing.T) {
	for _, mode := range []string{"deadline", "malformed_clock", "time_error", "malformed_time_reply"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, es256Signer(t))
			guard, server, client := newRedisClockGuard(t, h.now)
			h.auth.jti = guard
			h.auth.now = func() time.Time { t.Fatal("live authority consulted local clock"); return time.Time{} }
			claims := standardClaims(h.now)
			claims["exp"], claims["iat"] = h.now.Add(-57*time.Second).Unix(), h.now.Add(-2*time.Minute).Unix()
			compact := h.sk.sign(t, h.header(), claims)
			advanced := false
			client.AddHook(&jtiRedisHook{before: func(cmd redis.Cmder) {
				if !advanced && (cmd.Name() == "evalsha" || cmd.Name() == "eval") {
					advanced = true
					switch mode {
					case "deadline":
						server.SetTime(h.now.Add(3 * time.Second))
					case "malformed_clock":
						server.SetTime(time.Unix(maxUnixSeconds+1, 0))
					default:
						server.Server().SetPreHook(func(peer *miniredisserver.Peer, command string, _ ...string) bool {
							if command != "TIME" {
								return false
							}
							if mode == "time_error" {
								peer.WriteError("ERR raw private TIME failure")
							} else {
								peer.WriteLen(2)
								peer.WriteBulk("raw private TIME value")
								peer.WriteBulk("0")
							}
							return true
						})
					}
				}
			}})
			_, err := h.auth.Authenticate(t.Context(), form(compact))
			want := ErrInvalidReplayParams
			if mode != "deadline" {
				want = ErrReplayUnavailable
			}
			if !errors.Is(err, want) || !advanced {
				t.Fatalf("atomic clock recheck = %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("raw atomic TIME failure exposed")
			}
			if server.Exists(replayKey(testClientID, testAudience, stringClaim(claims, "jti"))) {
				t.Fatal("failed temporal admission recorded a claim")
			}
		})
	}
}

func TestRedisAuthoritativeRetentionBounds(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	guard, server, _ := newRedisClockGuard(t, now)
	for _, expiry := range []time.Time{now, now.Add(-time.Nanosecond), now.Add(maxReplayRetention + time.Nanosecond)} {
		if fresh, err := guard.Remember(t.Context(), testClientID, testAudience, "invalid", expiry); fresh || !errors.Is(err, ErrInvalidReplayParams) {
			t.Fatalf("invalid authoritative expiry = %v,%v", fresh, err)
		}
	}
	for i, remaining := range []time.Duration{time.Nanosecond, time.Millisecond, time.Millisecond + time.Nanosecond, maxReplayRetention} {
		jti := strconv.Itoa(i)
		if fresh, err := guard.Remember(t.Context(), testClientID, testAudience, jti, now.Add(remaining)); !fresh || err != nil {
			t.Fatalf("bounded claim = %v,%v", fresh, err)
		}
		want := time.Duration(remaining.Milliseconds()+1) * time.Millisecond
		if ttl := server.TTL(replayKey(testClientID, testAudience, jti)); ttl != want {
			t.Fatalf("rounded absolute TTL = %s, want %s", ttl, want)
		}
	}
}

func TestRedisServerTimeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  any
		err    error
		cancel bool
	}{
		{"storage", nil, errors.New("raw private TIME error"), false},
		{"nil", nil, nil, false}, {"wrong_shape", []any{"1"}, nil, false}, {"extra", []any{"1", "0", "0"}, nil, false},
		{"wrong_type", []any{int64(1), "0"}, nil, false}, {"negative", []any{"-1", "0"}, nil, false},
		{"text", []any{"private TIME value", "0"}, nil, false}, {"range", []any{"253402300800", "0"}, nil, false},
		{"micros", []any{"1", "1000000"}, nil, false}, {"fraction", []any{"1", "1.5"}, nil, false},
		{"cancel", []any{"1", "0"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			hook := &jtiRedisHook{timeReply: tc.reply, timeErr: tc.err}
			if tc.cancel {
				hook.timeCancel = cancel
			}
			client := redis.NewClient(&redis.Options{Addr: "unused", MaxRetries: -1})
			defer func() { _ = client.Close() }()
			client.AddHook(hook)
			guard, err := NewRedisJTIGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			h := newHarness(t, es256Signer(t))
			h.auth.jti = guard
			h.auth.now = func() time.Time { t.Fatal("TIME failure fell back to local clock"); return time.Time{} }
			result, err := h.auth.Authenticate(ctx, form(h.sk.sign(t, h.header(), standardClaims(h.now))))
			want := ErrReplayUnavailable
			if tc.cancel {
				want = context.Canceled
			}
			if result.ID != "" || !errors.Is(err, want) || hook.calls != 0 {
				t.Fatalf("TIME failure = %v", err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("raw TIME failure exposed")
			}
		})
	}
}

func TestRedisServerTimeStorageAndPrecision(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	now := h.now.Add(123456 * time.Microsecond)
	guard, server, client := newRedisClockGuard(t, now)
	if observed, err := guard.ServerTime(t.Context()); err != nil || !observed.Equal(now) || observed.Location() != time.UTC {
		t.Fatalf("shared microsecond clock = %v", err)
	}
	h.auth.jti = guard
	h.auth.now = func() time.Time { t.Fatal("storage outage used local clock"); return time.Time{} }
	server.SetError("ERR raw private TIME failure")
	compact := h.sk.sign(t, h.header(), standardClaims(h.now))
	if result, err := h.auth.Authenticate(t.Context(), form(compact)); result.ID != "" || !errors.Is(err, ErrReplayUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatalf("TIME outage = %v", err)
	}
	server.SetError("")
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if observed, err := guard.ServerTime(t.Context()); !observed.IsZero() || !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("closed TIME storage = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if observed, err := guard.ServerTime(ctx); !observed.IsZero() || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled TIME = %v", err)
	}
}
