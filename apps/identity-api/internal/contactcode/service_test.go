package contactcode

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

var errPrivate = errors.New("private-recipient private-code private-provider-diagnostic")

type delivery struct{ destination, code string }

type captureSender struct {
	mu         sync.Mutex
	deliveries []delivery
	err        error
}

func (s *captureSender) SendCode(_ context.Context, destination, code string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveries = append(s.deliveries, delivery{destination, code})
	return s.err
}

func (s *captureSender) last() delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deliveries[len(s.deliveries)-1]
}

func (s *captureSender) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.deliveries)
}

type smsSender struct{ capture *captureSender }

func (s smsSender) SendCode(ctx context.Context, destination, code string) error {
	return s.capture.SendCode(ctx, destination, code, time.Time{})
}

// These collaborators must never be invoked by contact login. Signup delivery
// also uses no SQL/user mutation; the coordinator owns all account checks.
type unusedUsers struct{ smsotp.UserStore }
type unusedEncryptor struct{ smsotp.Encryptor }
type unusedIndexer struct{ smsotp.BlindIndexer }

type fixture struct {
	ctx    context.Context
	client *redis.Client
	mr     *miniredis.Miniredis
	store  *RedisStore
	svc    *Service
	email  *captureSender
	sms    *captureSender
	phones *smsotp.Service
	id     uuid.UUID
	jkt    string
}

func capability(seed byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{seed}), 32)))
}

func newFixture(t *testing.T, cfg Config, smsConfig *smsotp.Config, emailEnabled bool) fixture {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	store, err := NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	email, sms := &captureSender{}, &captureSender{}
	var phones *smsotp.Service
	if smsConfig != nil {
		c := *smsConfig
		c.HashPepper = []byte(strings.Repeat("p", 32))
		otps, err := smsotp.NewRedisOTPStore(client)
		if err != nil {
			t.Fatal(err)
		}
		limiter, err := ratelimit.NewRedisLimiter(client)
		if err != nil {
			t.Fatal(err)
		}
		phones, err = smsotp.New(c, unusedUsers{}, unusedEncryptor{}, unusedIndexer{}, limiter, otps, smsSender{sms})
		if err != nil {
			t.Fatal(err)
		}
	}
	var sender Sender
	if emailEnabled {
		sender = email
	}
	if cfg.HashKey == nil {
		cfg.HashKey = []byte(strings.Repeat("k", 32))
	}
	svc, err := New(cfg, store, phones, sender)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{context.Background(), client, mr, store, svc, email, sms, phones, uuid.New(), capability(1)}
}

func (f fixture) request(t *testing.T, channel, destination string) (string, time.Time) {
	t.Helper()
	handle, expires, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, channel, destination, "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	return handle, expires
}

func TestChannelsAreIndependentlyConfigured(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			var sms *smsotp.Config
			if channel == ChannelSMS {
				sms = &smsotp.Config{}
			}
			f := newFixture(t, Config{}, sms, channel == ChannelEmail)
			destination := "owner@example.test"
			sender := f.email
			other := ChannelSMS
			if channel == ChannelSMS {
				destination, sender, other = "+989123456789", f.sms, ChannelEmail
			}
			handle, expires := f.request(t, channel, destination)
			if !validCapability(handle) || !expires.After(time.Now()) || time.Until(expires) > 3*time.Minute {
				t.Fatal("invalid capability or default lifetime")
			}
			if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, other, destination, "203.0.113.8"); err != ErrDisabled {
				t.Fatal("disabled alternate channel affected policy")
			}
			result, err := f.svc.Verify(f.ctx, handle, f.jkt, sender.last().code)
			if err != nil || result != (Result{f.id, 9, channel, destination}) {
				t.Fatal("contact proof did not preserve selected account and destination")
			}
			if _, err := f.svc.Verify(f.ctx, handle, f.jkt, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("proof replay accepted")
			}
		})
	}
	var typedNil *captureSender
	f := newFixture(t, Config{}, nil, false)
	svc, err := New(f.svc.cfg, f.store, nil, typedNil)
	if err != nil || svc.ChannelEnabled(ChannelEmail) || svc.ChannelEnabled(ChannelSMS) {
		t.Fatal("typed nil or disabled services enabled a channel")
	}
}

func TestBoundedConstructionAndRequestValidation(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	for _, cfg := range []Config{{HashKey: []byte("short")}, {CodeTTL: 4 * time.Minute}, {MaxAttempts: 4}, {MaxPending: 10001}, {PerDestinationPerMinute: 6}, {PerDestinationPerHour: 21}, {PerSourcePerHour: 101}} {
		if cfg.HashKey == nil {
			cfg.HashKey = f.svc.cfg.HashKey
		}
		if _, err := New(cfg, f.store, nil, f.email); err != ErrInvalid {
			t.Fatal("unbounded policy accepted")
		}
	}
	if _, err := New(f.svc.cfg, nil, nil, f.email); err != ErrUnavailable {
		t.Fatal("missing store accepted")
	}
	for _, tc := range []struct {
		id          uuid.UUID
		version     int64
		jkt, destIP string
		destination string
	}{
		{uuid.Nil, 9, f.jkt, "203.0.113.8", "owner@example.test"},
		{f.id, -1, f.jkt, "203.0.113.8", "owner@example.test"},
		{f.id, 9, "bad", "203.0.113.8", "owner@example.test"},
		{f.id, 9, f.jkt, "bad", "owner@example.test"},
		{f.id, 9, f.jkt, "203.0.113.8", "owner@EXAMPLE.test"},
		{f.id, 9, f.jkt, "203.0.113.8", "owner@example.test\r\nBcc: attacker@example.test"},
	} {
		if handle, _, err := f.svc.Request(f.ctx, tc.id, tc.version, tc.jkt, ChannelEmail, tc.destination, tc.destIP); err != ErrInvalid || handle != "" {
			t.Fatal("invalid request became deliverable")
		}
	}
	if f.email.calls() != 0 {
		t.Fatal("invalid request sent mail")
	}
	key := []byte(strings.Repeat("a", 32))
	svc, _ := New(Config{HashKey: key}, f.store, nil, f.email)
	key[0] = 'b'
	if svc.cfg.HashKey[0] != 'a' {
		t.Fatal("mutable caller HMAC secret retained")
	}
}

func TestPublicChallengeTTLDoesNotLookUpAccountOrContact(t *testing.T) {
	f := newFixture(t, Config{CodeTTL: 2 * time.Minute}, &smsotp.Config{CodeTTL: time.Minute}, true)
	if f.svc.ChallengeTTL(ChannelEmail) != 2*time.Minute || f.svc.ChallengeTTL(ChannelSMS) != time.Minute || f.svc.ChallengeTTL("unknown") != 0 || f.email.calls() != 0 || f.sms.calls() != 0 || len(f.mr.Keys()) != 0 {
		t.Fatal("public TTL did not preserve stricter independent channel policy")
	}
	var disabled *Service
	if disabled.ChallengeTTL(ChannelEmail) != 0 || disabled.ChannelEnabled(ChannelSMS) {
		t.Fatal("nil service exposed active channel policy")
	}
	f = newFixture(t, Config{}, nil, true)
	if f.svc.ChallengeTTL(ChannelSMS) != 0 || f.svc.ChannelEnabled(ChannelSMS) {
		t.Fatal("nil SMS collaborator exposed active channel policy")
	}
}

func TestHMACBindsEveryOperationContext(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	code := f.email.last().code
	if rec.CodeHash != f.svc.hashCode(rec, code) || rec.CodeHash == code {
		t.Fatal("code is not protected by keyed context HMAC")
	}
	for _, field := range []string{"account", "version", "jkt", "purpose", "channel", "destination", "operation", "expiry", "attempt_policy"} {
		other := rec
		switch field {
		case "account":
			other.AccountID = uuid.New()
		case "version":
			other.AuthVersion++
		case "jkt":
			other.JKT = capability(2)
		case "purpose":
			other.Purpose = "signup"
		case "channel":
			other.Channel = ChannelSMS
		case "destination":
			other.Destination = "other@example.test"
		case "operation":
			other.Operation = capability(3)
		case "expiry":
			other.ExpiresAt = rec.ExpiresAt.Add(time.Second)
		case "attempt_policy":
			other.MaxAttempts = 2
		}
		if f.svc.hashCode(other, code) == rec.CodeHash {
			t.Fatalf("HMAC omitted %s", field)
		}
	}
	if _, err := f.svc.Verify(f.ctx, handle, capability(2), code); err != ErrNoActiveCode || f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
		t.Fatal("foreign browser burned or authenticated challenge")
	}
	other := rec
	other.Destination = "other@example.test"
	f.mr.HSet(challengePrefix+handle, "payload", recordPayload(other))
	if result, err := f.svc.Verify(f.ctx, handle, f.jkt, code); err != ErrInvalidCode || result.AccountID != uuid.Nil {
		t.Fatal("mutated destination authenticated")
	}
	f.mr.HSet(challengePrefix+handle, "payload", recordPayload(rec))
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, code); err != nil {
		t.Fatal(err)
	}
}

func TestAttemptsAndOriginalExpiryDoNotReset(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, expires := f.request(t, ChannelEmail, "owner@example.test")
	key := challengePrefix + handle
	originalDeadline := f.mr.HGet(key, "expires_at")
	remainingTTL := f.mr.TTL(key) - time.Minute
	if remainingTTL <= 0 || remainingTTL > 2*time.Minute {
		t.Fatal("invalid original bounded challenge lifetime")
	}
	// PEXPIREAT includes elapsed request time and millisecond truncation.
	// FastForward changes TTLs only; advance TIME separately for expiry checks.
	f.mr.FastForward(time.Minute)
	f.mr.SetTime(expires.Add(-2 * time.Minute))
	for i, invalid := range []string{"", "12345", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"} {
		want := ErrInvalidCode
		if i == 2 {
			want = ErrLockedOut
		}
		if result, err := f.svc.Verify(f.ctx, handle, f.jkt, invalid); err != want || result.AccountID != uuid.Nil {
			t.Fatal("malformed code did not burn the bounded attempt")
		}
		if i < 2 {
			if f.mr.TTL(key) != remainingTTL || f.mr.HGet(key, "expires_at") != originalDeadline {
				t.Fatal("verification changed original deadline or remaining lifetime")
			}
			rec, err := f.store.Get(f.ctx, handle)
			if err != nil || !rec.ExpiresAt.Equal(expires) {
				t.Fatal("verification changed the HMAC-bound original expiry")
			}
		}
	}
	if f.mr.Exists(challengePrefix+handle) || f.client.ZCard(f.ctx, capacityKey).Val() != 0 {
		t.Fatal("exhausted challenge retained usable state or capacity")
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.1"); err != ErrLockedOut {
		t.Fatal("destination lockout bypassed")
	}

	f = newFixture(t, Config{CodeTTL: time.Second}, nil, true)
	handle, expires = f.request(t, ChannelEmail, "owner@example.test")
	if err := f.client.PExpire(f.ctx, challengePrefix+handle, 3*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	f.mr.SetTime(expires.Add(time.Millisecond))
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, f.email.last().code); err != ErrNoActiveCode {
		t.Fatal("Redis TTL extension bypassed original expiry")
	}
}

func TestSharedDestinationDoesNotSelectOrReplaceAccount(t *testing.T) {
	f := newFixture(t, Config{PerDestinationPerMinute: 2}, nil, true)
	firstID := f.id
	firstHandle, _ := f.request(t, ChannelEmail, "shared@example.test")
	firstCode := f.email.last().code
	f.id = uuid.New()
	secondHandle, _ := f.request(t, ChannelEmail, "shared@example.test")
	secondCode := f.email.last().code
	first, err := f.svc.Verify(f.ctx, firstHandle, f.jkt, firstCode)
	if err != nil || first.AccountID != firstID || first.AuthVersion != 9 || first.Destination != "shared@example.test" {
		t.Fatal("later shared-contact request replaced original account binding")
	}
	second, err := f.svc.Verify(f.ctx, secondHandle, f.jkt, secondCode)
	if err != nil || second.AccountID != f.id || second.AuthVersion != 9 || secondHandle == firstHandle {
		t.Fatal("shared destination selected a different account or operation")
	}
}

func TestConcurrentConsumeHasOneWinner(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	code := f.email.last().code
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, err := f.svc.Verify(f.ctx, handle, f.jkt, code)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrNoActiveCode {
			t.Fatal(err)
		}
	}
	if winners != 1 || f.client.ZCard(f.ctx, capacityKey).Val() != 0 {
		t.Fatal("concurrent consume did not have exactly one winner")
	}
}

func TestQuotasAndCapacityReserveTogetherAtomically(t *testing.T) {
	f := newFixture(t, Config{MaxPending: 2, PerDestinationPerMinute: 5, PerSourcePerHour: 2}, nil, true)
	for _, destination := range []string{"one@example.test", "two@example.test"} {
		f.request(t, ChannelEmail, destination)
	}
	before := len(f.mr.Keys())
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "three@example.test", "198.51.100.8"); err != ErrRateLimited {
		t.Fatal("capacity bypassed")
	}
	if f.email.calls() != 2 || len(f.mr.Keys()) != before || f.client.ZCard(f.ctx, "contact:login:global:1d").Val() != 2 {
		t.Fatal("rejected reservation created quota keys, delivery or spend")
	}

	f = newFixture(t, Config{PerSourcePerHour: 1}, nil, true)
	f.request(t, ChannelEmail, "one@example.test")
	before = len(f.mr.Keys())
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "two@example.test", "203.0.113.9"); err != ErrRateLimited || len(f.mr.Keys()) != before || f.client.ZCard(f.ctx, "contact:login:global:1d").Val() != 1 {
		t.Fatal("source rejection partially charged destination/global budgets")
	}

	f = newFixture(t, Config{PerDestinationPerMinute: 3, PerDestinationPerHour: 3, PerSourcePerHour: 100}, nil, true)
	results := make(chan error, 15)
	var wg sync.WaitGroup
	for range 15 {
		wg.Go(func() {
			_, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8")
			results <- err
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrRateLimited {
			t.Fatal(err)
		}
	}
	if winners != 3 || f.email.calls() != 3 || f.client.ZCard(f.ctx, "contact:login:global:1d").Val() != 3 {
		t.Fatal("concurrent requests bypassed destination quota")
	}
}

func TestSMSStricterPolicyAndSharedSignupSpend(t *testing.T) {
	f := newFixture(t, Config{}, &smsotp.Config{CodeTTL: time.Minute, MaxAttempts: 1, LockoutTTL: 30 * time.Minute, SignupEnabled: true, GlobalPerDay: 2, MaxPendingSignup: 2}, false)
	phone := "+989123456789"
	handle, _ := f.request(t, ChannelSMS, phone)
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil || rec.MaxAttempts != 1 || rec.LockoutTTL != 30*time.Minute || time.Until(rec.ExpiresAt) > time.Minute {
		t.Fatal("login loosened SMS policy")
	}
	if _, err := f.phones.SendSignupCode(f.ctx, uuid.New(), f.jkt, phone, "198.51.100.8", time.Now().Add(time.Minute)); err != smsotp.ErrRateLimited {
		t.Fatal("signup received separate destination allowance from login")
	}
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, "invalid"); err != ErrLockedOut || f.mr.TTL("otp:sms:lockout:"+phone) != 30*time.Minute {
		t.Fatal("login did not retain stricter shared phone lockout")
	}

	f = newFixture(t, Config{}, &smsotp.Config{SignupEnabled: true, GlobalPerDay: 2, MaxPendingSignup: 2}, true)
	if _, err := f.phones.SendSignupCode(f.ctx, uuid.New(), f.jkt, phone, "203.0.113.8", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelSMS, phone, "198.51.100.8"); err != ErrRateLimited {
		t.Fatal("login received separate allowance from signup")
	}
	// Independent email delivery still works after SMS spend is exhausted.
	f.request(t, ChannelEmail, "owner@example.test")
	for _, destination := range []string{"+989123456780", "+989123456781"} {
		_, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelSMS, destination, "192.0.2.8")
		if destination == "+989123456780" && err != nil || destination == "+989123456781" && err != ErrRateLimited {
			t.Fatal("global SMS spend did not include signup and login")
		}
	}
}

type uncertainRedis struct {
	redis.Cmdable
	script string
	calls  int
}

func (c *uncertainRedis) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	cmd := c.Cmdable.Eval(ctx, script, keys, args...)
	if script == c.script {
		c.calls++
		if cmd.Err() == nil {
			return redis.NewCmdResult(nil, errPrivate)
		}
	}
	return cmd
}

func TestUnknownDeliveryNeverActivatesOrAutomaticallyRetries(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	f.email.err = errPrivate
	handle, expires, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8")
	if err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || f.email.calls() != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("unknown delivery returned success/private diagnostic or retried")
	}
	for _, key := range f.mr.Keys() {
		if strings.HasPrefix(key, challengePrefix) {
			if f.mr.HGet(key, "active") != "0" || f.mr.TTL(key) <= 0 {
				t.Fatal("unknown delivery became usable or unbounded")
			}
			if _, err := f.store.Get(f.ctx, strings.TrimPrefix(key, challengePrefix)); err != ErrNoActiveCode {
				t.Fatal("unknown delivery yielded usable proof")
			}
		}
	}
}

func TestUnknownRedisReservationActivationAndConsumeNeverRetry(t *testing.T) {
	for _, script := range []string{reserveScript, activateScript, getScript, consumeScript} {
		t.Run(script[:min(20, len(script))], func(t *testing.T) {
			f := newFixture(t, Config{}, nil, true)
			client := &uncertainRedis{Cmdable: f.client, script: script}
			f.store.client = client
			if script == reserveScript || script == activateScript {
				handle, expires, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8")
				wantSends := 0
				if script == activateScript {
					wantSends = 1
				}
				if err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || client.calls != 1 || f.email.calls() != wantSends {
					t.Fatal("unknown Redis mutation was retried or returned capability")
				}
				return
			}
			handle, _ := f.request(t, ChannelEmail, "owner@example.test")
			result, err := f.svc.Verify(f.ctx, handle, f.jkt, f.email.last().code)
			if err != ErrOutcomeUnknown || result.AccountID != uuid.Nil || client.calls != 1 {
				t.Fatal("unknown consume granted authority or retried")
			}
			if script == consumeScript && f.mr.Exists(challengePrefix+handle) {
				t.Fatal("committed uncertain consume restored code")
			}
			if script == getScript && !f.mr.Exists(challengePrefix+handle) {
				t.Fatal("unknown read proceeded to consumption")
			}
		})
	}
}

func TestRetryingRedisClientRejected(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = client.Close() })
	if _, err := NewRedisStore(client); err != ErrInvalid {
		t.Fatal("automatic Redis mutation retries accepted")
	}
}
