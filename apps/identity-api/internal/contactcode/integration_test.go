//go:build integration

package contactcode

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Namespace only this fixture's EVAL keys; production key/budget semantics and
// real Redis Lua execution are unchanged. Never flush an inherited Redis DB.
type namespacedRedis struct {
	redis.Cmdable
	prefix string
}

func (c namespacedRedis) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	owned := make([]string, len(keys))
	for i, key := range keys {
		owned[i] = c.prefix + key
	}
	return c.Cmdable.Eval(ctx, script, owned, args...)
}

func realRedisFixture(t *testing.T, cfg Config) (fixture, string) {
	t.Helper()
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		if os.Getenv("REQUIRE_CONTACTCODE_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_SMS_INTEGRATION") == "1" {
			t.Fatal("REDIS_URL required for mandatory contactcode integration")
		}
		t.Skip("run-owned Redis fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid fixture Redis configuration")
	}
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("configured fixture Redis unavailable")
	}
	prefix := "contactcode_test:" + uuid.NewString() + ":"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		var cursor uint64
		for {
			keys, next, err := client.Scan(cleanup, cursor, prefix+"*", 100).Result()
			if err != nil {
				t.Error("run-owned contactcode fixture scan failed")
				return
			}
			if len(keys) > 0 {
				if err := client.Del(cleanup, keys...).Err(); err != nil {
					t.Error("run-owned contactcode fixture cleanup failed")
					return
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		keys, _, err := client.Scan(cleanup, 0, prefix+"*", 100).Result()
		if err != nil || len(keys) != 0 {
			t.Error("contactcode fixture teardown incomplete")
		}
	})
	store, err := NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	store.client = namespacedRedis{client, prefix}
	email := &captureSender{}
	cfg.HashKey = []byte(strings.Repeat("k", 32))
	svc, err := New(cfg, store, nil, email)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{ctx: ctx, client: client, store: store, svc: svc, email: email, id: uuid.New(), jkt: capability(1)}, prefix
}

func TestContactLoginRealRedisBoundSnapshotAndOneWinnerIntegration(t *testing.T) {
	f, prefix := realRedisFixture(t, Config{})
	handle, expires := f.request(t, ChannelEmail, "owner@example.test")
	code := f.email.last().code
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil || !rec.ExpiresAt.Equal(expires) {
		t.Fatal("stored expiry differs from original response")
	}
	if _, err := f.svc.Verify(f.ctx, handle, capability(2), code); err != ErrNoActiveCode {
		t.Fatal("foreign browser accepted")
	}
	for _, purpose := range []string{"signup", "enrollment"} {
		other := rec
		other.Purpose = purpose
		if err := f.client.HSet(f.ctx, prefix+challengePrefix+handle, "payload", recordPayload(other)).Err(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Verify(f.ctx, handle, f.jkt, code); err != ErrNoActiveCode {
			t.Fatal("foreign proof purpose accepted")
		}
	}
	if err := f.client.HSet(f.ctx, prefix+challengePrefix+handle, "payload", recordPayload(rec)).Err(); err != nil {
		t.Fatal(err)
	}
	other := rec
	other.AccountID, other.Destination = uuid.New(), "other@example.test"
	if err := f.store.Consume(f.ctx, other, rec.CodeHash, "test:lock"); err != ErrNoActiveCode {
		t.Fatal("foreign account/destination snapshot consumed proof")
	}
	if f.client.HGet(f.ctx, prefix+challengePrefix+handle, "attempts").Val() != "0" {
		t.Fatal("purpose/browser/destination mismatch burned an attempt")
	}
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			result, err := f.svc.Verify(f.ctx, handle, f.jkt, code)
			if err == nil && result != rec.Result {
				err = ErrInvalid
			}
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
	if winners != 1 || f.client.Exists(f.ctx, prefix+challengePrefix+handle).Val() != 0 || f.client.ZCard(f.ctx, prefix+capacityKey).Val() != 0 {
		t.Fatal("real Redis completion did not have one atomic winner")
	}
}

func TestContactLoginRealRedisOriginalExpiryAndAttemptLimitIntegration(t *testing.T) {
	f, prefix := realRedisFixture(t, Config{CodeTTL: time.Second})
	handle, expires := f.request(t, ChannelEmail, "owner@example.test")
	if err := f.client.PExpire(f.ctx, prefix+challengePrefix+handle, 3*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, f.email.last().code); err != ErrNoActiveCode {
		t.Fatal("extended Redis TTL bypassed original deadline")
	}
	f, prefix = realRedisFixture(t, Config{})
	handle, _ = f.request(t, ChannelEmail, "owner@example.test")
	before := f.client.PTTL(f.ctx, prefix+challengePrefix+handle).Val()
	for i := range 3 {
		want := ErrInvalidCode
		if i == 2 {
			want = ErrLockedOut
		}
		if _, err := f.svc.Verify(f.ctx, handle, f.jkt, "invalid"); err != want {
			t.Fatal("real Redis failed bounded attempt accounting")
		}
		if i < 2 && f.client.PTTL(f.ctx, prefix+challengePrefix+handle).Val() > before {
			t.Fatal("failed attempt extended expiry")
		}
	}
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, f.email.last().code); err != ErrNoActiveCode {
		t.Fatal("exhausted challenge authenticated")
	}
}

func TestContactLoginRealRedisAtomicQuotasAndCapacityIntegration(t *testing.T) {
	f, prefix := realRedisFixture(t, Config{MaxPending: 2, PerDestinationPerMinute: 2, PerSourcePerHour: 100})
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
	if winners != 2 || f.email.calls() != 2 || f.client.ZCard(f.ctx, prefix+capacityKey).Val() != 2 || f.client.ZCard(f.ctx, prefix+"contact:login:global:1d").Val() != 2 {
		t.Fatal("real Redis quota/capacity admission was not atomic")
	}
}

func TestContactLoginRealRedisUnknownCommittedConsumeIntegration(t *testing.T) {
	f, prefix := realRedisFixture(t, Config{})
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	client := &uncertainRedis{Cmdable: f.store.client, script: consumeScript}
	f.store.client = client
	result, err := f.svc.Verify(f.ctx, handle, f.jkt, f.email.last().code)
	if err != ErrOutcomeUnknown || result.AccountID != uuid.Nil || client.calls != 1 || f.client.Exists(f.ctx, prefix+challengePrefix+handle).Val() != 0 {
		t.Fatal("unknown committed consume retried, restored proof or granted authority")
	}
}

func realDeletionFixture(t *testing.T, cfg Config) (deletionFixture, string) {
	t.Helper()
	sender := &captureSender{}
	cfg.DeletionEmail = sender
	f, prefix := realRedisFixture(t, cfg)
	return deletionFixture{fixture: f, mail: sender, binding: DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}, evidence: strings.Repeat("a", 64)}, prefix
}

func TestContactDeletionRealRedisBoundSnapshotAndOneWinnerIntegration(t *testing.T) {
	f, prefix := realDeletionFixture(t, Config{PerDestinationPerMinute: 2})
	login, _ := f.request(t, ChannelEmail, "owner@example.test")
	loginCode := f.email.last().code
	handle, expires := f.requestDeletion(t, ChannelEmail, "owner@example.test")
	code := f.mail.last().code
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil || !rec.ExpiresAt.Equal(expires) || rec.ContactBinding != f.evidence || rec.SessionID != f.binding.SessionID {
		t.Fatal("deletion record did not freeze exact original bindings/deadline")
	}
	if _, err := f.svc.Verify(f.ctx, handle, f.jkt, code); err != ErrNoActiveCode {
		t.Fatal("deletion record authorized login")
	}
	if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, login, loginCode); err != ErrNoActiveCode {
		t.Fatal("login record authorized deletion")
	}
	for _, field := range []string{"account", "version", "session", "jkt"} {
		binding := f.binding
		switch field {
		case "account":
			binding.AccountID = uuid.New()
		case "version":
			binding.AuthVersion++
		case "session":
			binding.SessionID = uuid.NewString()
		case "jkt":
			binding.JKT = capability(2)
		}
		if _, err := f.svc.VerifyDeletion(f.ctx, binding, handle, code); err != ErrNoActiveCode {
			t.Fatalf("foreign %s accepted deletion", field)
		}
	}
	for _, field := range []string{"session", "contact"} {
		other := rec
		if field == "session" {
			other.SessionID = uuid.NewString()
		} else {
			other.ContactBinding = strings.Repeat("b", 64)
		}
		if err := f.store.Consume(f.ctx, other, rec.CodeHash, "test:lock"); err != ErrNoActiveCode {
			t.Fatal("changed deletion snapshot spent an attempt")
		}
	}
	for _, purpose := range []string{PurposeLogin, "signup", "enrollment"} {
		other := rec
		other.Purpose = purpose
		if err := f.client.HSet(f.ctx, prefix+challengePrefix+handle, "payload", recordPayload(other)).Err(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, code); err != ErrNoActiveCode {
			t.Fatal("foreign purpose authorized deletion")
		}
	}
	if err := f.client.HSet(f.ctx, prefix+challengePrefix+handle, "payload", recordPayload(rec)).Err(); err != nil {
		t.Fatal(err)
	}
	if f.client.HGet(f.ctx, prefix+challengePrefix+handle, "attempts").Val() != "0" || f.client.HGet(f.ctx, prefix+challengePrefix+login, "attempts").Val() != "0" {
		t.Fatal("foreign binding/purpose spent an attempt")
	}
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			result, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, code)
			if err == nil && result != rec {
				err = ErrInvalid
			}
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
	if _, err := f.svc.Verify(f.ctx, login, f.jkt, loginCode); err != nil {
		t.Fatal("deletion consumption affected independent login")
	}
	if winners != 1 || f.client.Exists(f.ctx, prefix+challengePrefix+handle).Val() != 0 || f.client.ZCard(f.ctx, prefix+capacityKey).Val() != 0 {
		t.Fatal("real Redis deletion completion did not have one atomic winner")
	}
}

func TestContactDeletionRealRedisConcurrentAttemptsAndSharedLockoutIntegration(t *testing.T) {
	f, prefix := realDeletionFixture(t, Config{})
	handle, _ := f.requestDeletion(t, ChannelEmail, "owner@example.test")
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, "invalid")
			results <- err
		})
	}
	wg.Wait()
	close(results)
	wrong, exhausted := 0, 0
	for err := range results {
		switch err {
		case ErrInvalidCode:
			wrong++
		case ErrLockedOut:
			exhausted++
		case ErrNoActiveCode:
		default:
			t.Fatal(err)
		}
	}
	if wrong != 2 || exhausted != 1 || f.client.Exists(f.ctx, prefix+challengePrefix+handle).Val() != 0 || f.client.ZCard(f.ctx, prefix+capacityKey).Val() != 0 {
		t.Fatal("real Redis deletion concurrent attempts exceeded captured limit")
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("login bypassed deletion lockout")
	}
	if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, "owner@example.test", f.evidence, "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("deletion bypassed shared destination lockout")
	}
}

func TestContactDeletionRealRedisMixedPurposeQuotasAndCapacityIntegration(t *testing.T) {
	f, prefix := realDeletionFixture(t, Config{MaxPending: 2, PerDestinationPerMinute: 2, PerSourcePerHour: 100})
	results := make(chan error, 20)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			var err error
			if i%2 == 0 {
				_, _, err = f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8")
			} else {
				_, _, err = f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, "owner@example.test", f.evidence, "203.0.113.8")
			}
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
	if winners != 2 || f.email.calls()+f.mail.calls() != 2 || f.client.ZCard(f.ctx, prefix+capacityKey).Val() != 2 || f.client.ZCard(f.ctx, prefix+"contact:login:global:1d").Val() != 2 {
		t.Fatal("mixed purpose requests obtained separate Redis quota/capacity")
	}
}

func TestContactDeletionRealRedisOriginalExpiryAndUnknownConsumeIntegration(t *testing.T) {
	f, prefix := realDeletionFixture(t, Config{CodeTTL: time.Second})
	handle, expires := f.requestDeletion(t, ChannelEmail, "owner@example.test")
	if err := f.client.PExpire(f.ctx, prefix+challengePrefix+handle, 3*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, f.mail.last().code); err != ErrNoActiveCode {
		t.Fatal("extended Redis TTL bypassed deletion original deadline")
	}
	f, prefix = realDeletionFixture(t, Config{})
	handle, _ = f.requestDeletion(t, ChannelEmail, "owner@example.test")
	client := &uncertainRedis{Cmdable: f.store.client, script: consumeScript}
	f.store.client = client
	result, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, f.mail.last().code)
	if err != ErrOutcomeUnknown || result != (Record{}) || client.calls != 1 || f.mail.calls() != 1 || f.client.Exists(f.ctx, prefix+challengePrefix+handle).Val() != 0 {
		t.Fatal("unknown committed deletion consume retried, restored proof or granted authority")
	}
}
