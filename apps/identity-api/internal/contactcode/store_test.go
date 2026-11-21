package contactcode

import (
	"strings"
	"testing"
	"time"
)

func TestSnapshotMismatchCannotBurnOrConsume(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	lockKey := "contact:login:email:lock:" + f.svc.digest("destination", rec.Channel, rec.Destination)
	for _, field := range []string{"account", "version", "jkt", "destination", "expiry", "hash"} {
		other := rec
		switch field {
		case "account":
			other.AccountID[0] ^= 1
		case "version":
			other.AuthVersion++
		case "jkt":
			other.JKT = capability(2)
		case "destination":
			other.Destination = "other@example.test"
		case "expiry":
			other.ExpiresAt = rec.ExpiresAt.Add(time.Second)
		case "hash":
			other.CodeHash = strings.Repeat("a", 64)
		}
		if err := f.store.Consume(f.ctx, other, rec.CodeHash, lockKey); err != ErrNoActiveCode {
			t.Fatal("foreign snapshot consumed or burned the code")
		}
	}
	if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
		t.Fatal("foreign snapshot changed attempts")
	}
}

func TestStoreRejectsMalformedAttemptsAndExpiry(t *testing.T) {
	for _, value := range []string{"", "-1", "01", "1.0", "1junk", "3", "999999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			f := newFixture(t, Config{}, nil, true)
			handle, _ := f.request(t, ChannelEmail, "owner@example.test")
			rec, err := f.store.Get(f.ctx, handle)
			if err != nil {
				t.Fatal(err)
			}
			f.mr.HSet(challengePrefix+handle, "attempts", value)
			if _, err := f.store.Get(f.ctx, handle); err != ErrNoActiveCode {
				t.Fatal("malformed attempts accepted by snapshot read")
			}
			if err := f.store.Consume(f.ctx, rec, rec.CodeHash, "test:lock"); err != ErrNoActiveCode {
				t.Fatal("malformed attempts accepted by atomic consume")
			}
		})
	}
	for _, mutation := range []string{"purpose", "deadline", "extra_field", "no_ttl", "excessive_ttl"} {
		t.Run(mutation, func(t *testing.T) {
			f := newFixture(t, Config{}, nil, true)
			handle, _ := f.request(t, ChannelEmail, "owner@example.test")
			rec, err := f.store.Get(f.ctx, handle)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "purpose":
				other := rec
				other.Purpose = "signup"
				f.mr.HSet(challengePrefix+handle, "payload", recordPayload(other))
			case "deadline":
				f.mr.HSet(challengePrefix+handle, "expires_at", "1")
			case "extra_field":
				f.mr.HSet(challengePrefix+handle, "extra", "unknown")
			case "no_ttl":
				if err := f.client.Persist(f.ctx, challengePrefix+handle).Err(); err != nil {
					t.Fatal(err)
				}
			case "excessive_ttl":
				if err := f.client.PExpire(f.ctx, challengePrefix+handle, 4*time.Minute).Err(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.store.Get(f.ctx, handle); err != ErrNoActiveCode {
				t.Fatal("malformed bound state accepted")
			}
			if err := f.store.Consume(f.ctx, rec, rec.CodeHash, "test:lock"); err != ErrNoActiveCode {
				t.Fatal("malformed bound state consumed")
			}
		})
	}
}

func TestCorruptQuotaTypeFailsBeforeAnyReservationWrite(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	key := "contact:login:destination:" + f.svc.digest("destination", ChannelEmail, "owner@example.test") + ":1h"
	if err := f.client.Set(f.ctx, key, "bad", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8"); err != ErrUnavailable {
		t.Fatal("corrupt budget type accepted")
	}
	if len(f.mr.Keys()) != 1 || f.email.calls() != 0 {
		t.Fatal("preflight failure partially reserved spend, capacity or delivery")
	}
}

func TestConcurrentWrongAttemptsCannotExceedCapturedLimit(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	results := make(chan error, 20)
	for range 20 {
		go func() {
			_, err := f.svc.Verify(f.ctx, handle, f.jkt, "invalid")
			results <- err
		}()
	}
	wrong, exhausted := 0, 0
	for range 20 {
		switch err := <-results; err {
		case ErrInvalidCode:
			wrong++
		case ErrLockedOut:
			exhausted++
		case ErrNoActiveCode:
		default:
			t.Fatal(err)
		}
	}
	if wrong != 2 || exhausted != 1 || f.mr.Exists(challengePrefix+handle) {
		t.Fatal("concurrent attempts bypassed the captured three-attempt limit")
	}
}
