package contactcode

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

type deletionFixture struct {
	fixture
	mail, text *captureSender
	binding    DeletionBinding
	evidence   string
}

func newDeletionFixture(t *testing.T, cfg Config, smsConfig *smsotp.Config) deletionFixture {
	t.Helper()
	mail, text := &captureSender{}, &captureSender{}
	cfg.DeletionEmail = mail
	if smsConfig != nil {
		policy := *smsConfig
		policy.DeletionSender = smsSender{text}
		smsConfig = &policy
	}
	f := newFixture(t, cfg, smsConfig, true)
	return deletionFixture{f, mail, text, DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}, strings.Repeat("a", 64)}
}

func (f deletionFixture) requestDeletion(t *testing.T, channel, destination string) (string, time.Time) {
	t.Helper()
	handle, expires, err := f.svc.RequestDeletion(f.ctx, f.binding, channel, destination, f.evidence, "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	return handle, expires
}

func TestDeletionChannelsRequireExplicitPurposeDelivery(t *testing.T) {
	f := newFixture(t, Config{}, &smsotp.Config{}, true)
	binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	for _, channel := range []string{ChannelEmail, ChannelSMS, "unknown"} {
		if f.svc.DeletionChannelEnabled(channel) || f.svc.DeletionChallengeTTL(channel) != 0 {
			t.Fatal("login sender enabled deletion delivery")
		}
		if handle, expires, err := f.svc.RequestDeletion(f.ctx, binding, channel, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrDisabled || handle != "" || !expires.IsZero() {
			t.Fatal("missing deletion sender returned a capability")
		}
	}
	if len(f.mr.Keys()) != 0 || f.email.calls() != 0 || f.sms.calls() != 0 {
		t.Fatal("disabled deletion spent capacity or used sign-in delivery")
	}
	var absent *Service
	if absent.DeletionChannelEnabled(ChannelEmail) || absent.DeletionChallengeTTL(ChannelSMS) != 0 {
		t.Fatal("nil service enabled deletion")
	}
	var typedNil *captureSender
	cfg := f.svc.cfg
	cfg.DeletionEmail = typedNil
	svc, err := New(cfg, f.store, f.phones, f.email)
	if err != nil || svc.DeletionChannelEnabled(ChannelEmail) {
		t.Fatal("typed nil deletion sender enabled delivery")
	}

	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		d := newDeletionFixture(t, Config{CodeTTL: 2 * time.Minute}, &smsotp.Config{CodeTTL: time.Minute})
		destination, sender, ttl := "owner@example.test", d.mail, 2*time.Minute
		if channel == ChannelSMS {
			destination, sender, ttl = "+989123456789", d.text, time.Minute
			d.svc.cfg.DeletionEmail = nil
		} else {
			d.svc.sms = nil
		}
		// Deletion email operates without any login email sender as well.
		d.svc.email = nil
		if d.svc.DeletionChallengeTTL(channel) != ttl {
			t.Fatal("deletion loosened channel lifetime")
		}
		handle, expires := d.requestDeletion(t, channel, destination)
		rec, err := d.svc.VerifyDeletion(d.ctx, d.binding, handle, sender.last().code)
		if err != nil || rec.Result != (Result{d.id, 9, channel, destination}) || rec.Purpose != PurposeAccountDeletion || rec.SessionID != d.binding.SessionID || rec.JKT != d.jkt || rec.ContactBinding != d.evidence || rec.Operation != handle || !rec.ExpiresAt.Equal(expires) || time.Until(expires) > ttl || time.Until(expires) > 5*time.Minute {
			t.Fatal("deletion did not return the complete frozen purpose-bound record")
		}
		if sender.calls() != 1 || d.email.calls() != 0 || d.sms.calls() != 0 {
			t.Fatal("deletion used sign-in delivery or resent")
		}
		if rec, err := d.svc.VerifyDeletion(d.ctx, d.binding, handle, sender.last().code); err != ErrNoActiveCode || rec != (Record{}) {
			t.Fatal("deletion proof replayed")
		}
	}
}

func TestDeletionRequestRejectsUnboundedOrMalformedBindings(t *testing.T) {
	f := newDeletionFixture(t, Config{}, nil)
	for _, field := range []string{"account", "version", "jkt", "session", "session_length", "session_whitespace", "session_nonascii"} {
		binding := f.binding
		switch field {
		case "account":
			binding.AccountID = uuid.Nil
		case "version":
			binding.AuthVersion = -1
		case "jkt":
			binding.JKT = "invalid"
		case "session":
			binding.SessionID = ""
		case "session_length":
			binding.SessionID = strings.Repeat("s", 129)
		case "session_whitespace":
			binding.SessionID = "session\nprivate"
		case "session_nonascii":
			binding.SessionID = "\u06f1"
		}
		if handle, _, err := f.svc.RequestDeletion(f.ctx, binding, ChannelEmail, "owner@example.test", f.evidence, "203.0.113.8"); err != ErrInvalid || handle != "" {
			t.Fatalf("invalid %s accepted", field)
		}
	}
	for _, evidence := range []string{"", "exact raw contact evidence", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, "owner@example.test", evidence, "203.0.113.8"); err != ErrInvalid {
			t.Fatal("noncanonical contact evidence HMAC accepted")
		}
	}
	for _, pair := range [][2]string{{"owner@EXAMPLE.test", "203.0.113.8"}, {"owner@example.test", "invalid"}} {
		if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, pair[0], f.evidence, pair[1]); err != ErrInvalid {
			t.Fatal("invalid destination or source accepted")
		}
	}
	if f.mail.calls() != 0 || len(f.mr.Keys()) != 0 {
		t.Fatal("invalid deletion request spent or delivered")
	}
}

func TestDeletionAndLoginPurposeExchangesDoNotSpendAttempts(t *testing.T) {
	f := newDeletionFixture(t, Config{PerDestinationPerMinute: 2}, nil)
	login, _ := f.request(t, ChannelEmail, "owner@example.test")
	loginCode := f.email.last().code
	deletion, _ := f.requestDeletion(t, ChannelEmail, "owner@example.test")
	deletionCode := f.mail.last().code
	if result, err := f.svc.Verify(f.ctx, deletion, f.jkt, deletionCode); err != ErrNoActiveCode || result != (Result{}) {
		t.Fatal("deletion authenticated login")
	}
	if result, err := f.svc.VerifyDeletion(f.ctx, f.binding, login, loginCode); err != ErrNoActiveCode || result != (Record{}) {
		t.Fatal("login authenticated deletion")
	}
	for _, field := range []string{"account", "version", "session", "jkt"} {
		other := f.binding
		switch field {
		case "account":
			other.AccountID = uuid.New()
		case "version":
			other.AuthVersion++
		case "session":
			other.SessionID = uuid.NewString()
		case "jkt":
			other.JKT = capability(2)
		}
		if result, err := f.svc.VerifyDeletion(f.ctx, other, deletion, deletionCode); err != ErrNoActiveCode || result != (Record{}) {
			t.Fatalf("foreign %s authenticated deletion", field)
		}
	}
	rec, err := f.store.Get(f.ctx, deletion)
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{PurposeLogin, "signup", "enrollment"} {
		other := rec
		other.Purpose = purpose
		f.mr.HSet(challengePrefix+deletion, "payload", recordPayload(other))
		if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, deletion, deletionCode); err != ErrNoActiveCode {
			t.Fatal("foreign record purpose authorized deletion")
		}
	}
	f.mr.HSet(challengePrefix+deletion, "payload", recordPayload(rec))
	if f.mr.HGet(challengePrefix+deletion, "attempts") != "0" || f.mr.HGet(challengePrefix+login, "attempts") != "0" {
		t.Fatal("foreign purpose or binding spent an attempt")
	}
	if _, err := f.svc.Verify(f.ctx, login, f.jkt, loginCode); err != nil {
		t.Fatal("purpose exchange corrupted login")
	}
	if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, deletion, deletionCode); err != nil {
		t.Fatal("binding mismatch corrupted deletion")
	}
}

func TestDeletionHMACAndSnapshotBindAllFrozenFields(t *testing.T) {
	f := newDeletionFixture(t, Config{}, nil)
	handle, _ := f.requestDeletion(t, ChannelEmail, "owner@example.test")
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	code := f.mail.last().code
	if rec.ContactBinding != f.evidence || f.svc.hashCode(rec, code) != rec.CodeHash {
		t.Fatal("coordinator evidence was transformed or code HMAC mismatched")
	}
	for _, field := range []string{"account", "version", "session", "contact", "jkt", "purpose", "channel", "destination", "operation", "expiry", "attempts", "lockout"} {
		other := rec
		switch field {
		case "account":
			other.AccountID = uuid.New()
		case "version":
			other.AuthVersion++
		case "session":
			other.SessionID = uuid.NewString()
		case "contact":
			other.ContactBinding = strings.Repeat("b", 64)
		case "jkt":
			other.JKT = capability(2)
		case "purpose":
			other.Purpose = PurposeLogin
		case "channel":
			other.Channel = ChannelSMS
		case "destination":
			other.Destination = "other@example.test"
		case "operation":
			other.Operation = capability(3)
		case "expiry":
			other.ExpiresAt = rec.ExpiresAt.Add(time.Second)
		case "attempts":
			other.MaxAttempts = 2
		case "lockout":
			other.LockoutTTL = 30 * time.Minute
		}
		if f.svc.hashCode(other, code) == rec.CodeHash {
			t.Fatalf("deletion code HMAC omitted %s", field)
		}
		if err := f.store.Consume(f.ctx, other, rec.CodeHash, "test:lock"); err != ErrNoActiveCode {
			t.Fatalf("foreign %s snapshot spent or consumed deletion", field)
		}
	}
	if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
		t.Fatal("foreign snapshot spent an attempt")
	}
	other := rec
	other.ContactBinding = strings.Repeat("b", 64)
	f.mr.HSet(challengePrefix+handle, "payload", recordPayload(other))
	if result, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, code); err != ErrInvalidCode || result != (Record{}) {
		t.Fatal("tampered contact HMAC returned authority")
	}
	f.mr.HSet(challengePrefix+handle, "payload", recordPayload(rec))
	if result, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, code); err != nil || result != rec {
		t.Fatal("verification did not return complete original frozen record")
	}
}

func TestDeletionOriginalDeadlineAndSharedLockout(t *testing.T) {
	for _, initiator := range []string{PurposeLogin, PurposeAccountDeletion} {
		f := newDeletionFixture(t, Config{}, nil)
		handle, expires := f.requestDeletion(t, ChannelEmail, "owner@example.test")
		if initiator == PurposeLogin {
			f = newDeletionFixture(t, Config{}, nil)
			handle, expires = f.request(t, ChannelEmail, "owner@example.test")
		}
		key := challengePrefix + handle
		deadline, ttl := f.mr.HGet(key, "expires_at"), f.mr.TTL(key)
		for i, code := range []string{"", "12345", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"} {
			var err error
			if initiator == PurposeLogin {
				_, err = f.svc.Verify(f.ctx, handle, f.jkt, code)
			} else {
				_, err = f.svc.VerifyDeletion(f.ctx, f.binding, handle, code)
			}
			want := ErrInvalidCode
			if i == 2 {
				want = ErrLockedOut
			}
			if err != want || i < 2 && (f.mr.TTL(key) != ttl || f.mr.HGet(key, "expires_at") != deadline) {
				t.Fatal("wrong deletion attempt did not retain bounded original deadline")
			}
		}
		if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, "owner@example.test", f.evidence, "198.51.100.8"); err != ErrLockedOut {
			t.Fatal("deletion bypassed shared destination lockout")
		}
		if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrLockedOut {
			t.Fatal("login bypassed shared deletion lockout")
		}
		if !expires.After(time.Now()) || f.mr.Exists(key) || f.client.ZCard(f.ctx, capacityKey).Val() != 0 {
			t.Fatal("attempt exhaustion left usable challenge or pending capacity")
		}
	}
	for _, offset := range []time.Duration{-time.Millisecond, 0, time.Millisecond} {
		f := newDeletionFixture(t, Config{CodeTTL: time.Second}, nil)
		handle, expires := f.requestDeletion(t, ChannelEmail, "owner@example.test")
		// Extending Redis TTL cannot extend the HMAC-bound deadline.
		if err := f.client.PExpire(f.ctx, challengePrefix+handle, 3*time.Minute).Err(); err != nil {
			t.Fatal(err)
		}
		f.mr.SetTime(expires.Add(offset))
		rec, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, f.mail.last().code)
		if offset < 0 {
			if err != nil || !rec.ExpiresAt.Equal(expires) {
				t.Fatal("verification just before deadline changed it or failed")
			}
		} else if err != ErrNoActiveCode || rec != (Record{}) {
			t.Fatal("deletion accepted at or after original deadline")
		}
	}
}

func TestDeletionAndLoginShareEveryContactBudgetAndCapacity(t *testing.T) {
	for _, quota := range []string{"destination_minute", "destination_hour", "source", "capacity", "global"} {
		t.Run(quota, func(t *testing.T) {
			cfg := Config{PerDestinationPerMinute: 5, PerDestinationPerHour: 5}
			switch quota {
			case "destination_minute":
				cfg.PerDestinationPerMinute = 1
			case "destination_hour":
				cfg.PerDestinationPerHour = 1
			case "source":
				cfg.PerSourcePerHour = 1
			case "capacity":
				cfg.MaxPending = 1
			}
			f := newDeletionFixture(t, cfg, nil)
			f.request(t, ChannelEmail, "owner@example.test")
			if quota == "global" {
				members := make([]redis.Z, 10000)
				for i := range 10000 {
					members[i] = redis.Z{Score: float64(time.Now().UnixMilli()), Member: strconv.Itoa(i)}
				}
				if err := f.client.ZAdd(f.ctx, "contact:login:global:1d", members...).Err(); err != nil {
					t.Fatal(err)
				}
			}
			destination := "owner@example.test"
			if quota == "source" || quota == "capacity" || quota == "global" {
				destination = "other@example.test"
			}
			before := len(f.mr.Keys())
			if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, destination, f.evidence, "203.0.113.8"); err != ErrRateLimited || f.mail.calls() != 0 || len(f.mr.Keys()) != before {
				t.Fatal("deletion received separate budget or partially reserved")
			}
		})
	}
	f := newDeletionFixture(t, Config{}, nil)
	f.requestDeletion(t, ChannelEmail, "owner@example.test")
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrRateLimited || f.email.calls() != 0 {
		t.Fatal("login received separate budget after deletion")
	}
}

func TestDeletionSMSSharesSignupSpendAndStrictLockout(t *testing.T) {
	f := newDeletionFixture(t, Config{}, &smsotp.Config{CodeTTL: time.Minute, MaxAttempts: 1, LockoutTTL: 30 * time.Minute, SignupEnabled: true, GlobalPerDay: 2, MaxPendingSignup: 2})
	phone := "+989123456789"
	handle, expires := f.requestDeletion(t, ChannelSMS, phone)
	rec, err := f.store.Get(f.ctx, handle)
	if err != nil || rec.MaxAttempts != 1 || rec.LockoutTTL != 30*time.Minute || time.Until(expires) > time.Minute || f.sms.calls() != 0 || f.text.calls() != 1 {
		t.Fatal("deletion loosened SMS policy or used sign-in sender")
	}
	if _, err := f.phones.SendSignupCode(f.ctx, uuid.New(), f.jkt, phone, "198.51.100.8", time.Now().Add(time.Minute)); err != smsotp.ErrRateLimited {
		t.Fatal("signup bypassed deletion phone spend")
	}
	if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, "invalid"); err != ErrLockedOut || f.mr.TTL("otp:sms:lockout:"+phone) != 30*time.Minute {
		t.Fatal("deletion did not establish shared stricter SMS lockout")
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelSMS, phone, "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("login bypassed deletion SMS lockout")
	}
	if _, err := f.phones.SendSignupCode(f.ctx, uuid.New(), f.jkt, phone, "198.51.100.8", time.Now().Add(time.Minute)); err != smsotp.ErrLockedOut {
		t.Fatal("signup bypassed deletion SMS lockout")
	}

	f = newDeletionFixture(t, Config{}, &smsotp.Config{SignupEnabled: true, GlobalPerDay: 2, MaxPendingSignup: 2})
	id, err := f.phones.SendSignupCode(f.ctx, uuid.New(), f.jkt, phone, "203.0.113.8", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelSMS, phone, f.evidence, "198.51.100.8"); err != ErrRateLimited {
		t.Fatal("deletion bypassed signup phone spend")
	}
	if _, err := f.svc.VerifyDeletion(f.ctx, f.binding, id, f.sms.last().code); err != ErrNoActiveCode {
		t.Fatal("real signup challenge exchanged for deletion")
	}
	f.requestDeletion(t, ChannelSMS, "+989123456780")
	if _, _, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelSMS, "+989123456781", f.evidence, "192.0.2.8"); err != ErrRateLimited {
		t.Fatal("deletion bypassed shared signup global SMS spend")
	}
	f.requestDeletion(t, ChannelEmail, "owner@example.test")
}

func TestDeletionUncertainDeliveryAndRedisOutcomesNeverRetry(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		for _, rejection := range []bool{false, true} {
			f := newDeletionFixture(t, Config{}, &smsotp.Config{})
			destination, sender, want := "owner@example.test", f.mail, ErrOutcomeUnknown
			if channel == ChannelSMS {
				destination, sender = "+989123456789", f.text
			}
			sender.err = errPrivate
			if rejection {
				if channel == ChannelSMS {
					sender.err = deletionDeliveryError("recipient")
				} else {
					sender.err = ErrSendFailed
				}
				want = ErrSendFailed
			}
			handle, expires, err := f.svc.RequestDeletion(f.ctx, f.binding, channel, destination, f.evidence, "203.0.113.8")
			if err != want || handle != "" || !expires.IsZero() || sender.calls() != 1 || f.email.calls() != 0 || f.sms.calls() != 0 {
				t.Fatal("uncertain/rejected deletion delivery retried or leaked capability")
			}
			for _, key := range f.mr.Keys() {
				if strings.HasPrefix(key, challengePrefix) && (f.mr.HGet(key, "active") != "0" || f.mr.TTL(key) <= 0) {
					t.Fatal("unconfirmed deletion became usable or unbounded")
				}
			}
		}
	}
	for _, script := range []string{reserveScript, activateScript, getScript, consumeScript} {
		f := newDeletionFixture(t, Config{}, nil)
		client := &uncertainRedis{Cmdable: f.client, script: script}
		f.store.client = client
		if script == reserveScript || script == activateScript {
			handle, expires, err := f.svc.RequestDeletion(f.ctx, f.binding, ChannelEmail, "owner@example.test", f.evidence, "203.0.113.8")
			wantSends := 0
			if script == activateScript {
				wantSends = 1
			}
			if err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || client.calls != 1 || f.mail.calls() != wantSends {
				t.Fatal("uncertain deletion reservation/activation retried or returned handle")
			}
			continue
		}
		handle, _ := f.requestDeletion(t, ChannelEmail, "owner@example.test")
		result, err := f.svc.VerifyDeletion(f.ctx, f.binding, handle, f.mail.last().code)
		if err != ErrOutcomeUnknown || result != (Record{}) || client.calls != 1 || f.mail.calls() != 1 {
			t.Fatal("uncertain deletion read/consume retried or returned record")
		}
		if script == consumeScript && f.mr.Exists(challengePrefix+handle) || script == getScript && !f.mr.Exists(challengePrefix+handle) {
			t.Fatal("unknown consumption restored proof or unknown read consumed it")
		}
	}
}

type deletionDeliveryError string

func (e deletionDeliveryError) Error() string          { return "private-provider-diagnostic" }
func (e deletionDeliveryError) DeliveryReason() string { return string(e) }
