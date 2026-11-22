package contactcode

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

func TestFirstPasskeyPurposeAndSharedContactSpend(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			sender := &captureSender{}
			cfg := Config{PerDestinationPerMinute: 3}
			var sms *smsotp.Config
			destination := "owner@example.test"
			if channel == ChannelEmail {
				cfg.FirstPasskeyEmail = sender
			} else {
				sms = &smsotp.Config{FirstPasskeySender: smsSender{sender}}
				destination = "+989123456789"
			}
			f := newFixture(t, cfg, sms, true)
			binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
			if !f.svc.FirstPasskeyChannelEnabled(channel) || f.svc.DeletionChannelEnabled(channel) || f.svc.PasswordChangeChannelEnabled(channel) {
				t.Fatal("purpose channels were not isolated")
			}
			handle, expires, err := f.svc.RequestFirstPasskey(f.ctx, binding, channel, destination, strings.Repeat("a", 64), "203.0.113.8")
			if err != nil || sender.calls() != 1 || f.email.calls() != 0 || f.sms.calls() != 0 {
				t.Fatal("first passkey used foreign delivery", err)
			}
			if _, err := f.svc.Verify(f.ctx, handle, f.jkt, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("first passkey authorized login")
			}
			if _, err := f.svc.VerifyDeletion(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("first passkey authorized deletion")
			}
			if _, err := f.svc.VerifyPasswordChange(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("first passkey authorized password change")
			}
			for _, field := range []string{"account", "version", "session", "jkt"} {
				other := binding
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
				if _, err := f.svc.VerifyFirstPasskey(f.ctx, other, handle, sender.last().code); err != ErrNoActiveCode {
					t.Fatal("foreign binding accepted")
				}
			}
			if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
				t.Fatal("foreign purpose/binding spent an attempt")
			}
			record, err := f.svc.VerifyFirstPasskey(f.ctx, binding, handle, sender.last().code)
			if err != nil || record.Purpose != PurposeFirstPasskey || !record.ExpiresAt.Equal(expires) || record.ContactBinding != strings.Repeat("a", 64) {
				t.Fatal("original first-passkey authority was not frozen", err)
			}
			if _, err := f.svc.VerifyFirstPasskey(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("first-passkey OTP replayed")
			}
			f.svc.cfg.PerDestinationPerMinute = 1
			if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, channel, destination, "198.51.100.8"); err != ErrRateLimited {
				t.Fatal("login bypassed shared contact spend")
			}
		})
	}
}

func TestFirstPasskeyDisabledUnknownDeliveryDeadlineAndLockout(t *testing.T) {
	f := newFixture(t, Config{}, &smsotp.Config{}, true)
	binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	for _, channel := range []string{ChannelEmail, ChannelSMS, "unknown"} {
		if f.svc.FirstPasskeyChannelEnabled(channel) || f.svc.FirstPasskeyChallengeTTL(channel) != 0 {
			t.Fatal("login enabled first-passkey channel")
		}
		if _, _, err := f.svc.RequestFirstPasskey(f.ctx, binding, channel, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrDisabled {
			t.Fatal("disabled channel issued authority")
		}
	}
	mail := &captureSender{err: errPrivate}
	f = newFixture(t, Config{FirstPasskeyEmail: mail}, nil, false)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	if handle, expires, err := f.svc.RequestFirstPasskey(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || mail.calls() != 1 {
		t.Fatal("unknown delivery retried or returned tentative authority")
	}
	mail = &captureSender{}
	f = newFixture(t, Config{FirstPasskeyEmail: mail, CodeTTL: time.Second}, nil, true)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, expires, err := f.svc.RequestFirstPasskey(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.PExpire(f.ctx, challengePrefix+handle, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	f.mr.SetTime(expires)
	if _, err := f.svc.VerifyFirstPasskey(f.ctx, binding, handle, mail.last().code); err != ErrNoActiveCode {
		t.Fatal("Redis TTL extended original first-passkey deadline")
	}
	f = newFixture(t, Config{FirstPasskeyEmail: mail}, nil, true)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, _, err = f.svc.RequestFirstPasskey(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_, err := f.svc.VerifyFirstPasskey(f.ctx, binding, handle, "invalid")
		if i < 2 && err != ErrInvalidCode || i == 2 && err != ErrLockedOut {
			t.Fatal("first-passkey attempt limit was not shared")
		}
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("login bypassed first-passkey lockout")
	}
}
