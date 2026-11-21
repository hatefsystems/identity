package contactcode

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

func TestPasswordChangePurposeChannelsBindingsAndSharedQuota(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			mail, text := &captureSender{}, &captureSender{}
			f := newFixture(t, Config{PasswordChangeEmail: mail, PerDestinationPerMinute: 3}, &smsotp.Config{PasswordChangeSender: smsSender{text}}, true)
			binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
			destination, sender := "owner@example.test", mail
			if channel == ChannelSMS {
				destination, sender = "+989123456789", text
			}
			if f.svc.DeletionChannelEnabled(channel) || !f.svc.PasswordChangeChannelEnabled(channel) {
				t.Fatal("purpose-specific delivery enabled deletion or disabled password change")
			}
			handle, expires, err := f.svc.RequestPasswordChange(f.ctx, binding, channel, destination, strings.Repeat("a", 64), "203.0.113.8")
			if err != nil || sender.calls() != 1 || f.email.calls() != 0 || f.sms.calls() != 0 {
				t.Fatal("password change used login delivery", err)
			}
			if _, err := f.svc.Verify(f.ctx, handle, f.jkt, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("password change authorized login")
			}
			if _, err := f.svc.VerifyDeletion(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("password change authorized deletion")
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
				if _, err := f.svc.VerifyPasswordChange(f.ctx, other, handle, sender.last().code); err != ErrNoActiveCode {
					t.Fatal("foreign binding authorized password change", field)
				}
			}
			if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
				t.Fatal("purpose/binding exchange burned attempt")
			}
			rec, err := f.svc.VerifyPasswordChange(f.ctx, binding, handle, sender.last().code)
			if err != nil || rec.Purpose != PurposePasswordChange || !rec.ExpiresAt.Equal(expires) || rec.ContactBinding != strings.Repeat("a", 64) {
				t.Fatal("verification lost fixed purpose/deadline/contact binding")
			}
			if _, err := f.svc.VerifyPasswordChange(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("password change replayed")
			}
			if channel == ChannelSMS {
				if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, channel, destination, "198.51.100.8"); err != ErrRateLimited {
					t.Fatal("login bypassed shared phone spend")
				}
			} else {
				f.svc.cfg.PerDestinationPerMinute = 1
				if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, channel, destination, "198.51.100.8"); err != ErrRateLimited {
					t.Fatal("login bypassed shared email spend")
				}
			}
		})
	}
}

func TestPasswordChangeDisabledChannelsAndUnknownDelivery(t *testing.T) {
	f := newFixture(t, Config{}, &smsotp.Config{}, true)
	binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	for _, channel := range []string{ChannelEmail, ChannelSMS, "unknown"} {
		if f.svc.PasswordChangeChannelEnabled(channel) || f.svc.PasswordChangeChallengeTTL(channel) != 0 {
			t.Fatal("login enabled password-change channel")
		}
		if _, _, err := f.svc.RequestPasswordChange(f.ctx, binding, channel, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrDisabled {
			t.Fatal("disabled password-change channel issued authority")
		}
	}
	mail := &captureSender{err: errPrivate}
	f = newFixture(t, Config{PasswordChangeEmail: mail}, nil, false)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	if handle, expires, err := f.svc.RequestPasswordChange(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || mail.calls() != 1 {
		t.Fatal("unknown password-change delivery retried or exposed authority")
	}
}

func TestPasswordChangeOriginalDeadlineAndSharedLockout(t *testing.T) {
	mail := &captureSender{}
	f := newFixture(t, Config{PasswordChangeEmail: mail, CodeTTL: time.Second}, nil, true)
	binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, expires, err := f.svc.RequestPasswordChange(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.PExpire(f.ctx, challengePrefix+handle, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	f.mr.SetTime(expires)
	if _, err := f.svc.VerifyPasswordChange(f.ctx, binding, handle, mail.last().code); err != ErrNoActiveCode {
		t.Fatal("Redis TTL extended original password-change deadline")
	}
	f = newFixture(t, Config{PasswordChangeEmail: mail}, nil, true)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, _, err = f.svc.RequestPasswordChange(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_, err = f.svc.VerifyPasswordChange(f.ctx, binding, handle, "invalid")
		if i < 2 && err != ErrInvalidCode || i == 2 && err != ErrLockedOut {
			t.Fatal("password change did not enforce shared attempt limit")
		}
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("login bypassed password-change lockout")
	}
}
