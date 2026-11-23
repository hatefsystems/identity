package contactcode

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

func TestMFAEnrollmentPurposeAndSharedContactSpend(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			sender := &captureSender{}
			cfg := Config{PerDestinationPerMinute: 3}
			var sms *smsotp.Config
			destination := "owner@example.test"
			if channel == ChannelEmail {
				cfg.MFAEnrollmentEmail = sender
			} else {
				sms = &smsotp.Config{MFAEnrollmentSender: smsSender{sender}}
				destination = "+989123456789"
			}
			f := newFixture(t, cfg, sms, true)
			binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
			if !f.svc.MFAEnrollmentChannelEnabled(channel) || f.svc.DeletionChannelEnabled(channel) || f.svc.PasswordChangeChannelEnabled(channel) || f.svc.FirstPasskeyChannelEnabled(channel) {
				t.Fatal("MFA enrollment enabled another purpose's transport")
			}
			handle, expires, err := f.svc.RequestMFAEnrollment(f.ctx, binding, channel, destination, strings.Repeat("a", 64), "203.0.113.8")
			if err != nil || sender.calls() != 1 || f.email.calls() != 0 || f.sms.calls() != 0 {
				t.Fatal("MFA enrollment used foreign delivery", err)
			}
			if _, err := f.svc.Verify(f.ctx, handle, f.jkt, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("MFA enrollment authorized login")
			}
			for _, verify := range []func(DeletionBinding) (Record, error){
				func(b DeletionBinding) (Record, error) {
					return f.svc.VerifyDeletion(f.ctx, b, handle, sender.last().code)
				},
				func(b DeletionBinding) (Record, error) {
					return f.svc.VerifyPasswordChange(f.ctx, b, handle, sender.last().code)
				},
				func(b DeletionBinding) (Record, error) {
					return f.svc.VerifyFirstPasskey(f.ctx, b, handle, sender.last().code)
				},
			} {
				if _, err := verify(binding); err != ErrNoActiveCode {
					t.Fatal("MFA enrollment authorized another action")
				}
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
				if _, err := f.svc.VerifyMFAEnrollment(f.ctx, other, handle, sender.last().code); err != ErrNoActiveCode {
					t.Fatal("foreign binding accepted")
				}
			}
			for _, malformed := range []string{"", "12345", "1234567", " 123456", "123456 ", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6", "12345a"} {
				if _, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, malformed); err != ErrInvalid {
					t.Fatal("malformed code was consumed", err)
				}
			}
			if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
				t.Fatal("foreign authority spent an attempt")
			}
			record, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, sender.last().code)
			if err != nil || record.Purpose != PurposeMFAEnrollment || !record.ExpiresAt.Equal(expires) || record.ContactBinding != strings.Repeat("a", 64) {
				t.Fatal("original MFA enrollment authority was not frozen", err)
			}
			if _, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("MFA enrollment code replayed")
			}
			f.svc.cfg.PerDestinationPerMinute = 1
			if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, channel, destination, "198.51.100.8"); err != ErrRateLimited {
				t.Fatal("login bypassed shared MFA contact spend")
			}
		})
	}
}

func TestMFAEnrollmentDisabledUnknownDeliveryAndLockout(t *testing.T) {
	f := newFixture(t, Config{}, &smsotp.Config{}, true)
	binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	for _, channel := range []string{ChannelEmail, ChannelSMS, "unknown"} {
		if f.svc.MFAEnrollmentChannelEnabled(channel) || f.svc.MFAEnrollmentChallengeTTL(channel) != 0 {
			t.Fatal("login enabled MFA enrollment channel")
		}
		if _, _, err := f.svc.RequestMFAEnrollment(f.ctx, binding, channel, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrDisabled {
			t.Fatal("disabled channel issued authority")
		}
	}
	mail := &captureSender{err: errPrivate}
	f = newFixture(t, Config{MFAEnrollmentEmail: mail}, nil, false)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	if handle, expires, err := f.svc.RequestMFAEnrollment(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8"); err != ErrOutcomeUnknown || handle != "" || !expires.IsZero() || mail.calls() != 1 {
		t.Fatal("unknown delivery retried or published authority")
	}
	mail = &captureSender{}
	f = newFixture(t, Config{MFAEnrollmentEmail: mail, CodeTTL: time.Second}, nil, true)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, expires, err := f.svc.RequestMFAEnrollment(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.client.PExpire(f.ctx, challengePrefix+handle, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	f.mr.SetTime(expires)
	if _, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, mail.last().code); err != ErrNoActiveCode {
		t.Fatal("Redis TTL extended frozen authority")
	}
	f = newFixture(t, Config{MFAEnrollmentEmail: mail}, nil, true)
	binding = DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
	handle, _, err = f.svc.RequestMFAEnrollment(f.ctx, binding, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if wrong == mail.last().code {
		wrong = "999999"
	}
	for i := range 3 {
		_, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, wrong)
		if i < 2 && err != ErrInvalidCode || i == 2 && err != ErrLockedOut {
			t.Fatal("MFA enrollment attempts escaped shared lockout")
		}
	}
	if _, _, err := f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "198.51.100.8"); err != ErrLockedOut {
		t.Fatal("login bypassed MFA enrollment lockout")
	}
}

func TestMFAEnrollmentRejectsEveryOtherContactCodePurpose(t *testing.T) {
	for _, purpose := range []string{PurposeLogin, PurposeAccountDeletion, PurposePasswordChange, PurposeFirstPasskey} {
		t.Run(purpose, func(t *testing.T) {
			sender := &captureSender{}
			f := newFixture(t, Config{MFAEnrollmentEmail: sender, DeletionEmail: sender, PasswordChangeEmail: sender, FirstPasskeyEmail: sender}, nil, true)
			binding := DeletionBinding{f.id, 9, uuid.NewString(), f.jkt}
			var handle, code string
			var err error
			if purpose == PurposeLogin {
				handle, _, err = f.svc.Request(f.ctx, f.id, 9, f.jkt, ChannelEmail, "owner@example.test", "203.0.113.8")
				code = f.email.last().code
			} else {
				handle, _, err = f.svc.requestAction(f.ctx, binding, purpose, ChannelEmail, "owner@example.test", strings.Repeat("a", 64), "203.0.113.8")
				code = sender.last().code
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.VerifyMFAEnrollment(f.ctx, binding, handle, code); err != ErrNoActiveCode || f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
				t.Fatal("foreign-purpose challenge authorized MFA or spent attempt", err)
			}
		})
	}
}
