package smsotp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type loginDeliveryError string

func (e loginDeliveryError) Error() string          { return "private-provider-diagnostic" }
func (e loginDeliveryError) DeliveryReason() string { return string(e) }

func TestContactLoginPolicyReusesExistingSpendAndStricterLimits(t *testing.T) {
	f := fixture(t, Config{CodeTTL: time.Minute, MaxAttempts: 1, LockoutTTL: 30 * time.Minute, GlobalPerDay: 4})
	p, err := f.svc.ContactLoginPolicy(testPhone, "203.0.113.8")
	if err != nil || p.CodeTTL != time.Minute || p.MaxAttempts != 1 || p.LockoutTTL != 30*time.Minute || p.LockoutKey != lockoutKey(testPhone) || len(p.Budgets) != 4 {
		t.Fatal("login did not retain existing SMS policy")
	}
	for i, want := range []DeliveryBudget{
		{phoneRateKey(testPhone, "1m"), 1, time.Minute},
		{phoneRateKey(testPhone, "1h"), 5, time.Hour},
		{subnetRateKey("203.0.113.0/24"), 10, time.Hour},
		{"rate:otp:global:1d", 4, 24 * time.Hour},
	} {
		if p.Budgets[i] != want {
			t.Fatal("login introduced independent SMS spend allowance")
		}
	}
	if f.sender.calls != 0 || len(f.limiter.calls) != 0 || f.users.writes != 0 {
		t.Fatal("policy lookup mutated delivery, budgets or account")
	}
}

func TestContactLoginDeliveryClassifiesUnknownAndNeverRetries(t *testing.T) {
	for _, reason := range []string{"credentials", "account", "egress", "template", "parameters", "credit", "throttle", "recipient", "unavailable", "rejected", "private"} {
		t.Run(reason, func(t *testing.T) {
			f := fixture(t, Config{})
			f.sender.err = loginDeliveryError(reason)
			err := f.svc.DeliverContactLoginCode(context.Background(), testPhone, "000042", time.Now().Add(time.Minute))
			want := ErrSendFailed
			if reason == "unavailable" || reason == "rejected" || reason == "private" {
				want = ErrOutcomeUnknown
			}
			if !errors.Is(err, want) || f.sender.calls != 1 || strings.Contains(err.Error(), "private") || f.users.writes != 0 {
				t.Fatal("transport acceptance uncertainty was hidden, leaked or retried")
			}
		})
	}
	f := fixture(t, Config{})
	f.sender.err = errPrivate
	if err := f.svc.DeliverContactLoginCode(context.Background(), testPhone, "000042", time.Now().Add(time.Minute)); err != ErrOutcomeUnknown || f.sender.calls != 1 {
		t.Fatal("unclassified transport error was not explicitly uncertain")
	}
}

func TestContactLoginAdapterValidatesBeforeDelivery(t *testing.T) {
	f := fixture(t, Config{})
	for _, phone := range []string{"", "invalid", "+98 9123456789"} {
		if _, err := f.svc.ContactLoginPolicy(phone, "203.0.113.8"); err != ErrInvalidPhone {
			t.Fatal("adapter changed canonical destination bytes")
		}
		if err := f.svc.DeliverContactLoginCode(context.Background(), phone, "000042", time.Now().Add(time.Minute)); err != ErrNoActiveCode {
			t.Fatal("adapter sent invalid destination")
		}
	}
	if err := f.svc.DeliverContactLoginCode(context.Background(), testPhone, "12345", time.Now().Add(time.Minute)); err != ErrNoActiveCode || f.sender.calls != 0 {
		t.Fatal("adapter sent invalid code")
	}
	if err := f.svc.DeliverContactLoginCode(context.Background(), testPhone, "000042", time.Now().Add(-time.Second)); err != ErrNoActiveCode || f.sender.calls != 0 {
		t.Fatal("adapter sent expired proof")
	}
	var disabled *Service
	if _, err := disabled.ContactLoginPolicy(testPhone, "203.0.113.8"); err != ErrDisabled {
		t.Fatal("nil SMS service enabled login delivery")
	}
}
