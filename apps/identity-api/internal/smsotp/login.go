package smsotp

import (
	"context"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// DeliveryBudget names an existing sliding-window spend bucket. Login reserves
// these exact buckets atomically with its own challenge, rather than sending
// through enrollment or creating an independent SMS spend allowance.
type DeliveryBudget struct {
	Key    string
	Limit  int
	Window time.Duration
}

// LoginPolicy exposes delivery bounds without exposing the enrollment HMAC key.
type LoginPolicy struct {
	CodeTTL     time.Duration
	MaxAttempts int
	LockoutTTL  time.Duration
	LockoutKey  string
	Budgets     []DeliveryBudget
}

// ContactLoginTTL is public channel policy, independent of any account/contact.
// A disabled SMS service returns zero and performs no lookup or delivery.
func (s *Service) ContactLoginTTL() time.Duration {
	if !s.DeliveryEnabled() {
		return 0
	}
	return s.cfg.CodeTTL
}

// ContactLoginPolicy does not mutate Redis or send. Its caller must reserve all
// returned budgets and check the shared lockout atomically before delivery.
func (s *Service) ContactLoginPolicy(phone, sourceIP string) (LoginPolicy, error) {
	if !s.DeliveryEnabled() {
		return LoginPolicy{}, ErrDisabled
	}
	canonical, err := NormalizePhone(phone)
	if err != nil || canonical != phone {
		return LoginPolicy{}, ErrInvalidPhone
	}
	p := LoginPolicy{CodeTTL: s.cfg.CodeTTL, MaxAttempts: s.cfg.MaxAttempts, LockoutTTL: s.cfg.LockoutTTL, LockoutKey: lockoutKey(phone), Budgets: []DeliveryBudget{
		{phoneRateKey(phone, "1m"), s.cfg.PerPhonePerMinute, time.Minute},
		{phoneRateKey(phone, "1h"), s.cfg.PerPhonePerHour, time.Hour},
		{subnetRateKey(ratelimit.Subnet(sourceIP)), s.cfg.PerSubnetPerHour, time.Hour},
	}}
	if s.cfg.GlobalPerDay > 0 {
		p.Budgets = append(p.Budgets, DeliveryBudget{"rate:otp:global:1d", s.cfg.GlobalPerDay, 24 * time.Hour})
	}
	return p, nil
}

// DeliverContactLoginCode is a transport adapter, not a separate issuance path.
// Only call after reserving ContactLoginPolicy's spend and capacity in Redis.
// It never retries. Unknown acceptance must not be converted to send failure.
func (s *Service) DeliverContactLoginCode(ctx context.Context, phone, code string, expiresAt time.Time) error {
	if !s.DeliveryEnabled() {
		return ErrDisabled
	}
	canonical, err := NormalizePhone(phone)
	if err != nil || canonical != phone || len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 || !expiresAt.After(time.Now()) {
		return ErrNoActiveCode
	}
	ctx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	if err := s.sender.SendCode(ctx, phone, code); err != nil {
		switch reason := SendFailureReason(err); reason {
		case "credentials", "account", "egress", "template", "parameters", "credit", "throttle", "recipient":
			return &sendError{reason: reason}
		default:
			return ErrOutcomeUnknown
		}
	}
	return nil
}
