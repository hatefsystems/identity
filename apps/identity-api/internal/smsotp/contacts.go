package smsotp

import (
	"context"
	"strings"
	"time"
)

// ContactDestinationSupported is the current SMS.ir Iranian mobile admission
// policy, not a broader E.164 or registration-alias normalization rule.
func ContactDestinationSupported(phone string) bool {
	return len(phone) == 13 && strings.HasPrefix(phone, "+989") && strings.IndexFunc(phone[4:], func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// ContactLockoutKey remains usable for finite code readers without a provider.
func ContactLockoutKey(phone string) string { return lockoutKey(phone) }

// ContactActionDeliveryEnabled requires a purpose-specific template. Ownership
// retains the existing phone-ownership sender and enablement, never an action OTP.
func (s *Service) ContactActionDeliveryEnabled(action string) bool {
	return s != nil && (action == "contact_change" && s.cfg.ContactChangeSender != nil || action == "contact_remove" && s.cfg.ContactRemovalSender != nil)
}

// ContactManagementPolicy shares the existing SMS spend, lockout and code bounds.
func (s *Service) ContactManagementPolicy(action, phone, sourceIP string) (LoginPolicy, error) {
	if !s.ContactActionDeliveryEnabled(action) && (action != "contact_ownership" || !s.DeliveryEnabled()) {
		return LoginPolicy{}, ErrDisabled
	}
	if !ContactDestinationSupported(phone) {
		return LoginPolicy{}, ErrInvalidPhone
	}
	return s.contactPolicy(phone, sourceIP)
}

// ContactManagementTTL exposes public bounds only while its sender is enabled.
func (s *Service) ContactManagementTTL(action string) time.Duration {
	if s.ContactActionDeliveryEnabled(action) || action == "contact_ownership" && s.DeliveryEnabled() {
		return s.cfg.CodeTTL
	}
	return 0
}

// DeliverContactManagementCode submits once, only after shared quota reservation
// and the coordinator's final admission check, without SQL locks or retry.
func (s *Service) DeliverContactManagementCode(ctx context.Context, action, phone, code string, deadline time.Time) error {
	if !ContactDestinationSupported(phone) {
		return ErrInvalidPhone
	}
	var sender Sender
	if s != nil {
		switch action {
		case "contact_change":
			sender = s.cfg.ContactChangeSender
		case "contact_remove":
			sender = s.cfg.ContactRemovalSender
		case "contact_ownership":
			sender = s.sender
		}
	}
	if sender == nil {
		return ErrDisabled
	}
	return deliverContactCode(ctx, sender, phone, code, deadline)
}
