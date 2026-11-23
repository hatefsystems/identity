package contactcode

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

// OwnershipBinding identifies a frozen SQL attempt's exact new destination.
// New ownership is never an action authorization capability.
type OwnershipBinding struct {
	DeletionBinding
	Target      string
	Destination string
}

// PreparedOwnership is an in-memory one-shot handoff. Only its public handle and
// absolute deadline escape; neither preparation nor clearing touches Redis/SQL.
type PreparedOwnership struct {
	mu          sync.Mutex
	service     *Service
	handle      string
	deadline    time.Time
	record      Record
	code        []byte
	budgets     []Budget
	lockKey     string
	destination string
}

// Handle is the caller's preallocated canonical public handle, not release permission.
func (p *PreparedOwnership) Handle() string { return p.handle }

// ExpiresAt is the immutable absolute SQL/code handoff deadline.
func (p *PreparedOwnership) ExpiresAt() time.Time { return p.deadline }

func (p *PreparedOwnership) String() string { return "contactcode: prepared code (private)" }

// GoString prevents detailed diagnostics from exposing private prepared fields.
func (p *PreparedOwnership) GoString() string { return p.String() }

// Clear also makes an undispatched preparation unusable. Call on SQL failures.
func (p *PreparedOwnership) Clear() {
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.clear()
	}
}

func (p *PreparedOwnership) clear() {
	clear(p.code)
	p.code, p.budgets, p.service = nil, nil, nil
	p.record, p.lockKey = Record{}, ""
	p.destination = ""
}

func contactAction(action string) bool {
	return action == PurposeContactChange || action == PurposeContactRemove
}

func contactTarget(target string) bool { return target == "email" || target == "phone" }

func ownershipChannel(target string) string {
	if target == "email" {
		return ChannelEmail
	}
	if target == "phone" {
		return ChannelSMS
	}
	return ""
}

// OwnershipDestinationSupported validates canonical bytes and current provider
// recipient policy before a caller spends any strong or SQL authority.
func OwnershipDestinationSupported(target, destination string) bool {
	return contactTarget(target) && validDestination(ownershipChannel(target), destination) && (target != "phone" || smsotp.ContactDestinationSupported(destination))
}

// ContactChannelEnabled requires an action-specific sender, not login copy.
func (s *Service) ContactChannelEnabled(action, channel string) bool {
	if s == nil || !contactAction(action) {
		return false
	}
	if channel == ChannelSMS {
		return s.sms != nil && s.sms.ContactActionDeliveryEnabled(action)
	}
	return channel == ChannelEmail && (action == PurposeContactChange && s.cfg.ContactChangeEmail != nil || action == PurposeContactRemove && s.cfg.ContactRemovalEmail != nil)
}

// OwnershipChannelEnabled independently admits email or existing SMS ownership.
func (s *Service) OwnershipChannelEnabled(channel string) bool {
	return s != nil && (channel == ChannelEmail && s.cfg.ContactOwnershipEmail != nil || channel == ChannelSMS && s.sms != nil && s.sms.DeliveryEnabled())
}

// ContactChallengeTTL exposes only the enabled action's shared channel ceiling.
func (s *Service) ContactChallengeTTL(action, channel string) time.Duration {
	if !s.ContactChannelEnabled(action, channel) {
		return 0
	}
	ttl := s.cfg.CodeTTL
	if channel == ChannelSMS {
		ttl = min(ttl, s.sms.ContactManagementTTL(action))
	}
	return ttl
}

// OwnershipTTL retains the stricter at-most-three-minute channel ceiling.
func (s *Service) OwnershipTTL(channel string) time.Duration {
	if !s.OwnershipChannelEnabled(channel) {
		return 0
	}
	ttl := s.cfg.CodeTTL
	if channel == ChannelSMS {
		ttl = min(ttl, s.sms.ContactManagementTTL(PurposeContactOwnership))
	}
	return ttl
}

// PrepareOwnership accepts the externally allocated canonical SQL attempt handle
// and never extends the supplied absolute deadline, even when dispatch is delayed.
func (s *Service) PrepareOwnership(ctx context.Context, binding OwnershipBinding, handle string, deadline time.Time, sourceIP string) (*PreparedOwnership, error) {
	if !OwnershipDestinationSupported(binding.Target, binding.Destination) {
		return nil, ErrInvalid
	}
	return s.prepareContact(ctx, binding.DeletionBinding, PurposeContactOwnership, PurposeContactChange, binding.Target, ownershipChannel(binding.Target), binding.Destination, "", handle, deadline, sourceIP)
}

func (s *Service) prepareContact(ctx context.Context, binding DeletionBinding, purpose, action, target, channel, destination, contactMAC, handle string, deadline time.Time, sourceIP string) (*PreparedOwnership, error) {
	if s == nil || purpose == PurposeContactOwnership && !s.OwnershipChannelEnabled(channel) || purpose != PurposeContactOwnership && !s.ContactChannelEnabled(action, channel) {
		return nil, ErrDisabled
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrUnavailable
	}
	if !validDeletionBinding(binding) || !contactAction(action) || !contactTarget(target) || !validCapability(handle) || !validDestination(channel, destination) || len(sourceIP) == 0 || len(sourceIP) > 128 || strings.HasPrefix(ratelimit.Subnet(sourceIP), "invalid/") {
		return nil, ErrInvalid
	}
	ttl := s.ContactChallengeTTL(action, channel)
	if purpose == PurposeContactOwnership {
		ttl = s.OwnershipTTL(channel)
	}
	now := time.Now().UTC()
	deadline = minTime(deadline, now.Add(ttl)).UTC().Truncate(time.Millisecond)
	if !now.Before(deadline) {
		return nil, ErrNoActiveCode
	}
	rec := Record{Result: Result{binding.AccountID, binding.AuthVersion, channel, destination}, Purpose: purpose, Action: action, Target: target, SessionID: binding.SessionID, JKT: binding.JKT, Operation: handle, ContactBinding: contactMAC, ExpiresAt: deadline, MaxAttempts: s.cfg.MaxAttempts, LockoutTTL: 15 * time.Minute}
	lockKey := "contact:login:email:lock:" + s.digest("destination", channel, destination)
	budgets := []Budget{
		{Key: "contact:login:destination:" + s.digest("destination", channel, destination) + ":1m", Limit: s.cfg.PerDestinationPerMinute, Window: time.Minute},
		{Key: "contact:login:destination:" + s.digest("destination", channel, destination) + ":1h", Limit: s.cfg.PerDestinationPerHour, Window: time.Hour},
		{Key: "contact:login:source:" + s.digest("source", channel, ratelimit.Subnet(sourceIP)), Limit: s.cfg.PerSourcePerHour, Window: time.Hour},
		{Key: "contact:login:global:1d", Limit: 10000, Window: 24 * time.Hour},
		// One shared account budget across both targets, actions and ownership;
		// freshly authorized replacement does not reset this spend.
		{Key: "contact:login:account:" + s.digest("account", "", binding.AccountID.String()) + ":1h", Limit: s.cfg.PerDestinationPerHour, Window: time.Hour},
	}
	if channel == ChannelSMS {
		policyPurpose := action
		if purpose == PurposeContactOwnership {
			policyPurpose = purpose
		}
		policy, err := s.sms.ContactManagementPolicy(policyPurpose, destination, sourceIP)
		if err != nil {
			return nil, ErrInvalid
		}
		rec.MaxAttempts, rec.LockoutTTL, lockKey = min(rec.MaxAttempts, policy.MaxAttempts), policy.LockoutTTL, policy.LockoutKey
		budgets = append(budgets, policy.Budgets...)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, ErrUnavailable
	}
	code := []byte(fmt.Sprintf("%06d", n.Int64()))
	if purpose == PurposeContactOwnership {
		rec.DestinationMAC = s.digest("ownership:destination", channel, destination)
		rec.Destination = ""
	}
	rec.CodeHash = s.hashCode(rec, string(code))
	if !validRecord(rec) {
		clear(code)
		return nil, ErrInvalid
	}
	return &PreparedOwnership{service: s, handle: handle, deadline: deadline, record: rec, code: code, budgets: budgets, lockKey: lockKey, destination: destination}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// DispatchOwnership must follow acknowledged SQL start commit. Shared quota and
// capacity are reserved first; finalAdmission must recheck frozen pending/session
// state without retaining locks across provider I/O. Nothing is refunded/retried.
func (s *Service) DispatchOwnership(ctx context.Context, p *PreparedOwnership, finalAdmission func(context.Context) error) error {
	if p == nil || finalAdmission == nil {
		if p != nil {
			p.Clear()
		}
		return ErrInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.clear()
	if s == nil || p.service != s || len(p.code) != 6 || !time.Now().Before(p.deadline) {
		return ErrNoActiveCode
	}
	if err := s.store.Reserve(ctx, p.record, p.budgets, p.lockKey, s.cfg.MaxPending); err != nil {
		return safeError(err)
	}
	if err := finalAdmission(ctx); err != nil {
		return err
	}
	if ctx.Err() != nil || !time.Now().Before(p.deadline) {
		return ErrNoActiveCode
	}
	var err error
	if p.record.Channel == ChannelSMS {
		purpose := p.record.Action
		if p.record.Purpose == PurposeContactOwnership {
			purpose = p.record.Purpose
		}
		err = s.sms.DeliverContactManagementCode(ctx, purpose, p.destination, string(p.code), p.deadline)
	} else {
		sender := s.cfg.ContactOwnershipEmail
		switch p.record.Purpose {
		case PurposeContactChange:
			sender = s.cfg.ContactChangeEmail
		case PurposeContactRemove:
			sender = s.cfg.ContactRemovalEmail
		}
		deliveryCtx, cancel := context.WithDeadline(ctx, p.deadline)
		err = sender.SendCode(deliveryCtx, p.destination, string(p.code), p.deadline)
		cancel()
	}
	if err != nil {
		if errors.Is(err, ErrSendFailed) || errors.Is(err, smsotp.ErrSendFailed) {
			return ErrSendFailed
		}
		return ErrOutcomeUnknown
	}
	if !time.Now().Before(p.deadline) || s.store.Activate(ctx, p.record) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// RequestContactAction uses a frozen absolute authority ceiling and the same
// quota -> final admission -> submission boundary as new ownership.
func (s *Service) RequestContactAction(ctx context.Context, binding DeletionBinding, action, target, channel, destination, contactMAC string, deadline time.Time, sourceIP string, finalAdmission func(context.Context) error) (string, time.Time, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	handle := base64.RawURLEncoding.EncodeToString(raw[:])
	p, err := s.prepareContact(ctx, binding, action, action, target, channel, destination, contactMAC, handle, deadline, sourceIP)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.DispatchOwnership(ctx, p, finalAdmission); err != nil {
		return "", time.Time{}, err
	}
	return p.Handle(), p.ExpiresAt(), nil
}

func validContactRecord(rec Record) bool {
	if !validDeletionBinding(DeletionBinding{rec.AccountID, rec.AuthVersion, rec.SessionID, rec.JKT}) || !contactTarget(rec.Target) {
		return false
	}
	if rec.Purpose == PurposeContactOwnership {
		mac, err := hex.DecodeString(rec.DestinationMAC)
		return rec.Action == PurposeContactChange && rec.ContactBinding == "" && rec.Channel == ownershipChannel(rec.Target) && rec.Destination == "" && err == nil && len(mac) == 32 && hex.EncodeToString(mac) == rec.DestinationMAC
	}
	mac, err := hex.DecodeString(rec.ContactBinding)
	return contactAction(rec.Purpose) && rec.Action == rec.Purpose && rec.DestinationMAC == "" && err == nil && len(mac) == 32 && hex.EncodeToString(mac) == rec.ContactBinding && (rec.Channel != ChannelSMS || smsotp.ContactDestinationSupported(rec.Destination))
}

// VerifyContactAction retains finite readers independently of send switches.
func (s *Service) VerifyContactAction(ctx context.Context, binding DeletionBinding, handle, code, action string) (Record, error) {
	if !contactAction(action) {
		return Record{}, ErrInvalid
	}
	return s.verifyContact(ctx, binding, handle, code, action, "", "")
}

// VerifyOwnership compares exact frozen subject/destination bindings before attempts.
func (s *Service) VerifyOwnership(ctx context.Context, binding OwnershipBinding, handle, code string) (Record, error) {
	if !OwnershipDestinationSupported(binding.Target, binding.Destination) {
		return Record{}, ErrNoActiveCode
	}
	return s.verifyContact(ctx, binding.DeletionBinding, handle, code, PurposeContactOwnership, binding.Target, binding.Destination)
}

func (s *Service) verifyContact(ctx context.Context, binding DeletionBinding, handle, code, purpose, target, destination string) (Record, error) {
	if s == nil {
		return Record{}, ErrUnavailable
	}
	if !validCode(code) {
		return Record{}, ErrInvalid
	}
	if !validDeletionBinding(binding) || !validCapability(handle) {
		return Record{}, ErrNoActiveCode
	}
	rec, err := s.store.Get(ctx, handle)
	if err != nil {
		return Record{}, safeError(err)
	}
	if !validRecord(rec) || rec.Operation != handle || rec.Purpose != purpose || rec.AccountID != binding.AccountID || rec.AuthVersion != binding.AuthVersion || rec.SessionID != binding.SessionID || rec.JKT != binding.JKT || target != "" && (rec.Target != target || !hmac.Equal([]byte(rec.DestinationMAC), []byte(s.digest("ownership:destination", rec.Channel, destination)))) {
		return Record{}, ErrNoActiveCode
	}
	if rec.Purpose != PurposeContactOwnership {
		destination = rec.Destination
	}
	lockKey := "contact:login:email:lock:" + s.digest("destination", rec.Channel, destination)
	if rec.Channel == ChannelSMS {
		lockKey = smsotp.ContactLockoutKey(destination)
	}
	if err := s.store.Consume(ctx, rec, s.hashCode(rec, code), lockKey); err != nil {
		return Record{}, safeError(err)
	}
	return rec, nil
}
