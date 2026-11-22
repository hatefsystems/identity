// Package contactcode extends contact delivery with purpose-isolated proofs.
// It does not identify accounts, select contacts, or issue authentication sessions.
package contactcode

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

const (
	// ChannelEmail selects delivery to a canonical verified email address.
	ChannelEmail = "email"
	// ChannelSMS selects delivery using the existing SMS service and spend policy.
	ChannelSMS = "sms"
	// PurposeLogin isolates these proofs from signup and contact enrollment.
	PurposeLogin = "login"
	// PurposeAccountDeletion authorizes only an account-deletion request.
	PurposeAccountDeletion = "account_deletion"
	// PurposePasswordChange authorizes only a password replacement.
	PurposePasswordChange = "password_change"
	// PurposeFirstPasskey authorizes one first-passkey enrollment start only.
	PurposeFirstPasskey = "first_passkey_enrollment"
)

var (
	// ErrDisabled means the requested delivery channel is not enabled.
	ErrDisabled = errors.New("contactcode: channel disabled")
	// ErrInvalid rejects malformed input or an unbounded configuration.
	ErrInvalid = errors.New("contactcode: invalid input or policy")
	// ErrInvalidCode means one bounded verification attempt did not match.
	ErrInvalidCode = errors.New("contactcode: invalid code")
	// ErrNoActiveCode covers expired, consumed, malformed and foreign challenges.
	ErrNoActiveCode = errors.New("contactcode: no active challenge")
	// ErrLockedOut means the destination's shared verification lockout is active.
	ErrLockedOut = errors.New("contactcode: contact locked out")
	// ErrRateLimited means an atomic spend or capacity reservation was denied.
	ErrRateLimited = errors.New("contactcode: bounded quota exhausted")
	// ErrUnavailable means a dependency is absent or its state is malformed.
	ErrUnavailable = errors.New("contactcode: dependency unavailable")
	// ErrSendFailed means the transport explicitly rejected this delivery.
	ErrSendFailed = errors.New("contactcode: delivery rejected")
	// ErrOutcomeUnknown forbids retrying or granting authority from an uncertain result.
	ErrOutcomeUnknown = errors.New("contactcode: outcome unknown; restart explicitly")
)

// Sender submits once; nil is confirmed transport acceptance, not inbox delivery.
// Any unclassified failure is conservatively treated as an unknown outcome.
type Sender interface {
	SendCode(context.Context, string, string, time.Time) error
}

// Config bounds contact proof lifetime, attempts, shared capacity and spend.
type Config struct {
	// DeletionEmail must identify deletion, never reuse sign-in copy as a fallback.
	DeletionEmail           Sender
	PasswordChangeEmail     Sender
	FirstPasskeyEmail       Sender
	HashKey                 []byte
	CodeTTL                 time.Duration
	MaxAttempts             int
	MaxPending              int
	PerDestinationPerMinute int
	PerDestinationPerHour   int
	PerSourcePerHour        int
}

// Result is earned contact proof only. Recheck SQL account/version and the exact
// currently verified contact after consumption and before granting authority.
type Result struct {
	AccountID   uuid.UUID
	AuthVersion int64
	Channel     string
	Destination string
}

// DeletionBinding captures the authenticated browser authority before delivery.
type DeletionBinding struct {
	AccountID   uuid.UUID
	AuthVersion int64
	SessionID   string
	JKT         string
}

// Record freezes the whole operation context; only the attempt counter and
// confirmed-delivery marker are mutable in Redis.
type Record struct {
	Result
	Purpose        string
	JKT            string
	SessionID      string
	ContactBinding string
	Operation      string
	ExpiresAt      time.Time
	MaxAttempts    int
	LockoutTTL     time.Duration
	CodeHash       string
}

// Budget preserves the existing SMS sliding-window spend representation.
type Budget = smsotp.DeliveryBudget

// Store implementations must never automatically retry an uncertain mutation.
type Store interface {
	Reserve(context.Context, Record, []Budget, string, int) error
	Activate(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Consume(context.Context, Record, string, string) error
}

// Service delivers and consumes bound contact proofs, but never issues sessions.
type Service struct {
	cfg   Config
	store Store
	sms   *smsotp.Service
	email Sender
}

// New configures email and SMS independently. A disabled SMS service does not
// prevent email operation; SMTP is never required for SMS-only operation.
func New(cfg Config, store Store, sms *smsotp.Service, email Sender) (*Service, error) {
	if missing(store) {
		return nil, ErrUnavailable
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 3 * time.Minute
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 1000
	}
	if cfg.PerDestinationPerMinute == 0 {
		cfg.PerDestinationPerMinute = 1
	}
	if cfg.PerDestinationPerHour == 0 {
		cfg.PerDestinationPerHour = 5
	}
	if cfg.PerSourcePerHour == 0 {
		cfg.PerSourcePerHour = 10
	}
	if len(cfg.HashKey) < 32 || len(cfg.HashKey) > 64 || cfg.CodeTTL < time.Second || cfg.CodeTTL > 3*time.Minute || cfg.MaxAttempts < 1 || cfg.MaxAttempts > 3 || cfg.MaxPending < 1 || cfg.MaxPending > 10000 || cfg.PerDestinationPerMinute < 1 || cfg.PerDestinationPerMinute > 5 || cfg.PerDestinationPerHour < 1 || cfg.PerDestinationPerHour > 20 || cfg.PerSourcePerHour < 1 || cfg.PerSourcePerHour > 100 {
		return nil, ErrInvalid
	}
	if missing(email) {
		email = nil
	}
	if missing(cfg.DeletionEmail) {
		cfg.DeletionEmail = nil
	}
	if missing(cfg.PasswordChangeEmail) {
		cfg.PasswordChangeEmail = nil
	}
	if missing(cfg.FirstPasskeyEmail) {
		cfg.FirstPasskeyEmail = nil
	}
	cfg.HashKey = append([]byte(nil), cfg.HashKey...)
	return &Service{cfg, store, sms, email}, nil
}

func missing(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}

// ChannelEnabled reports public delivery configuration without account lookup.
func (s *Service) ChannelEnabled(channel string) bool {
	return s != nil && (channel == ChannelEmail && s.email != nil || channel == ChannelSMS && s.sms != nil && s.sms.DeliveryEnabled())
}

// ChallengeTTL is public channel policy only. The coordinator can freeze a
// conservative, uniform real/decoy response deadline before account lookup.
// Disabled/unknown channels return zero without touching Redis or contacts.
func (s *Service) ChallengeTTL(channel string) time.Duration {
	if !s.ChannelEnabled(channel) {
		return 0
	}
	if channel == ChannelSMS {
		return min(s.cfg.CodeTTL, s.sms.ContactLoginTTL())
	}
	return s.cfg.CodeTTL
}

// DeletionChannelEnabled requires an explicitly configured deletion transport.
func (s *Service) DeletionChannelEnabled(channel string) bool {
	return s.actionChannelEnabled(PurposeAccountDeletion, channel)
}

// PasswordChangeChannelEnabled never falls back to login or deletion delivery.
func (s *Service) PasswordChangeChannelEnabled(channel string) bool {
	return s.actionChannelEnabled(PurposePasswordChange, channel)
}

// FirstPasskeyChannelEnabled requires its own configured transport.
func (s *Service) FirstPasskeyChannelEnabled(channel string) bool {
	return s.actionChannelEnabled(PurposeFirstPasskey, channel)
}

func (s *Service) actionChannelEnabled(purpose, channel string) bool {
	if s == nil {
		return false
	}
	switch purpose {
	case PurposeAccountDeletion:
		return channel == ChannelEmail && s.cfg.DeletionEmail != nil || channel == ChannelSMS && s.sms != nil && s.sms.DeletionDeliveryEnabled()
	case PurposePasswordChange:
		return channel == ChannelEmail && s.cfg.PasswordChangeEmail != nil || channel == ChannelSMS && s.sms != nil && s.sms.PasswordChangeDeliveryEnabled()
	case PurposeFirstPasskey:
		return channel == ChannelEmail && s.cfg.FirstPasskeyEmail != nil || channel == ChannelSMS && s.sms != nil && s.sms.FirstPasskeyDeliveryEnabled()
	default:
		return false
	}
}

// DeletionChallengeTTL cannot exceed the channel lifetime or five minutes.
func (s *Service) DeletionChallengeTTL(channel string) time.Duration {
	return s.actionChallengeTTL(PurposeAccountDeletion, channel)
}

// PasswordChangeChallengeTTL retains the same stricter shared channel bounds.
func (s *Service) PasswordChangeChallengeTTL(channel string) time.Duration {
	return s.actionChallengeTTL(PurposePasswordChange, channel)
}

// FirstPasskeyChallengeTTL preserves the stricter shared contact-code ceiling.
func (s *Service) FirstPasskeyChallengeTTL(channel string) time.Duration {
	return s.actionChallengeTTL(PurposeFirstPasskey, channel)
}

func (s *Service) actionChallengeTTL(purpose, channel string) time.Duration {
	if !s.actionChannelEnabled(purpose, channel) {
		return 0
	}
	ttl := min(s.cfg.CodeTTL, 5*time.Minute)
	if channel == ChannelSMS {
		switch purpose {
		case PurposeFirstPasskey:
			ttl = min(ttl, s.sms.ContactFirstPasskeyTTL())
		case PurposePasswordChange:
			ttl = min(ttl, s.sms.ContactPasswordChangeTTL())
		default:
			ttl = min(ttl, s.sms.ContactDeletionTTL())
		}
	}
	return ttl
}

// Request reserves spend and capacity, then submits one bound code without retry.
// The caller must select and authorize the account's current verified destination.
func (s *Service) Request(ctx context.Context, account uuid.UUID, version int64, jkt, channel, destination, sourceIP string) (string, time.Time, error) {
	if !s.ChannelEnabled(channel) {
		return "", time.Time{}, ErrDisabled
	}
	return s.request(ctx, DeletionBinding{AccountID: account, AuthVersion: version, JKT: jkt}, PurposeLogin, channel, destination, "", sourceIP)
}

// RequestDeletion freezes the coordinator's hex HMAC of exact verified contact
// evidence. The coordinator must authorize the verified destination before calling.
func (s *Service) RequestDeletion(ctx context.Context, binding DeletionBinding, channel, destination, contactBinding, sourceIP string) (string, time.Time, error) {
	return s.requestAction(ctx, binding, PurposeAccountDeletion, channel, destination, contactBinding, sourceIP)
}

// RequestPasswordChange uses the exact verified-contact HMAC and live binding.
func (s *Service) RequestPasswordChange(ctx context.Context, binding DeletionBinding, channel, destination, contactBinding, sourceIP string) (string, time.Time, error) {
	return s.requestAction(ctx, binding, PurposePasswordChange, channel, destination, contactBinding, sourceIP)
}

// RequestFirstPasskey freezes the earning session and complete-contact MAC.
func (s *Service) RequestFirstPasskey(ctx context.Context, binding DeletionBinding, channel, destination, contactBinding, sourceIP string) (string, time.Time, error) {
	return s.requestAction(ctx, binding, PurposeFirstPasskey, channel, destination, contactBinding, sourceIP)
}

func (s *Service) requestAction(ctx context.Context, binding DeletionBinding, purpose, channel, destination, contactBinding, sourceIP string) (string, time.Time, error) {
	if !s.actionChannelEnabled(purpose, channel) {
		return "", time.Time{}, ErrDisabled
	}
	contact, err := hex.DecodeString(contactBinding)
	if !validDeletionBinding(binding) || err != nil || len(contact) != 32 || hex.EncodeToString(contact) != contactBinding {
		return "", time.Time{}, ErrInvalid
	}
	return s.request(ctx, binding, purpose, channel, destination, contactBinding, sourceIP)
}

func (s *Service) request(ctx context.Context, binding DeletionBinding, purpose, channel, destination, contactBinding, sourceIP string) (string, time.Time, error) {
	account, version, jkt := binding.AccountID, binding.AuthVersion, binding.JKT
	if account == uuid.Nil || version < 0 || !validCapability(jkt) || !validDestination(channel, destination) || len(sourceIP) == 0 || len(sourceIP) > 128 || strings.HasPrefix(ratelimit.Subnet(sourceIP), "invalid/") {
		return "", time.Time{}, ErrInvalid
	}
	ttl, attempts := s.ChallengeTTL(channel), s.cfg.MaxAttempts
	if purpose != PurposeLogin {
		ttl = s.actionChallengeTTL(purpose, channel)
	}
	lockKey := "contact:login:email:lock:" + s.digest("destination", channel, destination)
	lockTTL := 15 * time.Minute
	budgets := []Budget{
		{Key: "contact:login:destination:" + s.digest("destination", channel, destination) + ":1m", Limit: s.cfg.PerDestinationPerMinute, Window: time.Minute},
		{Key: "contact:login:destination:" + s.digest("destination", channel, destination) + ":1h", Limit: s.cfg.PerDestinationPerHour, Window: time.Hour},
		{Key: "contact:login:source:" + s.digest("source", channel, ratelimit.Subnet(sourceIP)), Limit: s.cfg.PerSourcePerHour, Window: time.Hour},
		// This fixed daily bucket bounds quota-key cardinality even when proofs
		// are consumed immediately against many distinct destinations/sources.
		{Key: "contact:login:global:1d", Limit: 10000, Window: 24 * time.Hour},
	}
	if channel == ChannelSMS {
		var p smsotp.LoginPolicy
		var err error
		switch purpose {
		case PurposeAccountDeletion:
			p, err = s.sms.ContactDeletionPolicy(destination, sourceIP)
		case PurposePasswordChange:
			p, err = s.sms.ContactPasswordChangePolicy(destination, sourceIP)
		case PurposeFirstPasskey:
			p, err = s.sms.ContactFirstPasskeyPolicy(destination, sourceIP)
		default:
			p, err = s.sms.ContactLoginPolicy(destination, sourceIP)
		}
		if err != nil {
			return "", time.Time{}, ErrDisabled
		}
		ttl, attempts = min(ttl, p.CodeTTL), min(attempts, p.MaxAttempts)
		lockKey, lockTTL = p.LockoutKey, p.LockoutTTL
		budgets = append(budgets, p.Budgets...)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	handle := base64.RawURLEncoding.EncodeToString(raw)
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	code := fmt.Sprintf("%06d", n.Int64())
	rec := Record{Result: Result{account, version, channel, destination}, Purpose: purpose, JKT: jkt, Operation: handle, ExpiresAt: time.Now().UTC().Add(ttl).Truncate(time.Millisecond), MaxAttempts: attempts, LockoutTTL: lockTTL}
	if purpose != PurposeLogin {
		rec.SessionID = binding.SessionID
		rec.ContactBinding = contactBinding
	}
	rec.CodeHash = s.hashCode(rec, code)
	if err := s.store.Reserve(ctx, rec, budgets, lockKey, s.cfg.MaxPending); err != nil {
		return "", time.Time{}, safeError(err)
	}
	if channel == ChannelSMS {
		switch purpose {
		case PurposeAccountDeletion:
			err = s.sms.DeliverContactDeletionCode(ctx, destination, code, rec.ExpiresAt)
		case PurposePasswordChange:
			err = s.sms.DeliverContactPasswordChangeCode(ctx, destination, code, rec.ExpiresAt)
		case PurposeFirstPasskey:
			err = s.sms.DeliverContactFirstPasskeyCode(ctx, destination, code, rec.ExpiresAt)
		default:
			err = s.sms.DeliverContactLoginCode(ctx, destination, code, rec.ExpiresAt)
		}
	} else {
		sender := s.email
		switch purpose {
		case PurposeAccountDeletion:
			sender = s.cfg.DeletionEmail
		case PurposePasswordChange:
			sender = s.cfg.PasswordChangeEmail
		case PurposeFirstPasskey:
			sender = s.cfg.FirstPasskeyEmail
		}
		deliveryCtx, cancel := context.WithDeadline(ctx, rec.ExpiresAt)
		err = sender.SendCode(deliveryCtx, destination, code, rec.ExpiresAt)
		cancel()
	}
	if err != nil {
		if errors.Is(err, ErrSendFailed) || errors.Is(err, smsotp.ErrSendFailed) {
			return "", time.Time{}, ErrSendFailed
		}
		// No handle escapes, no cleanup/refund mutation or resend is attempted.
		// The inactive reservation retains its original finite expiry/capacity.
		return "", time.Time{}, ErrOutcomeUnknown
	}
	if err := s.store.Activate(ctx, rec); err != nil {
		return "", time.Time{}, safeError(err)
	}
	return handle, rec.ExpiresAt, nil
}

// Verify atomically consumes a browser-bound proof once. Its Result still needs
// the coordinator's current SQL authority and verified-contact recheck.
func (s *Service) Verify(ctx context.Context, handle, jkt, code string) (Result, error) {
	if s == nil {
		return Result{}, ErrDisabled
	}
	if !validCapability(handle) || !validCapability(jkt) {
		return Result{}, ErrNoActiveCode
	}
	rec, err := s.store.Get(ctx, handle)
	if err != nil {
		return Result{}, safeError(err)
	}
	if !validRecord(rec) || rec.Operation != handle || rec.Purpose != PurposeLogin || rec.JKT != jkt || !s.ChannelEnabled(rec.Channel) {
		return Result{}, ErrNoActiveCode
	}
	if err := s.consume(ctx, rec, code); err != nil {
		return Result{}, err
	}
	return rec.Result, nil
}

// VerifyDeletion rejects all foreign bindings before spending an attempt. The
// full frozen record, including its original deadline, needs a SQL recheck.
func (s *Service) VerifyDeletion(ctx context.Context, binding DeletionBinding, handle, code string) (Record, error) {
	return s.verifyAction(ctx, binding, PurposeAccountDeletion, handle, code)
}

// VerifyPasswordChange rejects foreign purposes/bindings without spending attempts.
func (s *Service) VerifyPasswordChange(ctx context.Context, binding DeletionBinding, handle, code string) (Record, error) {
	return s.verifyAction(ctx, binding, PurposePasswordChange, handle, code)
}

// VerifyFirstPasskey rejects foreign purposes before spending an attempt.
func (s *Service) VerifyFirstPasskey(ctx context.Context, binding DeletionBinding, handle, code string) (Record, error) {
	return s.verifyAction(ctx, binding, PurposeFirstPasskey, handle, code)
}

func (s *Service) verifyAction(ctx context.Context, binding DeletionBinding, purpose, handle, code string) (Record, error) {
	if s == nil {
		return Record{}, ErrDisabled
	}
	if !validDeletionBinding(binding) || !validCapability(handle) {
		return Record{}, ErrNoActiveCode
	}
	rec, err := s.store.Get(ctx, handle)
	if err != nil {
		return Record{}, safeError(err)
	}
	if !validRecord(rec) || rec.Operation != handle || rec.Purpose != purpose || rec.AccountID != binding.AccountID || rec.AuthVersion != binding.AuthVersion || rec.SessionID != binding.SessionID || rec.JKT != binding.JKT || !s.actionChannelEnabled(purpose, rec.Channel) {
		return Record{}, ErrNoActiveCode
	}
	if err := s.consume(ctx, rec, code); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *Service) consume(ctx context.Context, rec Record, code string) error {
	if !validCode(code) {
		code = "invalid"
	}
	lockKey := "contact:login:email:lock:" + s.digest("destination", rec.Channel, rec.Destination)
	if rec.Channel == ChannelSMS {
		var p smsotp.LoginPolicy
		var err error
		switch rec.Purpose {
		case PurposeAccountDeletion:
			p, err = s.sms.ContactDeletionPolicy(rec.Destination, "")
		case PurposePasswordChange:
			p, err = s.sms.ContactPasswordChangePolicy(rec.Destination, "")
		case PurposeFirstPasskey:
			p, err = s.sms.ContactFirstPasskeyPolicy(rec.Destination, "")
		default:
			p, err = s.sms.ContactLoginPolicy(rec.Destination, "")
		}
		if err != nil {
			return ErrDisabled
		}
		lockKey = p.LockoutKey
	}
	if err := s.store.Consume(ctx, rec, s.hashCode(rec, code), lockKey); err != nil {
		return safeError(err)
	}
	return nil
}

func safeError(err error) error {
	for _, known := range []error{ErrDisabled, ErrInvalid, ErrInvalidCode, ErrNoActiveCode, ErrLockedOut, ErrRateLimited, ErrUnavailable, ErrOutcomeUnknown} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrOutcomeUnknown
}

func validCapability(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func validCode(code string) bool {
	return len(code) == 6 && strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func validDestination(channel, destination string) bool {
	if len(destination) == 0 || len(destination) > 254 {
		return false
	}
	if channel == ChannelEmail {
		return emailaddress.ValidCanonicalMailbox(destination)
	}
	phone, err := smsotp.NormalizePhone(destination)
	return channel == ChannelSMS && err == nil && phone == destination
}

func validRecord(rec Record) bool {
	raw, err := hex.DecodeString(rec.CodeHash)
	purposeValid := rec.Purpose == PurposeLogin && rec.SessionID == "" && rec.ContactBinding == ""
	if rec.Purpose == PurposeAccountDeletion || rec.Purpose == PurposePasswordChange || rec.Purpose == PurposeFirstPasskey {
		contact, contactErr := hex.DecodeString(rec.ContactBinding)
		purposeValid = validDeletionBinding(DeletionBinding{rec.AccountID, rec.AuthVersion, rec.SessionID, rec.JKT}) && contactErr == nil && len(contact) == 32 && hex.EncodeToString(contact) == rec.ContactBinding
	}
	return rec.AccountID != uuid.Nil && rec.AuthVersion >= 0 && purposeValid && validCapability(rec.JKT) && validCapability(rec.Operation) && validDestination(rec.Channel, rec.Destination) && !rec.ExpiresAt.IsZero() && rec.ExpiresAt.Equal(rec.ExpiresAt.Truncate(time.Millisecond)) && rec.MaxAttempts >= 1 && rec.MaxAttempts <= 3 && rec.LockoutTTL >= 15*time.Minute && rec.LockoutTTL <= 24*time.Hour && err == nil && len(raw) == 32 && hex.EncodeToString(raw) == rec.CodeHash
}

func validDeletionBinding(binding DeletionBinding) bool {
	return binding.AccountID != uuid.Nil && binding.AuthVersion >= 0 && validCapability(binding.JKT) && len(binding.SessionID) > 0 && len(binding.SessionID) <= 128 && strings.IndexFunc(binding.SessionID, func(r rune) bool { return r < 33 || r > 126 }) < 0
}

func (s *Service) hashCode(rec Record, code string) string {
	rec.CodeHash = ""
	bound, _ := json.Marshal(rec)
	mac := hmac.New(sha256.New, s.cfg.HashKey)
	_, _ = mac.Write([]byte("contactcode:v1:code\x00"))
	_, _ = mac.Write(bound)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) digest(kind, channel, value string) string {
	mac := hmac.New(sha256.New, s.cfg.HashKey)
	_, _ = mac.Write([]byte("contactcode:v1:" + kind + "\x00" + channel + "\x00" + value))
	return hex.EncodeToString(mac.Sum(nil))
}
