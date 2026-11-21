// Package contactcode extends contact delivery with purpose-isolated login proofs.
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

// Config bounds login proof lifetime, attempts, pending capacity and spend.
type Config struct {
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

// Record freezes the whole operation context; only the attempt counter and
// confirmed-delivery marker are mutable in Redis.
type Record struct {
	Result
	Purpose     string
	JKT         string
	Operation   string
	ExpiresAt   time.Time
	MaxAttempts int
	LockoutTTL  time.Duration
	CodeHash    string
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

// Request reserves spend and capacity, then submits one bound code without retry.
// The caller must select and authorize the account's current verified destination.
func (s *Service) Request(ctx context.Context, account uuid.UUID, version int64, jkt, channel, destination, sourceIP string) (string, time.Time, error) {
	if !s.ChannelEnabled(channel) {
		return "", time.Time{}, ErrDisabled
	}
	if account == uuid.Nil || version < 0 || !validCapability(jkt) || !validDestination(channel, destination) || len(sourceIP) == 0 || len(sourceIP) > 128 || strings.HasPrefix(ratelimit.Subnet(sourceIP), "invalid/") {
		return "", time.Time{}, ErrInvalid
	}
	ttl, attempts := s.ChallengeTTL(channel), s.cfg.MaxAttempts
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
		p, err := s.sms.ContactLoginPolicy(destination, sourceIP)
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
	rec := Record{Result: Result{account, version, channel, destination}, Purpose: PurposeLogin, JKT: jkt, Operation: handle, ExpiresAt: time.Now().UTC().Add(ttl).Truncate(time.Millisecond), MaxAttempts: attempts, LockoutTTL: lockTTL}
	rec.CodeHash = s.hashCode(rec, code)
	if err := s.store.Reserve(ctx, rec, budgets, lockKey, s.cfg.MaxPending); err != nil {
		return "", time.Time{}, safeError(err)
	}
	if channel == ChannelSMS {
		err = s.sms.DeliverContactLoginCode(ctx, destination, code, rec.ExpiresAt)
	} else {
		deliveryCtx, cancel := context.WithDeadline(ctx, rec.ExpiresAt)
		err = s.email.SendCode(deliveryCtx, destination, code, rec.ExpiresAt)
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
	if !validCode(code) {
		code = "invalid"
	}
	lockKey := "contact:login:email:lock:" + s.digest("destination", rec.Channel, rec.Destination)
	if rec.Channel == ChannelSMS {
		p, err := s.sms.ContactLoginPolicy(rec.Destination, "")
		if err != nil {
			return Result{}, ErrDisabled
		}
		lockKey = p.LockoutKey
	}
	if err := s.store.Consume(ctx, rec, s.hashCode(rec, code), lockKey); err != nil {
		return Result{}, safeError(err)
	}
	return rec.Result, nil
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
	return rec.AccountID != uuid.Nil && rec.AuthVersion >= 0 && rec.Purpose == PurposeLogin && validCapability(rec.JKT) && validCapability(rec.Operation) && validDestination(rec.Channel, rec.Destination) && !rec.ExpiresAt.IsZero() && rec.ExpiresAt.Equal(rec.ExpiresAt.Truncate(time.Millisecond)) && rec.MaxAttempts >= 1 && rec.MaxAttempts <= 3 && rec.LockoutTTL >= 15*time.Minute && rec.LockoutTTL <= 24*time.Hour && err == nil && len(raw) == 32 && hex.EncodeToString(raw) == rec.CodeHash
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
