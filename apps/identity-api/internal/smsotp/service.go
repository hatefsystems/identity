// Package smsotp provides purpose-bound SMS proofs and fenced phone mutations.
package smsotp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// UserStore guarantees its mutations lock and recheck captured authority.
// NewUserStore is the production implementation; tests can inject bounded fakes.
type UserStore interface {
	GetUserByID(context.Context, uuid.UUID) (db.User, error)
	SetPhoneIfCurrent(context.Context, uuid.UUID, int64, []byte, string) error
	RemovePhoneIfCurrent(context.Context, uuid.UUID, int64) (bool, error)
}

// Encryptor encrypts phone data before persistence.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
}

// BlindIndexer computes the exact-match index for a normalized phone.
type BlindIndexer interface{ Compute(string) string }

// Config defines bounded OTP policy and explicit signup delivery budgets.
type Config struct {
	CodeTTL           time.Duration
	MaxAttempts       int
	LockoutTTL        time.Duration
	PerPhonePerMinute int
	PerPhonePerHour   int
	PerSubnetPerHour  int
	HashPepper        []byte
	// Signup requires explicit, finite spend and concurrent challenge budgets.
	SignupEnabled    bool
	GlobalPerDay     int
	MaxPendingSignup int
}

// Service delivers purpose-bound OTPs and performs authorized phone mutations.
type Service struct {
	users     UserStore
	encryptor Encryptor
	indexer   BlindIndexer
	limiter   ratelimit.Limiter
	otps      OTPStore
	sender    Sender
	cfg       Config
}

const verificationIDBytes = 32

// NewDisabled constructs DB-only phone removal without delivery collaborators.
func NewDisabled(users UserStore) (*Service, error) {
	if missingDependency(users) {
		return nil, ErrUnavailable
	}
	return &Service{users: users}, nil
}

// New enables delivery, never falling back to log delivery or missing secrets.
func New(cfg Config, users UserStore, enc Encryptor, idx BlindIndexer, limiter ratelimit.Limiter, otps OTPStore, sender Sender) (*Service, error) {
	if missingDependency(users) || missingDependency(enc) || missingDependency(idx) || missingDependency(limiter) || missingDependency(otps) || missingDependency(sender) {
		return nil, ErrUnavailable
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = 3 * time.Minute
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.LockoutTTL == 0 {
		cfg.LockoutTTL = 15 * time.Minute
	}
	if cfg.PerPhonePerMinute == 0 {
		cfg.PerPhonePerMinute = 1
	}
	if cfg.PerPhonePerHour == 0 {
		cfg.PerPhonePerHour = 5
	}
	if cfg.PerSubnetPerHour == 0 {
		cfg.PerSubnetPerHour = 10
	}
	if cfg.CodeTTL < time.Second || cfg.CodeTTL > 3*time.Minute || cfg.MaxAttempts < 1 || cfg.MaxAttempts > 3 || cfg.LockoutTTL < 15*time.Minute || cfg.LockoutTTL > 24*time.Hour || cfg.PerPhonePerMinute < 1 || cfg.PerPhonePerMinute > 5 || cfg.PerPhonePerHour < 1 || cfg.PerPhonePerHour > 20 || cfg.PerSubnetPerHour < 1 || cfg.PerSubnetPerHour > 100 || len(cfg.HashPepper) < 16 || len(cfg.HashPepper) > 64 || cfg.GlobalPerDay < 0 || cfg.GlobalPerDay > 100000 || cfg.MaxPendingSignup < 0 || cfg.MaxPendingSignup > 10000 || cfg.SignupEnabled && (cfg.GlobalPerDay == 0 || cfg.MaxPendingSignup == 0) {
		return nil, errors.New("smsotp: invalid bounded policy")
	}
	cfg.HashPepper = append([]byte(nil), cfg.HashPepper...)
	return &Service{users: users, encryptor: enc, indexer: idx, limiter: limiter, otps: otps, sender: sender, cfg: cfg}, nil
}
func missingDependency(value any) bool {
	return value == nil || (reflect.ValueOf(value).Kind() == reflect.Pointer && reflect.ValueOf(value).IsNil())
}

// DeliveryEnabled reports whether this service permits code sending and verification.
func (s *Service) DeliveryEnabled() bool { return s != nil && s.sender != nil }

// SendCode issues a challenge bound to the current account authorization and session.
func (s *Service) SendCode(ctx context.Context, userID uuid.UUID, authVersion int64, sessionID, rawPhone, clientIP string) (string, error) {
	if !s.DeliveryEnabled() {
		return "", ErrDisabled
	}
	if _, err := s.loadUser(ctx, userID, authVersion); err != nil {
		return "", err
	}
	return s.send(ctx, OTPBinding{PurposeEnrollment, userID.String(), sessionID}, rawPhone, clientIP, s.cfg.CodeTTL)
}

// SendSignupCode uses the attempt's UUID/JKT, never an invented account/session.
// The caller must authorize the durable attempt and verified email first, freeze
// its phone, and save this reference/revision. Resends do not extend its deadline.
func (s *Service) SendSignupCode(ctx context.Context, attemptID uuid.UUID, jkt, phone, clientIP string, expiresAt time.Time) (string, error) {
	if !s.DeliveryEnabled() || !s.cfg.SignupEnabled {
		return "", ErrDisabled
	}
	ttl := time.Until(expiresAt)
	if ttl > s.cfg.CodeTTL {
		ttl = s.cfg.CodeTTL
	}
	if ttl < time.Second {
		return "", ErrNoActiveCode
	}
	return s.send(ctx, OTPBinding{PurposeSignup, attemptID.String(), jkt}, phone, clientIP, ttl)
}
func (s *Service) send(ctx context.Context, binding OTPBinding, rawPhone, clientIP string, ttl time.Duration) (string, error) {
	if !validBinding(binding) {
		return "", ErrNoActiveCode
	}
	phone, err := NormalizePhone(rawPhone)
	if err != nil {
		return "", err
	}
	locked, err := s.otps.IsLockedOut(ctx, phone)
	if err != nil {
		return "", ErrUnavailable
	}
	if locked {
		return "", ErrLockedOut
	}
	for _, budget := range []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{subnetRateKey(ratelimit.Subnet(clientIP)), s.cfg.PerSubnetPerHour, time.Hour},
		{phoneRateKey(phone, "1m"), s.cfg.PerPhonePerMinute, time.Minute},
		{phoneRateKey(phone, "1h"), s.cfg.PerPhonePerHour, time.Hour},
		{"rate:otp:global:1d", s.cfg.GlobalPerDay, 24 * time.Hour},
	} {
		if budget.limit == 0 {
			continue
		}
		allowed, err := s.limiter.Allow(ctx, budget.key, budget.limit, budget.window)
		if err != nil {
			return "", ErrUnavailable
		}
		if !allowed {
			return "", ErrRateLimited
		}
	}
	code, err := generateCode()
	if err != nil {
		return "", ErrUnavailable
	}
	id, err := generateVerificationID()
	if err != nil {
		return "", ErrUnavailable
	}
	record := OTPRecord{OTPBinding: binding, Phone: phone, CodeHash: s.hashCode(phone, code)}
	if err := s.otps.Store(ctx, id, record, ttl, s.cfg.MaxPendingSignup); err != nil {
		return "", safeStoreError(err)
	}
	if err := s.sender.SendCode(ctx, phone, code); err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = s.otps.Delete(cleanup, id)
		// Even uncertain delivery cannot expose its capability or claim ownership.
		reason := SendFailureReason(err)
		if reason == "unavailable" {
			return "", ErrSendFailed
		}
		return "", &sendError{reason: reason}
	}
	return id, nil
}

// Verify consumes the bound proof before a locked, auth-version-fenced phone write.
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, authVersion int64, sessionID, id, code string) error {
	if !s.DeliveryEnabled() {
		return ErrDisabled
	}
	if _, err := s.loadUser(ctx, userID, authVersion); err != nil {
		return err
	}
	phone, err := s.consume(ctx, OTPBinding{PurposeEnrollment, userID.String(), sessionID}, "", id, code)
	if err != nil {
		return err
	}
	encrypted, err := s.encryptor.Encrypt(ctx, []byte(phone))
	if err != nil || len(encrypted) == 0 {
		return errors.Join(ErrRestartRequired, ErrEncryptFailed)
	}
	err = s.users.SetPhoneIfCurrent(ctx, userID, authVersion, encrypted, s.indexer.Compute(phone))
	if err != nil {
		for _, known := range []error{ErrStaleSession, ErrAccountNotActive, ErrUserNotFound} {
			if errors.Is(err, known) {
				return known
			}
		}
		return ErrRestartRequired
	}
	return nil
}

// ConsumeSignupCode proves only the frozen phone for this exact attempt/JKT.
// Persist proof under the locked SQL attempt and recheck revision/expiry. On SQL
// failure inspect durable state or require a fresh proof; never restore the OTP.
func (s *Service) ConsumeSignupCode(ctx context.Context, attemptID uuid.UUID, jkt, phone, id, code string) error {
	if !s.DeliveryEnabled() || !s.cfg.SignupEnabled {
		return ErrDisabled
	}
	canonical, err := NormalizePhone(phone)
	if err != nil || canonical != phone {
		return ErrInvalidPhone
	}
	_, err = s.consume(ctx, OTPBinding{PurposeSignup, attemptID.String(), jkt}, phone, id, code)
	return err
}
func (s *Service) consume(ctx context.Context, binding OTPBinding, phone, id, code string) (string, error) {
	if !validBinding(binding) || !validVerificationID(id) {
		return "", ErrNoActiveCode
	}
	rec, err := s.otps.Get(ctx, id)
	if err != nil {
		return "", safeStoreError(err)
	}
	if !validRecord(rec) || rec.OTPBinding != binding || phone != "" && rec.Phone != phone {
		return "", ErrNoActiveCode
	}
	// Non-six-digit submissions still burn one attempt, but are never hashed as
	// a potentially valid code. The candidate remains a fixed-length digest.
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		code = "invalid"
	}
	if err := s.otps.Consume(ctx, id, rec, s.hashCode(rec.Phone, code), s.cfg.MaxAttempts, s.cfg.LockoutTTL); err != nil {
		return "", safeStoreError(err)
	}
	return rec.Phone, nil
}

// RemovePhone performs an authorized conditional removal and reports an actual change.
func (s *Service) RemovePhone(ctx context.Context, id uuid.UUID, authVersion int64) (bool, error) {
	if s == nil || s.users == nil {
		return false, ErrUnavailable
	}
	if id == uuid.Nil || authVersion < 0 {
		return false, ErrStaleSession
	}
	changed, err := s.users.RemovePhoneIfCurrent(ctx, id, authVersion)
	if err != nil {
		for _, known := range []error{ErrStaleSession, ErrAccountNotActive, ErrUserNotFound} {
			if errors.Is(err, known) {
				return false, known
			}
		}
		return false, ErrUnavailable
	}
	return changed, nil
}
func (s *Service) loadUser(ctx context.Context, id uuid.UUID, version int64) (db.User, error) {
	if id == uuid.Nil || version < 0 {
		return db.User{}, ErrStaleSession
	}
	u, err := s.users.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, ErrUserNotFound
	}
	if err != nil {
		return db.User{}, ErrUnavailable
	}
	if u.DeletedAt.Valid || u.Status != "active" {
		return db.User{}, ErrAccountNotActive
	}
	if u.AuthVersion != version {
		return db.User{}, ErrStaleSession
	}
	return u, nil
}
func safeStoreError(err error) error {
	for _, known := range []error{ErrNoActiveCode, ErrInvalidCode, ErrLockedOut, ErrRateLimited} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}
func generateVerificationID() (string, error) {
	raw := make([]byte, verificationIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func validVerificationID(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == verificationIDBytes && base64.RawURLEncoding.EncodeToString(raw) == s
}
func (s *Service) hashCode(phone, code string) string {
	mac := hmac.New(sha256.New, s.cfg.HashPepper)
	_, _ = mac.Write([]byte(phone))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}
func phoneRateKey(phone, window string) string { return "rate:otp:phone:" + phone + ":" + window }
func subnetRateKey(subnet string) string       { return "rate:otp:subnet:" + subnet }
