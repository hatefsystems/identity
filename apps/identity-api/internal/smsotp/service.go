// Package smsotp implements the SMS OTP phone-verification workflow (Task 4.5):
// sending a 6-digit code under independent per-phone and per-subnet Redis rate
// limits, then verifying it under a 3-attempt brute-force lockout before
// persisting the envelope-encrypted phone number and its blind index.
//
// The rate limiting is intentionally split across independent dimensions rather
// than a composite phone:IP key (docs/data-architecture.md §3.2,
// threat-modeling.md D2): a per-phone window (1/min AND 5/hour) blocks targeted
// SMS bombing, while a per-subnet window (10/hour, grouping IPv4 to /24 and IPv6
// to /48) blocks distributed toll-fraud via proxy rotation. Verification uses a
// constant-time comparison and, on the third failure, purges the code and locks
// the phone out for 15 minutes.
package smsotp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// UserStore is the database query subset the SMS OTP service needs: loading the
// account (to confirm it exists / is active) and writing or clearing the verified
// phone.
type UserStore interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	SetUserPhone(ctx context.Context, arg db.SetUserPhoneParams) (int64, error)
	RemoveUserPhone(ctx context.Context, id uuid.UUID) (int64, error)
}

// Encryptor performs envelope encryption of the phone number prior to storage.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
}

// BlindIndexer computes the deterministic blind index used for O(1) exact-match
// phone lookups (docs/data-architecture.md §2.2).
type BlindIndexer interface {
	Compute(pii string) string
}

// Config carries the OTP lifetime, lockout, and rate-limit policy. Zero-valued
// fields fall back to the documented defaults in New.
type Config struct {
	// CodeTTL is how long an issued OTP remains valid (default 3m).
	CodeTTL time.Duration
	// MaxAttempts is the number of failed verifications tolerated before the
	// code is purged and the phone is locked out (default 3).
	MaxAttempts int
	// LockoutTTL is the brute-force lockout duration applied after MaxAttempts
	// failures (default 15m).
	LockoutTTL time.Duration

	// PerPhonePerMinute / PerPhonePerHour bound sends to a single phone number
	// (defaults 1 and 5). PerSubnetPerHour bounds sends from one IP subnet
	// (default 10).
	PerPhonePerMinute int
	PerPhonePerHour   int
	PerSubnetPerHour  int

	// MessageTemplate renders the SMS body; it must contain a single %s where
	// the code is substituted (default "Your Hatef verification code is %s").
	MessageTemplate string

	// HashPepper optionally binds stored OTP hashes to a secret so a Redis
	// snapshot alone cannot be brute-forced offline within the TTL. When empty
	// the code is bound to the phone number only.
	HashPepper []byte
}

// Service orchestrates the SMS OTP send and verify flows.
type Service struct {
	users     UserStore
	encryptor Encryptor
	indexer   BlindIndexer
	limiter   ratelimit.Limiter
	otps      OTPStore
	sender    Sender

	codeTTL     time.Duration
	maxAttempts int
	lockoutTTL  time.Duration

	perPhonePerMinute int
	perPhonePerHour   int
	perSubnetPerHour  int

	messageTemplate string
	hashPepper      []byte
}

// Default policy values applied when the corresponding Config field is zero.
const (
	verificationIDBytes      = 32
	defaultCodeTTL           = 3 * time.Minute
	defaultMaxAttempts       = 3
	defaultLockoutTTL        = 15 * time.Minute
	defaultPerPhonePerMinute = 1
	defaultPerPhonePerHour   = 5
	defaultPerSubnetPerHour  = 10
	defaultMessageTemplate   = "Your Hatef verification code is %s"
)

// New constructs a Service, validating that all collaborators are present and
// applying default policy values for any unset Config field.
func New(cfg Config, users UserStore, encryptor Encryptor, indexer BlindIndexer, limiter ratelimit.Limiter, otps OTPStore, sender Sender) (*Service, error) {
	if users == nil {
		return nil, errors.New("smsotp: user store is required")
	}
	if encryptor == nil {
		return nil, errors.New("smsotp: encryptor is required")
	}
	if indexer == nil {
		return nil, errors.New("smsotp: blind indexer is required")
	}
	if limiter == nil {
		return nil, errors.New("smsotp: limiter is required")
	}
	if otps == nil {
		return nil, errors.New("smsotp: otp store is required")
	}
	if sender == nil {
		return nil, errors.New("smsotp: sms sender is required")
	}

	s := &Service{
		users:             users,
		encryptor:         encryptor,
		indexer:           indexer,
		limiter:           limiter,
		otps:              otps,
		sender:            sender,
		codeTTL:           cfg.CodeTTL,
		maxAttempts:       cfg.MaxAttempts,
		lockoutTTL:        cfg.LockoutTTL,
		perPhonePerMinute: cfg.PerPhonePerMinute,
		perPhonePerHour:   cfg.PerPhonePerHour,
		perSubnetPerHour:  cfg.PerSubnetPerHour,
		messageTemplate:   cfg.MessageTemplate,
		hashPepper:        cfg.HashPepper,
	}

	if s.codeTTL <= 0 {
		s.codeTTL = defaultCodeTTL
	}
	if s.maxAttempts <= 0 {
		s.maxAttempts = defaultMaxAttempts
	}
	if s.lockoutTTL <= 0 {
		s.lockoutTTL = defaultLockoutTTL
	}
	if s.perPhonePerMinute <= 0 {
		s.perPhonePerMinute = defaultPerPhonePerMinute
	}
	if s.perPhonePerHour <= 0 {
		s.perPhonePerHour = defaultPerPhonePerHour
	}
	if s.perSubnetPerHour <= 0 {
		s.perSubnetPerHour = defaultPerSubnetPerHour
	}
	if s.messageTemplate == "" {
		s.messageTemplate = defaultMessageTemplate
	}

	return s, nil
}

// SendCode issues a fresh OTP to rawPhone on behalf of userID and the exact
// initiating session. On success it returns a cryptographically random 256-bit
// verification ID; the client must present that ID from the same session to
// verify the code. clientIP is reduced to its /24 or /48 subnet for the
// independent per-subnet rate limit.
func (s *Service) SendCode(ctx context.Context, userID uuid.UUID, sessionID, rawPhone, clientIP string) (string, error) {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return "", err
	}
	if strings.TrimSpace(sessionID) == "" {
		return "", errors.New("smsotp: session ID is required")
	}

	phone, err := NormalizePhone(rawPhone)
	if err != nil {
		return "", err
	}

	// A phone serving out its brute-force lockout cannot request new codes
	// either, so a locked-out attacker cannot refresh the guessing budget.
	locked, err := s.otps.IsLockedOut(ctx, phone)
	if err != nil {
		return "", err
	}
	if locked {
		return "", ErrLockedOut
	}

	// Per-subnet limit: 10/hour grouped to /24 (IPv4) or /48 (IPv6).
	// Checking the subnet limit first prevents requests from a saturated proxy or
	// malicious subnet from consuming per-phone rate limit quotas of targeted users.
	subnet := ratelimit.Subnet(clientIP)
	okSubnet, err := s.limiter.Allow(ctx, subnetRateKey(subnet), s.perSubnetPerHour, time.Hour)
	if err != nil {
		return "", err
	}
	if !okSubnet {
		return "", ErrRateLimited
	}

	// Per-phone limit: enforce BOTH the 1/min burst guard and the 5/hour cap.
	// Checking the minute window first means a saturated hourly cap still
	// consumes only the (already-full) minute window on a rejected request.
	okMinute, err := s.limiter.Allow(ctx, phoneRateKey(phone, "1m"), s.perPhonePerMinute, time.Minute)
	if err != nil {
		return "", err
	}
	if !okMinute {
		return "", ErrRateLimited
	}
	okHour, err := s.limiter.Allow(ctx, phoneRateKey(phone, "1h"), s.perPhonePerHour, time.Hour)
	if err != nil {
		return "", err
	}
	if !okHour {
		return "", ErrRateLimited
	}

	code, err := generateCode()
	if err != nil {
		return "", fmt.Errorf("smsotp: generate code: %w", err)
	}
	verificationID, err := generateVerificationID()
	if err != nil {
		return "", fmt.Errorf("smsotp: generate verification ID: %w", err)
	}

	record := OTPRecord{
		UserID:    userID.String(),
		SessionID: sessionID,
		Phone:     phone,
		CodeHash:  s.hashCode(phone, code),
	}
	if err := s.otps.Store(ctx, verificationID, record, s.codeTTL); err != nil {
		return "", err
	}

	message := fmt.Sprintf(s.messageTemplate, code)
	if err := s.sender.Send(ctx, phone, message); err != nil {
		// Best-effort cleanup: drop the pending code so a delivery failure does
		// not leave an unusable challenge behind.
		_ = s.otps.Delete(ctx, verificationID)
		return "", fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	return verificationID, nil
}

// Verify checks code against the pending challenge identified by
// verificationID. The record must belong to both userID and the exact initiating
// sessionID. A foreign account/session receives the same ErrNoActiveCode as an
// unknown ID, and crucially does not consume the code or burn an attempt.
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, sessionID, verificationID, code string) error {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return err
	}

	if strings.TrimSpace(sessionID) == "" || !validVerificationID(verificationID) {
		return ErrNoActiveCode
	}

	record, err := s.otps.Get(ctx, verificationID)
	if err != nil {
		return err
	}
	if record.UserID != userID.String() || record.SessionID != sessionID {
		return ErrNoActiveCode
	}

	// Records are created only from normalized input. Re-validating on read
	// fails closed if Redis was corrupted or an older incompatible record is
	// encountered; the client can never choose the phone during verification.
	phone, err := NormalizePhone(record.Phone)
	if err != nil || phone != record.Phone {
		return ErrNoActiveCode
	}

	locked, err := s.otps.IsLockedOut(ctx, phone)
	if err != nil {
		return err
	}
	if locked {
		return ErrLockedOut
	}

	if s.codeMatches(phone, code, record.CodeHash) {
		if err := s.persistPhone(ctx, userID, phone); err != nil {
			return err
		}
		// Consume the code so it cannot be replayed.
		_ = s.otps.Delete(ctx, verificationID)
		return nil
	}

	// Wrong code: burn an attempt. On reaching the cap, purge and lock out.
	attempts, err := s.otps.IncrementAttempts(ctx, verificationID)
	if err != nil {
		return err
	}
	if attempts >= s.maxAttempts {
		_ = s.otps.Delete(ctx, verificationID)
		if err := s.otps.Lockout(ctx, phone, s.lockoutTTL); err != nil {
			return err
		}
		return ErrLockedOut
	}

	return ErrInvalidCode
}

// generateVerificationID returns 256 bits of OS entropy encoded as unpadded
// base64url. The encoding is safe in JSON and Redis keys and is 43 characters
// long for the fixed 32-byte payload.
func generateVerificationID() (string, error) {
	raw := make([]byte, verificationIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// validVerificationID rejects user-controlled Redis key suffixes that were not
// produced by generateVerificationID.
func validVerificationID(value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == verificationIDBytes
}

// persistPhone envelope-encrypts the normalized phone and writes it together
// with its blind index so the two never drift apart (api-design.md §1.5).
func (s *Service) persistPhone(ctx context.Context, userID uuid.UUID, phone string) error {
	encrypted, err := s.encryptor.Encrypt(ctx, []byte(phone))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}

	index := s.indexer.Compute(phone)
	affected, err := s.users.SetUserPhone(ctx, db.SetUserPhoneParams{
		ID:              userID,
		PhoneEncrypted:  encrypted,
		PhoneBlindIndex: &index,
	})
	if err != nil {
		return fmt.Errorf("smsotp: store phone: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// RemovePhone clears the verified phone number from an account
// (DELETE /api/v1/users/me/phone, step-up gated per docs/api-design.md §1.5).
//
// The encrypted payload and its blind index are cleared together by the single
// RemoveUserPhone statement, so they cannot drift apart — the same invariant
// persistPhone maintains on the way in. There is no separate "verified" flag to
// reset: a phone is verified precisely while phone_encrypted is non-NULL.
//
// It is idempotent with respect to the phone itself (removing an absent phone is
// a no-op success) but not with respect to the account: a missing or soft-deleted
// account still reports ErrUserNotFound, because the caller's session should not
// outlive its account.
func (s *Service) RemovePhone(ctx context.Context, userID uuid.UUID) error {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return err
	}

	affected, err := s.users.RemoveUserPhone(ctx, userID)
	if err != nil {
		return fmt.Errorf("smsotp: remove phone: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// loadUser confirms the account exists and is active, mapping a missing row to
// ErrUserNotFound.
func (s *Service) loadUser(ctx context.Context, userID uuid.UUID) (db.User, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("smsotp: load user: %w", err)
	}
	if user.Status != "active" {
		return db.User{}, ErrAccountNotActive
	}
	return user, nil
}

// codeMatches compares a submitted code against the stored hash in constant time
// (docs/architecture.md "Timing Attack Resistance").
func (s *Service) codeMatches(phone, code, storedHash string) bool {
	candidate := s.hashCode(phone, code)
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(storedHash)) == 1
}

// hashCode derives the stored representation of an OTP: HMAC-SHA-256 keyed by the
// service pepper over "phone:code". Binding the phone in prevents a hash from
// one number validating against another, and the pepper (when configured) blocks
// offline brute-force of the small code space from a Redis snapshot.
func (s *Service) hashCode(phone, code string) string {
	mac := hmac.New(sha256.New, s.hashPepper)
	_, _ = mac.Write([]byte(phone))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// phoneRateKey builds the rate:otp:phone:{phone} ZSET key, suffixed by the
// window label so the 1-minute and 1-hour windows track independently.
func phoneRateKey(phone, window string) string {
	return "rate:otp:phone:" + phone + ":" + window
}

// subnetRateKey builds the rate:otp:subnet:{ip_subnet} ZSET key.
func subnetRateKey(subnet string) string {
	return "rate:otp:subnet:" + subnet
}
