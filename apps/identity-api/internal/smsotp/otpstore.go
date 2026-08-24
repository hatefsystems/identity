package smsotp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis key templates for the SMS OTP workflow (docs/data-architecture.md §3.1).
// The pending code lives in a Hash under otpKeyPrefix; a separate string key
// under lockoutKeyPrefix holds the brute-force lockout so a purged code and an
// active lockout can coexist independently.
const (
	otpKeyPrefix     = "otp:sms:secret:"
	lockoutKeyPrefix = "otp:sms:lockout:"

	// Hash field names inside the otp:sms:secret:{verification_id} record.
	fieldUserID    = "user_id"
	fieldSessionID = "session_id"
	fieldPhone     = "phone"
	fieldCodeHash  = "code_hash"
	fieldAttempts  = "attempts"
	fieldCreatedAt = "created_at"
)

// OTPRecord is a pending SMS OTP challenge. The challenge is addressed by an
// opaque verification ID, while these fields bind it to the exact account,
// initiating browser session, and normalized phone number.
type OTPRecord struct {
	// UserID is the UUID string of the account that initiated enrollment.
	UserID string
	// SessionID is the public ID of the authenticated session that initiated
	// enrollment. It is not the secret session token.
	SessionID string
	// Phone is the E.164-normalized phone number the code was delivered to.
	Phone string
	// CodeHash is the HMAC-SHA-256 hash of the issued OTP (never the plaintext).
	CodeHash string
	// Attempts is the count of failed verification attempts recorded so far.
	Attempts int
}

// OTPStore persists short-lived pending OTP challenges and per-phone
// brute-force lockouts. Pending records are keyed by high-entropy verification
// IDs rather than phone numbers, so callers cannot transplant a challenge
// between accounts or sessions. Lockout methods still receive an
// E.164-normalized phone so the lockout remains shared across challenges.
type OTPStore interface {
	// Store writes record under verificationID with a fresh zero attempt
	// counter and applies ttl to the record.
	Store(ctx context.Context, verificationID string, record OTPRecord, ttl time.Duration) error
	// Get returns the pending record for verificationID, or ErrNoActiveCode
	// when none is present (never issued, expired, malformed, or consumed).
	Get(ctx context.Context, verificationID string) (OTPRecord, error)
	// IncrementAttempts atomically increments and returns the failed-attempt
	// counter for verificationID without extending the challenge lifetime.
	IncrementAttempts(ctx context.Context, verificationID string) (int, error)
	// Delete removes the pending challenge identified by verificationID.
	Delete(ctx context.Context, verificationID string) error
	// Lockout marks phone as locked out for ttl, blocking further verification.
	Lockout(ctx context.Context, phone string, ttl time.Duration) error
	// IsLockedOut reports whether phone currently has an active lockout.
	IsLockedOut(ctx context.Context, phone string) (bool, error)
}

// RedisOTPStore is the Redis-backed OTPStore. A pending challenge is a Hash
// keyed otp:sms:secret:{verification_id} carrying its account/session/phone
// binding, code hash, attempt counter, and issue timestamp. The lockout is a
// string keyed otp:sms:lockout:{phone}. Both rely on Redis TTLs for expiry so no
// sweeper is needed.
type RedisOTPStore struct {
	client redis.Cmdable
}

// NewRedisOTPStore constructs a RedisOTPStore over the given client.
func NewRedisOTPStore(client redis.Cmdable) (*RedisOTPStore, error) {
	if client == nil {
		return nil, errors.New("smsotp: redis client is required")
	}
	return &RedisOTPStore{client: client}, nil
}

func otpKey(verificationID string) string { return otpKeyPrefix + verificationID }
func lockoutKey(phone string) string      { return lockoutKeyPrefix + phone }

// Store implements OTPStore.
func (s *RedisOTPStore) Store(ctx context.Context, verificationID string, record OTPRecord, ttl time.Duration) error {
	if !validVerificationID(verificationID) {
		return errors.New("smsotp: invalid verification ID")
	}
	if record.UserID == "" || record.SessionID == "" || record.Phone == "" || record.CodeHash == "" {
		return errors.New("smsotp: incomplete OTP record")
	}

	key := otpKey(verificationID)
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, key)
	pipe.HSet(ctx, key, map[string]any{
		fieldUserID:    record.UserID,
		fieldSessionID: record.SessionID,
		fieldPhone:     record.Phone,
		fieldCodeHash:  record.CodeHash,
		fieldAttempts:  0,
		fieldCreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("smsotp: store code: %w", err)
	}
	return nil
}

// Get implements OTPStore.
func (s *RedisOTPStore) Get(ctx context.Context, verificationID string) (OTPRecord, error) {
	vals, err := s.client.HGetAll(ctx, otpKey(verificationID)).Result()
	if err != nil {
		return OTPRecord{}, fmt.Errorf("smsotp: load code: %w", err)
	}
	if len(vals) == 0 {
		return OTPRecord{}, ErrNoActiveCode
	}

	userID := vals[fieldUserID]
	sessionID := vals[fieldSessionID]
	phone := vals[fieldPhone]
	hash := vals[fieldCodeHash]
	if userID == "" || sessionID == "" || phone == "" || hash == "" {
		return OTPRecord{}, ErrNoActiveCode
	}

	attempts := 0
	if raw, ok := vals[fieldAttempts]; ok && raw != "" {
		// A malformed counter is treated as zero attempts rather than failing
		// the request; the code hash is the security-critical field.
		if n, convErr := parseInt(raw); convErr == nil {
			attempts = n
		}
	}

	return OTPRecord{
		UserID:    userID,
		SessionID: sessionID,
		Phone:     phone,
		CodeHash:  hash,
		Attempts:  attempts,
	}, nil
}

// IncrementAttempts implements OTPStore.
func (s *RedisOTPStore) IncrementAttempts(ctx context.Context, verificationID string) (int, error) {
	// Check-and-increment in one Redis command. A plain HINCRBY would recreate
	// an expired challenge with only an attempts field, and resetting the TTL
	// here would silently extend the original code lifetime.
	const incrementIfPresent = `
if redis.call('EXISTS', KEYS[1]) == 0 then
  return -1
end
return redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
`
	result, err := s.client.Eval(ctx, incrementIfPresent, []string{otpKey(verificationID)}, fieldAttempts).Int64()
	if err != nil {
		return 0, fmt.Errorf("smsotp: increment attempts: %w", err)
	}
	if result < 0 {
		return 0, ErrNoActiveCode
	}
	return int(result), nil
}

// Delete implements OTPStore.
func (s *RedisOTPStore) Delete(ctx context.Context, verificationID string) error {
	if err := s.client.Del(ctx, otpKey(verificationID)).Err(); err != nil {
		return fmt.Errorf("smsotp: delete code: %w", err)
	}
	return nil
}

// Lockout implements OTPStore.
func (s *RedisOTPStore) Lockout(ctx context.Context, phone string, ttl time.Duration) error {
	if err := s.client.Set(ctx, lockoutKey(phone), "1", ttl).Err(); err != nil {
		return fmt.Errorf("smsotp: set lockout: %w", err)
	}
	return nil
}

// IsLockedOut implements OTPStore.
func (s *RedisOTPStore) IsLockedOut(ctx context.Context, phone string) (bool, error) {
	n, err := s.client.Exists(ctx, lockoutKey(phone)).Result()
	if err != nil {
		return false, fmt.Errorf("smsotp: check lockout: %w", err)
	}
	return n > 0, nil
}

// parseInt parses a base-10 integer, used for the attempt counter stored as a
// Redis Hash string field.
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
