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

	// Hash field names inside the otp:sms:secret:{phone} record.
	fieldCodeHash  = "code_hash"
	fieldAttempts  = "attempts"
	fieldCreatedAt = "created_at"
)

// OTPRecord is the pending SMS OTP state for a phone: the hashed code and the
// number of failed verification attempts so far.
type OTPRecord struct {
	// CodeHash is the HMAC-SHA-256 hash of the issued OTP (never the plaintext).
	CodeHash string
	// Attempts is the count of failed verification attempts recorded so far.
	Attempts int
}

// OTPStore persists the short-lived pending OTP and the brute-force lockout for
// a phone number. The production implementation is Redis-backed (RedisOTPStore);
// tests substitute an in-memory fake. Phone numbers passed here must already be
// E.164-normalized so keys are stable.
type OTPStore interface {
	// Store writes the hashed code for phone with a fresh zero attempt counter,
	// replacing any previous pending code, and applies ttl to the record.
	Store(ctx context.Context, phone, codeHash string, ttl time.Duration) error
	// Get returns the pending record for phone, or ErrNoActiveCode when none is
	// present (never issued, expired, or already consumed).
	Get(ctx context.Context, phone string) (OTPRecord, error)
	// IncrementAttempts atomically increments and returns the failed-attempt
	// counter for phone.
	IncrementAttempts(ctx context.Context, phone string) (int, error)
	// Delete removes any pending code for phone (called on success and on
	// lockout purge).
	Delete(ctx context.Context, phone string) error
	// Lockout marks phone as locked out for ttl, blocking further verification.
	Lockout(ctx context.Context, phone string, ttl time.Duration) error
	// IsLockedOut reports whether phone currently has an active lockout.
	IsLockedOut(ctx context.Context, phone string) (bool, error)
}

// RedisOTPStore is the Redis-backed OTPStore. The pending code is a Hash keyed
// otp:sms:secret:{phone} carrying the code hash, attempt counter, and issue
// timestamp; the lockout is a string keyed otp:sms:lockout:{phone}. Both rely on
// Redis TTLs for expiry so no sweeper is needed.
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

func otpKey(phone string) string     { return otpKeyPrefix + phone }
func lockoutKey(phone string) string { return lockoutKeyPrefix + phone }

// Store implements OTPStore. It overwrites any prior record and resets the
// attempt counter so a re-request always starts a clean 3-attempt budget.
func (s *RedisOTPStore) Store(ctx context.Context, phone, codeHash string, ttl time.Duration) error {
	key := otpKey(phone)
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, key)
	pipe.HSet(ctx, key, map[string]any{
		fieldCodeHash:  codeHash,
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
func (s *RedisOTPStore) Get(ctx context.Context, phone string) (OTPRecord, error) {
	vals, err := s.client.HGetAll(ctx, otpKey(phone)).Result()
	if err != nil {
		return OTPRecord{}, fmt.Errorf("smsotp: load code: %w", err)
	}
	if len(vals) == 0 {
		return OTPRecord{}, ErrNoActiveCode
	}

	hash, ok := vals[fieldCodeHash]
	if !ok || hash == "" {
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

	return OTPRecord{CodeHash: hash, Attempts: attempts}, nil
}

// IncrementAttempts implements OTPStore.
func (s *RedisOTPStore) IncrementAttempts(ctx context.Context, phone string) (int, error) {
	key := otpKey(phone)
	pipe := s.client.TxPipeline()
	incrCmd := pipe.HIncrBy(ctx, key, fieldAttempts, 1)
	pipe.Expire(ctx, key, 5*time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("smsotp: increment attempts: %w", err)
	}
	return int(incrCmd.Val()), nil
}

// Delete implements OTPStore.
func (s *RedisOTPStore) Delete(ctx context.Context, phone string) error {
	if err := s.client.Del(ctx, otpKey(phone)).Err(); err != nil {
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
