package smsotp

import (
	"context"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	otpKeyPrefix      = "otp:sms:secret:"
	lockoutKeyPrefix  = "otp:sms:lockout:"
	signupCapacityKey = "otp:sms:signup:capacity"
	// PurposeEnrollment binds a challenge to an authenticated account and session.
	PurposeEnrollment = "enrollment"
	// PurposeSignup binds a challenge to a signup attempt and its DPoP JKT.
	PurposeSignup = "signup"
)

// OTPBinding is authority, not a login session. Signup uses attempt UUID and JKT.
type OTPBinding struct{ Purpose, OwnerID, BindingID string }

// OTPRecord carries the bound phone, code hash, and failed-attempt count.
type OTPRecord struct {
	OTPBinding
	Phone    string
	CodeHash string
	Attempts int
}

// OTPStore persists bounded challenges and atomically consumes or locks them out.
type OTPStore interface {
	Store(context.Context, string, OTPRecord, time.Duration, int) error
	Get(context.Context, string) (OTPRecord, error)
	Consume(context.Context, string, OTPRecord, string, int, time.Duration) error
	Delete(context.Context, string) error
	IsLockedOut(context.Context, string) (bool, error)
}

// RedisOTPStore implements OTPStore with atomic Redis scripts.
type RedisOTPStore struct{ client redis.Cmdable }

// NewRedisOTPStore constructs a store over a caller-owned Redis client.
func NewRedisOTPStore(client redis.Cmdable) (*RedisOTPStore, error) {
	if missingDependency(client) {
		return nil, ErrUnavailable
	}
	return &RedisOTPStore{client}, nil
}
func otpKey(id string) string        { return otpKeyPrefix + id }
func lockoutKey(phone string) string { return lockoutKeyPrefix + phone }
func validBinding(b OTPBinding) bool {
	if len(b.OwnerID) != 36 {
		return false
	}
	id, err := uuid.Parse(b.OwnerID)
	if err != nil || id == uuid.Nil || id.String() != b.OwnerID || len(b.BindingID) == 0 || len(b.BindingID) > 128 {
		return false
	}
	if b.Purpose == PurposeSignup {
		return validVerificationID(b.BindingID)
	}
	if b.Purpose != PurposeEnrollment {
		return false
	}
	for _, c := range b.BindingID {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func validHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	raw, err := hex.DecodeString(hash)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == hash
}
func validRecord(rec OTPRecord) bool {
	if len(rec.Phone) > 16 {
		return false
	}
	phone, err := NormalizePhone(rec.Phone)
	return validBinding(rec.OTPBinding) && err == nil && phone == rec.Phone && validHash(rec.CodeHash) && rec.Attempts >= 0 && rec.Attempts < 3
}

const storeScript = `
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
local lockKind = redis.call('TYPE', KEYS[3]).ok
if lockKind ~= 'none' then
  if lockKind ~= 'string' or redis.call('GET', KEYS[3]) ~= '1' or redis.call('PTTL', KEYS[3]) <= 0 then return -1 end
  return 3
end
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
local deadline = now + tonumber(ARGV[6])
if ARGV[1] == 'signup' then
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
  if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[7]) then return 2 end
  redis.call('ZADD', KEYS[2], deadline, ARGV[8])
  redis.call('PEXPIRE', KEYS[2], 180000)
end
redis.call('HSET', KEYS[1], 'purpose', ARGV[1], 'owner_id', ARGV[2], 'binding_id', ARGV[3], 'phone', ARGV[4], 'code_hash', ARGV[5], 'attempts', '0', 'expires_at', tostring(deadline))
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return 1
`

// Store creates a challenge without overwriting state or bypassing lockout/capacity.
func (s *RedisOTPStore) Store(ctx context.Context, id string, rec OTPRecord, ttl time.Duration, capacity int) error {
	if !validVerificationID(id) || !validRecord(rec) || rec.Attempts != 0 || ttl < time.Second || ttl > 3*time.Minute || capacity < 0 || capacity > 10000 || rec.Purpose == PurposeSignup && capacity == 0 {
		return ErrNoActiveCode
	}
	n, err := s.client.Eval(ctx, storeScript, []string{otpKey(id), signupCapacityKey, lockoutKey(rec.Phone)}, rec.Purpose, rec.OwnerID, rec.BindingID, rec.Phone, rec.CodeHash, ttl.Milliseconds(), capacity, id).Int()
	if err != nil {
		return ErrUnavailable
	}
	if n == 2 {
		return ErrRateLimited
	}
	if n == 3 {
		return ErrLockedOut
	}
	if n < 0 {
		return ErrUnavailable
	}
	if n != 1 {
		return ErrNoActiveCode
	}
	return nil
}

// Get returns a validated challenge snapshot without changing attempts or expiry.
func (s *RedisOTPStore) Get(ctx context.Context, id string) (OTPRecord, error) {
	if !validVerificationID(id) {
		return OTPRecord{}, ErrNoActiveCode
	}
	pipe := s.client.TxPipeline()
	fields := pipe.HGetAll(ctx, otpKey(id))
	lifetime := pipe.PTTL(ctx, otpKey(id))
	clock := pipe.Time(ctx)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return OTPRecord{}, ErrUnavailable
	}
	vals := fields.Val()
	if len(vals) != 7 {
		return OTPRecord{}, ErrNoActiveCode
	}
	n, err := strconv.Atoi(vals["attempts"])
	if err != nil || strconv.Itoa(n) != vals["attempts"] {
		return OTPRecord{}, ErrNoActiveCode
	}
	rec := OTPRecord{OTPBinding: OTPBinding{vals["purpose"], vals["owner_id"], vals["binding_id"]}, Phone: vals["phone"], CodeHash: vals["code_hash"], Attempts: n}
	if !validRecord(rec) {
		return OTPRecord{}, ErrNoActiveCode
	}
	ttl := lifetime.Val()
	deadline, err := strconv.ParseInt(vals["expires_at"], 10, 64)
	remaining := deadline - clock.Val().UnixMilli()
	if err != nil || remaining <= 0 || remaining > (3*time.Minute).Milliseconds() || ttl <= 0 || ttl > 3*time.Minute {
		return OTPRecord{}, ErrNoActiveCode
	}
	return rec, nil
}

// The first read only supplies the HMAC phone input. This operation rechecks the
// exact snapshot and authority, expiry, attempts and lockout before any mutation.
const consumeScript = `
local ttl = redis.call('PTTL', KEYS[1])
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' or ttl <= 0 or ttl > 180000 then return 0 end
local v = redis.call('HMGET', KEYS[1], 'purpose', 'owner_id', 'binding_id', 'phone', 'code_hash', 'attempts', 'expires_at')
for i=1,5 do if v[i] ~= ARGV[i] then return 0 end end
local attempts = tonumber(v[6])
if not attempts or not string.match(v[6], '^%d+$') or tostring(attempts) ~= v[6] or attempts < 0 or attempts >= tonumber(ARGV[7]) then return 0 end
local expires = tonumber(v[7])
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
if not expires or not string.match(v[7], '^%d+$') or expires <= now or expires-now > 180000 then return 0 end
local kind = redis.call('TYPE', KEYS[2]).ok
if kind ~= 'none' then
  if kind ~= 'string' or redis.call('GET', KEYS[2]) ~= '1' or redis.call('PTTL', KEYS[2]) <= 0 then return -1 end
  return 3
end
local capacityKind = redis.call('TYPE', KEYS[3]).ok
if capacityKind ~= 'none' and capacityKind ~= 'zset' then return -1 end
local equal = 0
for i=1,64 do if string.byte(v[5],i) ~= string.byte(ARGV[6],i) then equal = equal+1 end end
if equal == 0 then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[3], ARGV[9])
  return 1
end
if attempts+1 >= tonumber(ARGV[7]) then
  -- Lua errors do not roll back writes. Saturate before allocating the lockout.
  redis.call('HSET', KEYS[1], 'attempts', ARGV[7])
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[8])
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[3], ARGV[9])
  return 3
end
redis.call('HSET', KEYS[1], 'attempts', tostring(attempts+1))
return 2
`

// Consume atomically rechecks binding and expiry, then consumes or records failure.
func (s *RedisOTPStore) Consume(ctx context.Context, id string, rec OTPRecord, candidate string, maxAttempts int, lockout time.Duration) error {
	if !validVerificationID(id) || !validRecord(rec) || !validHash(candidate) || maxAttempts < 1 || maxAttempts > 3 || lockout < 15*time.Minute || lockout > 24*time.Hour {
		return ErrNoActiveCode
	}
	n, err := s.client.Eval(ctx, consumeScript, []string{otpKey(id), lockoutKey(rec.Phone), signupCapacityKey}, rec.Purpose, rec.OwnerID, rec.BindingID, rec.Phone, rec.CodeHash, candidate, maxAttempts, lockout.Milliseconds(), id).Int()
	if err != nil {
		return ErrUnavailable
	}
	switch n {
	case 1:
		return nil
	case 2:
		return ErrInvalidCode
	case 3:
		return ErrLockedOut
	case -1:
		return ErrUnavailable
	default:
		return ErrNoActiveCode
	}
}

// Delete removes the challenge and releases its outstanding signup capacity.
func (s *RedisOTPStore) Delete(ctx context.Context, id string) error {
	if !validVerificationID(id) {
		return ErrNoActiveCode
	}
	n, err := s.client.Eval(ctx, `local k=redis.call('TYPE',KEYS[2]).ok; if k~='none' and k~='zset' then return -1 end; redis.call('DEL',KEYS[1]); redis.call('ZREM',KEYS[2],ARGV[1]); return 1`, []string{otpKey(id), signupCapacityKey}, id).Int()
	if err != nil || n != 1 {
		return ErrUnavailable
	}
	return nil
}

// IsLockedOut checks the shared phone lockout and rejects malformed lockout state.
func (s *RedisOTPStore) IsLockedOut(ctx context.Context, phone string) (bool, error) {
	n, err := s.client.Eval(ctx, `local k=redis.call('TYPE',KEYS[1]).ok; if k=='none' then return 0 end; if k~='string' or redis.call('GET',KEYS[1])~='1' or redis.call('PTTL',KEYS[1])<=0 then return -1 end; return 1`, []string{lockoutKey(phone)}).Int()
	if err != nil || n < 0 {
		return false, ErrUnavailable
	}
	return n == 1, nil
}
