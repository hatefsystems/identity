package webauthn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	redisChallengePrefix  = "webauthn:challenge:v1:"
	redisFirstSlotPrefix  = "webauthn:first-registration:v1:"
	redisChallengeTimeout = 2 * time.Second
)

var saveChallengeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) ~= 0 then
  return 0
end
redis.call('HSET', KEYS[1], 'flow', ARGV[1], 'user', ARGV[2],
  'session', ARGV[3], 'jkt', ARGV[4], 'data', ARGV[5])
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return 1
`)

// Establish the expiring slot first: Redis Lua runtime errors do not roll back
// previous writes. A slot-only failure conservatively excludes another start.
const saveFirstRegistrationLua = `
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local deadline = tonumber(ARGV[6])
if not deadline or deadline <= now then return -2 end
if deadline - now > tonumber(ARGV[8]) then return redis.error_reply('invalid deadline') end
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return -1 end
redis.call('SET', KEYS[2], ARGV[7], 'PXAT', ARGV[6], 'NX')
redis.call('HSET', KEYS[1], 'flow', ARGV[1], 'user', ARGV[2],
  'session', ARGV[3], 'jkt', ARGV[4], 'data', ARGV[5])
redis.call('PEXPIREAT', KEYS[1], ARGV[6])
return 1
`

var saveFirstRegistrationScript = redis.NewScript(saveFirstRegistrationLua)

var checkFirstRegistrationScript = redis.NewScript(`
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local deadline = tonumber(ARGV[2])
if not deadline or deadline <= now then return 0 end
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('TYPE', KEYS[1]).ok ~= 'string' then return redis.error_reply('invalid slot') end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 or ttl > tonumber(ARGV[3]) or redis.call('STRLEN', KEYS[1]) ~= 64 then
  return redis.error_reply('invalid slot')
end
if redis.call('GET', KEYS[1]) ~= ARGV[1] or redis.call('PEXPIRETIME', KEYS[1]) ~= deadline then return 0 end
return 1
`)

// Authority integers stay inside an opaque JSON string. Lua compares only
// bounded binding strings and never decodes/re-encodes 64-bit versions/epochs.
var takeChallengeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return {0}
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 or ttl > tonumber(ARGV[6]) or redis.call('HLEN', KEYS[1]) ~= 5 or
    redis.call('HSTRLEN', KEYS[1], 'data') > tonumber(ARGV[5]) then
  return redis.error_reply('invalid WebAuthn challenge state')
end
local fields = redis.call('HMGET', KEYS[1], 'flow', 'user', 'session', 'jkt', 'data')
for i = 1, 5 do
  if not fields[i] then
    return redis.error_reply('invalid WebAuthn challenge state')
  end
end
if not string.find(ARGV[1], ',' .. fields[1] .. ',', 1, true) then
  return {-1}
end
if (ARGV[2] ~= '' and fields[2] ~= ARGV[2]) or
    fields[3] ~= ARGV[3] or fields[4] ~= ARGV[4] then
  return {-2}
end
redis.call('DEL', KEYS[1])
return {1, fields[5]}
`)

// RedisChallengeStore shares one-use ceremonies across API replicas. The caller
// owns the client's lifetime. There is deliberately no process-local fallback.
type RedisChallengeStore struct {
	client *redis.Client
	now    func() time.Time
}

var _ ChallengeStore = (*RedisChallengeStore)(nil)

// NewRedisChallengeStore requires a client that enforces request I/O deadlines.
func NewRedisChallengeStore(client *redis.Client) (*RedisChallengeStore, error) {
	if client == nil || !client.Options().ContextTimeoutEnabled {
		return nil, errors.New("webauthn: Redis client with context timeouts is required")
	}
	return &RedisChallengeStore{client: client, now: time.Now}, nil
}

func challengeRedisKey(challenge string) string {
	digest := sha256.Sum256([]byte(challenge))
	return redisChallengePrefix + hex.EncodeToString(digest[:])
}

func firstRegistrationRedisKey(id uuid.UUID) string {
	digest := sha256.Sum256([]byte(id.String()))
	return redisFirstSlotPrefix + hex.EncodeToString(digest[:])
}

// SaveFirstRegistration atomically creates one account slot and pending hash.
func (s *RedisChallengeStore) SaveFirstRegistration(ctx context.Context, challenge string, pc PendingChallenge) error {
	ctx, cancel := context.WithTimeout(ctx, redisChallengeTimeout)
	defer cancel()
	if s.client.Options().MaxRetries != 0 {
		return ErrChallengeStoreUnavailable
	}
	if pc.FirstRegistration == nil {
		return ErrInvalidChallenge
	}
	data, _, err := encodePendingChallenge(challenge, pc, s.now())
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(challenge))
	saved, err := saveFirstRegistrationScript.Run(ctx, s.client,
		[]string{challengeRedisKey(challenge), firstRegistrationRedisKey(pc.UserRef)},
		pc.Flow.String(), pc.UserRef.String(), pc.SessionID, pc.DPoPJKT, data,
		pc.Expires.UnixMilli(), hex.EncodeToString(digest[:]), MaxChallengeTTL.Milliseconds()).Int()
	if err != nil {
		return challengeStoreError(ctx)
	}
	switch saved {
	case 1:
		return nil
	case 0:
		return ErrChallengeConflict
	case -1:
		return ErrEnrollmentInProgress
	case -2:
		return ErrChallengeExpired
	default:
		return ErrChallengeStoreUnavailable
	}
}

// CheckFirstRegistration validates live digest ownership using Redis time.
func (s *RedisChallengeStore) CheckFirstRegistration(ctx context.Context, challenge string, pc PendingChallenge) error {
	ctx, cancel := context.WithTimeout(ctx, redisChallengeTimeout)
	defer cancel()
	if s.client.Options().MaxRetries != 0 {
		return ErrChallengeStoreUnavailable
	}
	if pc.FirstRegistration == nil || validatePendingChallenge(challenge, pc) != nil {
		return ErrInvalidChallenge
	}
	digest := sha256.Sum256([]byte(challenge))
	valid, err := checkFirstRegistrationScript.Run(ctx, s.client, []string{firstRegistrationRedisKey(pc.UserRef)},
		hex.EncodeToString(digest[:]), pc.Expires.UnixMilli(), MaxChallengeTTL.Milliseconds()).Int()
	if err != nil {
		return challengeStoreError(ctx)
	}
	if valid != 1 {
		return ErrChallengeNotFound
	}
	return nil
}

func challengeStoreError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrChallengeStoreUnavailable, err)
	}
	// Do not propagate Redis error strings, which may contain stored data.
	return ErrChallengeStoreUnavailable
}

// Save atomically creates bounded, expiring state without overwriting a ceremony.
func (s *RedisChallengeStore) Save(ctx context.Context, challenge string, pc PendingChallenge) error {
	if pc.FirstRegistration != nil {
		return s.SaveFirstRegistration(ctx, challenge, pc)
	}
	ctx, cancel := context.WithTimeout(ctx, redisChallengeTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return challengeStoreError(ctx)
	}
	data, ttl, err := encodePendingChallenge(challenge, pc, s.now())
	if err != nil {
		return err
	}
	saved, err := saveChallengeScript.Run(ctx, s.client, []string{challengeRedisKey(challenge)},
		pc.Flow.String(), pc.UserRef.String(), pc.SessionID, pc.DPoPJKT, data, ttl.Milliseconds()).Int()
	if err != nil {
		return challengeStoreError(ctx)
	}
	if saved == 0 {
		return ErrChallengeConflict
	}
	if saved != 1 {
		return ErrChallengeStoreUnavailable
	}
	return nil
}

// Take atomically consumes state only when all applicable bindings match.
func (s *RedisChallengeStore) Take(ctx context.Context, challenge string, binding ChallengeBinding) (PendingChallenge, error) {
	ctx, cancel := context.WithTimeout(ctx, redisChallengeTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return PendingChallenge{}, challengeStoreError(ctx)
	}
	if challenge == "" || len(challenge) > maxChallengeKeyBytes {
		return PendingChallenge{}, ErrChallengeNotFound
	}
	if err := binding.validate(); err != nil {
		return PendingChallenge{}, err
	}
	flows := make([]string, len(binding.Flows))
	for i, flow := range binding.Flows {
		flows[i] = flow.String()
	}
	user := ""
	if !isLoginFlow(binding.Flows[0]) {
		user = binding.UserRef.String()
	}
	result, err := takeChallengeScript.Run(ctx, s.client, []string{challengeRedisKey(challenge)},
		","+strings.Join(flows, ",")+",", user, binding.SessionID, binding.DPoPJKT,
		maxChallengeBytes, MaxChallengeTTL.Milliseconds()).Slice()
	if err != nil {
		return PendingChallenge{}, challengeStoreError(ctx)
	}
	if len(result) == 0 {
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	switch result[0] {
	case int64(0), int64(-2):
		return PendingChallenge{}, ErrChallengeNotFound
	case int64(-1):
		return PendingChallenge{}, ErrChallengeFlowMismatch
	case int64(1):
		if len(result) != 2 {
			return PendingChallenge{}, ErrChallengeStoreUnavailable
		}
	default:
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	data, ok := result[1].(string)
	if !ok {
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	pc, err := decodePendingChallenge(challenge, []byte(data))
	if err != nil || binding.matches(pc) != nil {
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	if !s.now().Before(pc.Expires) {
		return PendingChallenge{}, ErrChallengeExpired
	}
	return pc, nil
}
