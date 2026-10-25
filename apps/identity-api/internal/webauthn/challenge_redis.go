package webauthn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisChallengePrefix  = "webauthn:challenge:v1:"
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

func challengeStoreError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrChallengeStoreUnavailable, err)
	}
	// Do not propagate Redis error strings, which may contain stored data.
	return ErrChallengeStoreUnavailable
}

// Save atomically creates bounded, expiring state without overwriting a ceremony.
func (s *RedisChallengeStore) Save(ctx context.Context, challenge string, pc PendingChallenge) error {
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
