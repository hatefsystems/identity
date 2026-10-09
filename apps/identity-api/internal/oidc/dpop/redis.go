package dpop

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisReplayPrefix = "dpop:v1:replay:"
	redisNoncePrefix  = "dpop:v1:nonce:"
	redisStateValue   = "1"
)

// Existing records are checked inside the same atomic operation as the claim.
// Wrong types, values, or missing TTLs are corrupt authority, not proof errors.
var rememberProofScript = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if value then
  if value ~= '1' or redis.call('PTTL', KEYS[1]) < 0 then
    return redis.error_reply('invalid DPoP replay state')
  end
  return 0
end
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1], 'NX')
return 1
`)

var consumeNonceScript = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then
  return 0
end
if value ~= '1' or redis.call('PTTL', KEYS[1]) < 0 then
  return redis.error_reply('invalid DPoP nonce state')
end
redis.call('DEL', KEYS[1])
return 1
`)

// RedisReplayGuard atomically claims proofs across instances. Redis is the
// authority; outages never fall back to a process-local replay guard.
type RedisReplayGuard struct {
	client redis.UniversalClient
	now    func() time.Time
}

var _ ReplayGuard = (*RedisReplayGuard)(nil)

// NewRedisReplayGuard uses a shared client whose lifetime belongs to the caller.
func NewRedisReplayGuard(client redis.UniversalClient) (*RedisReplayGuard, error) {
	if client == nil || (reflect.ValueOf(client).Kind() == reflect.Pointer && reflect.ValueOf(client).IsNil()) {
		return nil, ErrInvalidParams
	}
	return &RedisReplayGuard{client: client, now: time.Now}, nil
}

// Remember retains a claim through the inclusive expiry instant. Rounding up
// by a Redis millisecond also prevents truncation from opening a replay gap.
func (g *RedisReplayGuard) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" || expiresAt.IsZero() {
		return false, ErrInvalidParams
	}
	ttl := expiresAt.Sub(g.now())
	if ttl < 0 {
		return false, nil
	}
	claimed, err := rememberProofScript.Run(ctx, g.client, []string{stateKey(redisReplayPrefix, key)},
		ttl.Milliseconds()+1).Int()
	if err != nil {
		return false, stateStoreError(ctx, err)
	}
	if claimed != 0 && claimed != 1 {
		return false, ErrStoreUnavailable
	}
	return claimed == 1, nil
}

// RedisNonceStore shares realm/key-bound, single-use nonces across instances.
// Values contain only a version marker, and keys contain only scoped hashes.
type RedisNonceStore struct {
	client redis.UniversalClient
}

var _ NonceStore = (*RedisNonceStore)(nil)

// NewRedisNonceStore uses a shared client whose lifetime belongs to the caller.
func NewRedisNonceStore(client redis.UniversalClient) (*RedisNonceStore, error) {
	if client == nil || (reflect.ValueOf(client).Kind() == reflect.Pointer && reflect.ValueOf(client).IsNil()) {
		return nil, ErrInvalidParams
	}
	return &RedisNonceStore{client: client}, nil
}

// Issue creates a short-lived nonce bound to a verified realm and proof key.
func (s *RedisNonceStore) Issue(ctx context.Context, realm, jkt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(jkt) == "" {
		return "", ErrInvalidParams
	}
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	issued, err := s.client.SetNX(ctx, stateKey(redisNoncePrefix, realm, jkt, nonce),
		redisStateValue, DefaultNonceTTL).Result()
	if err != nil {
		return "", stateStoreError(ctx, err)
	}
	if !issued {
		return "", ErrStoreUnavailable
	}
	return nonce, nil
}

// Validate atomically consumes a nonce only in its original realm and key scope.
func (s *RedisNonceStore) Validate(ctx context.Context, realm, jkt, nonce string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(jkt) == "" {
		return false, ErrInvalidParams
	}
	if nonce == "" {
		return false, nil
	}
	consumed, err := consumeNonceScript.Run(ctx, s.client,
		[]string{stateKey(redisNoncePrefix, realm, jkt, nonce)}).Int()
	if err != nil {
		return false, stateStoreError(ctx, err)
	}
	if consumed != 0 && consumed != 1 {
		return false, ErrStoreUnavailable
	}
	return consumed == 1, nil
}
