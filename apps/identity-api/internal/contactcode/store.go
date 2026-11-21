package contactcode

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	challengePrefix = "contact:login:challenge:"
	capacityKey     = "contact:login:capacity"
)

// RedisStore enforces proof bindings and bounded spend with nonretrying scripts.
type RedisStore struct{ client redis.Cmdable }

// NewRedisStore requires a nonretrying caller-owned client. go-redis normalizes
// the constructor's MaxRetries=-1 to Options().MaxRetries=0. EVAL is used directly
// so there is no script-cache fallback that could replay an unknown result.
func NewRedisStore(client *redis.Client) (*RedisStore, error) {
	if client == nil || client.Options().MaxRetries != 0 {
		return nil, ErrInvalid
	}
	return &RedisStore{client}, nil
}

func recordPayload(rec Record) string {
	payload, _ := json.Marshal(rec)
	return string(payload)
}

// Every type and budget is checked before writes. No delivery is attempted until
// the entire reservation returns confirmed success; Lua/OOM errors cannot make a
// partially written reservation usable. All windows share Redis's atomic clock.
const reserveScript = `
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
local capKind = redis.call('TYPE', KEYS[2]).ok
if capKind ~= 'none' and capKind ~= 'zset' then return -1 end
local lockKind = redis.call('TYPE', KEYS[3]).ok
if lockKind ~= 'none' then
  if lockKind ~= 'string' or redis.call('GET', KEYS[3]) ~= '1' or redis.call('PTTL', KEYS[3]) <= 0 then return -1 end
  return 3
end
for i=4,#KEYS do
  local kind = redis.call('TYPE', KEYS[i]).ok
  if kind ~= 'none' and kind ~= 'zset' then return -1 end
end
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
local deadline = tonumber(ARGV[2])
if deadline <= now or deadline-now > 180000 then return 0 end
local count = redis.call('ZCOUNT', KEYS[2], '('..tostring(now), '+inf')
if count >= tonumber(ARGV[3]) then return 2 end
for i=4,#KEYS do
  local offset = 5 + (i-4)*2
  local window = tonumber(ARGV[offset])
  local limit = tonumber(ARGV[offset+1])
  if redis.call('ZCOUNT', KEYS[i], '('..tostring(now-window), '+inf') >= limit then return 2 end
end
redis.call('HSET', KEYS[1], 'payload', ARGV[1], 'expires_at', ARGV[2], 'attempts', '0', 'active', '0')
redis.call('PEXPIREAT', KEYS[1], ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('ZADD', KEYS[2], deadline, ARGV[4])
redis.call('PEXPIRE', KEYS[2], 180000)
for i=4,#KEYS do
  local offset = 5 + (i-4)*2
  local window = tonumber(ARGV[offset])
  redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now-window)
  redis.call('ZADD', KEYS[i], now, ARGV[4])
  redis.call('PEXPIRE', KEYS[i], window)
end
return 1
`

// Reserve atomically admits all spend/capacity dimensions and stores an inactive proof.
func (s *RedisStore) Reserve(ctx context.Context, rec Record, budgets []Budget, lockKey string, capacity int) error {
	if !validRecord(rec) || len(budgets) < 1 || len(budgets) > 8 || capacity < 1 || capacity > 10000 || !validKey(lockKey) {
		return ErrInvalid
	}
	keys := []string{challengePrefix + rec.Operation, capacityKey, lockKey}
	args := []any{recordPayload(rec), rec.ExpiresAt.UnixMilli(), capacity, rec.Operation}
	seen := map[string]bool{keys[0]: true, keys[1]: true, keys[2]: true}
	for _, b := range budgets {
		if !validKey(b.Key) || seen[b.Key] || b.Limit < 1 || b.Limit > 100000 || b.Window < time.Second || b.Window > 24*time.Hour {
			return ErrInvalid
		}
		seen[b.Key] = true
		keys = append(keys, b.Key)
		args = append(args, b.Window.Milliseconds(), b.Limit)
	}
	n, err := s.client.Eval(ctx, reserveScript, keys, args...).Int()
	if err != nil {
		return ErrOutcomeUnknown
	}
	return scriptResult(n)
}

const activateScript = `
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
local v = redis.call('HMGET', KEYS[1], 'payload', 'expires_at', 'attempts', 'active')
if ttl <= 0 or ttl > 180000 or v[1] ~= ARGV[1] or v[2] ~= ARGV[2] or tonumber(ARGV[2]) <= now or tonumber(ARGV[2])-now > 180000 or v[3] ~= '0' or v[4] ~= '0' then return 0 end
redis.call('HSET', KEYS[1], 'active', '1')
return 1
`

// Activate marks confirmed transport acceptance without changing expiry or attempts.
func (s *RedisStore) Activate(ctx context.Context, rec Record) error {
	if !validRecord(rec) {
		return ErrNoActiveCode
	}
	n, err := s.client.Eval(ctx, activateScript, []string{challengePrefix + rec.Operation}, recordPayload(rec), rec.ExpiresAt.UnixMilli()).Int()
	if err != nil {
		return ErrOutcomeUnknown
	}
	return scriptResult(n)
}

const getScript = `
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' or redis.call('HLEN', KEYS[1]) ~= 4 then return {} end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 or ttl > 180000 then return {} end
local v = redis.call('HMGET', KEYS[1], 'payload', 'expires_at', 'attempts', 'active')
if v[4] ~= '1' then return {} end
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
return {v[1], v[2], v[3], tostring(now)}
`

// Get returns an active, validated snapshot without changing attempts or expiry.
func (s *RedisStore) Get(ctx context.Context, handle string) (Record, error) {
	if !validCapability(handle) {
		return Record{}, ErrNoActiveCode
	}
	values, err := s.client.Eval(ctx, getScript, []string{challengePrefix + handle}).StringSlice()
	if err != nil {
		return Record{}, ErrOutcomeUnknown
	}
	if len(values) != 4 || len(values[0]) > 2048 {
		return Record{}, ErrNoActiveCode
	}
	var rec Record
	if json.Unmarshal([]byte(values[0]), &rec) != nil || !validRecord(rec) || rec.Operation != handle || recordPayload(rec) != values[0] || strconv.FormatInt(rec.ExpiresAt.UnixMilli(), 10) != values[1] {
		return Record{}, ErrNoActiveCode
	}
	attempts, err := strconv.Atoi(values[2])
	if err != nil || strconv.Itoa(attempts) != values[2] || attempts < 0 || attempts >= rec.MaxAttempts {
		return Record{}, ErrNoActiveCode
	}
	now, err := strconv.ParseInt(values[3], 10, 64)
	if err != nil || rec.ExpiresAt.UnixMilli() <= now || rec.ExpiresAt.UnixMilli()-now > (3*time.Minute).Milliseconds() {
		return Record{}, ErrNoActiveCode
	}
	return rec, nil
}

// Snapshot equality includes the HMAC-protected purpose, account, version, JKT,
// channel, destination, operation, original expiry and captured stricter policy.
// It deliberately excludes the mutable counter so concurrent wrong attempts all
// count, and at most one correct attempt can consume the proof.
const consumeScript = `
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' or redis.call('HLEN', KEYS[1]) ~= 4 then return 0 end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 or ttl > 180000 then return 0 end
local v = redis.call('HMGET', KEYS[1], 'payload', 'expires_at', 'attempts', 'active')
if v[1] ~= ARGV[1] or v[2] ~= ARGV[2] or v[4] ~= '1' then return 0 end
local attempts = tonumber(v[3])
if not attempts or not string.match(v[3], '^%d+$') or tostring(attempts) ~= v[3] or attempts < 0 or attempts >= tonumber(ARGV[5]) then return 0 end
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + math.floor(tonumber(t[2])/1000)
if tonumber(ARGV[2]) <= now or tonumber(ARGV[2])-now > 180000 then return 0 end
local capKind = redis.call('TYPE', KEYS[2]).ok
if capKind ~= 'none' and capKind ~= 'zset' then return -1 end
local lockKind = redis.call('TYPE', KEYS[3]).ok
if lockKind ~= 'none' then
  if lockKind ~= 'string' or redis.call('GET', KEYS[3]) ~= '1' or redis.call('PTTL', KEYS[3]) <= 0 then return -1 end
  return 3
end
local diff = 0
for i=1,64 do if string.byte(ARGV[3],i) ~= string.byte(ARGV[4],i) then diff = diff+1 end end
if diff == 0 then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[7])
  return 1
end
if attempts+1 >= tonumber(ARGV[5]) then
  -- Lua errors do not roll back prior writes. Saturate before lock allocation.
  redis.call('HSET', KEYS[1], 'attempts', ARGV[5])
  redis.call('SET', KEYS[3], '1', 'PX', ARGV[6])
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[7])
  return 3
end
redis.call('HSET', KEYS[1], 'attempts', tostring(attempts+1))
return 4
`

// Consume rechecks the exact snapshot and original expiry before one-time consumption.
// A wrong candidate records one bounded attempt or establishes the shared lockout.
func (s *RedisStore) Consume(ctx context.Context, rec Record, candidate, lockKey string) error {
	raw, err := hex.DecodeString(candidate)
	if !validRecord(rec) || !validKey(lockKey) || err != nil || len(raw) != 32 || hex.EncodeToString(raw) != candidate {
		return ErrNoActiveCode
	}
	n, err := s.client.Eval(ctx, consumeScript, []string{challengePrefix + rec.Operation, capacityKey, lockKey}, recordPayload(rec), rec.ExpiresAt.UnixMilli(), rec.CodeHash, candidate, rec.MaxAttempts, rec.LockoutTTL.Milliseconds(), rec.Operation).Int()
	if err != nil {
		return ErrOutcomeUnknown
	}
	return scriptResult(n)
}

func scriptResult(n int) error {
	switch n {
	case 1:
		return nil
	case 2:
		return ErrRateLimited
	case 3:
		return ErrLockedOut
	case 4:
		return ErrInvalidCode
	case -1:
		return ErrUnavailable
	case 0:
		return ErrNoActiveCode
	default:
		return ErrOutcomeUnknown
	}
}

func validKey(key string) bool {
	return len(key) > 0 && len(key) <= 512 && strings.IndexFunc(key, func(r rune) bool { return r < 33 || r > 126 }) < 0
}
