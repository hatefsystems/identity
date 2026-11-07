package clientauth

import (
	"context"
	"reflect"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

var claimJTIScript = redis.NewScript(`
local clock = redis.call('TIME')
if type(clock) ~= 'table' or #clock ~= 2 or
   type(clock[1]) ~= 'string' or type(clock[2]) ~= 'string' or
   #clock[1] > 12 or #clock[2] > 6 or
   not string.match(clock[1], '^%d+$') or not string.match(clock[2], '^%d+$') then
  return redis.error_reply('invalid client assertion clock')
end
local seconds = tonumber(clock[1])
local micros = tonumber(clock[2])
if seconds > 253402300799 or micros > 999999 then
  return redis.error_reply('invalid client assertion clock')
end
local expiresSeconds = tonumber(ARGV[1])
local expiresNanos = tonumber(ARGV[2])
local remainingSeconds = expiresSeconds - seconds
local remainingNanos = expiresNanos - micros * 1000
if remainingSeconds < 0 or (remainingSeconds == 0 and remainingNanos <= 0) or
   remainingSeconds > 86400 or (remainingSeconds == 86400 and remainingNanos > 0) then
  return -1
end
local value = redis.call('GET', KEYS[1])
if value then
  if value ~= '1' or redis.call('PTTL', KEYS[1]) < 0 then
    return redis.error_reply('invalid client assertion replay state')
  end
  return 0
end
local deadline = expiresSeconds * 1000 + math.floor(expiresNanos / 1000000) + 1
if not redis.call('SET', KEYS[1], '1', 'PXAT', string.format('%.0f', deadline), 'NX') then
  return redis.error_reply('invalid client assertion replay claim')
end
return 1
`)

// RedisJTIGuard shares atomic claims across validators and reconstructed processes.
// The caller owns the client lifetime. Storage errors never fall back to memory.
type RedisJTIGuard struct {
	client redis.UniversalClient
}

var _ JTIReplayGuard = (*RedisJTIGuard)(nil)
var _ assertionClock = (*RedisJTIGuard)(nil)

// NewRedisJTIGuard constructs the shared guard without dialing or changing state.
func NewRedisJTIGuard(client redis.UniversalClient) (*RedisJTIGuard, error) {
	if client == nil || (reflect.ValueOf(client).Kind() == reflect.Pointer && reflect.ValueOf(client).IsNil()) {
		return nil, ErrInvalidReplayParams
	}
	return &RedisJTIGuard{client: client}, nil
}

// ServerTime supplies the shared clock for assertion admission. Malformed TIME
// replies and storage errors are redacted and never replaced by a local clock.
func (g *RedisJTIGuard) ServerTime(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	reply, err := g.client.Do(ctx, "TIME").Slice()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return time.Time{}, ctxErr
	}
	if err != nil || len(reply) != 2 {
		return time.Time{}, ErrReplayUnavailable
	}
	var parts [2]int64
	for i, limit := range []int{12, 6} {
		value, ok := reply[i].(string)
		if !ok || len(value) == 0 || len(value) > limit {
			return time.Time{}, ErrReplayUnavailable
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return time.Time{}, ErrReplayUnavailable
			}
		}
		parts[i], err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, ErrReplayUnavailable
		}
	}
	if parts[0] > maxUnixSeconds || parts[1] > 999999 {
		return time.Time{}, ErrReplayUnavailable
	}
	return time.Unix(parts[0], parts[1]*1000).UTC(), nil
}

// Remember claims the tuple through the assertion's exp plus accepted leeway.
func (g *RedisJTIGuard) Remember(ctx context.Context, clientID, audience, jti string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	seconds := expiresAt.Unix()
	if !validReplayPart(clientID, maxClientIDBytes) || !validReplayPart(audience, maxAudienceBytes) ||
		!validReplayPart(jti, maxJTIBytes) || expiresAt.IsZero() || seconds < 0 ||
		seconds > maxUnixSeconds+int64(clockSkewLeeway/time.Second) {
		return false, ErrInvalidReplayParams
	}
	claimed, err := claimJTIScript.Run(ctx, g.client, []string{replayKey(clientID, audience, jti)}, seconds, expiresAt.Nanosecond()).Int()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if err != nil {
		return false, ErrReplayUnavailable
	}
	if claimed == -1 {
		return false, ErrInvalidReplayParams
	}
	if claimed != 0 && claimed != 1 {
		return false, ErrReplayUnavailable
	}
	return claimed == 1, nil
}
