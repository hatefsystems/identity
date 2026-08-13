package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter reports whether an action identified by key is permitted under a
// sliding window, atomically recording the request when it is allowed. It is
// the seam the SMS OTP service depends on: the production implementation is
// Redis-backed (RedisLimiter), while tests can substitute a fake.
type Limiter interface {
	// Allow evaluates the sliding window of length window for key, admitting at
	// most limit requests within it. It returns true and records the request
	// when there is capacity, or false when the window is saturated.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// slidingWindowLua is the atomic sliding-window rate-limit script from
// docs/data-architecture.md §3.2, reproduced verbatim. Running it inside Redis
// collapses the read-modify-write (evict expired, count, conditionally add) into
// a single round-trip so concurrent requests cannot race past the limit.
//
//	KEYS[1] = the ZSET key (e.g. rate:otp:phone:{phone})
//	ARGV[1] = now       (current time, same unit as window)
//	ARGV[2] = window    (window length)
//	ARGV[3] = limit     (max requests per window)
//	ARGV[4] = member    (unique member for this request)
//
// Returns 1 when the request is admitted, 0 when the window is saturated.
const slidingWindowLua = `local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local current_requests = redis.call('ZCARD', key)
if current_requests < limit then
    redis.call('ZADD', key, now, member)
    redis.call('PEXPIRE', key, window)
    return 1
else
    return 0
end`

// scriptRunner is the subset of the go-redis client the limiter needs. Modeling
// it as an interface keeps the limiter unit-testable and lets EvalSha fall back
// to Eval without depending on the concrete *redis.Client.
type scriptRunner interface {
	EvalSha(ctx context.Context, sha1 string, keys []string, args ...any) *redis.Cmd
	Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd
	ScriptLoad(ctx context.Context, script string) *redis.StringCmd
}

// RedisLimiter is a sliding-window Limiter backed by a Redis sorted set per key,
// driven by the atomic Lua script (docs/data-architecture.md §3.2). Windows are
// tracked in milliseconds so sub-second precision survives the ZSET score.
type RedisLimiter struct {
	client scriptRunner
	sha    string
	now    func() time.Time
}

// NewRedisLimiter constructs a RedisLimiter over the given client. It attempts
// to pre-load the Lua script so subsequent calls use the compact EVALSHA path;
// if pre-loading fails (e.g. Redis momentarily unreachable) the first Allow will
// transparently load it, so construction never fails on a transient hiccup.
func NewRedisLimiter(client *redis.Client) (*RedisLimiter, error) {
	if client == nil {
		return nil, errors.New("ratelimit: redis client is required")
	}
	l := &RedisLimiter{client: client, now: time.Now}
	if sha, err := client.ScriptLoad(context.Background(), slidingWindowLua).Result(); err == nil {
		l.sha = sha
	}
	return l, nil
}

// Allow implements Limiter using the sliding-window Lua script. window is
// converted to milliseconds; a unique member per call (now-nanos + random
// suffix) guarantees distinct ZSET entries even for requests landing in the same
// millisecond, so none are silently coalesced.
func (l *RedisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return false, nil
	}

	now := l.now()
	nowMillis := now.UnixMilli()
	windowMillis := window.Milliseconds()
	if windowMillis <= 0 {
		windowMillis = 1
	}

	member, err := uniqueMember(now)
	if err != nil {
		return false, err
	}

	args := []any{nowMillis, windowMillis, limit, member}

	res, err := l.eval(ctx, key, args)
	if err != nil {
		return false, fmt.Errorf("ratelimit: evaluate sliding window: %w", err)
	}

	allowed, ok := res.(int64)
	if !ok {
		return false, fmt.Errorf("ratelimit: unexpected script result type %T", res)
	}
	return allowed == 1, nil
}

// eval runs the script via EVALSHA and falls back to EVAL (reloading the script)
// when the server reports NOSCRIPT, caching the returned SHA for next time.
func (l *RedisLimiter) eval(ctx context.Context, key string, args []any) (any, error) {
	keys := []string{key}

	if l.sha != "" {
		res, err := l.client.EvalSha(ctx, l.sha, keys, args...).Result()
		if err == nil {
			return res, nil
		}
		if !isNoScript(err) {
			return nil, err
		}
		// Fall through to EVAL when the script was evicted from the cache.
	}

	res, err := l.client.Eval(ctx, slidingWindowLua, keys, args...).Result()
	if err != nil {
		return nil, err
	}
	// Best-effort refresh of the cached SHA for subsequent EVALSHA calls.
	if sha, loadErr := l.client.ScriptLoad(ctx, slidingWindowLua).Result(); loadErr == nil {
		l.sha = sha
	}
	return res, nil
}

// isNoScript reports whether err is Redis's NOSCRIPT error (the SHA is no longer
// cached), which is the signal to reload the script and retry via EVAL.
func isNoScript(err error) bool {
	if err == nil {
		return false
	}
	const noScriptPrefix = "NOSCRIPT"
	msg := err.Error()
	return len(msg) >= len(noScriptPrefix) && msg[:len(noScriptPrefix)] == noScriptPrefix
}

// uniqueMember builds a ZSET member that is unique per request: the call's
// nanosecond timestamp plus a short random suffix so two requests in the same
// nanosecond still occupy distinct members and are both counted.
func uniqueMember(now time.Time) (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("ratelimit: generate member: %w", err)
	}
	return fmt.Sprintf("%d-%s", now.UnixNano(), hex.EncodeToString(buf)), nil
}
