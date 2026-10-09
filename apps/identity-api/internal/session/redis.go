package session

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisSessionPrefix = "identity:session:v1:"

// RedisStore is session authority on standalone Redis, not a cache. Its layout is:
//
//	identity:session:v1:token:<token hash>                 HASH of Session fields
//	identity:session:v1:id:<user byte length>:<user>:<id>  STRING token hash
//	identity:session:v1:user:<user byte length>:<user>     HASH public ID -> token hash
//
// Records and ID lookups expire at the idle deadline. The owner index expires at
// its latest absolute deadline. Revocation deletes the record and index entry,
// retaining the ID lookup as "revoked" until absolute expiry to reject delayed
// Create retries. No bearer secrets are stored. Integer values, including times
// in Unix nanoseconds and auth versions, are decimal strings, never Lua doubles.
// Multi-key scripts require standalone Redis; Redis Cluster is not supported.
type RedisStore struct {
	client redis.UniversalClient
	now    func() time.Time
}

var _ Store = (*RedisStore)(nil)

// NewRedisStore uses the caller-owned client. Configure ContextTimeoutEnabled
// and finite I/O timeouts on that client so socket waits honor request deadlines.
func NewRedisStore(client redis.UniversalClient) (*RedisStore, error) {
	if client == nil || (reflect.ValueOf(client).Kind() == reflect.Pointer && reflect.ValueOf(client).IsNil()) {
		return nil, fmt.Errorf("%w: Redis client is required", ErrStoreUnavailable)
	}
	return &RedisStore{client: client, now: time.Now}, nil
}

func redisTokenKey(hash string) string { return redisSessionPrefix + "token:" + hash }

func redisUserKey(userID string) string {
	return redisSessionPrefix + "user:" + strconv.Itoa(len(userID)) + ":" + userID
}

func redisIDKey(userID, sessionID string) string {
	return redisSessionPrefix + "id:" + strconv.Itoa(len(userID)) + ":" + userID + ":" + sessionID
}

// Create inserts live authority and rejects retries against a revoked public ID.
func (r *RedisStore) Create(ctx context.Context, tokenHash string, s Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tokenHash == "" || !validSession(s) {
		return ErrStoreUnavailable
	}
	bit := func(value bool) string {
		if value {
			return "1"
		}
		return "0"
	}
	_, err := r.run(ctx, "create", tokenHash, s.UserID, s.ID,
		s.ID, string(s.Kind), s.UserID, strconv.FormatInt(s.AuthVersion, 10), bit(s.AuthVersionSet),
		s.IP, s.UserAgent, s.DPoPJKT, strconv.FormatInt(s.CreatedAt.UnixNano(), 10),
		strconv.FormatInt(s.LastSeenAt.UnixNano(), 10), strconv.FormatInt(s.AbsoluteExpiry.UnixNano(), 10),
		strconv.FormatInt(s.IdleExpiry.UnixNano(), 10), bit(s.EnrollmentClaimed))
	return err
}

// Get reads live authority by the hash of the browser's bearer secret.
func (r *RedisStore) Get(ctx context.Context, tokenHash string) (Session, error) {
	value, err := r.run(ctx, "get", tokenHash, "", "")
	if err != nil {
		return Session{}, err
	}
	return decodeRedisSession(value)
}

// GetByID reads owner-scoped authority without extending its idle lifetime.
func (r *RedisStore) GetByID(ctx context.Context, userID, sessionID string) (Session, error) {
	value, err := r.run(ctx, "get_id", "", userID, sessionID)
	if err != nil {
		return Session{}, err
	}
	return decodeRedisSession(value)
}

// Touch atomically advances live idle expiry, bounded by absolute expiry.
func (r *RedisStore) Touch(ctx context.Context, tokenHash string, idleExpiry time.Time) error {
	_, err := r.run(ctx, "touch", tokenHash, "", "", strconv.FormatInt(idleExpiry.UnixNano(), 10))
	return err
}

// Delete revokes a session and retains a bounded marker against delayed retries.
func (r *RedisStore) Delete(ctx context.Context, tokenHash string) error {
	_, err := r.run(ctx, "delete", tokenHash, "", "")
	if errors.Is(err, ErrSessionNotFound) {
		return nil
	}
	return err
}

// ListForUser returns live owner-scoped sessions, newest first.
func (r *RedisStore) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	value, err := r.run(ctx, "list", "", userID, "")
	if err != nil {
		return nil, err
	}
	values, ok := value.([]any)
	if !ok {
		return nil, ErrStoreUnavailable
	}
	result := make([]Session, 0, len(values))
	for _, value := range values {
		s, err := decodeRedisSession(value)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}

// DeleteForUser atomically checks ownership before revoking a public session ID.
func (r *RedisStore) DeleteForUser(ctx context.Context, userID, sessionID string) (bool, error) {
	_, err := r.run(ctx, "delete_id", "", userID, sessionID)
	if errors.Is(err, ErrSessionNotFound) {
		return false, nil
	}
	return err == nil, err
}

// DeleteAllForUser atomically revokes indexed sessions without scanning other users.
func (r *RedisStore) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.run(ctx, "delete_all", "", userID, "")
	return err
}

// ClaimRecoveryEnrollment admits one pending ceremony on a live restricted session.
func (r *RedisStore) ClaimRecoveryEnrollment(ctx context.Context, userID, sessionID string) (bool, error) {
	value, err := r.run(ctx, "claim", "", userID, sessionID)
	if errors.Is(err, ErrSessionNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	claimed, ok := value.(int64)
	if !ok || (claimed != 0 && claimed != 1) {
		return false, ErrStoreUnavailable
	}
	return claimed == 1, nil
}

// ReleaseRecoveryEnrollment clears a claim without restoring expired authority.
func (r *RedisStore) ReleaseRecoveryEnrollment(ctx context.Context, userID, sessionID string) error {
	_, err := r.run(ctx, "release", "", userID, sessionID)
	if errors.Is(err, ErrSessionNotFound) {
		return nil
	}
	return err
}

func (r *RedisStore) run(ctx context.Context, op, hash, userID, sessionID string, extra ...any) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := []any{op, strconv.FormatInt(r.now().UnixNano(), 10), hash, userID, sessionID}
	args = append(args, extra...)
	value, err := redisSessionOperations.Run(ctx, r.client,
		[]string{redisTokenKey(hash), redisIDKey(userID, sessionID), redisUserKey(userID)}, args...).Result()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if errors.Is(err, redis.Nil) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return value, nil
}

func decodeRedisSession(value any) (Session, error) {
	values, ok := value.([]any)
	if !ok || len(values) != 13 {
		return Session{}, ErrStoreUnavailable
	}
	fields := make([]string, len(values))
	for i, value := range values {
		if fields[i], ok = value.(string); !ok {
			return Session{}, ErrStoreUnavailable
		}
	}
	version, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return Session{}, ErrStoreUnavailable
	}
	var times [4]time.Time
	for i := range times {
		ns, err := strconv.ParseInt(fields[8+i], 10, 64)
		if err != nil {
			return Session{}, ErrStoreUnavailable
		}
		times[i] = time.Unix(0, ns).UTC()
	}
	s := Session{
		ID: fields[0], Kind: Kind(fields[1]), UserID: fields[2], AuthVersion: version,
		AuthVersionSet: fields[4] == "1", IP: fields[5], UserAgent: fields[6], DPoPJKT: fields[7],
		CreatedAt: times[0], LastSeenAt: times[1], AbsoluteExpiry: times[2], IdleExpiry: times[3],
		EnrollmentClaimed: fields[12] == "1",
	}
	if !validSession(s) || (fields[4] != "0" && fields[4] != "1") || (fields[12] != "0" && fields[12] != "1") {
		return Session{}, ErrStoreUnavailable
	}
	return s, nil
}

// All mutation decisions happen inside one script. Touch and claim only HSET
// records whose record, ID lookup, and owner index are still present and live.
// In particular, neither operation can recreate indexes after bulk revocation.
var redisSessionOperations = redis.NewScript(`
local prefix = 'identity:session:v1:'
local op, hash, user, id = ARGV[1], ARGV[3], ARGV[4], ARGV[5]
local fields = {'id', 'kind', 'user_id', 'auth_version', 'auth_version_set', 'ip', 'user_agent',
                'dpop_jkt', 'created_at', 'last_seen_at', 'absolute_expiry', 'idle_expiry', 'enrollment_claimed'}

local function corrupt() error('SESSION_CORRUPT') end
local function uint(s)
    return type(s) == 'string' and (s == '0' or string.match(s, '^[1-9][0-9]*$'))
        and (#s < 19 or (#s == 19 and s <= '9223372036854775807'))
end
local function before(a, b) return #a < #b or (#a == #b and a < b) end
local function milliseconds(ns)
    local whole = #ns > 6 and tonumber(string.sub(ns, 1, -7)) or 0
    local remainder = #ns > 6 and string.sub(ns, -6) or ns
    return whole + (tonumber(remainder) > 0 and 1 or 0)
end
local clock = redis.call('TIME')
local serverNow = clock[1] .. string.format('%09d', tonumber(clock[2]) * 1000)
local serverMS = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local now = ARGV[2]
if not uint(now) then corrupt() end
if before(now, serverNow) then now = serverNow end

local function userKey(uid) return prefix .. 'user:' .. #uid .. ':' .. uid end
local function idKey(uid, sid) return prefix .. 'id:' .. #uid .. ':' .. uid .. ':' .. sid end
local function tokenKey(h) return prefix .. 'token:' .. h end
local function present(key, expected)
    local kind = redis.call('TYPE', key).ok
    if kind == 'none' then return false end
    if kind ~= expected or redis.call('PTTL', key) < 0 then corrupt() end
    return true
end
local function valid(s)
    for _, field in ipairs(fields) do if type(s[field]) ~= 'string' then corrupt() end end
    if s.id == '' or s.user_id == '' or not uint(s.auth_version)
        or (s.auth_version_set ~= '0' and s.auth_version_set ~= '1')
        or (s.enrollment_claimed ~= '0' and s.enrollment_claimed ~= '1')
        or (s.kind ~= 'authenticated' and s.kind ~= 'recovery_enrollment')
        or (s.enrollment_claimed == '1' and s.kind ~= 'recovery_enrollment') then corrupt() end
    for _, field in ipairs({'created_at', 'last_seen_at', 'absolute_expiry', 'idle_expiry'}) do
        if not uint(s[field]) or s[field] == '0' then corrupt() end
    end
    if before(s.last_seen_at, s.created_at) or not before(s.last_seen_at, s.idle_expiry)
        or before(s.absolute_expiry, s.idle_expiry) then corrupt() end
end
local function record(h, uid, sid)
    local key = tokenKey(h)
    if not present(key, 'hash') then return nil end
    if redis.call('HLEN', key) ~= #fields then corrupt() end
    local values = redis.call('HMGET', key, unpack(fields))
    local s = {}
    for i, field in ipairs(fields) do s[field] = values[i] end
    valid(s)
    if (uid and s.user_id ~= uid) or (sid and s.id ~= sid) then corrupt() end
    return s
end
local function values(s)
    local out = {}
    for _, field in ipairs(fields) do out[#out + 1] = s[field] end
    return out
end
local function retire(h, s)
    redis.call('DEL', tokenKey(h))
    local lookup = idKey(s.user_id, s.id)
    if before(now, s.absolute_expiry) then
        redis.call('SET', lookup, 'revoked')
        redis.call('PEXPIREAT', lookup, milliseconds(s.absolute_expiry))
    else
        redis.call('DEL', lookup)
    end
    local owner = userKey(s.user_id)
    redis.call('HDEL', owner, s.id)
    if redis.call('HLEN', owner) == 0 then redis.call('DEL', owner) end
end
local function live(h, uid, sid)
    local s = record(h, uid, sid)
    if not s then return nil end
    local owner, lookup = userKey(s.user_id), idKey(s.user_id, s.id)
    if not present(owner, 'hash') or not present(lookup, 'string') then return nil end
    local indexed = redis.call('HGET', owner, s.id)
    local pointed = redis.call('GET', lookup)
    if not indexed or pointed == 'revoked' then return nil end
    if indexed ~= h or pointed ~= h then corrupt() end
    if not before(now, s.absolute_expiry) or not before(now, s.idle_expiry) then
        retire(h, s)
        return nil
    end
    return s
end

if op == 'create' then
    local s = {}
    for i, field in ipairs(fields) do s[field] = ARGV[5 + i] end
    valid(s)
    if not before(now, s.absolute_expiry) or not before(now, s.idle_expiry) then return false end
    if redis.call('EXISTS', KEYS[1], KEYS[2]) ~= 0 then error('SESSION_EXISTS') end
    present(KEYS[3], 'hash')
    if redis.call('HEXISTS', KEYS[3], s.id) ~= 0 then error('SESSION_EXISTS') end
    local ownerTTL = redis.call('PTTL', KEYS[3])
    local args = {}
    for _, field in ipairs(fields) do args[#args + 1] = field; args[#args + 1] = s[field] end
    redis.call('HSET', KEYS[1], unpack(args))
    redis.call('PEXPIREAT', KEYS[1], milliseconds(s.idle_expiry))
    redis.call('SET', KEYS[2], hash)
    redis.call('PEXPIREAT', KEYS[2], milliseconds(s.idle_expiry))
    redis.call('HSET', KEYS[3], s.id, hash)
    if ownerTTL < milliseconds(s.absolute_expiry) - serverMS then
        redis.call('PEXPIREAT', KEYS[3], milliseconds(s.absolute_expiry))
    end
    return 1
end

if op == 'list' or op == 'delete_all' then
    if not present(KEYS[3], 'hash') then
        if op == 'list' then return {} else return 1 end
    end
    local entries = redis.call('HGETALL', KEYS[3])
    local ownerTTL = redis.call('PTTL', KEYS[3])
    local out, records = {}, {}
    -- Validate every owner link before bulk deletion, avoiding partial success
    -- or deleting another user's state when an index has been corrupted.
    for i = 1, #entries, 2 do
        local sid, h = entries[i], entries[i + 1]
        if sid == '' or h == '' then corrupt() end
        local s = record(h, user, sid)
        local lookup = idKey(user, sid)
        if present(lookup, 'string') then
            local pointer = redis.call('GET', lookup)
            if pointer ~= h and pointer ~= 'revoked' then corrupt() end
        end
        records[i] = s
    end
    for i = 1, #entries, 2 do
        local sid, h = entries[i], entries[i + 1]
        if op == 'delete_all' then
            if records[i] then
                retire(h, records[i])
            else
                -- A missing record has no recoverable authority. Keep only a
                -- bounded negative ID marker, never recreate a session.
                redis.call('SET', idKey(user, sid), 'revoked', 'PX', math.max(1, ownerTTL))
            end
        else
            local s = live(h, user, sid)
            if s then out[#out + 1] = values(s)
            else redis.call('HDEL', KEYS[3], sid) end
        end
    end
    if op == 'delete_all' or redis.call('HLEN', KEYS[3]) == 0 then redis.call('DEL', KEYS[3]) end
    if op == 'list' then return out else return 1 end
end

local scoped = op == 'get_id' or op == 'delete_id' or op == 'claim' or op == 'release'
if scoped then
    if not present(KEYS[2], 'string') then return false end
    hash = redis.call('GET', KEYS[2])
    if hash == 'revoked' then return false end
    if hash == '' then corrupt() end
end
local s = live(hash, scoped and user or nil, scoped and id or nil)
if not s then return false end
if op == 'get' or op == 'get_id' then return values(s) end
if op == 'delete' or op == 'delete_id' then retire(hash, s); return 1 end
if op == 'touch' then
    local idle = ARGV[6]
    if not uint(idle) or idle == '0' then corrupt() end
    if before(s.absolute_expiry, idle) then idle = s.absolute_expiry end
    if before(idle, s.idle_expiry) then idle = s.idle_expiry end
    local seen = before(s.last_seen_at, now) and now or s.last_seen_at
    redis.call('HSET', tokenKey(hash), 'idle_expiry', idle, 'last_seen_at', seen)
    redis.call('PEXPIREAT', tokenKey(hash), milliseconds(idle))
    redis.call('PEXPIREAT', idKey(s.user_id, s.id), milliseconds(idle))
    return 1
end
if op == 'claim' then
    if s.kind ~= 'recovery_enrollment' or s.enrollment_claimed == '1' then return 0 end
    redis.call('HSET', tokenKey(hash), 'enrollment_claimed', '1')
    return 1
end
if op == 'release' then
    if s.kind == 'recovery_enrollment' then redis.call('HSET', tokenKey(hash), 'enrollment_claimed', '0') end
    return 1
end
error('SESSION_OPERATION')
`)
