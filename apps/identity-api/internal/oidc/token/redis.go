package token

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisCodePrefix    = "identity:v1:oauth:code:"
	redisGrantPrefix   = "identity:v1:oauth:grant:"
	redisRefreshPrefix = "identity:v1:oauth:refresh:"
	redisUserPrefix    = "identity:v1:oauth:user:"
)

// RedisCodeStore provides shared, single-use authorization-code authority.
type RedisCodeStore struct{ client redis.UniversalClient }

// NewRedisCodeStore uses a caller-owned client with bounded I/O and no retries.
func NewRedisCodeStore(client redis.UniversalClient) (*RedisCodeStore, error) {
	if client == nil {
		return nil, errors.New("token: Redis client required")
	}
	return &RedisCodeStore{client: client}, nil
}

// Save inserts expiring code authority without replacing an existing code.
func (s *RedisCodeStore) Save(ctx context.Context, hash string, data AuthorizationCodeData) error {
	if hash == "" || !validCode(data) || !data.ExpiresAt.After(time.Now()) {
		return ErrStoreUnavailable
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return ErrStoreUnavailable
	}
	ttl := time.Until(data.ExpiresAt)
	if ttl <= 0 {
		return ErrStoreUnavailable
	}
	ok, err := s.client.SetNX(ctx, redisCodePrefix+hash, raw, ttl).Result()
	if err != nil {
		return storeError(err)
	}
	if !ok {
		return ErrStoreUnavailable
	}
	return nil
}

// Consume atomically removes a code across all API instances.
func (s *RedisCodeStore) Consume(ctx context.Context, hash string) (AuthorizationCodeData, error) {
	raw, err := s.client.GetDel(ctx, redisCodePrefix+hash).Result()
	if errors.Is(err, redis.Nil) {
		return AuthorizationCodeData{}, ErrCodeNotFound
	}
	if err != nil {
		return AuthorizationCodeData{}, storeError(err)
	}
	var data AuthorizationCodeData
	if decodeState(raw, &data) != nil || !validCode(data) {
		return AuthorizationCodeData{}, ErrStoreUnavailable
	}
	if !data.ExpiresAt.After(time.Now()) {
		return AuthorizationCodeData{}, ErrCodeNotFound
	}
	return data, nil
}

// RedisRefreshTokenStore holds shared grant authority on standalone Redis.
type RedisRefreshTokenStore struct{ client redis.UniversalClient }

// NewRedisRefreshTokenStore uses a caller-owned client and never falls back locally.
func NewRedisRefreshTokenStore(client redis.UniversalClient) (*RedisRefreshTokenStore, error) {
	if client == nil {
		return nil, errors.New("token: Redis client required")
	}
	return &RedisRefreshTokenStore{client: client}, nil
}

var createGrantScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
if ARGV[3] ~= '' and redis.call('EXISTS', KEYS[2]) == 1 then return 1 end
local now = redis.call('TIME')
if tonumber(ARGV[2]) <= tonumber(now[1])*1000 + math.floor(tonumber(now[2])/1000) then return 1 end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PEXPIREAT', KEYS[1], ARGV[2])
if ARGV[3] ~= '' then
  redis.call('SET', KEYS[2], ARGV[3])
  redis.call('PEXPIREAT', KEYS[2], ARGV[2])
  redis.call('ZADD', KEYS[3], ARGV[2], ARGV[4])
  local last = redis.call('ZRANGE', KEYS[3], -1, -1, 'WITHSCORES')
  redis.call('PEXPIREAT', KEYS[3], last[2])
end
return 0
`)

// CreateGrant atomically inserts the grant, first refresh secret and owner index.
func (s *RedisRefreshTokenStore) CreateGrant(ctx context.Context, g GrantData, hash string, r RefreshTokenData) error {
	if !validGrant(g) || g.Status != StatusActive || !g.ExpiresAt.After(time.Now()) ||
		(g.PrincipalType == PrincipalUser && (hash == "" || !refreshMatchesGrant(r, g) || r.Status != StatusActive || !r.ExpiresAt.After(time.Now()))) ||
		(g.PrincipalType == PrincipalClient && hash != "") {
		return ErrStoreUnavailable
	}
	grantJSON, err := json.Marshal(g)
	if err != nil {
		return ErrStoreUnavailable
	}
	var refreshJSON []byte
	if hash != "" {
		refreshJSON, err = json.Marshal(r)
		if err != nil {
			return ErrStoreUnavailable
		}
	}
	result, err := createGrantScript.Run(ctx, s.client,
		[]string{redisGrantPrefix + g.ID, redisRefreshPrefix + hash, redisUserPrefix + g.Subject},
		string(grantJSON), g.ExpiresAt.UnixMilli(), string(refreshJSON), g.ID).Int64()
	if err != nil {
		return storeError(err)
	}
	if result != 0 {
		return ErrStoreUnavailable
	}
	return nil
}

// GetGrant reads current authority without renewing the grant's expiry.
func (s *RedisRefreshTokenStore) GetGrant(ctx context.Context, id string) (GrantData, error) {
	raw, err := s.client.Get(ctx, redisGrantPrefix+id).Result()
	if errors.Is(err, redis.Nil) {
		return GrantData{}, ErrGrantNotFound
	}
	if err != nil {
		return GrantData{}, storeError(err)
	}
	var g GrantData
	if decodeState(raw, &g) != nil || g.ID != id || !validGrant(g) {
		return GrantData{}, ErrStoreUnavailable
	}
	if !g.ExpiresAt.After(time.Now()) {
		return GrantData{}, ErrGrantNotFound
	}
	return g, nil
}

// Get combines refresh metadata with current grant state, preserving reuse evidence.
func (s *RedisRefreshTokenStore) Get(ctx context.Context, hash string) (RefreshTokenData, error) {
	raw, err := s.client.Get(ctx, redisRefreshPrefix+hash).Result()
	if errors.Is(err, redis.Nil) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	if err != nil {
		return RefreshTokenData{}, storeError(err)
	}
	var r RefreshTokenData
	if decodeState(raw, &r) != nil || r.FamilyID == "" {
		return RefreshTokenData{}, ErrStoreUnavailable
	}
	g, err := s.GetGrant(ctx, r.FamilyID)
	if errors.Is(err, ErrGrantNotFound) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	if err != nil {
		return RefreshTokenData{}, err
	}
	if !refreshMatchesGrant(r, g) || (r.Status != StatusActive && r.Status != StatusRotated && r.Status != StatusRevoked) {
		return RefreshTokenData{}, ErrStoreUnavailable
	}
	if g.Status == StatusRevoked {
		r.Status = StatusRevoked
	}
	if r.Status == StatusActive && !r.ExpiresAt.After(time.Now()) {
		return RefreshTokenData{}, ErrRefreshTokenNotFound
	}
	return r, nil
}

// The old secret is retired and the successor is written in one operation.
// Keeping the grant key separate makes revocation fence all outstanding tokens.
var rotateRefreshScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
local grantRaw = redis.call('GET', KEYS[3])
if not raw or not grantRaw then return 1 end
local old = cjson.decode(raw)
local grant = cjson.decode(grantRaw)
if old.status ~= 'active' or grant.status == 'revoked' then return 2 end
if grant.status ~= 'active' or raw ~= ARGV[1] or grant.id ~= old.family_id then return 3 end
local now = redis.call('TIME')
local nowMS = tonumber(now[1])*1000 + math.floor(tonumber(now[2])/1000)
if tonumber(ARGV[3]) <= nowMS then return 1 end
if tonumber(ARGV[4]) <= nowMS or redis.call('EXISTS', KEYS[2]) == 1 then return 3 end
local ttl = redis.call('PTTL', KEYS[3])
if ttl <= 0 then return 1 end
old.status = 'rotated'
redis.call('SET', KEYS[1], cjson.encode(old), 'PX', ttl)
redis.call('SET', KEYS[2], ARGV[2], 'PX', ttl)
return 0
`)

// Rotate atomically retires the expected secret and persists its bound successor.
func (s *RedisRefreshTokenStore) Rotate(ctx context.Context, hash string, expected RefreshTokenData, nextHash string, next RefreshTokenData) error {
	if nextHash == "" || hash == nextHash || expected.Status != StatusActive || next.Status != StatusActive ||
		next.FamilyID != expected.FamilyID || next.UserID != expected.UserID || next.ClientID != expected.ClientID ||
		next.SessionID != expected.SessionID || next.Scope != expected.Scope || next.DPoPJKT != expected.DPoPJKT ||
		next.AuthVersion != expected.AuthVersion || !next.AuthVersionSet || !expected.AuthVersionSet {
		return ErrStoreUnavailable
	}
	g, err := s.GetGrant(ctx, expected.FamilyID)
	if errors.Is(err, ErrGrantNotFound) {
		return ErrRefreshTokenNotFound
	}
	if err != nil {
		return err
	}
	if g.Status == StatusRevoked {
		return ErrRefreshReuse
	}
	if !refreshMatchesGrant(expected, g) || !refreshMatchesGrant(next, g) {
		return ErrStoreUnavailable
	}
	oldJSON, err := json.Marshal(expected)
	if err != nil {
		return ErrStoreUnavailable
	}
	nextJSON, err := json.Marshal(next)
	if err != nil {
		return ErrStoreUnavailable
	}
	result, err := rotateRefreshScript.Run(ctx, s.client,
		[]string{redisRefreshPrefix + hash, redisRefreshPrefix + nextHash, redisGrantPrefix + expected.FamilyID},
		string(oldJSON), string(nextJSON), expected.ExpiresAt.UnixMilli(), next.ExpiresAt.UnixMilli()).Int64()
	if err != nil {
		return storeError(err)
	}
	switch result {
	case 0:
		return nil
	case 1:
		return ErrRefreshTokenNotFound
	case 2:
		return ErrRefreshReuse
	default:
		return ErrStoreUnavailable
	}
}

var revokeGrantScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local grant = cjson.decode(raw)
if grant.status ~= 'active' and grant.status ~= 'revoked' then return redis.error_reply('invalid grant state') end
grant.status = 'revoked'
redis.call('SET', KEYS[1], cjson.encode(grant), 'KEEPTTL')
return 0
`)

// RevokeFamily fences all tokens associated with an existing grant.
func (s *RedisRefreshTokenStore) RevokeFamily(ctx context.Context, id string) error {
	if _, err := revokeGrantScript.Run(ctx, s.client, []string{redisGrantPrefix + id}).Result(); err != nil {
		return storeError(err)
	}
	return nil
}

var revokeUserGrantsScript = redis.NewScript(`
local ids = redis.call('ZRANGE', KEYS[1], 0, -1)
local updates = {}
for _, id in ipairs(ids) do
  local key = ARGV[1] .. id
  local raw = redis.call('GET', key)
  if raw then
    local g = cjson.decode(raw)
    if g.principal_type ~= 'user' or g.subject ~= ARGV[2] then return redis.error_reply('invalid grant index') end
    g.status = 'revoked'
    table.insert(updates, {key, cjson.encode(g)})
  end
end
for _, update in ipairs(updates) do redis.call('SET', update[1], update[2], 'KEEPTTL') end
return 0
`)

// RevokeAllForUser invalidates indexed grants without scanning unrelated keys.
func (s *RedisRefreshTokenStore) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := revokeUserGrantsScript.Run(ctx, s.client, []string{redisUserPrefix + userID}, redisGrantPrefix, userID).Result()
	if err != nil {
		return storeError(err)
	}
	return nil
}

func decodeState(raw string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrStoreUnavailable
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrStoreUnavailable
	}
	return nil
}
