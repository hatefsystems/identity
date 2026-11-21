package login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Pending is bounded preauthentication state, not a session or access grant.
type Pending struct {
	Issue     session.IssueParams `json:"issue"`
	ExpiresAt time.Time           `json:"expires_at"`
	Contact   *ContactBinding     `json:"contact,omitempty"`
}

// ContactBinding retains the exact consumed proof until final session issuance.
// It stays in private preauthentication state and never enters a normal session.
type ContactBinding struct {
	Channel     string `json:"channel"`
	Destination string `json:"destination"`
}

// PendingStore preserves deadlines/attempts and admits one completion at a time.
type PendingStore interface {
	Create(context.Context, string, Pending) error
	Claim(context.Context, string, string, string) (Pending, error)
	Release(context.Context, string, string) error
	Consume(context.Context, string, string) error
}

// RedisPending is shared, fixed-lifetime, no-retry MFA challenge authority.
type RedisPending struct{ client *redis.Client }

// NewRedisPending rejects clients configured to retry uncertain mutations.
func NewRedisPending(client *redis.Client) (*RedisPending, error) {
	if client == nil || client.Options().MaxRetries > 0 {
		return nil, ErrUnavailable
	}
	return &RedisPending{client: client}, nil
}

func pendingKey(handle string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(handle)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != handle {
		return "", ErrChallengeExpired
	}
	digest := sha256.Sum256(raw)
	return "login:preauth:v1:" + hex.EncodeToString(digest[:]), nil
}

const pendingCapacityKey = "login:preauth:capacity:v1"
const createPendingLua = `
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
local deadline=tonumber(ARGV[3])
if deadline<=now or deadline>now+300000 then return 0 end
redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',now)
if redis.call('ZCARD',KEYS[2])>=10000 or redis.call('EXISTS',KEYS[1])~=0 then return 0 end
redis.call('HSET',KEYS[1],'purpose','login_mfa','jkt',ARGV[2],'payload',ARGV[1],'deadline',ARGV[3],'attempts','0','claim','')
redis.call('PEXPIREAT',KEYS[1],deadline)
redis.call('ZADD',KEYS[2],deadline,KEYS[1]); redis.call('PEXPIRE',KEYS[2],300000)
return 1`

// Create atomically admits a new challenge under a finite shared capacity.
func (s *RedisPending) Create(ctx context.Context, handle string, pending Pending) error {
	key, err := pendingKey(handle)
	if err != nil {
		return err
	}
	body, err := json.Marshal(pending)
	if err != nil || len(body) > 4096 {
		return ErrUnavailable
	}
	result, err := s.client.Eval(ctx, createPendingLua, []string{key, pendingCapacityKey}, string(body), pending.Issue.DPoPJKT, pending.ExpiresAt.UnixMilli()).Int()
	if err != nil {
		return ErrOutcomeUnknown
	}
	if result != 1 {
		return ErrUnavailable
	}
	return nil
}

const claimPendingLua = `
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
if redis.call('HLEN',KEYS[1])~=6 or redis.call('HGET',KEYS[1],'purpose')~='login_mfa' or redis.call('HGET',KEYS[1],'jkt')~=ARGV[1] then return false end
local deadline=tonumber(redis.call('HGET',KEYS[1],'deadline')); local attempts=tonumber(redis.call('HGET',KEYS[1],'attempts'))
if not deadline or not attempts or deadline<=now or attempts>=3 or redis.call('HGET',KEYS[1],'claim')~='' then return false end
redis.call('HINCRBY',KEYS[1],'attempts',1); redis.call('HSET',KEYS[1],'claim',ARGV[2]); return redis.call('HGET',KEYS[1],'payload')`

// Claim spends one original attempt and exclusively reserves its completion.
func (s *RedisPending) Claim(ctx context.Context, handle, jkt, claim string) (Pending, error) {
	key, err := pendingKey(handle)
	if err != nil {
		return Pending{}, err
	}
	body, err := s.client.Eval(ctx, claimPendingLua, []string{key}, jkt, claim).Text()
	if err == redis.Nil {
		return Pending{}, ErrChallengeExpired
	}
	if err != nil {
		return Pending{}, ErrOutcomeUnknown
	}
	var p Pending
	if len(body) > 4096 || json.Unmarshal([]byte(body), &p) != nil || !p.Issue.AuthVersionSet || p.Issue.DPoPJKT != jkt || p.ExpiresAt.IsZero() || p.Issue.Evidence.AuthenticatedAt.IsZero() {
		return Pending{}, ErrChallengeExpired
	}
	return p, nil
}

const finishPendingLua = `
local t=redis.call('TIME'); local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
if redis.call('HGET',KEYS[1],'purpose')~='login_mfa' or redis.call('HGET',KEYS[1],'claim')~=ARGV[1] then return 0 end
local deadline=tonumber(redis.call('HGET',KEYS[1],'deadline'))
if not deadline or deadline<=now then return 0 end
if ARGV[2]=='consume' then redis.call('DEL',KEYS[1]); redis.call('ZREM',KEYS[2],KEYS[1]) else redis.call('HSET',KEYS[1],'claim','') end
return 1`

func (s *RedisPending) finish(ctx context.Context, handle, claim, action string) error {
	key, err := pendingKey(handle)
	if err != nil {
		return err
	}
	result, err := s.client.Eval(ctx, finishPendingLua, []string{key, pendingCapacityKey}, claim, action).Int()
	if err != nil {
		return ErrOutcomeUnknown
	}
	if result != 1 {
		return ErrChallengeExpired
	}
	return nil
}

// Release allows a definitive failed proof to retry within its remaining budget.
func (s *RedisPending) Release(ctx context.Context, handle, claim string) error {
	return s.finish(ctx, handle, claim, "release")
}

// Consume permanently removes the successfully verified challenge before issuance.
func (s *RedisPending) Consume(ctx context.Context, handle, claim string) error {
	return s.finish(ctx, handle, claim, "consume")
}
