package login

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func TestRedisPendingRequiresExplicitNoRetryClient(t *testing.T) {
	if _, err := NewRedisPending(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil Redis admitted")
	}
	for _, retries := range []int{0, 1, 3, -1} {
		client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: retries})
		_, err := NewRedisPending(client)
		_ = client.Close()
		if retries == -1 {
			if err != nil {
				t.Fatalf("explicit no-retry client rejected after normalization: %v", err)
			}
		} else if !errors.Is(err, ErrUnavailable) {
			t.Fatal("retrying mutation client admitted")
		}
	}
}

func TestPendingKeyCanonicalOpaqueAndHashed(t *testing.T) {
	valid := testCapability('h')
	key, err := pendingKey(valid)
	if err != nil || !strings.HasPrefix(key, "login:preauth:v1:") || strings.Contains(key, valid) {
		t.Fatal("pending handle persisted unhashed")
	}
	for _, value := range []string{"", "plaintext", valid + "=", valid[:42], testCapability('h') + "A"} {
		if _, err := pendingKey(value); !errors.Is(err, ErrChallengeExpired) {
			t.Fatal("noncanonical capability admitted")
		}
	}
}

func TestPendingFixedExpiryAttemptsPurposeAndClaimOwnership(t *testing.T) {
	f := newLoginFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	f.redis.SetTime(now)
	p := Pending{Issue: session.IssueParams{UserID: f.users.user.ID.String(), AuthVersion: 7, AuthVersionSet: true, DPoPJKT: testCapability('b'), Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, AuthenticatedAt: now}}, ExpiresAt: now.Add(5 * time.Minute)}
	handle := testCapability('h')
	if err := f.pending.Create(t.Context(), handle, p); err != nil {
		t.Fatal(err)
	}
	key, err := pendingKey(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pending.Create(t.Context(), handle, p); !errors.Is(err, ErrUnavailable) {
		t.Fatal("existing pending reset attempts/deadline")
	}
	if _, err := f.pending.Claim(t.Context(), handle, testCapability('x'), "foreign"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatal("wrong browser claimed pending")
	}
	if got := f.redis.HGet(key, "attempts"); got != "0" {
		t.Fatal("wrong browser burned attempt")
	}
	for attempt := range 3 {
		claim := testCapability(byte('1' + attempt))
		got, err := f.pending.Claim(t.Context(), handle, p.Issue.DPoPJKT, claim)
		if err != nil || !got.ExpiresAt.Equal(p.ExpiresAt) || got.Issue.AuthVersion != 7 {
			t.Fatalf("captured state changed: %v", err)
		}
		if _, err := f.pending.Claim(t.Context(), handle, p.Issue.DPoPJKT, "competitor"); !errors.Is(err, ErrChallengeExpired) {
			t.Fatal("concurrent claim admitted")
		}
		if err := f.pending.Release(t.Context(), handle, "competitor"); !errors.Is(err, ErrChallengeExpired) {
			t.Fatal("foreign claim released pending")
		}
		if err := f.pending.Consume(t.Context(), handle, "competitor"); !errors.Is(err, ErrChallengeExpired) {
			t.Fatal("foreign claim consumed pending")
		}
		if err := f.pending.Release(t.Context(), handle, claim); err != nil {
			t.Fatal(err)
		}
		if f.redis.HGet(key, "deadline") != strconv.FormatInt(p.ExpiresAt.UnixMilli(), 10) || f.redis.TTL(key) != 5*time.Minute {
			t.Fatal("release extended original expiry")
		}
	}
	if _, err := f.pending.Claim(t.Context(), handle, p.Issue.DPoPJKT, "fourth"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatal("three-attempt limit reset")
	}

	second := testCapability('e')
	if err := f.pending.Create(t.Context(), second, p); err != nil {
		t.Fatal(err)
	}
	secondKey, _ := pendingKey(second)
	f.redis.HSet(secondKey, "purpose", "stepup")
	if _, err := f.pending.Claim(t.Context(), second, p.Issue.DPoPJKT, "purpose"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatal("wrong-purpose challenge admitted")
	}
	f.redis.HSet(secondKey, "purpose", "login_mfa")
	f.redis.SetTime(p.ExpiresAt)
	if _, err := f.pending.Claim(t.Context(), second, p.Issue.DPoPJKT, "expired"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatal("original deadline bypassed")
	}
}

type pendingLostReply struct {
	script string
	after  bool
	calls  atomic.Int32
}

func (*pendingLostReply) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}
func (h *pendingLostReply) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == "eval" && len(cmd.Args()) > 1 && cmd.Args()[1] == h.script {
			h.calls.Add(1)
			if h.after {
				if err := next(ctx, cmd); err != nil {
					return err
				}
			}
			return errors.New("mutation response lost")
		}
		return next(ctx, cmd)
	}
}
func (*pendingLostReply) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestPendingUnknownMutationIsNotRetriedOrReleased(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_commit", true: "after_commit"}[after], func(t *testing.T) {
			f := newLoginFixture(t)
			f.users.user.IsMfaEnabled = true
			first := f.prepare(t, session.MethodPassword)
			hook := &pendingLostReply{script: claimPendingLua, after: after}
			f.client.AddHook(hook)
			result, err := f.svc.CompleteMFA(t.Context(), first.Preauthentication, testCapability('b'), "123456")
			if !errors.Is(err, ErrOutcomeUnknown) || hook.calls.Load() != 1 || f.factor.calls.Load() != 0 {
				t.Fatalf("unknown claim granted/retried: %v", err)
			}
			requireNoAuthority(t, result)
			key, _ := pendingKey(first.Preauthentication)
			if after && f.redis.HGet(key, "claim") == "" {
				t.Fatal("uncertain claim released automatically")
			}
		})
	}
}
