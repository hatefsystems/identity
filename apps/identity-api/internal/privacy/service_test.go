package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	svc      *Service
	store    *fakeStore
	cipher   Cipher
	notifier *fakeNotifier
	recorder *fakeRecorder
	sessions *fakeRevoker
	tokens   *fakeRevoker
	limiter  *fakeLimiter
	passkeys *fakePasskeys
	totp     *fakeTOTP
	guard    *fakeGuard
	clock    *testClock
}

// Real transaction/lock behavior is tested in the integration suite. These
// sequential fakes reproduce the SQL guards, including auth-version advancement.
func newHarness(t *testing.T, cfg Config, extra ...Option) *harness {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	h := &harness{store: newFakeStore(clock.now), cipher: newTestCipher(t), notifier: &fakeNotifier{},
		recorder: &fakeRecorder{}, sessions: &fakeRevoker{}, tokens: &fakeRevoker{}, limiter: newFakeLimiter(),
		passkeys: &fakePasskeys{}, totp: &fakeTOTP{accept: "123456"}, guard: newFakeGuard(), clock: clock}
	opts := append([]Option{WithSessionRevoker(h.sessions), WithTokenRevoker(h.tokens),
		WithRateLimiter(h.limiter), WithPasskeyReclaimer(h.passkeys), WithTOTPReclaimer(h.totp),
		WithReplayGuard(h.guard), WithLogger(discardLogger()), WithClock(clock.now)}, extra...)
	var err error
	h.svc, err = New(cfg, h.store, h.cipher, h.recorder, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) queuedNotice(t *testing.T) DeletionNotice {
	t.Helper()
	if len(h.store.notificationIDs) == 0 {
		t.Fatal("no queued notice")
	}
	row := h.store.notifications[h.store.notificationIDs[len(h.store.notificationIDs)-1]]
	request, ok := h.store.requestByID(row.RequestID)
	if !ok {
		t.Fatal("queued request missing")
	}
	plaintext, err := h.cipher.Decrypt(t.Context(), row.PayloadEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	notice, err := decodeNotificationPayload(plaintext, row, request)
	if err != nil {
		t.Fatal(err)
	}
	return notice
}

func requestDeletionAndToken(t *testing.T, h *harness, email string) (string, string) {
	t.Helper()
	user := h.store.addActiveUser(email)
	if _, err := h.svc.RequestDeletion(t.Context(), user.ID, user.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	return h.queuedNotice(t).ReclaimToken, user.ID.String()
}

func TestNewAndRecoveryOnly(t *testing.T) {
	store, cipher, recorder := newFakeStore(time.Now), newTestCipher(t), &fakeRecorder{}
	if _, err := New(Config{}, nil, cipher, recorder); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := New(Config{}, store, cipher, nil); err == nil {
		t.Fatal("nil recorder accepted")
	}
	if _, err := New(Config{ReclaimMaxAttempts: math.MaxInt32 + 1}, store, cipher, recorder); err == nil {
		t.Fatal("overflowing attempt limit accepted")
	}
	recoveryOnly, err := New(Config{}, store, nil, recorder)
	if err != nil {
		t.Fatal(err)
	}
	u := store.addActiveUser("disabled@example.test")
	if _, err := recoveryOnly.RequestDeletion(t.Context(), u.ID, u.AuthVersion, ""); !errors.Is(err, ErrDeletionUnavailable) || store.user(u.ID).Status != "active" {
		t.Fatal("recovery-only service did not fail closed")
	}
	h := newHarness(t, Config{})
	if h.svc.GracePeriod() != defaultGracePeriod || h.svc.reclaimMaxAttempts != defaultReclaimMaxAttempts {
		t.Fatal("policy defaults changed")
	}
	token, _ := requestDeletionAndToken(t, h, "recovery-only@example.test")
	h.svc.cipher = nil
	if _, err := h.svc.ReclaimOptions(t.Context(), token, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatal("disabling new deletion stranded existing recovery", err)
	}
}

func TestDeletionQueuesEncryptedNoticeAndRevokes(t *testing.T) {
	h := newHarness(t, Config{})
	user := h.store.addActiveUser("delete-me@example.test")
	result, err := h.svc.RequestDeletion(t.Context(), user.ID, user.AuthVersion, "203.0.113.10")
	if err != nil || result.AlreadyPending || !result.TokenMinted || !result.NotificationQueued {
		t.Fatalf("deletion outcome: %+v, %v", result, err)
	}
	stored := h.store.user(user.ID)
	if stored.Status != statusPendingDeletion || stored.AuthVersion != user.AuthVersion+1 || !stored.DeletedAt.Valid ||
		!result.ExpiresAt.Equal(stored.DeletedAt.Time.Add(defaultGracePeriod)) {
		t.Fatal("deletion state, version, or original deadline incorrect")
	}
	if h.sessions.count() != 1 || h.tokens.count() != 1 || h.notifier.count() != 0 || len(h.store.notifications) != 1 {
		t.Fatal("deletion did not revoke and queue without synchronous delivery")
	}
	notice := h.queuedNotice(t)
	request := h.store.requests[0]
	if notice.DeliveryID == uuid.Nil || notice.PrimaryEmail != user.Email || notice.BackupEmail != nil ||
		!validReclaimToken(notice.ReclaimToken) || HashReclaimToken(notice.ReclaimToken) != request.TokenHash || request.NotifiedAt.Valid {
		t.Fatal("queued token/recipient binding incorrect or falsely reported sent")
	}
	row := h.store.notifications[notice.DeliveryID]
	for _, secret := range []string{user.Email, notice.ReclaimToken} {
		if bytes.Contains(row.PayloadEncrypted, []byte(secret)) {
			t.Fatal("notification material was persisted unencrypted")
		}
		encoded, err := json.Marshal(h.recorder.events)
		if err != nil || bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("notification secret entered audit")
		}
	}
	if len(h.store.intents) != 1 || stored.LifecycleRevision != 1 {
		t.Fatal("reversible lifecycle event missing")
	}
	event, err := lifecycle.UnmarshalEvent([]byte(h.store.intents[0].Payload))
	if err != nil || event.EventType != lifecycle.SubjectUpdated || event.GetRevision() != 1 || event.UserId != user.ID.String() {
		t.Fatal("invalid lifecycle event", err)
	}
}

func TestDeletionCoalescesWithoutRotationOrDeadlineReset(t *testing.T) {
	h := newHarness(t, Config{})
	token, id := requestDeletionAndToken(t, h, "duplicate@example.test")
	userID := mustParseUUID(t, id)
	first := h.store.user(userID)
	firstRequest := h.store.requests[0]
	for _, advance := range []time.Duration{0, 30 * time.Minute, 2 * time.Hour} {
		h.clock.advance(advance)
		result, err := h.svc.RequestDeletion(t.Context(), userID, 0, "")
		if err != nil || !result.AlreadyPending || result.TokenMinted || !result.NotificationQueued || !result.ExpiresAt.Equal(firstRequest.ExpiresAt.Time) {
			t.Fatalf("duplicate did not coalesce: %+v, %v", result, err)
		}
	}
	if len(h.store.requests) != 1 || len(h.store.notifications) != 1 || len(h.store.intents) != 1 ||
		h.queuedNotice(t).ReclaimToken != token || !h.store.user(userID).DeletedAt.Time.Equal(first.DeletedAt.Time) {
		t.Fatal("duplicate rotated token, re-enqueued, or moved deletion deadline")
	}
	if _, err := h.store.ConsumeDeletionRequest(t.Context(), firstRequest.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.RequestDeletion(t.Context(), userID, 0, ""); !errors.Is(err, ErrStaleAuthority) || len(h.store.requests) != 1 {
		t.Fatal("retired token was replaced by an admitted duplicate")
	}
}

func TestDeletionRejectsStaleAuthority(t *testing.T) {
	for _, change := range []string{"version", "suspended", "banned", "deleted", "negative", "overflow"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser("authority@example.test")
			expected := u.AuthVersion
			switch change {
			case "version":
				u.AuthVersion++
			case "suspended", "banned":
				u.Status = change
			case "deleted":
				u.DeletedAt = ts(h.clock.now())
			case "negative":
				expected = -1
			case "overflow":
				expected = math.MaxInt64
			}
			h.store.users[u.ID] = u
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, expected, ""); !errors.Is(err, ErrStaleAuthority) {
				t.Fatal("stale admission accepted", err)
			}
			if len(h.store.requests)+len(h.store.notifications)+len(h.store.intents)+h.sessions.count() != 0 {
				t.Fatal("stale admission produced side effects")
			}
		})
	}
}

func TestDeletionRecipientsAndFailures(t *testing.T) {
	for _, backup := range []string{"other@example.test", "PRIMARY@example.test", "primary@example.test", "primary@EXAMPLE.test", "", "bad\r\naddress@example.test", "backup@localhost", "backup@[127.0.0.1]", strings.Repeat("a", 65) + "@example.test"} {
		t.Run(backup, func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser("primary@example.test")
			var err error
			u.BackupEmailEncrypted, err = h.cipher.Encrypt(t.Context(), []byte(backup))
			if err != nil {
				t.Fatal(err)
			}
			h.store.users[u.ID] = u
			_, err = h.svc.RequestDeletion(t.Context(), u.ID, u.AuthVersion, "")
			if !validNotificationAddress(backup) {
				if err == nil || h.store.user(u.ID).Status != "active" {
					t.Fatal("invalid configured backup was silently omitted")
				}
				return
			}
			want := 2
			if backup == "primary@example.test" || backup == "primary@EXAMPLE.test" {
				want = 1
			}
			if err != nil || len(h.store.notifications) != want {
				t.Fatal("server-selected recipient count incorrect", err)
			}
		})
	}
	t.Run("backup decryption", func(t *testing.T) {
		h := newHarness(t, Config{})
		u := h.store.addActiveUser("backup-fault@example.test")
		u.BackupEmailEncrypted = []byte("unavailable envelope")
		h.store.users[u.ID] = u
		if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, ""); err == nil || h.store.user(u.ID).Status != "active" {
			t.Fatal("backup decryption failure was ignored")
		}
	})
	for _, stage := range []string{"encryption", "queue", "lifecycle"} {
		t.Run(stage, func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser("fault@example.test")
			switch stage {
			case "encryption":
				h.svc.cipher = failingCipher{Cipher: h.cipher, encryptErr: errBoom}
			case "queue":
				h.store.enqueueErr = errBoom
			case "lifecycle":
				h.store.lifecycleErr = errBoom
			}
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, ""); err == nil {
				t.Fatal("persistence fault accepted")
			}
			if h.sessions.count()+h.tokens.count()+len(h.store.notifications) != 0 || h.recorder.countOf(audit.EventDeletionRequested, audit.StatusSuccess) != 0 {
				t.Fatal("precommit fault produced success effects")
			}
		})
	}
}

func TestDeletionRejectsRecipientsUnsupportedBySMTPBeforeMutation(t *testing.T) {
	for _, address := range []string{"user@localhost", "user@127.0.0.1", "user@[127.0.0.1]", "\"user\"@example.test", strings.Repeat("a", 65) + "@example.test"} {
		t.Run(address, func(t *testing.T) {
			h := newHarness(t, Config{})
			u := h.store.addActiveUser(address)
			if _, err := h.svc.RequestDeletion(t.Context(), u.ID, u.AuthVersion, ""); err == nil {
				t.Fatal("undeliverable recipient accepted")
			}
			if h.store.user(u.ID).Status != "active" || h.store.user(u.ID).AuthVersion != u.AuthVersion || len(h.store.requests)+len(h.store.notifications)+len(h.store.intents) != 0 {
				t.Fatal("unsupported recipient mutated deletion state")
			}
		})
	}
}

func TestDeletionUnknownRateLimitedAndRevokerFailure(t *testing.T) {
	h := newHarness(t, Config{DeletePerAccountPerDay: 3})
	if _, err := h.svc.RequestDeletion(t.Context(), newUUID(), 0, ""); !errors.Is(err, ErrUserNotFound) {
		t.Fatal(err)
	}
	u := h.store.addActiveUser("limited@example.test")
	h.limiter.deny[deleteAccountRateKey(u.ID)] = true
	if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, ""); !errors.Is(err, ErrRateLimited) || h.store.user(u.ID).Status != "active" {
		t.Fatal("rate limit changed account", err)
	}
	call := h.limiter.calls[len(h.limiter.calls)-1]
	if call.window != 24*time.Hour || call.limit != 3 {
		t.Fatal("deletion rate policy changed")
	}
	delete(h.limiter.deny, deleteAccountRateKey(u.ID))
	h.sessions.err, h.tokens.err = errBoom, errBoom
	if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, ""); err != nil || h.store.user(u.ID).Status != statusPendingDeletion {
		t.Fatal("postcommit revoker failure reported failed deletion", err)
	}
	if h.recorder.countOf(audit.EventDeletionRequested, audit.StatusFailure) != 2 {
		t.Fatal("cleanup failures were not audited")
	}
}

func TestRevocationUsesBoundedCleanupContext(t *testing.T) {
	h := newHarness(t, Config{})
	u := h.store.addActiveUser("cleanup@example.test")
	type requestKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), requestKey{}, "request-value"))
	cancel()
	var contexts []context.Context
	for _, revoker := range []*fakeRevoker{h.sessions, h.tokens} {
		revoker.onRevoke = func(cleanup context.Context, userID string) {
			deadline, ok := cleanup.Deadline()
			if cleanup.Err() != nil || userID != u.ID.String() || cleanup.Value(requestKey{}) != "request-value" ||
				!ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
				t.Error("cleanup lost context values or bounded independent lifetime")
			}
			contexts = append(contexts, cleanup)
		}
	}
	h.svc.revokeEverything(ctx, u.ID)
	if len(contexts) != 2 || contexts[0] != contexts[1] || !errors.Is(contexts[0].Err(), context.Canceled) {
		t.Fatal("cleanup contexts were not shared and canceled")
	}
}

func TestReclaimOptionsFactorPolicyAndRequestBinding(t *testing.T) {
	for _, factor := range []string{FactorWebAuthn, FactorTOTP, "none"} {
		t.Run(factor, func(t *testing.T) {
			h := newHarness(t, Config{})
			token, id := requestDeletionAndToken(t, h, "factors@example.test")
			uid := mustParseUUID(t, id)
			if factor != FactorWebAuthn {
				h.passkeys.beginErr = webauthn.ErrNoCredentials
				u := h.store.user(uid)
				u.IsMfaEnabled = factor == FactorTOTP
				h.store.users[uid] = u
			}
			for range 2 {
				challenge, err := h.svc.ReclaimOptions(t.Context(), token, "")
				if factor == "none" {
					if !errors.Is(err, ErrInvalidToken) {
						t.Fatal("factor inventory disclosed", err)
					}
					return
				}
				if err != nil || challenge.Factor != factor || (challenge.WebAuthn != nil) != (factor == FactorWebAuthn) {
					t.Fatal("wrong factor offered", err)
				}
			}
			if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: factor, Code: "123456"}); err != nil {
				t.Fatal(err)
			}
			if factor == FactorWebAuthn && h.passkeys.beginCalls[0] != h.passkeys.finishCalls[0] {
				t.Fatal("ceremony not bound to exact request")
			}
			if h.store.user(uid).Status != "active" || h.store.user(uid).AuthVersion != 2 || h.store.user(uid).DeletedAt.Valid {
				t.Fatal("reclaim did not advance authority and restore state")
			}
			if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: factor}); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("reclaim token was reusable")
			}
		})
	}
}

func TestReclaimTokenFailuresAreOpaque(t *testing.T) {
	for _, mode := range []string{"empty", "malformed", "unknown", "expired", "consumed", "status", "deletion_time", "version", "attempts"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{})
			token, id := requestDeletionAndToken(t, h, "opaque@example.test")
			uid := mustParseUUID(t, id)
			u := h.store.user(uid)
			switch mode {
			case "empty":
				token = ""
			case "malformed":
				token += "="
			case "unknown":
				token, _, _ = NewReclaimToken()
			case "expired":
				h.clock.advance(defaultGracePeriod)
			case "consumed":
				h.store.requests[0].ConsumedAt = ts(h.clock.now())
			case "status":
				u.Status = "suspended"
			case "deletion_time":
				u.DeletedAt = ts(u.DeletedAt.Time.Add(time.Second))
			case "version":
				u.AuthVersion++
			case "attempts":
				h.store.requests[0].FailedAttempts = defaultReclaimMaxAttempts
			}
			h.store.users[uid] = u
			if _, err := h.svc.ReclaimOptions(t.Context(), token, ""); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("options error was not opaque", err)
			}
			if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) || h.passkeys.finishCallCount() != 0 {
				t.Fatal("invalid token reached factor verification", err)
			}
		})
	}
}

func TestReclaimChecksExactRequestAfterFactorAndLockWait(t *testing.T) {
	for _, race := range []string{"consume", "attempt_cap", "replace", "hash", "expiry", "status", "deadline_during_lock"} {
		t.Run(race, func(t *testing.T) {
			h := newHarness(t, Config{})
			token, id := requestDeletionAndToken(t, h, "inflight@example.test")
			uid := mustParseUUID(t, id)
			h.passkeys.onFinish = func() {
				switch race {
				case "consume":
					h.store.requests[0].ConsumedAt = ts(h.clock.now())
				case "attempt_cap":
					r := h.store.requests[0]
					for range defaultReclaimMaxAttempts {
						if _, err := h.store.RecordDeletionRequestFailure(t.Context(), db.RecordDeletionRequestFailureParams{ID: r.ID, UserID: r.UserID, TokenHash: r.TokenHash, MaxAttempts: defaultReclaimMaxAttempts}); err != nil {
							t.Fatal(err)
						}
					}
				case "replace":
					h.store.requests[0].ID = uuid.New()
				case "hash":
					h.store.requests[0].TokenHash = HashReclaimToken("another-token")
				case "expiry":
					h.store.requests[0].ExpiresAt = ts(h.store.requests[0].ExpiresAt.Time.Add(time.Second))
				case "status":
					u := h.store.user(uid)
					u.Status = "banned"
					h.store.users[uid] = u
				case "deadline_during_lock":
					h.store.onLockRequest = func() { h.clock.advance(defaultGracePeriod) }
				}
			}
			if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
				t.Fatal("stale in-flight factor restored account", err)
			}
			if h.store.user(uid).Status == "active" || h.recorder.countOf(audit.EventDeletionReclaimed, audit.StatusSuccess) != 0 {
				t.Fatal("invalidated request reported restoration")
			}
		})
	}
}

func TestReclaimAttemptCapIsAtomicAndAuditsActualCount(t *testing.T) {
	h := newHarness(t, Config{ReclaimMaxAttempts: 3})
	token, _ := requestDeletionAndToken(t, h, "attempts@example.test")
	h.passkeys.finishErr = webauthn.ErrVerification
	for i := 1; i <= 3; i++ {
		if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
		r := h.store.requests[0]
		event, ok := h.recorder.lastOf(audit.EventDeletionReclaimFailed)
		if r.FailedAttempts != int32(i) || r.ConsumedAt.Valid != (i == 3) || !ok || event.Payload["attempts"] != i || event.Payload["exhausted"] != (i == 3) {
			t.Fatal("attempt count/retirement/audit inconsistent")
		}
	}
	h.passkeys.finishErr = nil
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("correct factor revived exhausted request")
	}
}

func TestReclaimFailedAttemptAndInfrastructure(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "retry-factor@example.test")
	h.passkeys.finishErr = webauthn.ErrVerification
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) || h.store.requests[0].ConsumedAt.Valid {
		t.Fatal("one rejected factor destroyed recovery", err)
	}
	h.passkeys.finishErr = errBoom
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, errBoom) || h.store.requests[0].FailedAttempts != 1 {
		t.Fatal("infrastructure error spent attempts", err)
	}
	h.passkeys.finishErr = nil
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatal(err)
	}
}

func TestReclaimTOTPReplayAndGuardFailure(t *testing.T) {
	h := newHarness(t, Config{})
	token, id := requestDeletionAndToken(t, h, "totp@example.test")
	uid := mustParseUUID(t, id)
	h.guard.err = errBoom
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); err == nil || errors.Is(err, ErrInvalidToken) || h.store.incrementCalls != 0 {
		t.Fatal("replay infrastructure spent attempts", err)
	}
	h.guard.err = nil
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); err != nil {
		t.Fatal(err)
	}
	u := h.store.user(uid)
	if _, err := h.svc.RequestDeletion(t.Context(), uid, u.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	attempts := h.totp.attemptCount()
	if err := h.svc.Reclaim(t.Context(), h.queuedNotice(t).ReclaimToken, ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); !errors.Is(err, ErrInvalidToken) || h.totp.attemptCount() != attempts {
		t.Fatal("replayed TOTP reached verifier", err)
	}
}

func TestReclaimRateLimitsSubnetFirst(t *testing.T) {
	h := newHarness(t, Config{ReclaimPerAccountPerHour: 4, ReclaimPerSubnetPerHour: 9})
	token, id := requestDeletionAndToken(t, h, "rates@example.test")
	uid := mustParseUUID(t, id)
	h.limiter.calls = nil
	if _, err := h.svc.ReclaimOptions(t.Context(), token, "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	keys := h.limiter.keys()
	if len(keys) != 2 || keys[0] != reclaimSubnetRateKey("203.0.113.0/24") || keys[1] != reclaimAccountRateKey(uid) || h.limiter.calls[0].limit != 9 || h.limiter.calls[1].limit != 4 {
		t.Fatal("rate limit order or policy changed")
	}
	h.limiter.calls = nil
	h.limiter.deny[keys[0]] = true
	if _, err := h.svc.ReclaimOptions(t.Context(), token, "203.0.113.10"); !errors.Is(err, ErrRateLimited) || len(h.limiter.calls) != 1 {
		t.Fatal("saturated subnet consumed account budget", err)
	}
	delete(h.limiter.deny, keys[0])
	h.limiter.deny[keys[1]] = true
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrRateLimited) || h.passkeys.finishCallCount() != 0 {
		t.Fatal("account rate limit did not stop verification", err)
	}
}

func TestReclaimUnsupportedFactorAuditAndBookkeepingFailure(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "audit@example.test")
	secret := "private-address@example.test"
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: secret}); !errors.Is(err, ErrInvalidToken) {
		t.Fatal(err)
	}
	event, _ := h.recorder.lastOf(audit.EventDeletionReclaimFailed)
	if event.Payload["factor"] != "unsupported" {
		t.Fatal("untrusted factor value entered audit")
	}
	h.store.incrementErr = errBoom
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: "password"}); !errors.Is(err, ErrInvalidToken) || h.recorder.countOf(audit.EventDeletionReclaimFailed, audit.StatusFailure) != 1 {
		t.Fatal("failed bookkeeping invented an audited attempt count", err)
	}
}

func TestLegacyRequestStillRecoversWithoutQueueOrCapturedVersion(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "legacy@example.test")
	h.store.requests[0].RequestedAuthVersion = nil
	h.store.notifications = nil
	h.svc.cipher = nil
	if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatal("legacy hash-only request stranded", err)
	}
}

func TestMissingDeletedAtCannotReclaim(t *testing.T) {
	h := newHarness(t, Config{})
	token, id := requestDeletionAndToken(t, h, "missing-timestamp@example.test")
	uid := mustParseUUID(t, id)
	u := h.store.user(uid)
	u.DeletedAt = pgtype.Timestamptz{}
	h.store.users[uid] = u
	if _, err := h.svc.ReclaimOptions(t.Context(), token, ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatal(err)
	}
	if _, err := h.store.GetActiveDeletionRequestByTokenHashForUpdate(t.Context(), HashReclaimToken(token)); errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("test did not retain the apparently live request")
	}
}
