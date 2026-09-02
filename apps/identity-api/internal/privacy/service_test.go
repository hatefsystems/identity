package privacy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// testClock is a manually advanced clock shared by the service and its fakes so
// cooldown and cutoff arithmetic is exact rather than wall-clock dependent.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// harness bundles a Service with every fake the tests inspect.
type harness struct {
	svc      *Service
	store    *fakeStore
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

// newHarness builds a Service with no Transacter: these are unit tests, so runInTx
// executes directly against the fake store. The atomicity claims that need a real
// transaction are covered in integration_test.go.
func newHarness(t *testing.T, cfg Config, extra ...Option) *harness {
	t.Helper()

	clock := &testClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	h := &harness{
		store:    newFakeStore(clock.now),
		notifier: &fakeNotifier{},
		recorder: &fakeRecorder{},
		sessions: &fakeRevoker{},
		tokens:   &fakeRevoker{},
		limiter:  newFakeLimiter(),
		passkeys: &fakePasskeys{},
		totp:     &fakeTOTP{accept: "123456"},
		guard:    newFakeGuard(),
		clock:    clock,
	}

	opts := append([]Option{
		WithSessionRevoker(h.sessions),
		WithTokenRevoker(h.tokens),
		WithRateLimiter(h.limiter),
		WithPasskeyReclaimer(h.passkeys),
		WithTOTPReclaimer(h.totp),
		WithReplayGuard(h.guard),
		WithLogger(discardLogger()),
		WithClock(clock.now),
	}, extra...)

	svc, err := New(cfg, h.store, h.notifier, h.recorder, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.svc = svc
	return h
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewRequiresCollaborators(t *testing.T) {
	store := newFakeStore(time.Now)
	notifier := &fakeNotifier{}
	recorder := &fakeRecorder{}

	if _, err := New(Config{}, nil, notifier, recorder); err == nil {
		t.Error("New with a nil store = nil error, want error")
	}
	// The notifier is required rather than optional: a deletion whose reclaim token
	// cannot be delivered has no recovery window, so there is no safe fallback mode.
	if _, err := New(Config{}, store, nil, recorder); err == nil {
		t.Error("New with a nil notifier = nil error, want error")
	}
	if _, err := New(Config{}, store, notifier, nil); err == nil {
		t.Error("New with a nil recorder = nil error, want error")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	h := newHarness(t, Config{})
	if got := h.svc.GracePeriod(); got != defaultGracePeriod {
		t.Errorf("GracePeriod = %v, want the %v default", got, defaultGracePeriod)
	}
	if h.svc.reclaimMaxAttempts != defaultReclaimMaxAttempts {
		t.Errorf("reclaimMaxAttempts = %d, want %d", h.svc.reclaimMaxAttempts, defaultReclaimMaxAttempts)
	}
	if h.svc.deleteResendCooldown != defaultDeleteResendCooldown {
		t.Errorf("deleteResendCooldown = %v, want %v", h.svc.deleteResendCooldown, defaultDeleteResendCooldown)
	}
}

// ---------------------------------------------------------------------------
// RequestDeletion
// ---------------------------------------------------------------------------

func TestRequestDeletionDeactivatesRevokesAndNotifies(t *testing.T) {
	h := newHarness(t, Config{GracePeriod: 720 * time.Hour})
	user := h.store.addActiveUser("delete-me@test.local")

	result, err := h.svc.RequestDeletion(context.Background(), user.ID, "203.0.113.10")
	if err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}

	if result.AlreadyPending {
		t.Error("AlreadyPending = true on a first request")
	}
	if !result.TokenMinted {
		t.Error("TokenMinted = false on a first request")
	}
	if !result.Notified {
		t.Error("Notified = false, want the notice to have been delivered")
	}

	stored := h.store.user(user.ID)
	if stored.Status != "pending_deletion" {
		t.Errorf("status = %q, want pending_deletion", stored.Status)
	}
	if !stored.DeletedAt.Valid {
		t.Error("deleted_at was not stamped")
	}

	// The token expiry must be derived from deleted_at, so it and the purge cutoff
	// cannot disagree.
	wantExpiry := stored.DeletedAt.Time.Add(720 * time.Hour)
	if !result.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want deleted_at + grace period = %v", result.ExpiresAt, wantExpiry)
	}

	if h.sessions.count() != 1 {
		t.Errorf("session revocations = %d, want 1", h.sessions.count())
	}
	if h.tokens.count() != 1 {
		t.Errorf("refresh-token revocations = %d, want 1", h.tokens.count())
	}
	if h.notifier.count() != 1 {
		t.Errorf("notices = %d, want 1", h.notifier.count())
	}
	if got := h.recorder.countOf(audit.EventDeletionRequested, audit.StatusSuccess); got != 1 {
		t.Errorf("%s success events = %d, want 1", audit.EventDeletionRequested, got)
	}

	// The plaintext token must reach the notice and only the hash the store.
	notice, ok := h.notifier.last()
	if !ok {
		t.Fatal("no notice recorded")
	}
	if notice.ReclaimToken == "" {
		t.Fatal("notice carries no reclaim token")
	}
	if notice.PrimaryEmail != user.Email {
		t.Errorf("notice PrimaryEmail = %q, want %q", notice.PrimaryEmail, user.Email)
	}
	request, err := h.store.GetActiveDeletionRequestByTokenHashForUpdate(
		context.Background(), HashReclaimToken(notice.ReclaimToken))
	if err != nil {
		t.Fatalf("the minted token does not resolve its request: %v", err)
	}
	if request.TokenHash == notice.ReclaimToken {
		t.Error("the store holds the plaintext token, not its hash")
	}
	if !request.NotifiedAt.Valid {
		t.Error("notified_at was not stamped after a successful send")
	}
}

// TestRequestDeletionIsIdempotentWithinCooldown is the anti-email-bomb property: a
// repeat request succeeds, does not deactivate twice, and does not mint or resend.
func TestRequestDeletionIsIdempotentWithinCooldown(t *testing.T) {
	h := newHarness(t, Config{GracePeriod: 720 * time.Hour, DeleteResendCooldown: time.Hour})
	user := h.store.addActiveUser("idempotent@test.local")

	first, err := h.svc.RequestDeletion(context.Background(), user.ID, "203.0.113.10")
	if err != nil {
		t.Fatalf("first RequestDeletion: %v", err)
	}
	firstDeletedAt := h.store.user(user.ID).DeletedAt.Time

	h.clock.advance(30 * time.Minute) // inside the 1h cooldown

	second, err := h.svc.RequestDeletion(context.Background(), user.ID, "203.0.113.10")
	if err != nil {
		t.Fatalf("second RequestDeletion: %v", err)
	}

	if !second.AlreadyPending {
		t.Error("AlreadyPending = false on a repeat request")
	}
	if second.TokenMinted {
		t.Error("TokenMinted = true inside the resend cooldown; that is an email bomb")
	}
	if second.Notified {
		t.Error("Notified = true inside the resend cooldown")
	}
	if h.notifier.count() != 1 {
		t.Errorf("notices = %d, want 1 (the repeat must not resend)", h.notifier.count())
	}
	if !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Errorf("ExpiresAt moved on a repeat: %v then %v", first.ExpiresAt, second.ExpiresAt)
	}
	// deleted_at must not be re-stamped, or the grace window would slide forward
	// every time the endpoint was called.
	if got := h.store.user(user.ID).DeletedAt.Time; !got.Equal(firstDeletedAt) {
		t.Errorf("deleted_at moved on a repeat: %v then %v", firstDeletedAt, got)
	}
}

// TestRequestDeletionResendsAfterCooldown covers the other half: a user who lost the
// first mail can get a replacement, and the superseded token stops working.
func TestRequestDeletionResendsAfterCooldown(t *testing.T) {
	h := newHarness(t, Config{GracePeriod: 720 * time.Hour, DeleteResendCooldown: time.Hour})
	user := h.store.addActiveUser("resend@test.local")

	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("first RequestDeletion: %v", err)
	}
	firstNotice, _ := h.notifier.last()

	h.clock.advance(2 * time.Hour) // outside the cooldown

	second, err := h.svc.RequestDeletion(context.Background(), user.ID, "")
	if err != nil {
		t.Fatalf("second RequestDeletion: %v", err)
	}
	if !second.AlreadyPending {
		t.Error("AlreadyPending = false on a repeat request")
	}
	if !second.TokenMinted {
		t.Error("TokenMinted = false outside the cooldown; a user who lost the mail cannot recover")
	}
	if h.notifier.count() != 2 {
		t.Errorf("notices = %d, want 2", h.notifier.count())
	}

	secondNotice, _ := h.notifier.last()
	if secondNotice.ReclaimToken == firstNotice.ReclaimToken {
		t.Error("the resend reused the previous token instead of minting a fresh one")
	}
	// Only the newest token may be live.
	if _, err := h.store.GetActiveDeletionRequestByTokenHashForUpdate(
		context.Background(), HashReclaimToken(firstNotice.ReclaimToken)); err == nil {
		t.Error("the superseded token is still active")
	}

	// The grace window must still be measured from the original deactivation, not
	// extended by the resend — otherwise repeated requests would postpone erasure
	// indefinitely.
	deletedAt := h.store.user(user.ID).DeletedAt.Time
	if !second.ExpiresAt.Equal(deletedAt.Add(720 * time.Hour)) {
		t.Errorf("ExpiresAt = %v, want the original deleted_at + grace period = %v",
			second.ExpiresAt, deletedAt.Add(720*time.Hour))
	}
}

// TestRequestDeletionSurvivesNotifierFailure pins the fail-safe direction: the
// deletion commits even when the mail fails, and the cooldown stays unarmed so the
// next call retries delivery.
func TestRequestDeletionSurvivesNotifierFailure(t *testing.T) {
	h := newHarness(t, Config{GracePeriod: 720 * time.Hour, DeleteResendCooldown: time.Hour})
	user := h.store.addActiveUser("nomail@test.local")
	h.notifier.err = errBoom

	result, err := h.svc.RequestDeletion(context.Background(), user.ID, "")
	if err != nil {
		t.Fatalf("RequestDeletion must not fail because the notifier did: %v", err)
	}
	if result.Notified {
		t.Error("Notified = true after a failed send")
	}
	if h.store.user(user.ID).Status != "pending_deletion" {
		t.Error("the deletion was rolled back by a notifier failure")
	}
	if got := h.recorder.countOf(audit.EventDeletionRequested, audit.StatusFailure); got == 0 {
		t.Error("a failed notification was not audited")
	}
	if h.store.notifiedCalls != 0 {
		t.Error("notified_at was stamped despite the send failing; the cooldown would suppress the retry")
	}

	// An unarmed cooldown means the immediate next call retries the send.
	h.notifier.err = nil
	second, err := h.svc.RequestDeletion(context.Background(), user.ID, "")
	if err != nil {
		t.Fatalf("retry RequestDeletion: %v", err)
	}
	if !second.Notified {
		t.Error("the retry did not attempt delivery even though no notice was ever delivered")
	}
}

// TestRequestDeletionSurvivesRevokerFailure: revocation failures are audited but
// must not undo a committed deletion.
func TestRequestDeletionSurvivesRevokerFailure(t *testing.T) {
	h := newHarness(t, Config{})
	user := h.store.addActiveUser("norevoke@test.local")
	h.sessions.err = errBoom
	h.tokens.err = errBoom

	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion must not fail because revocation did: %v", err)
	}
	if h.store.user(user.ID).Status != "pending_deletion" {
		t.Error("the deletion was rolled back by a revocation failure")
	}
	if got := h.recorder.countOf(audit.EventDeletionRequested, audit.StatusFailure); got != 2 {
		t.Errorf("revocation failure events = %d, want 2 (sessions and refresh tokens)", got)
	}
}

func TestRequestDeletionUnknownUser(t *testing.T) {
	h := newHarness(t, Config{})
	if _, err := h.svc.RequestDeletion(context.Background(), h.store.addActiveUser("x@test.local").ID, ""); err != nil {
		t.Fatalf("sanity RequestDeletion: %v", err)
	}
	if _, err := h.svc.RequestDeletion(context.Background(), newUUID(), ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("RequestDeletion for an unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestRequestDeletionRateLimited(t *testing.T) {
	h := newHarness(t, Config{DeletePerAccountPerDay: 3})
	user := h.store.addActiveUser("throttled@test.local")
	h.limiter.deny[deleteAccountRateKey(user.ID)] = true

	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("RequestDeletion = %v, want ErrRateLimited", err)
	}
	// Nothing may happen once the limit is saturated.
	if h.store.user(user.ID).Status != "active" {
		t.Error("a rate-limited request still deactivated the account")
	}
	if h.notifier.count() != 0 {
		t.Error("a rate-limited request still sent a notice")
	}

	calls := h.limiter.keys()
	if len(calls) != 1 || calls[0] != deleteAccountRateKey(user.ID) {
		t.Errorf("limiter calls = %v, want exactly the per-account key", calls)
	}
	if h.limiter.calls[0].window != 24*time.Hour {
		t.Errorf("delete limit window = %v, want 24h", h.limiter.calls[0].window)
	}
	if h.limiter.calls[0].limit != 3 {
		t.Errorf("delete limit = %d, want the configured 3", h.limiter.calls[0].limit)
	}
}

// ---------------------------------------------------------------------------
// ReclaimOptions
// ---------------------------------------------------------------------------

// requestDeletionAndToken drives a deletion and returns the plaintext reclaim token
// the user would have received.
func requestDeletionAndToken(t *testing.T, h *harness, email string) (string, string) {
	t.Helper()
	user := h.store.addActiveUser(email)
	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, ok := h.notifier.last()
	if !ok {
		t.Fatal("no notice recorded")
	}
	return notice.ReclaimToken, user.ID.String()
}

func TestReclaimOptionsPrefersWebAuthn(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "passkey@test.local")

	challenge, err := h.svc.ReclaimOptions(context.Background(), token, "203.0.113.10")
	if err != nil {
		t.Fatalf("ReclaimOptions: %v", err)
	}
	if challenge.Factor != FactorWebAuthn {
		t.Errorf("Factor = %q, want %q", challenge.Factor, FactorWebAuthn)
	}
	if challenge.WebAuthn == nil {
		t.Error("WebAuthn options are nil for the webauthn factor")
	}
}

// TestReclaimOptionsFallsBackToTOTP covers the passkey-less account: the WebAuthn
// ceremony reports "no credentials", which must not fail the request.
func TestReclaimOptionsFallsBackToTOTP(t *testing.T) {
	h := newHarness(t, Config{})
	h.passkeys.beginErr = webauthn.ErrNoCredentials

	user := h.store.addActiveUser("totp@test.local")
	u := h.store.user(user.ID)
	u.IsMfaEnabled = true
	h.store.users[user.ID] = u

	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := h.notifier.last()

	challenge, err := h.svc.ReclaimOptions(context.Background(), notice.ReclaimToken, "")
	if err != nil {
		t.Fatalf("ReclaimOptions: %v", err)
	}
	if challenge.Factor != FactorTOTP {
		t.Errorf("Factor = %q, want %q", challenge.Factor, FactorTOTP)
	}
	if challenge.WebAuthn != nil {
		t.Error("WebAuthn options are set for the totp factor")
	}
}

// TestReclaimOptionsNoFactorIsOpaque is the factor-inventory guard: an account with
// neither a passkey nor TOTP must look exactly like an invalid token.
func TestReclaimOptionsNoFactorIsOpaque(t *testing.T) {
	h := newHarness(t, Config{})
	h.passkeys.beginErr = webauthn.ErrNoCredentials
	// IsMfaEnabled stays false, so no factor is available.
	token, _ := requestDeletionAndToken(t, h, "nofactor@test.local")

	_, err := h.svc.ReclaimOptions(context.Background(), token, "")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ReclaimOptions with no factor = %v, want ErrInvalidToken", err)
	}
}

// TestReclaimOptionsDoesNotConsume: a user who abandons the ceremony halfway must be
// able to restart it, so listing the factor must leave the token usable.
func TestReclaimOptionsDoesNotConsume(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "abandon@test.local")

	for i := 0; i < 3; i++ {
		if _, err := h.svc.ReclaimOptions(context.Background(), token, ""); err != nil {
			t.Fatalf("ReclaimOptions call %d: %v", i+1, err)
		}
	}
	if err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim after repeated options calls: %v", err)
	}
}

// TestReclaimTokenFailuresAreIndistinguishable pins the no-oracle property across
// every token failure mode.
func TestReclaimTokenFailuresAreIndistinguishable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, h *harness) string
	}{
		{
			name:  "Empty",
			setup: func(*testing.T, *harness) string { return "" },
		},
		{
			name: "Unknown",
			setup: func(t *testing.T, _ *harness) string {
				token, _, err := NewReclaimToken()
				if err != nil {
					t.Fatalf("NewReclaimToken: %v", err)
				}
				return token
			},
		},
		{
			name: "Expired",
			setup: func(t *testing.T, h *harness) string {
				token, _ := requestDeletionAndToken(t, h, "expired@test.local")
				h.clock.advance(2 * defaultGracePeriod)
				return token
			},
		},
		{
			name: "Consumed",
			setup: func(t *testing.T, h *harness) string {
				token, _ := requestDeletionAndToken(t, h, "consumed@test.local")
				if _, err := h.store.ExpireDeletionRequestsForUser(
					context.Background(), h.store.requests[0].UserID); err != nil {
					t.Fatalf("ExpireDeletionRequestsForUser: %v", err)
				}
				return token
			},
		},
		{
			name: "AccountNoLongerPendingDeletion",
			setup: func(t *testing.T, h *harness) string {
				token, id := requestDeletionAndToken(t, h, "reactivated@test.local")
				uid := mustParseUUID(t, id)
				u := h.store.user(uid)
				u.Status = "active"
				h.store.users[uid] = u
				return token
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			token := tc.setup(t, h)

			if _, err := h.svc.ReclaimOptions(context.Background(), token, ""); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("ReclaimOptions = %v, want ErrInvalidToken", err)
			}
			err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn})
			if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Reclaim = %v, want ErrInvalidToken", err)
			}
		})
	}
}

// TestReclaimRateLimitsSubnetFirst asserts the ordering that stops a saturated
// shared proxy from consuming a targeted account's budget, and that a saturated
// subnet window short-circuits before any database lookup.
func TestReclaimRateLimitsSubnetFirst(t *testing.T) {
	h := newHarness(t, Config{ReclaimPerAccountPerHour: 4, ReclaimPerSubnetPerHour: 9})
	token, id := requestDeletionAndToken(t, h, "ratelimit@test.local")
	userID := mustParseUUID(t, id)

	// Reset the recorded calls from RequestDeletion.
	h.limiter.calls = nil

	if _, err := h.svc.ReclaimOptions(context.Background(), token, "203.0.113.10"); err != nil {
		t.Fatalf("ReclaimOptions: %v", err)
	}
	keys := h.limiter.keys()
	if len(keys) != 2 {
		t.Fatalf("limiter calls = %v, want the subnet then the account window", keys)
	}
	if got, want := keys[0], reclaimSubnetRateKey("203.0.113.0/24"); got != want {
		t.Errorf("first limiter key = %q, want the subnet key %q", got, want)
	}
	if got, want := keys[1], reclaimAccountRateKey(userID); got != want {
		t.Errorf("second limiter key = %q, want the account key %q", got, want)
	}
	if h.limiter.calls[0].limit != 9 {
		t.Errorf("subnet limit = %d, want the configured 9", h.limiter.calls[0].limit)
	}
	if h.limiter.calls[1].limit != 4 {
		t.Errorf("account limit = %d, want the configured 4", h.limiter.calls[1].limit)
	}

	// A saturated subnet must be refused before the token is even looked up.
	h.limiter.calls = nil
	h.limiter.deny[reclaimSubnetRateKey("203.0.113.0/24")] = true
	if _, err := h.svc.ReclaimOptions(context.Background(), token, "203.0.113.10"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("ReclaimOptions = %v, want ErrRateLimited", err)
	}
	if got := h.limiter.keys(); len(got) != 1 {
		t.Errorf("limiter calls after a saturated subnet = %v, want only the subnet key", got)
	}

	// A saturated account window is also ErrRateLimited, not the opaque token error:
	// throttling is not a credential failure and the caller can usefully back off.
	h.limiter.calls = nil
	delete(h.limiter.deny, reclaimSubnetRateKey("203.0.113.0/24"))
	h.limiter.deny[reclaimAccountRateKey(userID)] = true
	if err := h.svc.Reclaim(context.Background(), token,
		ReclaimAttempt{Method: FactorWebAuthn, ClientIP: "203.0.113.10"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Reclaim = %v, want ErrRateLimited", err)
	}
	if h.passkeys.finishCallCount() != 0 {
		t.Error("a rate-limited reclaim still verified the factor")
	}
}

// ---------------------------------------------------------------------------
// Reclaim
// ---------------------------------------------------------------------------

func TestReclaimRestoresAccountAndRetiresTokens(t *testing.T) {
	h := newHarness(t, Config{GracePeriod: 720 * time.Hour})
	token, id := requestDeletionAndToken(t, h, "reclaim@test.local")
	userID := mustParseUUID(t, id)

	if err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}

	restored := h.store.user(userID)
	if restored.Status != "active" {
		t.Errorf("status = %q, want active", restored.Status)
	}
	if restored.DeletedAt.Valid {
		t.Error("deleted_at was not cleared")
	}
	// A reclaimed account must not be reclaimable again with the same token.
	if err := h.svc.Reclaim(context.Background(), token,
		ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("second Reclaim = %v, want ErrInvalidToken", err)
	}
	if got := h.recorder.countOf(audit.EventDeletionReclaimed, audit.StatusSuccess); got != 1 {
		t.Errorf("%s events = %d, want 1", audit.EventDeletionReclaimed, got)
	}
}

func TestReclaimWithTOTP(t *testing.T) {
	h := newHarness(t, Config{})
	user := h.store.addActiveUser("totp-reclaim@test.local")
	u := h.store.user(user.ID)
	u.IsMfaEnabled = true
	h.store.users[user.ID] = u
	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := h.notifier.last()

	if err := h.svc.Reclaim(context.Background(), notice.ReclaimToken,
		ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); err != nil {
		t.Fatalf("Reclaim with TOTP: %v", err)
	}
	if h.store.user(user.ID).Status != "active" {
		t.Error("the account was not restored")
	}
}

// TestReclaimTOTPPasscodeIsSingleUse: the guard is claimed before validation, so one
// passcode cannot be replayed across its whole ±1-step acceptance window.
func TestReclaimTOTPPasscodeIsSingleUse(t *testing.T) {
	h := newHarness(t, Config{})
	user := h.store.addActiveUser("replay@test.local")
	u := h.store.user(user.ID)
	u.IsMfaEnabled = true
	h.store.users[user.ID] = u
	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := h.notifier.last()

	if err := h.svc.Reclaim(context.Background(), notice.ReclaimToken,
		ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); err != nil {
		t.Fatalf("first Reclaim: %v", err)
	}

	// Deactivate again and replay the same passcode: the guard must reject it before
	// the verifier is consulted.
	h.clock.advance(2 * time.Hour)
	if _, err := h.svc.RequestDeletion(context.Background(), user.ID, ""); err != nil {
		t.Fatalf("second RequestDeletion: %v", err)
	}
	second, _ := h.notifier.last()

	attemptsBefore := h.totp.attemptCount()
	if err := h.svc.Reclaim(context.Background(), second.ReclaimToken,
		ReclaimAttempt{Method: FactorTOTP, Code: "123456"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("replayed passcode = %v, want ErrInvalidToken", err)
	}
	if h.totp.attemptCount() != attemptsBefore {
		t.Error("the replayed passcode reached the verifier; the guard must claim before validating")
	}
	if h.store.user(user.ID).Status != "pending_deletion" {
		t.Error("a replayed passcode reclaimed the account")
	}
}

// TestReclaimWrongFactorDoesNotConsumeToken is the load-bearing trade-off: a
// mistyped code must not destroy the account's only recovery path.
func TestReclaimWrongFactorDoesNotConsumeToken(t *testing.T) {
	h := newHarness(t, Config{ReclaimMaxAttempts: 5})
	token, id := requestDeletionAndToken(t, h, "wrongfactor@test.local")
	userID := mustParseUUID(t, id)
	h.passkeys.finishErr = webauthn.ErrVerification

	err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Reclaim with a wrong factor = %v, want ErrInvalidToken", err)
	}

	if h.store.consumeCalls != 0 {
		t.Error("a wrong factor consumed the reclaim token")
	}
	request, err := h.store.GetActiveDeletionRequestByTokenHashForUpdate(
		context.Background(), HashReclaimToken(token))
	if err != nil {
		t.Fatalf("the token stopped working after a wrong factor: %v", err)
	}
	if request.FailedAttempts != 1 {
		t.Errorf("failed_attempts = %d, want 1", request.FailedAttempts)
	}
	if got := h.recorder.countOf(audit.EventDeletionReclaimFailed, audit.StatusFailure); got != 1 {
		t.Errorf("%s events = %d, want 1", audit.EventDeletionReclaimFailed, got)
	}

	// The same token must still be able to succeed once the right factor arrives.
	h.passkeys.finishErr = nil
	if err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim after a failed attempt: %v", err)
	}
	if h.store.user(userID).Status != "active" {
		t.Error("the account was not restored")
	}
}

// TestReclaimAttemptCapRetiresRequest: the cap, not single use, is what bounds abuse.
func TestReclaimAttemptCapRetiresRequest(t *testing.T) {
	const maxAttempts = 3
	h := newHarness(t, Config{ReclaimMaxAttempts: maxAttempts})
	token, _ := requestDeletionAndToken(t, h, "capped@test.local")
	h.passkeys.finishErr = webauthn.ErrVerification
	requestID := h.store.requests[0].ID

	for i := 1; i <= maxAttempts; i++ {
		if err := h.svc.Reclaim(context.Background(), token,
			ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("attempt %d = %v, want ErrInvalidToken", i, err)
		}
		// The token must survive every attempt *before* the cap, or the cap is
		// meaningless.
		_, lookupErr := h.store.GetActiveDeletionRequestByTokenHashForUpdate(
			context.Background(), HashReclaimToken(token))
		stillActive := lookupErr == nil
		if i < maxAttempts && !stillActive {
			t.Fatalf("the token was retired at attempt %d, before the cap of %d", i, maxAttempts)
		}
		if i == maxAttempts && stillActive {
			t.Fatalf("the token survived attempt %d, which reaches the cap of %d", i, maxAttempts)
		}
	}

	// The row is retired by consumption, not by expiry: the grace window is still
	// open, so only consumed_at can be what makes it unusable.
	row, ok := h.store.requestByID(requestID)
	if !ok {
		t.Fatal("the deletion request row disappeared")
	}
	if !row.ConsumedAt.Valid {
		t.Error("the exhausted request was not consumed")
	}
	if int(row.FailedAttempts) != maxAttempts {
		t.Errorf("failed_attempts = %d, want %d", row.FailedAttempts, maxAttempts)
	}

	// Even a correct factor cannot revive a retired request.
	h.passkeys.finishErr = nil
	if err := h.svc.Reclaim(context.Background(), token,
		ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Reclaim on a retired request = %v, want ErrInvalidToken", err)
	}

	last, ok := h.recorder.lastOf(audit.EventDeletionReclaimFailed)
	if !ok {
		t.Fatal("no reclaim_failed event recorded")
	}
	if exhausted, _ := last.Payload["exhausted"].(bool); !exhausted {
		t.Errorf("the capping attempt was not audited as exhausted: %v", last.Payload)
	}
}

// TestReclaimInfrastructureFaultDoesNotBurnAttempts: a database or Redis outage must
// not eat a user's recovery attempts.
func TestReclaimInfrastructureFaultDoesNotBurnAttempts(t *testing.T) {
	h := newHarness(t, Config{ReclaimMaxAttempts: 5})
	token, _ := requestDeletionAndToken(t, h, "outage@test.local")
	h.guard.err = errBoom

	user := h.store.requests[0].UserID
	u := h.store.user(user)
	u.IsMfaEnabled = true
	h.store.users[user] = u

	err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorTOTP, Code: "123456"})
	if err == nil {
		t.Fatal("Reclaim with a broken replay guard = nil error, want an error")
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Error("an infrastructure fault was reported as an invalid token")
	}
	if h.store.incrementCalls != 0 {
		t.Error("an infrastructure fault was charged to the attempt budget")
	}
}

// TestReclaimUnsupportedFactorIsOpaque: naming a factor the service cannot verify
// must not distinguish itself from a wrong code.
func TestReclaimUnsupportedFactorIsOpaque(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "badfactor@test.local")

	for _, method := range []string{"", "password", "recovery_code", "sms"} {
		err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: method})
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Reclaim with factor %q = %v, want ErrInvalidToken", method, err)
		}
	}
}

// TestReclaimBindsCeremonyToRequest: the WebAuthn ceremony must be bound to the
// deletion request, so an assertion obtained for one request cannot complete
// another.
func TestReclaimBindsCeremonyToRequest(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "bound@test.local")

	if _, err := h.svc.ReclaimOptions(context.Background(), token, ""); err != nil {
		t.Fatalf("ReclaimOptions: %v", err)
	}
	if err := h.svc.Reclaim(context.Background(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}

	requestID := h.store.requests[0].ID.String()
	if len(h.passkeys.beginCalls) != 1 || h.passkeys.beginCalls[0] != requestID {
		t.Errorf("begin binding = %v, want [%s]", h.passkeys.beginCalls, requestID)
	}
	if len(h.passkeys.finishCalls) != 1 || h.passkeys.finishCalls[0] != requestID {
		t.Errorf("finish binding = %v, want [%s]", h.passkeys.finishCalls, requestID)
	}
}

// TestWithinResendCooldown covers the cooldown predicate directly, including the
// "never notified is never inside the cooldown" rule.
func TestWithinResendCooldown(t *testing.T) {
	h := newHarness(t, Config{DeleteResendCooldown: time.Hour})
	base := h.clock.now()

	if h.svc.withinResendCooldown(dbRequestNotifiedAt(nil)) {
		t.Error("a never-notified request is inside the cooldown; a failed send would never be retried")
	}
	inside := base.Add(-30 * time.Minute)
	if !h.svc.withinResendCooldown(dbRequestNotifiedAt(&inside)) {
		t.Error("a 30m-old notice is not inside the 1h cooldown")
	}
	// Exactly at the boundary the cooldown has elapsed (strict <).
	boundary := base.Add(-time.Hour)
	if h.svc.withinResendCooldown(dbRequestNotifiedAt(&boundary)) {
		t.Error("a notice exactly one cooldown old is still inside the cooldown")
	}
	outside := base.Add(-2 * time.Hour)
	if h.svc.withinResendCooldown(dbRequestNotifiedAt(&outside)) {
		t.Error("a 2h-old notice is inside the 1h cooldown")
	}
}
