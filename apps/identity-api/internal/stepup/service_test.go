package stepup

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// --- Fakes ------------------------------------------------------------------

// fakeUserStore serves one configurable account. The zero value serves an active
// account with no factors, which is the least-privileged starting point.
type fakeUserStore struct {
	user    db.User
	missing bool
	err     error
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if f.err != nil {
		return db.User{}, f.err
	}
	if f.missing {
		return db.User{}, pgx.ErrNoRows
	}
	u := f.user
	u.ID = id
	if u.Status == "" {
		u.Status = "active"
	}
	return u, nil
}

// fakePasskeys is a PasskeyVerifier whose outcome each test dictates.
type fakePasskeys struct {
	beginErr        error
	finishErr       error
	beginCalls      int
	finishCalls     int
	beginSessionID  string
	finishSessionID string
}

func (f *fakePasskeys) BeginStepUp(
	_ context.Context,
	_ uuid.UUID,
	sessionID string,
) (*protocol.CredentialAssertion, error) {
	f.beginCalls++
	f.beginSessionID = sessionID
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:        protocol.URLEncodedBase64("challenge"),
			UserVerification: protocol.VerificationRequired,
		},
	}, nil
}

func (f *fakePasskeys) FinishStepUp(
	_ context.Context,
	_ uuid.UUID,
	sessionID string,
	_ []byte,
) error {
	f.finishCalls++
	f.finishSessionID = sessionID
	return f.finishErr
}

// fakeTOTP accepts one fixed passcode.
type fakeTOTP struct {
	valid string
	err   error
	calls int
}

type concurrentTOTP struct {
	valid string
	calls atomic.Int32
}

func (f *concurrentTOTP) VerifyEnabledCode(_ context.Context, _ uuid.UUID, code string) error {
	f.calls.Add(1)
	if code != f.valid {
		return mfa.ErrInvalidCode
	}
	return nil
}

func (f *fakeTOTP) VerifyEnabledCode(_ context.Context, _ uuid.UUID, code string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if code != f.valid {
		return mfa.ErrInvalidCode
	}
	return nil
}

// recordingLimiter records every window it was asked about, in order, and denies
// the first key matching denyKey.
type recordingLimiter struct {
	keys    []string
	limits  []int
	windows []time.Duration
	denyKey string
	err     error
}

func (l *recordingLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	l.keys = append(l.keys, key)
	l.limits = append(l.limits, limit)
	l.windows = append(l.windows, window)
	return key != l.denyKey, nil
}

// newServiceWith builds a Service around caller-supplied collaborators.
func newServiceWith(
	t *testing.T,
	users UserStore,
	passkeys PasskeyVerifier,
	totp TOTPVerifier,
	guard ReplayGuard,
	opts ...Option,
) *Service {
	t.Helper()

	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	next, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	km, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	if guard == nil {
		// Share the Service's fixed clock so entry expiry is judged against the
		// same instant the Service stamps onto it.
		guard = NewMemoryReplayGuard(WithReplayClock(func() time.Time { return testNow }))
	}
	opts = append([]Option{WithClock(func() time.Time { return testNow })}, opts...)

	svc, err := New(Config{Issuer: testIssuer}, km, users, passkeys, totp, guard, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// --- Challenge --------------------------------------------------------------

func TestChallengeReportsAvailableFactors(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name        string
		user        db.User
		passkeys    PasskeyVerifier
		totp        TOTPVerifier
		wantMethods []string
		wantErr     error
		wantOptions bool
	}{
		{
			name:        "both factors",
			user:        db.User{Status: "active", IsMfaEnabled: true},
			passkeys:    &fakePasskeys{},
			totp:        &fakeTOTP{},
			wantMethods: []string{MethodWebAuthn, MethodTOTP},
			wantOptions: true,
		},
		{
			name:        "passkey only",
			user:        db.User{Status: "active"},
			passkeys:    &fakePasskeys{},
			totp:        &fakeTOTP{},
			wantMethods: []string{MethodWebAuthn},
			wantOptions: true,
		},
		{
			name:        "totp only",
			user:        db.User{Status: "active", IsMfaEnabled: true},
			passkeys:    &fakePasskeys{beginErr: webauthn.ErrNoCredentials},
			totp:        &fakeTOTP{},
			wantMethods: []string{MethodTOTP},
		},
		{
			name:     "no factor at all",
			user:     db.User{Status: "active"},
			passkeys: &fakePasskeys{beginErr: webauthn.ErrNoCredentials},
			totp:     &fakeTOTP{},
			wantErr:  ErrNoFactorAvailable,
		},
		{
			name:     "suspended account",
			user:     db.User{Status: "suspended", IsMfaEnabled: true},
			passkeys: &fakePasskeys{},
			totp:     &fakeTOTP{},
			wantErr:  ErrAccountNotActive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newServiceWith(t, &fakeUserStore{user: tc.user}, tc.passkeys, tc.totp, nil)

			result, err := svc.Challenge(context.Background(), userID, "sess-challenge")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			if len(result.Methods) != len(tc.wantMethods) {
				t.Fatalf("methods = %v, want %v", result.Methods, tc.wantMethods)
			}
			for i, want := range tc.wantMethods {
				if result.Methods[i] != want {
					t.Fatalf("method %d = %q, want %q", i, result.Methods[i], want)
				}
			}
			if tc.wantOptions != (result.WebAuthn != nil) {
				t.Fatalf("webauthn options present = %v, want %v", result.WebAuthn != nil, tc.wantOptions)
			}
		})
	}
}

func TestChallengeBindsPasskeyCeremonyToInitiatingSession(t *testing.T) {
	passkeys := &fakePasskeys{}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}}, passkeys, nil, nil)

	const sessionID = "sess-that-started-challenge"
	if _, err := svc.Challenge(context.Background(), uuid.New(), sessionID); err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if passkeys.beginSessionID != sessionID {
		t.Fatalf("BeginStepUp session = %q, want %q", passkeys.beginSessionID, sessionID)
	}
}

func TestChallengeRequiresSessionBeforeStartingPasskeyCeremony(t *testing.T) {
	passkeys := &fakePasskeys{}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}}, passkeys, nil, nil)

	if _, err := svc.Challenge(context.Background(), uuid.New(), ""); err == nil {
		t.Fatal("Challenge accepted an empty session ID")
	}
	if passkeys.beginCalls != 0 {
		t.Fatalf("empty-session challenge reached passkey service (%d calls)", passkeys.beginCalls)
	}
}

// TestChallengeSurfacesInfrastructureFailures confirms a database or ceremony
// fault is not silently degraded into "this factor is unavailable", which would
// hide an outage behind a confusing UX.
func TestChallengeSurfacesInfrastructureFailures(t *testing.T) {
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}},
		&fakePasskeys{beginErr: errors.New("database on fire")},
		&fakeTOTP{}, nil,
	)

	_, err := svc.Challenge(context.Background(), uuid.New(), "sess-challenge")
	if err == nil {
		t.Fatal("expected the infrastructure error to propagate")
	}
	if errors.Is(err, ErrNoFactorAvailable) {
		t.Fatal("an infrastructure fault was reported as 'no factor available'")
	}
}

// --- Verify -----------------------------------------------------------------

func TestVerifyWithPasskeyMintsAGrant(t *testing.T) {
	passkeys := &fakePasskeys{}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}}, passkeys, nil, nil)

	compact, expiresAt, err := svc.Verify(context.Background(), VerifyParams{
		UserID:    uuid.New(),
		SessionID: "sess-1",
		Method:    MethodWebAuthn,
		Assertion: []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if compact == "" {
		t.Fatal("expected a grant")
	}
	if !expiresAt.Equal(testNow.Add(DefaultTokenTTL)) {
		t.Fatalf("expiresAt = %v", expiresAt)
	}
	if passkeys.finishCalls != 1 {
		t.Fatalf("expected one assertion verification, got %d", passkeys.finishCalls)
	}
	if passkeys.finishSessionID != "sess-1" {
		t.Fatalf("FinishStepUp session = %q, want %q", passkeys.finishSessionID, "sess-1")
	}
}

func TestVerifyWithTOTPMintsAGrant(t *testing.T) {
	totp := &fakeTOTP{valid: "123456"}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}}, nil, totp, nil)

	compact, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID:    uuid.New(),
		SessionID: "sess-1",
		Method:    MethodTOTP,
		Code:      "123456",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if compact == "" {
		t.Fatal("expected a grant")
	}
}

func TestVerifyRejectsNonCanonicalTOTPWithoutBurningCanonicalCode(t *testing.T) {
	userID := uuid.New()
	verifier := &fakeTOTP{valid: "123456"}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}},
		nil,
		verifier,
		nil,
	)

	malformed := VerifyParams{
		UserID: userID, SessionID: "sess-1", Method: MethodTOTP, Code: " 123456",
	}
	if _, _, err := svc.Verify(context.Background(), malformed); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("non-canonical TOTP error = %v, want ErrInvalidCredentials", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("non-canonical input reached TOTP verifier (%d calls)", verifier.calls)
	}

	canonical := malformed
	canonical.Code = "123456"
	if _, _, err := svc.Verify(context.Background(), canonical); err != nil {
		t.Fatalf("canonical code was burned by malformed input: %v", err)
	}
}

// TestVerifyRejectsAReplayedPasscode is the defence against the TOTP ±1-step
// acceptance window: without it, one observed passcode could mint several grants
// over its ~90-second life.
func TestVerifyRejectsAReplayedPasscode(t *testing.T) {
	userID := uuid.New()
	totp := &fakeTOTP{valid: "123456"}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}}, nil, totp, nil)

	params := VerifyParams{UserID: userID, SessionID: "sess-1", Method: MethodTOTP, Code: "123456"}

	if _, _, err := svc.Verify(context.Background(), params); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, _, err := svc.Verify(context.Background(), params); !errors.Is(err, ErrCodeReplayed) {
		t.Fatalf("expected ErrCodeReplayed, got %v", err)
	}
	// The guard must short-circuit before the verifier runs again.
	if totp.calls != 1 {
		t.Fatalf("expected the verifier to be consulted once, got %d", totp.calls)
	}
}

func TestVerifyConcurrentExactPasscodeMintsOneGrant(t *testing.T) {
	userID := uuid.New()
	verifier := &concurrentTOTP{valid: "123456"}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}}, nil, verifier, nil)
	params := VerifyParams{UserID: userID, SessionID: "sess-1", Method: MethodTOTP, Code: "123456"}

	type result struct {
		token string
		err   error
	}
	const workers = 32
	results := make(chan result, workers)
	for range workers {
		go func() {
			token, _, err := svc.Verify(context.Background(), params)
			results <- result{token: token, err: err}
		}()
	}
	var minted, replayed int
	for range workers {
		result := <-results
		switch {
		case result.err == nil && result.token != "":
			minted++
		case errors.Is(result.err, ErrCodeReplayed) && result.token == "":
			replayed++
		default:
			t.Fatalf("unexpected concurrent result: token=%q err=%v", result.token, result.err)
		}
	}
	if minted != 1 || replayed != workers-1 {
		t.Fatalf("minted/replayed = %d/%d, want 1/%d", minted, replayed, workers-1)
	}
	if calls := verifier.calls.Load(); calls != 1 {
		t.Fatalf("TOTP verifier calls = %d, want 1", calls)
	}
}

// TestVerifyScopesThePasscodeGuardPerAccount confirms the replay guard keys on
// the account, so two users legitimately holding the same 6-digit code at the
// same instant do not block each other.
func TestVerifyScopesThePasscodeGuardPerAccount(t *testing.T) {
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}},
		nil, &fakeTOTP{valid: "123456"}, nil)

	first := VerifyParams{UserID: uuid.New(), SessionID: "sess-1", Method: MethodTOTP, Code: "123456"}
	second := VerifyParams{UserID: uuid.New(), SessionID: "sess-2", Method: MethodTOTP, Code: "123456"}

	if _, _, err := svc.Verify(context.Background(), first); err != nil {
		t.Fatalf("first account: %v", err)
	}
	if _, _, err := svc.Verify(context.Background(), second); err != nil {
		t.Fatalf("a second account was blocked by the first account's passcode: %v", err)
	}
}

func TestVerifyErrorTranslation(t *testing.T) {
	tests := []struct {
		name     string
		params   VerifyParams
		passkeys PasskeyVerifier
		totp     TOTPVerifier
		user     db.User
		want     error
	}{
		{
			name:     "user verification missing stays distinct",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{finishErr: webauthn.ErrUserVerificationRequired},
			want:     ErrUserVerificationRequired,
		},
		{
			name:     "failed assertion is opaque",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{finishErr: webauthn.ErrVerification},
			want:     ErrInvalidCredentials,
		},
		{
			name:     "stale challenge is opaque",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{finishErr: webauthn.ErrChallengeExpired},
			want:     ErrInvalidCredentials,
		},
		{
			name:     "a login challenge redeemed here is opaque",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{finishErr: webauthn.ErrChallengeFlowMismatch},
			want:     ErrInvalidCredentials,
		},
		{
			name:     "cloned authenticator is opaque",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{finishErr: webauthn.ErrCredentialCloned},
			want:     ErrInvalidCredentials,
		},
		{
			name:   "wrong passcode is opaque",
			params: VerifyParams{Method: MethodTOTP, Code: "000000"},
			totp:   &fakeTOTP{valid: "123456"},
			user:   db.User{Status: "active", IsMfaEnabled: true},
			want:   ErrInvalidCredentials,
		},
		{
			name:   "empty passcode is opaque",
			params: VerifyParams{Method: MethodTOTP},
			totp:   &fakeTOTP{valid: "123456"},
			user:   db.User{Status: "active", IsMfaEnabled: true},
			want:   ErrInvalidCredentials,
		},
		{
			name:   "totp not enrolled",
			params: VerifyParams{Method: MethodTOTP, Code: "123456"},
			totp:   &fakeTOTP{err: mfa.ErrMfaNotSetup},
			user:   db.User{Status: "active"},
			want:   ErrMethodUnavailable,
		},
		{
			// Recovery codes are a login bypass, not a step-up factor.
			name:     "recovery code is not a step-up method",
			params:   VerifyParams{Method: "recovery_code", Code: "ABCDEFGH"},
			passkeys: &fakePasskeys{},
			want:     ErrUnsupportedMethod,
		},
		{
			name:     "empty method",
			params:   VerifyParams{},
			passkeys: &fakePasskeys{},
			want:     ErrUnsupportedMethod,
		},
		{
			name:     "suspended account cannot elevate",
			params:   VerifyParams{Method: MethodWebAuthn, Assertion: []byte(`{}`)},
			passkeys: &fakePasskeys{},
			user:     db.User{Status: "suspended"},
			want:     ErrAccountNotActive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := tc.user
			if user.Status == "" {
				user.Status = "active"
			}
			svc := newServiceWith(t, &fakeUserStore{user: user}, tc.passkeys, tc.totp, nil)

			params := tc.params
			params.UserID = uuid.New()
			params.SessionID = "sess-1"

			_, _, err := svc.Verify(context.Background(), params)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyRequiresASessionID(t *testing.T) {
	svc := newServiceWith(t, &fakeUserStore{}, &fakePasskeys{}, nil, nil)

	if _, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID: uuid.New(), Method: MethodWebAuthn,
	}); err == nil {
		t.Fatal("expected an unbindable grant request to be refused")
	}
}

func TestVerifyRejectsAMethodWithNoVerifier(t *testing.T) {
	// A service built with only a passkey verifier must refuse TOTP rather than
	// panic on the nil collaborator.
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active", IsMfaEnabled: true}},
		&fakePasskeys{}, nil, nil)

	if _, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID: uuid.New(), SessionID: "sess-1", Method: MethodTOTP, Code: "123456",
	}); !errors.Is(err, ErrMethodUnavailable) {
		t.Fatalf("expected ErrMethodUnavailable, got %v", err)
	}
}

// --- Rate limiting ----------------------------------------------------------

// TestVerifyChecksSubnetWindowBeforeAccountWindows pins the ordering: a saturated
// shared proxy must not be able to burn a targeted account's budget, so the
// subnet window is consulted first (matching recovery.Service).
func TestVerifyChecksSubnetWindowBeforeAccountWindows(t *testing.T) {
	limiter := &recordingLimiter{}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}},
		&fakePasskeys{}, nil, nil, WithRateLimiter(limiter))

	if _, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID:    uuid.New(),
		SessionID: "sess-1",
		Method:    MethodWebAuthn,
		Assertion: []byte(`{}`),
		ClientIP:  "203.0.113.7:44321",
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if len(limiter.keys) != 3 {
		t.Fatalf("expected three windows, got %v", limiter.keys)
	}
	if got := limiter.keys[0]; got[:len("rate:stepup:verify:subnet:")] != "rate:stepup:verify:subnet:" {
		t.Fatalf("first window = %q, want the subnet window", got)
	}
	if limiter.windows[1] != time.Minute {
		t.Fatalf("second window = %v, want the per-minute account window", limiter.windows[1])
	}
	if limiter.windows[2] != time.Hour {
		t.Fatalf("third window = %v, want the hourly account window", limiter.windows[2])
	}
}

func TestVerifyRefusesWhenAWindowIsSaturated(t *testing.T) {
	userID := uuid.New()
	passkeys := &fakePasskeys{}
	limiter := &recordingLimiter{denyKey: accountRateKey(userID)}
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}},
		passkeys, nil, nil, WithRateLimiter(limiter))

	_, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID:    userID,
		SessionID: "sess-1",
		Method:    MethodWebAuthn,
		Assertion: []byte(`{}`),
		ClientIP:  "203.0.113.7",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	// Throttling must happen before any factor work, or a brute-force attempt
	// still costs a signature verification per try.
	if passkeys.finishCalls != 0 {
		t.Fatalf("the factor was verified despite the limit being saturated (%d calls)", passkeys.finishCalls)
	}
}

func TestVerifyWithoutALimiterIsUnthrottled(t *testing.T) {
	// Development runs without Redis; the absence of a limiter must not break
	// the flow, only leave it unthrottled.
	svc := newServiceWith(t,
		&fakeUserStore{user: db.User{Status: "active"}}, &fakePasskeys{}, nil, nil)

	if _, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID: uuid.New(), SessionID: "sess-1", Method: MethodWebAuthn, Assertion: []byte(`{}`),
	}); err != nil {
		t.Fatalf("Verify without a limiter: %v", err)
	}
}

// --- Account gate -----------------------------------------------------------

func TestVerifyRejectsAMissingAccount(t *testing.T) {
	svc := newServiceWith(t, &fakeUserStore{missing: true}, &fakePasskeys{}, nil, nil)

	if _, _, err := svc.Verify(context.Background(), VerifyParams{
		UserID: uuid.New(), SessionID: "sess-1", Method: MethodWebAuthn, Assertion: []byte(`{}`),
	}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}
