package webauthn

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testRequestID = "11111111-2222-3333-4444-555555555555"

// pendingFixture returns a fixture whose account holds a passkey and has already
// been soft-deleted, which is the only state the reclaim ceremony serves.
//
// The passkey is registered while the account is still active, because that is the
// real sequence: an account acquires credentials, then requests deletion.
func pendingFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	f := newFixture(t)
	f.register(t, f.auth)
	f.setStatus(t, "pending_deletion")
	return f
}

// reclaim drives a full reclaim ceremony. When presenceOnly is set the
// authenticator reports user presence but not user verification.
func (f *ceremonyFixture) reclaim(t *testing.T, auth *softAuthenticator, presenceOnly bool) error {
	t.Helper()

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		return err
	}
	challenge := challengeOf(options.Response.Challenge)
	handle := f.handle(t)

	body := auth.assertion(challenge, handle)
	if presenceOnly {
		body = auth.assertionPresenceOnly(challenge, handle)
	}
	return f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, body)
}

// --- BeginReclaimAssertion --------------------------------------------------

// TestBeginReclaimAssertionRequiresUserVerification is the ceremony half of the
// guarantee: reclaiming an account is a high-consequence action, so the options
// must demand a PIN or biometric regardless of the configured default (which ships
// as "preferred").
func TestBeginReclaimAssertionRequiresUserVerification(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	if got := options.Response.UserVerification; got != "required" {
		t.Fatalf("userVerification = %q, want required", got)
	}
	if len(options.Response.AllowedCredentials) == 0 {
		t.Fatal("expected the account's credentials in allowCredentials")
	}
}

// TestBeginReclaimAssertionTagsAndBindsTheChallenge confirms both the flow tag and
// the deletion-request binding. The tag is what keeps the ceremony out of the login
// verifier; the binding is what stops an assertion obtained for one deletion
// request from completing another.
func TestBeginReclaimAssertionTagsAndBindsTheChallenge(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}

	pending, err := f.challenges.Take(challengeOf(options.Response.Challenge))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if pending.Flow != FlowReclaim {
		t.Fatalf("flow = %v, want %v", pending.Flow, FlowReclaim)
	}
	if pending.UserRef != f.user.ID {
		t.Fatalf("UserRef = %s, want %s", pending.UserRef, f.user.ID)
	}
	if pending.SessionID != testRequestID {
		t.Fatalf("binding = %q, want the deletion request id %q", pending.SessionID, testRequestID)
	}
}

// TestBeginReclaimAssertionRequiresPendingDeletion is the inverse of every other
// ceremony's gate: only the status that cannot log in may reclaim. An active account
// has no deletion to cancel, and a suspended one must not be able to launder itself
// back to active through the privacy flow.
func TestBeginReclaimAssertionRequiresPendingDeletion(t *testing.T) {
	for _, status := range []string{"active", "suspended", "pending_verification"} {
		t.Run(status, func(t *testing.T) {
			f := newFixture(t)
			f.register(t, f.auth)
			f.setStatus(t, status)

			if _, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID); !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("BeginReclaimAssertion for %q = %v, want ErrAccountNotActive", status, err)
			}
		})
	}
}

func TestBeginReclaimAssertionWithoutACredential(t *testing.T) {
	f := newFixture(t)
	f.setStatus(t, "pending_deletion")

	// The caller (internal/privacy) turns this into "offer TOTP instead", and
	// collapses it into the opaque token error when no factor exists at all.
	if _, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("BeginReclaimAssertion = %v, want ErrNoCredentials", err)
	}
}

func TestBeginReclaimAssertionRejectsUnknownAccountAndEmptyRequestID(t *testing.T) {
	f := pendingFixture(t)

	if _, err := f.svc.BeginReclaimAssertion(f.ctx(), uuid.New(), testRequestID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("BeginReclaimAssertion for an unknown account = %v, want ErrUserNotFound", err)
	}
	// An empty binding would make the challenge completable by anyone holding it,
	// since TakeBound treats an empty session id as no binding at all.
	if _, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, ""); err == nil {
		t.Error("BeginReclaimAssertion with an empty request id = nil error, want error")
	}
}

// --- FinishReclaimAssertion -------------------------------------------------

func TestFinishReclaimAssertionAcceptsAUserVerifiedAssertion(t *testing.T) {
	f := pendingFixture(t)

	if err := f.reclaim(t, f.auth, false); err != nil {
		t.Fatalf("FinishReclaimAssertion: %v", err)
	}
}

// TestFinishReclaimAssertionRejectsAPresenceOnlyAssertion: a security key tapped by
// whoever is at the keyboard must not be able to cancel a deletion the account
// holder requested.
func TestFinishReclaimAssertionRejectsAPresenceOnlyAssertion(t *testing.T) {
	f := pendingFixture(t)

	if err := f.reclaim(t, f.auth, true); !errors.Is(err, ErrUserVerificationRequired) {
		t.Fatalf("presence-only reclaim = %v, want ErrUserVerificationRequired", err)
	}
}

// TestFinishReclaimAssertionCannotBeFooledByAForgedUVFlag guards the early flag
// read, which exists only to make the error actionable. The flag lives inside the
// signed authenticator data, so flipping it invalidates the signature.
func TestFinishReclaimAssertionCannotBeFooledByAForgedUVFlag(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	body := f.auth.assertionWithForgedUVFlag(challengeOf(options.Response.Challenge), f.handle(t))

	err = f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, body)
	if err == nil {
		t.Fatal("a forged user-verification flag was accepted")
	}
	if errors.Is(err, ErrUserVerificationRequired) {
		t.Fatal("the forged flag should fail the signature check, not the flag check")
	}
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("FinishReclaimAssertion = %v, want ErrVerification", err)
	}
}

func TestFinishReclaimAssertionConsumesItsChallenge(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))

	if err := f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, body); err != nil {
		t.Fatalf("first FinishReclaimAssertion: %v", err)
	}
	if err := f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed reclaim = %v, want ErrChallengeNotFound", err)
	}
}

// TestFinishReclaimAssertionRejectsAForeignRequestID confirms the binding, and that
// a probe with the wrong request id does not burn the legitimate caller's ceremony.
func TestFinishReclaimAssertionRejectsAForeignRequestID(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))

	const otherRequestID = "99999999-8888-7777-6666-555555555555"
	if err := f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, otherRequestID, body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("foreign-request reclaim = %v, want ErrChallengeNotFound", err)
	}
	if err := f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, body); err != nil {
		t.Fatalf("legitimate reclaim after a foreign probe: %v", err)
	}
}

func TestFinishReclaimAssertionRejectsAnExpiredChallenge(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	// testConfig sets ChallengeTTL to five minutes.
	f.advance(5*time.Minute + time.Nanosecond)

	err = f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID,
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("FinishReclaimAssertion = %v, want ErrChallengeExpired", err)
	}
}

func TestFinishReclaimAssertionRejectsAMalformedBody(t *testing.T) {
	f := pendingFixture(t)

	if err := f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID, []byte("{")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("FinishReclaimAssertion = %v, want ErrInvalidResponse", err)
	}
}

// TestFinishReclaimAssertionRejectsAnAccountReclaimedMidCeremony covers the
// post-verification re-check: a concurrent reclaim (or the purge worker) may change
// the row while the browser is showing the biometric prompt.
func TestFinishReclaimAssertionRejectsAnAccountReclaimedMidCeremony(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}
	f.setStatus(t, "active")

	err = f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID,
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("FinishReclaimAssertion = %v, want ErrAccountNotActive", err)
	}
}

// TestFinishReclaimAssertionPersistsTheSignatureCounter: a reclaim assertion
// advances the authenticator's counter exactly like a login, so it must be
// persisted or the next authentication would compare against a stale value.
func TestFinishReclaimAssertionPersistsTheSignatureCounter(t *testing.T) {
	f := newFixture(t)
	f.auth.signCount = 4
	f.register(t, f.auth)
	f.setStatus(t, "pending_deletion")

	f.auth.signCount = 9
	if err := f.reclaim(t, f.auth, false); err != nil {
		t.Fatalf("FinishReclaimAssertion: %v", err)
	}

	rows, err := f.creds.ListWebauthnCredentialsByUser(f.ctx(), f.user.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one credential, got %d", len(rows))
	}
	if rows[0].SignCount != 9 {
		t.Fatalf("sign count = %d, want 9", rows[0].SignCount)
	}
}

// TestFinishReclaimAssertionDetectsACloneViaTheCounter confirms clone detection
// still applies on this path.
func TestFinishReclaimAssertionDetectsACloneViaTheCounter(t *testing.T) {
	f := newFixture(t)
	f.auth.signCount = 5
	f.register(t, f.auth)
	f.setStatus(t, "pending_deletion")

	f.auth.signCount = 5 // did not advance
	if err := f.reclaim(t, f.auth, false); !errors.Is(err, ErrCredentialCloned) {
		t.Fatalf("FinishReclaimAssertion = %v, want ErrCredentialCloned", err)
	}
}

// --- Cross-flow isolation ---------------------------------------------------

// TestReclaimChallengeCannotMintASession is the more serious direction: a reclaim
// challenge redeemed at the login verifier would mint a session for an account that
// is pending deletion and suspended from every service.
func TestReclaimChallengeCannotMintASession(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}

	_, err = f.svc.FinishLogin(f.ctx(),
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeFlowMismatch) {
		t.Fatalf("FinishLogin with a reclaim challenge = %v, want ErrChallengeFlowMismatch", err)
	}
}

// TestReclaimChallengeCannotSatisfyStepUp closes the sideways direction: a reclaim
// grant must not be convertible into elevated authority on a live session.
func TestReclaimChallengeCannotSatisfyStepUp(t *testing.T) {
	f := pendingFixture(t)

	options, err := f.svc.BeginReclaimAssertion(f.ctx(), f.user.ID, testRequestID)
	if err != nil {
		t.Fatalf("BeginReclaimAssertion: %v", err)
	}

	err = f.svc.FinishStepUp(f.ctx(), f.user.ID, testRequestID,
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeFlowMismatch) {
		t.Fatalf("FinishStepUp with a reclaim challenge = %v, want ErrChallengeFlowMismatch", err)
	}
}

// TestOtherChallengesCannotSatisfyReclaim is the other direction: no login,
// registration, or step-up challenge may be redeemed at the reclaim verifier. A
// login challenge in particular was issued without the user-verification
// requirement, so accepting it would bypass the ceremony's whole point.
func TestOtherChallengesCannotSatisfyReclaim(t *testing.T) {
	tests := []struct {
		name  string
		begin func(t *testing.T, f *ceremonyFixture) (string, error)
	}{
		{
			name: "discoverable login challenge",
			begin: func(_ *testing.T, f *ceremonyFixture) (string, error) {
				options, err := f.svc.BeginDiscoverableLogin(f.ctx())
				if err != nil {
					return "", err
				}
				return challengeOf(options.Response.Challenge), nil
			},
		},
		{
			name: "step-up challenge",
			begin: func(t *testing.T, f *ceremonyFixture) (string, error) {
				// Step-up requires an active account, so the challenge is minted
				// before the deletion request lands.
				f.setStatus(t, "active")
				options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, testRequestID)
				if err != nil {
					return "", err
				}
				f.setStatus(t, "pending_deletion")
				return challengeOf(options.Response.Challenge), nil
			},
		},
		{
			name: "registration challenge",
			begin: func(t *testing.T, f *ceremonyFixture) (string, error) {
				f.setStatus(t, "active")
				options, err := f.svc.BeginRegistration(f.ctx(), f.user.ID, testRequestID)
				if err != nil {
					return "", err
				}
				f.setStatus(t, "pending_deletion")
				return challengeOf(options.Response.Challenge), nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := pendingFixture(t)

			challenge, err := tc.begin(t, f)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			err = f.svc.FinishReclaimAssertion(f.ctx(), f.user.ID, testRequestID,
				f.auth.assertion(challenge, f.handle(t)))
			if !errors.Is(err, ErrChallengeFlowMismatch) {
				t.Fatalf("FinishReclaimAssertion = %v, want ErrChallengeFlowMismatch", err)
			}
		})
	}
}

// --- Flow stringer ----------------------------------------------------------

// TestFlowStringIncludesReclaim keeps log and error messages readable, and guards
// the iota ordering: FlowReclaim was appended, so the existing tags must not have
// shifted.
func TestFlowStringIncludesReclaim(t *testing.T) {
	for flow, want := range map[Flow]string{
		FlowRegistration:         "registration",
		FlowLoginNamed:           "login_named",
		FlowLoginDiscoverable:    "login_discoverable",
		FlowLoginMock:            "login_mock",
		FlowStepUp:               "step_up",
		FlowRecoveryRegistration: "recovery_registration",
		FlowReclaim:              "reclaim",
	} {
		if got := flow.String(); got != want {
			t.Errorf("Flow(%d).String() = %q, want %q", flow, got, want)
		}
	}
}
