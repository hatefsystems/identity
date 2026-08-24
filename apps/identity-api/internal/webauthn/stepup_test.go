package webauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// --- BeginStepUp ------------------------------------------------------------

// TestBeginStepUpRequiresUserVerification is the ceremony half of the step-up
// guarantee: the options handed to the browser must demand a PIN or biometric,
// regardless of the configured default (which ships as "preferred").
func TestBeginStepUpRequiresUserVerification(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}
	if got := options.Response.UserVerification; got != "required" {
		t.Fatalf("userVerification = %q, want required", got)
	}
	// A step-up ceremony names the account's own credentials, unlike the
	// discoverable login path which deliberately sends an empty list.
	if len(options.Response.AllowedCredentials) == 0 {
		t.Fatal("expected the account's credentials in allowCredentials")
	}
}

// TestBeginStepUpTagsTheChallengeAsStepUp confirms the stored flow tag, which is
// what keeps the two ceremony families from being interchangeable.
func TestBeginStepUpTagsTheChallengeAsStepUp(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}

	pending, err := f.challenges.Take(challengeOf(options.Response.Challenge))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if pending.Flow != FlowStepUp {
		t.Fatalf("flow = %v, want %v", pending.Flow, FlowStepUp)
	}
	if pending.UserRef != f.user.ID {
		t.Fatalf("UserRef = %s, want %s", pending.UserRef, f.user.ID)
	}
}

// TestBeginStepUpWithoutACredential reports honestly rather than issuing a decoy.
//
// The mock ceremony exists to defeat account enumeration on the *login* path. Here
// the caller already holds a session for this account, so there is nothing to
// enumerate, and a decoy would only leave the portal unable to explain why the
// passkey option is missing.
func TestBeginStepUpWithoutACredential(t *testing.T) {
	f := newFixture(t)

	if _, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session"); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
}

func TestBeginStepUpRejectsIneligibleAccounts(t *testing.T) {
	for _, status := range []string{"suspended", "pending_verification", "pending_deletion"} {
		t.Run(status, func(t *testing.T) {
			f := newFixture(t)
			f.register(t, f.auth)
			f.setStatus(t, status)

			if _, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session"); !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("expected ErrAccountNotActive, got %v", err)
			}
		})
	}
}

func TestBeginStepUpRejectsAnUnknownAccount(t *testing.T) {
	f := newFixture(t)

	if _, err := f.svc.BeginStepUp(f.ctx(), uuid.New(), "test-session"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

// --- FinishStepUp -----------------------------------------------------------

func TestFinishStepUpAcceptsAUserVerifiedAssertion(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	if err := f.stepUp(t, f.auth, false); err != nil {
		t.Fatalf("FinishStepUp: %v", err)
	}
}

// TestFinishStepUpRejectsAPresenceOnlyAssertion is the enforcement this whole
// ceremony exists for.
//
// The assertion is cryptographically valid and comes from a genuinely enrolled
// credential; the only thing wrong with it is that the authenticator reported no
// user verification. Accepting it would let a security key tapped by whoever is
// at the keyboard authorise account deletion.
func TestFinishStepUpRejectsAPresenceOnlyAssertion(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	if err := f.stepUp(t, f.auth, true); !errors.Is(err, ErrUserVerificationRequired) {
		t.Fatalf("expected ErrUserVerificationRequired, got %v", err)
	}
}

// TestFinishStepUpConsumesItsChallenge confirms single use, so a captured
// assertion cannot be replayed into a second grant.
func TestFinishStepUpConsumesItsChallenge(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}
	body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))

	if err := f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session", body); err != nil {
		t.Fatalf("first FinishStepUp: %v", err)
	}
	if err := f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session", body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound on replay, got %v", err)
	}
}

func TestFinishStepUpForeignSessionCannotBurnChallenge(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "session-a")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}
	body := f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t))

	if err := f.svc.FinishStepUp(f.ctx(), f.user.ID, "session-b", body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("foreign-session FinishStepUp = %v, want ErrChallengeNotFound", err)
	}
	if err := f.svc.FinishStepUp(f.ctx(), f.user.ID, "session-a", body); err != nil {
		t.Fatalf("legitimate FinishStepUp after foreign probe: %v", err)
	}
}

func TestFinishStepUpRejectsAnExpiredChallenge(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}
	// testConfig sets ChallengeTTL to five minutes.
	f.advance(5*time.Minute + time.Nanosecond)

	err = f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session",
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

// TestFinishStepUpRejectsAnotherAccountsChallenge confirms ownership is enforced,
// reported as "unknown challenge" so the caller learns nothing about it.
func TestFinishStepUpRejectsAnotherAccountsChallenge(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}

	err = f.svc.FinishStepUp(f.ctx(), uuid.New(), "test-session",
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expected ErrChallengeNotFound, got %v", err)
	}
}

func TestFinishStepUpRejectsAMalformedBody(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	if err := f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session", []byte("{")); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

// TestFinishStepUpPersistsTheSignatureCounter confirms a step-up assertion
// advances the stored counter exactly like a login. If it did not, the next login
// would see a counter that had moved without a recorded reason — either failing a
// legitimate user or masking a real cloned authenticator.
func TestFinishStepUpPersistsTheSignatureCounter(t *testing.T) {
	f := newFixture(t)
	f.auth.signCount = 4
	row := f.register(t, f.auth)

	before := row.SignCount
	f.auth.signCount = 9
	if err := f.stepUp(t, f.auth, false); err != nil {
		t.Fatalf("FinishStepUp: %v", err)
	}

	rows, err := f.creds.ListWebauthnCredentialsByUser(f.ctx(), f.user.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one credential, got %d", len(rows))
	}
	if rows[0].SignCount != 9 {
		t.Fatalf("sign count = %d, want 9 (was %d at registration)", rows[0].SignCount, before)
	}
}

// TestFinishStepUpDetectsACloneViaTheCounter confirms clone detection still
// applies on this path: a counter that fails to advance is the signature of a
// duplicated credential.
//
// Counters of zero are exempt (authenticators that do not implement one always
// report zero), so the fixture registers at a non-zero value first.
func TestFinishStepUpDetectsACloneViaTheCounter(t *testing.T) {
	f := newFixture(t)
	f.auth.signCount = 5
	f.register(t, f.auth)

	f.auth.signCount = 5 // did not advance
	if err := f.stepUp(t, f.auth, false); !errors.Is(err, ErrCredentialCloned) {
		t.Fatalf("expected ErrCredentialCloned, got %v", err)
	}
}

func TestFinishStepUpRejectsAnAccountSuspendedMidCeremony(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}
	// The moderator acts while the browser is showing the biometric prompt.
	f.setStatus(t, "suspended")

	err = f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session",
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("expected ErrAccountNotActive, got %v", err)
	}
}

// TestFinishStepUpCannotBeFooledByAForgedUVFlag guards the early flag read.
//
// FinishStepUp inspects the user-verification flag before the library validates
// the signature, in order to return an actionable error. That is only sound
// because the flag lives inside the signed authenticator data: an attacker who
// takes a genuine presence-only assertion and flips the bit invalidates the
// signature, so they gain nothing but the generic rejection.
func TestFinishStepUpCannotBeFooledByAForgedUVFlag(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}

	// A presence-only assertion whose authenticator data claims verification,
	// signed over the *honest* flags so the tampering is detectable.
	body := f.auth.assertionWithForgedUVFlag(challengeOf(options.Response.Challenge), f.handle(t))

	err = f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session", body)
	if err == nil {
		t.Fatal("a forged user-verification flag was accepted")
	}
	if errors.Is(err, ErrUserVerificationRequired) {
		t.Fatal("the forged flag should fail the signature check, not the flag check")
	}
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("expected ErrVerification, got %v", err)
	}
}

// --- Cross-flow isolation ---------------------------------------------------

// TestStepUpChallengeCannotMintASession is the more serious direction of the
// cross-flow check: a step-up challenge redeemed at the login verifier would turn
// a re-authentication prompt into a session-issuing login.
func TestStepUpChallengeCannotMintASession(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginStepUp: %v", err)
	}

	_, err = f.svc.FinishLogin(f.ctx(),
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeFlowMismatch) {
		t.Fatalf("expected ErrChallengeFlowMismatch, got %v", err)
	}
}

// TestLoginChallengeCannotSatisfyStepUp is the other direction: a login challenge
// was issued without the user-verification requirement, so redeeming it here
// would let a presence-only ceremony raise the authentication context.
func TestLoginChallengeCannotSatisfyStepUp(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	for _, tc := range []struct {
		name  string
		begin func() (string, error)
	}{
		{
			name: "discoverable login challenge",
			begin: func() (string, error) {
				options, err := f.svc.BeginDiscoverableLogin(f.ctx())
				if err != nil {
					return "", err
				}
				return challengeOf(options.Response.Challenge), nil
			},
		},
		{
			name: "user-named login challenge",
			begin: func() (string, error) {
				options, err := f.svc.BeginLogin(f.ctx(), f.user.Email)
				if err != nil {
					return "", err
				}
				return challengeOf(options.Response.Challenge), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := tc.begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			err = f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session", f.auth.assertion(challenge, f.handle(t)))
			if !errors.Is(err, ErrChallengeFlowMismatch) {
				t.Fatalf("expected ErrChallengeFlowMismatch, got %v", err)
			}
		})
	}
}

// TestRegistrationChallengeCannotSatisfyStepUp closes the last combination.
func TestRegistrationChallengeCannotSatisfyStepUp(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)

	options, err := f.svc.BeginRegistration(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	err = f.svc.FinishStepUp(f.ctx(), f.user.ID, "test-session",
		f.auth.assertion(challengeOf(options.Response.Challenge), f.handle(t)))
	if !errors.Is(err, ErrChallengeFlowMismatch) {
		t.Fatalf("expected ErrChallengeFlowMismatch, got %v", err)
	}
}

// --- DeleteCredential -------------------------------------------------------

// TestDeleteCredentialRemovesOneOfSeveral is the ordinary case.
func TestDeleteCredentialRemovesOneOfSeveral(t *testing.T) {
	f := newFixture(t)
	first := f.register(t, f.auth)
	second := f.register(t, newSoftAuthenticator(t))

	if err := f.svc.DeleteCredential(f.ctx(), f.user.ID, first.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	rows, err := f.creds.ListWebauthnCredentialsByUser(f.ctx(), f.user.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one credential to remain, got %d", len(rows))
	}
	if !bytes.Equal(rows[0].ID, second.ID) {
		t.Fatal("the wrong credential was removed")
	}
}

// TestDeleteCredentialRefusesTheLastFactor prevents an irrecoverable lockout: with
// no other passkey, no TOTP, and no password, removing the final credential would
// leave the owner with no way in at all.
func TestDeleteCredentialRefusesTheLastFactor(t *testing.T) {
	f := newFixture(t)
	only := f.register(t, f.auth)

	if err := f.svc.DeleteCredential(f.ctx(), f.user.ID, only.ID); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("expected ErrLastCredential, got %v", err)
	}
	if f.creds.count(f.user.ID) != 1 {
		t.Fatal("the credential was removed despite the refusal")
	}
}

// TestDeleteCredentialRefusesTheLastPasskeyDespiteDormantFactors reflects the
// live login surface: only WebAuthn currently issues sessions, so TOTP and a
// stored password do not make deletion of the final passkey safe.
func TestDeleteCredentialRefusesTheLastPasskeyDespiteDormantFactors(t *testing.T) {
	tests := []struct {
		name  string
		apply func(u *db.User)
	}{
		{
			name: "totp enabled",
			apply: func(u *db.User) {
				u.IsMfaEnabled = true
				u.MfaTotpSecretEncrypted = []byte("enc_secret")
			},
		},
		{
			name: "password set",
			apply: func(u *db.User) {
				hash := "argon2id$dummy"
				u.PasswordHash = &hash
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			only := f.register(t, f.auth)

			user := f.users.mustGet(t, f.user.ID)
			tc.apply(&user)
			f.users.byID[user.ID] = user

			if err := f.svc.DeleteCredential(f.ctx(), f.user.ID, only.ID); !errors.Is(err, ErrLastCredential) {
				t.Fatalf("DeleteCredential = %v, want ErrLastCredential", err)
			}
			if f.creds.count(f.user.ID) != 1 {
				t.Fatal("the final credential was removed")
			}
		})
	}
}

// TestDeleteCredentialIgnoresAnEnabledFlagWithoutASecret guards against a
// half-configured account being mistaken for one that still has TOTP: MFA is only
// a usable factor when a secret is actually stored.
func TestDeleteCredentialIgnoresAnEnabledFlagWithoutASecret(t *testing.T) {
	f := newFixture(t)
	only := f.register(t, f.auth)

	user := f.users.mustGet(t, f.user.ID)
	user.IsMfaEnabled = true // but MfaTotpSecretEncrypted stays empty
	f.users.byID[user.ID] = user

	if err := f.svc.DeleteCredential(f.ctx(), f.user.ID, only.ID); !errors.Is(err, ErrLastCredential) {
		t.Fatalf("expected ErrLastCredential, got %v", err)
	}
}

// TestDeleteCredentialIsScopedToTheOwner confirms one account cannot remove
// another's authenticator, and that the refusal is indistinguishable from "no
// such credential" so credential IDs cannot be probed.
func TestDeleteCredentialIsScopedToTheOwner(t *testing.T) {
	f := newFixture(t)
	victim := f.register(t, f.auth)
	// A second credential so the last-factor guard is not what rejects this.
	f.register(t, newSoftAuthenticator(t))

	attacker := db.User{ID: uuid.New(), Email: "attacker@example.com", Status: "active"}
	f.users.byID[attacker.ID] = attacker

	if err := f.svc.DeleteCredential(f.ctx(), attacker.ID, victim.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}
	if f.creds.count(f.user.ID) != 2 {
		t.Fatal("a foreign account removed the victim's credential")
	}
}

func TestDeleteCredentialRejectsUnknownAndEmptyIDs(t *testing.T) {
	f := newFixture(t)
	f.register(t, f.auth)
	f.register(t, newSoftAuthenticator(t))

	for _, tc := range []struct {
		name string
		id   []byte
	}{
		{"unknown id", []byte("no-such-credential")},
		{"empty id", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := f.svc.DeleteCredential(f.ctx(), f.user.ID, tc.id); !errors.Is(err, ErrCredentialNotFound) {
				t.Fatalf("expected ErrCredentialNotFound, got %v", err)
			}
		})
	}
}

func TestDeleteCredentialRejectsAnUnknownAccount(t *testing.T) {
	f := newFixture(t)
	row := f.register(t, f.auth)

	if err := f.svc.DeleteCredential(f.ctx(), uuid.New(), row.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

// --- Flow stringer ----------------------------------------------------------

// TestFlowStringIncludesStepUp keeps log and error messages readable, and guards
// the iota ordering: FlowStepUp was appended, so the existing tags must not have
// shifted.
func TestFlowStringIncludesStepUp(t *testing.T) {
	for flow, want := range map[Flow]string{
		FlowRegistration:         "registration",
		FlowLoginNamed:           "login_named",
		FlowLoginDiscoverable:    "login_discoverable",
		FlowLoginMock:            "login_mock",
		FlowStepUp:               "step_up",
		FlowRecoveryRegistration: "recovery_registration",
	} {
		if got := flow.String(); got != want {
			t.Errorf("Flow(%d).String() = %q, want %q", flow, got, want)
		}
	}
}

// --- Fixture helper ---------------------------------------------------------

// stepUp drives a full step-up ceremony. When presenceOnly is set the
// authenticator reports user presence but not user verification.
func (f *ceremonyFixture) stepUp(t *testing.T, auth *softAuthenticator, presenceOnly bool) error {
	t.Helper()

	options, err := f.svc.BeginStepUp(f.ctx(), f.user.ID, "test-session")
	if err != nil {
		return err
	}
	challenge := challengeOf(options.Response.Challenge)
	handle := f.handle(t)

	body := auth.assertion(challenge, handle)
	if presenceOnly {
		body = auth.assertionPresenceOnly(challenge, handle)
	}
	return f.svc.FinishStepUp(context.Background(), f.user.ID, "test-session", body)
}
