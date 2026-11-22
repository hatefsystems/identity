package webauthn

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func firstPending(id uuid.UUID, deadline time.Time) PendingChallenge {
	pc := newPendingChallenge(uuid.NewString(), id, deadline.UTC().Truncate(time.Millisecond))
	pc.DPoPJKT = testBrowserJKT
	pc.Session.UserVerification = protocol.VerificationRequired
	pc.Session.Expires = pc.Expires
	pc.FirstRegistration = &FirstRegistrationMetadata{Authorization: FirstPasskeyStepUp}
	return pc
}

func TestFirstRegistrationExplicitAuthorityAndOriginalDeadline(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.BeginRegistration(f.ctx(), f.user.ID, "test-session", ""); !errors.Is(err, ErrRegistrationUnauthorized) {
		t.Fatalf("untagged zero-key start: %v", err)
	}
	deadline := f.clock.Add(23*time.Second + 999999*time.Nanosecond)
	options, expires, err := f.svc.BeginAuthorizedRegistration(f.ctx(), f.user.ID, "test-session", "Frozen", RegistrationAuthorization{
		UserID: f.user.ID, SessionID: "test-session", DPoPJKT: testBrowserJKT, ExpiresAt: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(deadline.Truncate(time.Millisecond)) || options.Response.Timeout > 23000 ||
		options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("deadline or UV policy changed")
	}
	pc := f.challenges.byChallenge[challengeOf(options.Response.Challenge)]
	if pc.FirstRegistration.Authorization != FirstPasskeyStepUp || len(pc.FirstRegistration.ContactBinding) != 0 || !pc.Session.Expires.Equal(expires) {
		t.Fatal("strong authority was confused with contact proof")
	}
	if len(f.handle(t)) != 0 || f.creds.count(f.user.ID) != 0 {
		t.Fatal("options wrote account state")
	}
	if _, _, err := f.svc.BeginAuthorizedRegistration(f.ctx(), f.user.ID, "test-session", "", RegistrationAuthorization{
		UserID: f.user.ID, SessionID: "test-session", DPoPJKT: testBrowserJKT, ExpiresAt: deadline,
	}); !errors.Is(err, ErrEnrollmentInProgress) {
		t.Fatalf("concurrent start: %v", err)
	}
}

func TestFirstRegistrationSignedNonUVAndMissingUPFailClosed(t *testing.T) {
	for _, flags := range []byte{flagUserPresent, flagUserVerified, 0} {
		t.Run(string(rune('0'+flags)), func(t *testing.T) {
			f := newFixture(t)
			options, err := f.beginRegistration(f.ctx(), f.user.ID, "test-session", "")
			if err != nil {
				t.Fatal(err)
			}
			challenge := challengeOf(options.Response.Challenge)
			pending := f.challenges.byChallenge[challenge]
			body := f.auth.attestationWithFlags(challenge, flags, true)
			if flags == flagUserPresent {
				parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
				if err != nil {
					t.Fatal(err)
				}
				relaxed := pending.Session
				relaxed.UserVerification = protocol.VerificationPreferred
				verified, err := f.svc.wa.CreateCredential(newUserAdapter(f.user, pending.Session.UserID, nil), relaxed, parsed)
				if err != nil || verified.Flags.UserVerified || !verified.Flags.UserPresent {
					t.Fatal("signed non-UV fixture is not cryptographically valid", err)
				}
			}
			if _, err := f.svc.FinishRegistration(f.ctx(), f.user.ID, "test-session", body); err == nil {
				t.Fatal("signed non-UV/UP credential accepted")
			}
			if len(f.handle(t)) != 0 || f.creds.count(f.user.ID) != 0 {
				t.Fatal("rejected ceremony wrote state")
			}
			if err := f.challenges.CheckFirstRegistration(t.Context(), challenge, pending); err != nil {
				t.Fatal("Take/failure released slot", err)
			}
		})
	}
}

func TestFirstRegistrationFinalSlotAndZeroCountFences(t *testing.T) {
	for _, change := range []string{"missing", "replacement", "expired", "credential appeared", "metadata removed"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			options, err := f.beginRegistration(f.ctx(), f.user.ID, "test-session", "")
			if err != nil {
				t.Fatal(err)
			}
			challenge := challengeOf(options.Response.Challenge)
			switch change {
			case "missing":
				delete(f.challenges.firstSlots, f.user.ID)
			case "replacement":
				slot := f.challenges.firstSlots[f.user.ID]
				slot.digest[0] ^= 1
				f.challenges.firstSlots[f.user.ID] = slot
			case "expired":
				f.advance(f.svc.challengeTTL)
			case "credential appeared":
				f.creds.byUser = map[uuid.UUID][]db.WebauthnCredential{f.user.ID: {{UserID: f.user.ID}}}
			case "metadata removed":
				pc := f.challenges.byChallenge[challenge]
				pc.FirstRegistration = nil
				f.challenges.byChallenge[challenge] = pc
			}
			before := f.creds.count(f.user.ID)
			if _, err := f.svc.FinishRegistration(f.ctx(), f.user.ID, "test-session", f.auth.attestation(challenge)); err == nil {
				t.Fatal("stale first authority accepted")
			}
			if len(f.handle(t)) != 0 || f.creds.count(f.user.ID) != before {
				t.Fatal("stale finish wrote account state")
			}
		})
	}
}

func TestMemoryFirstRegistrationSlotsAreBoundedAndRetained(t *testing.T) {
	now := testNow
	store := newFixedChallengeStore(&now)
	store.maxEntries = 1
	pc := firstPending(uuid.New(), now.Add(time.Minute))
	if err := store.Save(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Take(t.Context(), pc.Session.Challenge, bindingFor(pc)); err != nil {
		t.Fatal(err)
	}
	other := firstPending(pc.UserRef, pc.Expires)
	if err := store.Save(t.Context(), other.Session.Challenge, other); !errors.Is(err, ErrEnrollmentInProgress) {
		t.Fatal("Take released slot", err)
	}
	other.UserRef = uuid.New()
	if err := store.Save(t.Context(), other.Session.Challenge, other); !errors.Is(err, ErrChallengeStoreUnavailable) {
		t.Fatal("live slot evicted for capacity", err)
	}
	if err := store.CheckFirstRegistration(t.Context(), pc.Session.Challenge, pc); err != nil {
		t.Fatal(err)
	}
	now = pc.Expires
	other.Expires = now.Add(time.Minute)
	other.Session.Expires = other.Expires
	if err := store.Save(t.Context(), other.Session.Challenge, other); err != nil {
		t.Fatal("expired slots not swept", err)
	}
}

func TestMemoryFirstRegistrationAccountWideRace(t *testing.T) {
	store := NewMemoryChallengeStore()
	id := uuid.New()
	deadline := time.Now().Add(time.Minute)
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() { pc := firstPending(id, deadline); results <- store.Save(t.Context(), pc.Session.Challenge, pc) })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrEnrollmentInProgress) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners: %d", winners)
	}
}

func TestFirstRegistrationMetadataCannotDowngrade(t *testing.T) {
	for _, change := range []string{"unknown", "contact missing", "strong contact", "wrong flow", "UV preferred", "deadline rounded up"} {
		pc := firstPending(uuid.New(), time.Now().Add(time.Minute))
		switch change {
		case "unknown":
			pc.FirstRegistration.Authorization = "other"
		case "contact missing":
			pc.FirstRegistration.Authorization = FirstPasskeyEnrollment
		case "strong contact":
			pc.FirstRegistration.Channel = "email"
		case "wrong flow":
			pc.Flow = FlowRecoveryRegistration
		case "UV preferred":
			pc.Session.UserVerification = protocol.VerificationPreferred
		case "deadline rounded up":
			pc.Session.Expires = pc.Expires.Add(time.Millisecond)
		}
		if err := NewMemoryChallengeStore().Save(t.Context(), pc.Session.Challenge, pc); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("%s: %v", change, err)
		}
	}
}
