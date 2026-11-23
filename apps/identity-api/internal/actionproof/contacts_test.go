package actionproof

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func contactProofFixture(t *testing.T, enabled bool) proofFixture {
	t.Helper()
	f := newProofFixture(t)
	store, err := contactcode.NewRedisStore(f.client)
	if err != nil {
		t.Fatal(err)
	}
	deps := f.service.deps
	deps.Codes, err = contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{3}, 32), ContactChangeEmail: f.delivery, ContactRemovalEmail: f.delivery}, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = NewContacts(Config{BindingKey: bytes.Repeat([]byte{11}, 32), ContactIssuanceEnabled: enabled}, deps)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestContactProofDefaultOffReaderAndStrictInput(t *testing.T) {
	f := contactProofFixture(t, false)
	if _, _, err := f.service.ContactChallenge(t.Context(), f.sess, testSecret, "email", "contact_change", "phone", "203.0.113.8"); err != contactcode.ErrDisabled || f.delivery.calls != 0 || f.database.beginCalls != 0 {
		t.Fatal("default-off issuance dispatched", err)
	}
	deps := f.service.deps
	deps.Codes, deps.Limiter = nil, nil
	reader, err := NewContacts(Config{BindingKey: f.service.key}, deps)
	if err != nil {
		t.Fatal("disabled SQL reader required sender", err)
	}
	if _, err := NewContacts(Config{BindingKey: make([]byte, 32)}, deps); err != ErrInvalid {
		t.Fatal("unprotected contact binding key accepted")
	}
	for _, isolation := range []string{"repeatable read", "serializable"} {
		f.database.isolation = isolation
		if _, err := reader.ConsumeContactStartTx(t.Context(), f.database, f.sess, testCapability(8), "contact_change", "phone", username.GuardAuthority{}); err != ErrTransaction {
			t.Fatal("consumer admitted stale transaction isolation", err)
		}
		if err := reader.ValidateContactTx(t.Context(), f.database, f.sess, ContactAuthorization{}, username.GuardAuthority{}); err != ErrTransaction {
			t.Fatal("validator admitted stale transaction isolation", err)
		}
	}
	for _, batch := range []int32{-1, 0, 1001} {
		if _, err := reader.CleanupExpiredContacts(t.Context(), batch); err != ErrInvalid {
			t.Fatal("unbounded contact proof cleanup")
		}
	}
}

func TestContactChallengeExactPasswordEligibilityAndEmailGate(t *testing.T) {
	f := contactProofFixture(t, true)
	f.service.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true})
	for _, input := range []struct{ secret, action, target string }{
		{strings.TrimSpace(testSecret), "contact_change", "phone"},
		{testSecret, "account_deletion", "phone"},
		{testSecret, "contact_change", "sms"},
		{strings.Repeat("a", 1025), "contact_change", "phone"},
	} {
		if _, _, err := f.service.ContactChallenge(t.Context(), f.sess, input.secret, "email", input.action, input.target, "203.0.113.8"); err != ErrUnauthorized && err != ErrInvalid {
			t.Fatal("invalid input or normalized password admitted", err)
		}
	}
	if f.database.beginCalls != 0 || f.delivery.calls != 0 {
		t.Fatal("malformed/password rejection acquired account locks or dispatched")
	}
	before := len(f.limiter.keys)
	if _, _, err := f.service.ContactChallenge(t.Context(), f.sess, testSecret, "email", "contact_remove", "email", "203.0.113.8"); err != ErrEmailRemovalUnavailable || len(f.limiter.keys) != before || f.delivery.calls != 0 {
		t.Fatal("present-email gate allowed avoidable hashing/delivery", err)
	}
	for _, scenario := range []string{"login-off", "unsupported-password", "configured-totp", "enabled-mfa", "role", "passkey", "inactive", "version"} {
		t.Run(scenario, func(t *testing.T) {
			f := contactProofFixture(t, true)
			f.service.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true})
			switch scenario {
			case "login-off":
				f.service.SetAccountPolicy(accountpolicy.Policy{})
			case "unsupported-password":
				f.database.user.PasswordHash = new("unsupported")
			case "configured-totp":
				f.database.user.MfaTotpSecretEncrypted = []byte("configured")
			case "enabled-mfa":
				f.database.user.IsMfaEnabled = true
			case "role":
				f.database.privileged = true
			case "passkey":
				f.database.passkeys = 1
			case "inactive":
				f.database.user.Status = "suspended"
			case "version":
				f.database.user.AuthVersion++
			}
			if _, _, err := f.service.ContactChallenge(t.Context(), f.sess, testSecret, "email", "contact_change", "phone", "203.0.113.8"); err != ErrUnauthorized || f.delivery.calls != 0 {
				t.Fatal("ineligible fallback authorized or dispatched", err)
			}
		})
	}
}

func TestContactMACBindsActionTargetAndTruthfulCompleteEvidence(t *testing.T) {
	f := contactProofFixture(t, false)
	binding, err := f.service.live(t.Context(), f.sess)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := f.service.contact(t.Context(), f.service.deps.Queries, binding, "email")
	if err != nil {
		t.Fatal(err)
	}
	mac := f.service.contactManagementMAC(binding, "contact_change", "phone", "email", *evidence)
	auth := ContactAuthorization{"contact_change", "phone", "email", mac, binding.SessionID, binding.JKT, binding.AuthVersion, time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)}
	if err := f.service.contactAuthorization(t.Context(), f.database, binding, auth); err != nil {
		t.Fatal("matching complete evidence rejected", err)
	}
	for _, field := range []string{"action", "target", "channel", "session", "jkt", "version", "method", "time", "destination"} {
		other, changed := auth, *evidence
		switch field {
		case "action":
			other.Action = "contact_remove"
		case "target":
			other.Target = "email"
		case "channel":
			other.Channel = "sms"
		case "session":
			other.SessionID = "foreign"
		case "jkt":
			other.DPoPJKT = testCapability(9)
		case "version":
			other.AuthVersion++
		case "method":
			changed.Method = contactproof.EmailOTP
		case "time":
			changed.VerifiedAt = changed.VerifiedAt.Add(time.Second)
		case "destination":
			changed.Destination = "foreign@example.test"
		}
		if field == "method" || field == "time" || field == "destination" {
			if bytes.Equal(mac, f.service.contactManagementMAC(binding, auth.Action, auth.Target, auth.Channel, changed)) {
				t.Fatal("MAC omitted complete evidence", field)
			}
		} else if err := f.service.contactAuthorization(t.Context(), f.database, binding, other); err != ErrUnauthorized {
			t.Fatal("foreign authorization binding accepted", field, err)
		}
	}
	for _, purpose := range []string{contactcode.PurposeLogin, contactcode.PurposeAccountDeletion, contactcode.PurposeFirstPasskey, contactcode.PurposeMFAEnrollment, contactcode.PurposePasswordChange} {
		if bytes.Equal(mac, f.service.contactBindingFor(binding, purpose, "email", *evidence)) {
			t.Fatal("contact management MAC exchanged with another action")
		}
	}
	auth.ExpiresAt = time.Now().Add(-time.Second).Truncate(time.Millisecond)
	if err := f.service.contactAuthorization(t.Context(), f.database, binding, auth); err != ErrContactExpired {
		t.Fatal("expired bounded authorization accepted", err)
	}
	auth.EvidenceMAC = make([]byte, 31)
	if err := f.service.contactAuthorization(t.Context(), f.database, binding, auth); err != ErrUnauthorized {
		t.Fatal("invalid binding confused with expiry", err)
	}
}
