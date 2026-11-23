package actionproof

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func TestMFAEnrollmentReaderConstructsWithoutDelivery(t *testing.T) {
	f := newProofFixture(t)
	deps := f.service.deps
	deps.Codes, deps.Limiter = nil, nil
	reader, err := NewMFAEnrollment(Config{BindingKey: bytes.Repeat([]byte{11}, 32)}, deps)
	if err != nil {
		t.Fatal("binding reader required an enabled provider", err)
	}
	if _, _, err := reader.ChallengeMFAEnrollment(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); err != contactcode.ErrDisabled {
		t.Fatal("reader enabled contact delivery", err)
	}
	if _, _, err := reader.VerifyMFAEnrollment(t.Context(), f.sess, testCapability(8), "123456"); err != contactcode.ErrDisabled {
		t.Fatal("reader issued a proof", err)
	}
	if _, err := NewMFAEnrollment(Config{BindingKey: make([]byte, 32)}, deps); err != ErrInvalid {
		t.Fatal("reader admitted unprotected bindings")
	}
	for _, isolation := range []string{"repeatable read", "serializable"} {
		f.database.isolation = isolation
		if _, err := reader.ConsumeMFAEnrollmentStartTx(t.Context(), f.database, f.sess, testCapability(8), username.GuardAuthority{}); err != ErrTransaction {
			t.Fatal("consumer accepted stale isolation")
		}
		if err := reader.ValidateMFAEnrollmentTx(t.Context(), f.database, f.sess, MFAEnrollmentAuthorization{time.Now().Add(time.Minute), "email", make([]byte, 32)}, username.GuardAuthority{}); err != ErrTransaction {
			t.Fatal("validator accepted stale isolation")
		}
	}
	for _, batch := range []int32{-1, 0, 1001} {
		if _, err := reader.CleanupExpiredMFAEnrollment(t.Context(), batch); err != ErrInvalid {
			t.Fatal("unbounded proof cleanup")
		}
	}
}

func TestMFAEnrollmentExactPasswordAndFailClosedEligibility(t *testing.T) {
	f := newProofFixture(t)
	deps := f.service.deps
	deps.Codes = purposeCodes(t, f.client, f.delivery, true, false, contactcode.PurposeMFAEnrollment)
	var err error
	f.service, err = NewMFAEnrollment(Config{BindingKey: bytes.Repeat([]byte{11}, 32)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.service.ChallengeMFAEnrollment(t.Context(), f.sess, strings.TrimSpace(testSecret), "email", "203.0.113.8"); err != ErrUnauthorized || f.database.beginCalls != 0 || f.delivery.calls != 0 {
		t.Fatal("password normalized or verified inside transaction", err)
	}
	if _, _, err := f.service.ChallengeMFAEnrollment(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); err != ErrUnauthorized || f.delivery.calls != 0 {
		t.Fatal("disabled password login authorized enrollment", err)
	}
	f.service.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true})
	if _, _, err := f.service.ChallengeMFAEnrollment(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); err != ErrUnavailable || f.delivery.calls != 0 {
		t.Fatal("missing admitted username authority authorized enrollment", err)
	}
}

func TestMFAEnrollmentContactMACCannotChangePurpose(t *testing.T) {
	f := newProofFixture(t)
	binding, err := f.service.live(t.Context(), f.sess)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := f.service.contact(t.Context(), f.service.deps.Queries, binding, "email")
	if err != nil {
		t.Fatal(err)
	}
	enrollment := f.service.contactBindingFor(binding, contactcode.PurposeMFAEnrollment, "email", *evidence)
	for _, purpose := range []string{contactcode.PurposeAccountDeletion, contactcode.PurposePasswordChange, contactcode.PurposeFirstPasskey, contactcode.PurposeLogin} {
		if bytes.Equal(enrollment, f.service.contactBindingFor(binding, purpose, "email", *evidence)) {
			t.Fatal("MFA enrollment contact MAC can authorize another purpose")
		}
	}
}

func TestMFAEnrollmentExpiryDoesNotReclassifyInvalidBinding(t *testing.T) {
	f := newProofFixture(t)
	binding, err := f.service.live(t.Context(), f.sess)
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	for _, authorization := range []MFAEnrollmentAuthorization{
		{ExpiresAt: expired, Channel: "email", ContactBinding: make([]byte, 31)},
		{ExpiresAt: expired, Channel: "login", ContactBinding: make([]byte, 32)},
	} {
		if err := f.service.mfaEnrollmentBinding(t.Context(), f.service.deps.Queries, binding, authorization); err != ErrUnauthorized {
			t.Fatal("invalid binding was classified as expiry", err)
		}
	}
	if err := f.service.mfaEnrollmentBinding(t.Context(), f.service.deps.Queries, binding, MFAEnrollmentAuthorization{ExpiresAt: expired, Channel: "email", ContactBinding: make([]byte, 32)}); err != ErrMFAEnrollmentExpired {
		t.Fatal("expired bounded authority was not identified distinctly", err)
	}
}
