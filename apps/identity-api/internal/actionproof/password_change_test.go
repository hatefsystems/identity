package actionproof

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
)

func newPasswordChangeFixture(t *testing.T) proofFixture {
	t.Helper()
	f := newProofFixture(t)
	deps := f.service.deps
	deps.Codes = passwordChangeCodes(t, f.client, f.delivery, true, true)
	var err error
	f.service, err = NewPasswordChange(Config{BindingKey: bytes.Repeat([]byte{2}, 32)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BindingKey: bytes.Repeat([]byte{2}, 32)}, deps); err != ErrUnavailable {
		t.Fatal("password-change transport enabled deletion")
	}
	return f
}

func (f proofFixture) issuePasswordChange(t *testing.T, channel string) (string, time.Time) {
	t.Helper()
	handle, deadline, err := f.service.ChallengePasswordChange(t.Context(), f.sess, testSecret, channel, "203.0.113.8")
	if err != nil || !capability(handle) {
		t.Fatal("password-change challenge failed", err)
	}
	proof, expires, err := f.service.VerifyPasswordChange(t.Context(), f.sess, handle, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("password-change issuance changed original deadline", err)
	}
	return proof, expires
}

func TestPasswordChangeIndependentChannelsAndNonconsumingPreflight(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newPasswordChangeFixture(t)
			f.service.deps.Codes = passwordChangeCodes(t, f.client, f.delivery, channel == "email", channel == "sms")
			proof, deadline := f.issuePasswordChange(t, channel)
			digest := sha256.Sum256([]byte(proof))
			row := f.database.changeSaved
			if f.database.saved != nil || !bytes.Equal(row.ProofDigest, digest[:]) || !row.ExpiresAt.Time.Equal(deadline) || row.Channel != channel || len(row.ContactBinding) != 32 {
				t.Fatal("password-change issuance used deletion storage or persisted raw authority")
			}
			begins, commits, rollbacks := f.database.beginCalls, f.database.commits, f.database.rollbacks
			f.database.events = nil
			for range 2 {
				if err := f.service.CheckPasswordChange(t.Context(), f.sess, proof); err != nil {
					t.Fatal("non-consuming preflight failed", err)
				}
			}
			if f.database.deleteCalls != 0 || strings.Contains(strings.Join(f.database.events, ","), "advisory") || f.database.beginCalls != begins || f.database.commits != commits || f.database.rollbacks != rollbacks {
				t.Fatal("preflight consumed authority or acquired an account transaction/lock")
			}
			if err := f.service.ConsumeTx(t.Context(), f.database, f.sess, proof); err != ErrInvalid {
				t.Fatal("password-change proof authorized deletion", err)
			}
			if err := f.service.ConsumePasswordChangeTx(t.Context(), f.database, f.sess, proof); err != nil {
				t.Fatal("password-change consumer rejected valid proof", err)
			}
			if f.database.deleteCalls != 1 || f.database.commits != commits || f.database.rollbacks != rollbacks || f.database.beginCalls != begins || f.sessions.sess != f.sess {
				t.Fatal("consumer owned transaction finalization or renewed session")
			}
			if err := f.database.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := f.service.CheckPasswordChange(t.Context(), f.sess, proof); err != ErrInvalid {
				t.Fatal("committed no-op retained reusable proof")
			}
		})
	}
}

func TestPasswordChangeChallengeRejectsAuthorityTransitionsAndExactPassword(t *testing.T) {
	for _, scenario := range []string{"password", "version", "passkey", "mfa", "role", "status", "contact", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPasswordChangeFixture(t)
			f.database.onLock = func() {
				switch scenario {
				case "password":
					f.database.user.PasswordHash = new("changed-hash")
				case "version":
					f.database.user.AuthVersion++
				case "passkey":
					f.database.passkeys = 1
				case "mfa":
					f.database.user.IsMfaEnabled = true
				case "role":
					f.database.privileged = true
				case "status":
					f.database.user.Status = "suspended"
				case "contact":
					delete(f.database.evidence, "email")
				case "revoked":
					f.sessions.revoke()
				}
			}
			if handle, _, err := f.service.ChallengePasswordChange(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); handle != "" || err != ErrUnauthorized || f.delivery.calls != 0 {
				t.Fatal("changed authority dispatched password-change code", err)
			}
		})
	}
	f := newPasswordChangeFixture(t)
	if handle, _, err := f.service.ChallengePasswordChange(t.Context(), f.sess, strings.TrimSpace(testSecret), "email", "203.0.113.8"); handle != "" || err != ErrUnauthorized || f.database.beginCalls != 0 {
		t.Fatal("current password was normalized or verified under account lock")
	}
	if _, _, err := f.service.Challenge(t.Context(), f.sess, testSecret, "email", "203.0.113.8"); err != contactcode.ErrDisabled {
		t.Fatal("independent password-change email enabled deletion")
	}
}

func TestPasswordChangePreflightAndConsumerRecheckBindings(t *testing.T) {
	for _, scenario := range []string{"contact-time", "contact", "version", "session", "jkt", "revoked", "mfa", "role", "passkey", "expired", "foreign"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPasswordChangeFixture(t)
			proof, _ := f.issuePasswordChange(t, "email")
			sess, want := f.sess, ErrUnauthorized
			switch scenario {
			case "contact-time":
				f.seal(t, time.Now().UTC().Add(-20*time.Second))
			case "contact":
				f.database.user.Email = new("other@example.test")
			case "version":
				f.database.user.AuthVersion++
			case "session":
				sess.ID = uuid.NewString()
			case "jkt":
				sess.DPoPJKT = testCapability(7)
			case "revoked":
				f.sessions.revoke()
			case "mfa":
				f.database.user.IsMfaEnabled = true // Required flag, even without usable TOTP.
			case "role":
				f.database.privileged = true
			case "passkey":
				f.database.passkeys = 1
			case "expired":
				f.database.changeSaved.ExpiresAt.Time = time.Now()
				want = ErrInvalid
			case "foreign":
				proof, want = testCapability(9), ErrInvalid
			}
			if err := f.service.CheckPasswordChange(t.Context(), sess, proof); err != want {
				t.Fatal("preflight accepted stale binding", err)
			}
			if err := f.service.ConsumePasswordChangeTx(t.Context(), f.database, sess, proof); err != want || f.database.deleteCalls != 0 {
				t.Fatal("consumer accepted stale binding or consumed proof", err)
			}
		})
	}
}

func TestPasswordChangeFailedIssuanceAndConsumerIsolation(t *testing.T) {
	for _, scenario := range []string{"begin", "insert", "deadline", "commit", "contact-time"} {
		f := newPasswordChangeFixture(t)
		handle, _, err := f.service.ChallengePasswordChange(t.Context(), f.sess, testSecret, "email", "203.0.113.8")
		if err != nil {
			t.Fatal(err)
		}
		want := ErrOutcomeUnknown
		switch scenario {
		case "begin":
			f.database.beginErr = errors.New("private dependency failure")
		case "insert":
			f.database.createErr = errors.New("private dependency failure")
		case "deadline":
			f.database.createZero = true
		case "commit":
			f.database.commitErr = errors.New("private dependency failure")
		case "contact-time":
			f.seal(t, time.Now().UTC().Add(-20*time.Second))
			want = ErrUnauthorized
		}
		if proof, expires, err := f.service.VerifyPasswordChange(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || !expires.IsZero() || err != want || f.database.changeSaved != nil {
			t.Fatal("failed issuance returned authority", scenario, err)
		}
		if _, _, err := f.service.VerifyPasswordChange(t.Context(), f.sess, handle, f.delivery.lastCode()); err != contactcode.ErrNoActiveCode || f.delivery.calls != 1 {
			t.Fatal("failed issuance retried consumed OTP")
		}
	}
	f := newPasswordChangeFixture(t)
	proof, _ := f.issuePasswordChange(t, "email")
	for _, isolation := range []string{"repeatable read", "serializable"} {
		f.database.isolation = isolation
		if err := f.service.ConsumePasswordChangeTx(t.Context(), f.database, f.sess, proof); err != ErrTransaction || f.database.deleteCalls != 0 {
			t.Fatal("password-change consumer accepted stale snapshot isolation")
		}
	}
	for _, batch := range []int32{0, -1, 1001} {
		if _, err := f.service.CleanupExpiredPasswordChange(t.Context(), batch); err != ErrInvalid {
			t.Fatal("unbounded password-change cleanup accepted")
		}
	}
}
