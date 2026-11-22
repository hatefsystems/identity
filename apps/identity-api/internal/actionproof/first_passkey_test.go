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
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func firstPasskeyFixture(t *testing.T, channel string) proofFixture {
	t.Helper()
	f := newProofFixture(t)
	deps := f.service.deps
	deps.Codes = firstPasskeyCodes(t, f.client, f.delivery, channel == "email", channel == "sms")
	var err error
	f.service, err = NewFirstPasskey(Config{BindingKey: bytes.Repeat([]byte{8}, 32)}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BindingKey: bytes.Repeat([]byte{8}, 32)}, deps); err != ErrUnavailable {
		t.Fatal("first-passkey delivery enabled deletion")
	}
	if _, err := NewPasswordChange(Config{BindingKey: bytes.Repeat([]byte{8}, 32)}, deps); err != ErrUnavailable {
		t.Fatal("first-passkey delivery enabled password change")
	}
	return f
}

func (f proofFixture) issueFirstPasskey(t *testing.T, channel string) (string, time.Time) {
	t.Helper()
	challenge, deadline, err := f.service.ChallengeFirstPasskey(t.Context(), f.sess, testSecret, channel, "203.0.113.8")
	if err != nil || !capability(challenge) {
		t.Fatal("first-passkey challenge failed", err)
	}
	proof, expires, err := f.service.VerifyFirstPasskey(t.Context(), f.sess, challenge, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("first-passkey issuance lost original deadline", err)
	}
	return proof, expires
}

func TestFirstPasskeySelectedChannelsFrozenStartAndReadOnlyFinal(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := firstPasskeyFixture(t, channel)
			proof, deadline := f.issueFirstPasskey(t, channel)
			digest := sha256.Sum256([]byte(proof))
			row := f.database.firstSaved
			if f.database.saved != nil || f.database.changeSaved != nil || !bytes.Equal(row.ProofDigest, digest[:]) || !row.ExpiresAt.Time.Equal(deadline) || row.Channel != channel || len(row.ContactBinding) != 32 {
				t.Fatal("first-passkey proof used foreign storage or persisted raw authority")
			}
			begins, commits, rollbacks := f.database.beginCalls, f.database.commits, f.database.rollbacks
			f.database.events = nil
			for range 2 {
				if err := f.service.CheckFirstPasskey(t.Context(), f.sess, proof); err != nil {
					t.Fatal("nonconsuming preflight failed", err)
				}
			}
			if err := f.service.ConsumeTx(t.Context(), f.database, f.sess, proof); err != ErrInvalid {
				t.Fatal("first-passkey proof authorized deletion")
			}
			if err := f.service.ConsumePasswordChangeTx(t.Context(), f.database, f.sess, proof); err != ErrInvalid {
				t.Fatal("first-passkey proof authorized password change")
			}
			f.database.events = nil
			// Deciding reads must use the caller's transaction, not the pool reader.
			originalQueries := f.service.deps.Queries
			f.service.deps.Queries = db.New(&proofDB{})
			authorization, err := f.service.ConsumeFirstPasskeyStartTx(t.Context(), f.database, f.sess, proof)
			if err != nil || !authorization.ExpiresAt.Equal(deadline) || authorization.Channel != channel || !bytes.Equal(authorization.ContactBinding, row.ContactBinding) {
				t.Fatal("start lost DELETE RETURNING original authority", err)
			}
			if strings.Contains(strings.Join(f.database.events, ","), "advisory") || strings.Contains(strings.Join(f.database.events, ","), "row") || f.database.beginCalls != begins || f.database.commits != commits || f.database.rollbacks != rollbacks || f.database.deleteCalls != 1 {
				t.Fatal("consumer reacquired account lock/row or owned transaction")
			}
			if _, err := f.service.ConsumeFirstPasskeyStartTx(t.Context(), f.database, f.sess, proof); err != ErrInvalid {
				t.Fatal("uncommitted start consumption replayed")
			}
			if err := f.database.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := f.service.ValidateFirstPasskeyTx(t.Context(), f.database, f.sess, authorization); err != nil {
					t.Fatal("final validation required spent proof", err)
				}
			}
			f.service.deps.Queries = originalQueries
			if f.database.deleteCalls != 1 || f.database.firstSaved != nil || f.database.beginCalls != begins || f.database.commits != commits+1 || f.database.rollbacks != rollbacks {
				t.Fatal("final validation mutated state or finalized transaction")
			}
		})
	}
}

func TestFirstPasskeyStaleStartAndFinalBindings(t *testing.T) {
	for _, scenario := range []string{"contact-time", "contact", "password", "version", "session", "jkt", "revoked", "mfa", "role", "passkey", "expired", "foreign", "status", "deleted"} {
		t.Run(scenario, func(t *testing.T) {
			f := firstPasskeyFixture(t, "email")
			proof, deadline := f.issueFirstPasskey(t, "email")
			authorization := FirstPasskeyAuthorization{deadline, "email", append([]byte(nil), f.database.firstSaved.ContactBinding...)}
			sess, want := f.sess, ErrUnauthorized
			switch scenario {
			case "contact-time":
				f.seal(t, time.Now().UTC().Add(-20*time.Second))
			case "contact":
				f.database.user.Email = new("other@example.test")
			case "password":
				f.database.user.PasswordHash = new("unsupported")
			case "version":
				f.database.user.AuthVersion++
			case "session":
				sess.ID = uuid.NewString()
			case "jkt":
				sess.DPoPJKT = testCapability(7)
			case "revoked":
				f.sessions.revoke()
			case "mfa":
				f.database.user.IsMfaEnabled = true
			case "role":
				f.database.privileged = true
			case "passkey":
				f.database.passkeys = 1
			case "expired":
				f.database.firstSaved.ExpiresAt.Time = time.Now()
				authorization.ExpiresAt = time.Now()
				want = ErrInvalid
			case "foreign":
				proof, want = testCapability(9), ErrInvalid
				authorization.ContactBinding[0] ^= 1
			case "status":
				f.database.user.Status = "suspended"
			case "deleted":
				f.database.user.DeletedAt.Valid = true
			}
			if err := f.service.CheckFirstPasskey(t.Context(), sess, proof); err != want {
				t.Fatal("preflight accepted stale authority", err)
			}
			if _, err := f.service.ConsumeFirstPasskeyStartTx(t.Context(), f.database, sess, proof); err != want || f.database.deleteCalls != 0 {
				t.Fatal("start accepted stale authority or spent proof", err)
			}
			if err := f.service.ValidateFirstPasskeyTx(t.Context(), f.database, sess, authorization); err != ErrUnauthorized || f.database.deleteCalls != 0 {
				t.Fatal("final accepted stale authority or mutated proof", err)
			}
		})
	}
}

func TestFirstPasskeyExactPasswordUnknownIssuanceAndTransactionIsolation(t *testing.T) {
	f := firstPasskeyFixture(t, "email")
	if _, _, err := f.service.ChallengeFirstPasskey(t.Context(), f.sess, strings.TrimSpace(testSecret), "email", "203.0.113.8"); err != ErrUnauthorized || f.database.beginCalls != 0 {
		t.Fatal("password bytes normalized or hashed under lock")
	}
	for _, failure := range []string{"begin", "insert", "deadline", "commit"} {
		t.Run(failure, func(t *testing.T) {
			f := firstPasskeyFixture(t, "email")
			handle, _, err := f.service.ChallengeFirstPasskey(t.Context(), f.sess, testSecret, "email", "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "begin":
				f.database.beginErr = errors.New("private failure")
			case "insert":
				f.database.createErr = errors.New("private failure")
			case "deadline":
				f.database.createZero = true
			case "commit":
				f.database.commitErr = errors.New("private failure")
			}
			if proof, expires, err := f.service.VerifyFirstPasskey(t.Context(), f.sess, handle, f.delivery.lastCode()); proof != "" || !expires.IsZero() || err != ErrOutcomeUnknown || f.database.firstSaved != nil {
				t.Fatal("uncertain issuance leaked authority", err)
			}
			if _, _, err := f.service.VerifyFirstPasskey(t.Context(), f.sess, handle, f.delivery.lastCode()); err != contactcode.ErrNoActiveCode || f.delivery.calls != 1 {
				t.Fatal("failed issuance refunded OTP or retried transport")
			}
		})
	}
	f = firstPasskeyFixture(t, "email")
	proof, deadline := f.issueFirstPasskey(t, "email")
	for _, isolation := range []string{"repeatable read", "serializable"} {
		f.database.isolation = isolation
		if _, err := f.service.ConsumeFirstPasskeyStartTx(t.Context(), f.database, f.sess, proof); err != ErrTransaction {
			t.Fatal("start accepted stale isolation")
		}
		if err := f.service.ValidateFirstPasskeyTx(t.Context(), f.database, f.sess, FirstPasskeyAuthorization{deadline, "email", make([]byte, 32)}); err != ErrTransaction {
			t.Fatal("final accepted stale isolation")
		}
	}
	for _, batch := range []int32{0, -1, 1001} {
		if _, err := f.service.CleanupExpiredFirstPasskey(t.Context(), batch); err != ErrInvalid {
			t.Fatal("unbounded first-passkey cleanup")
		}
	}
}
