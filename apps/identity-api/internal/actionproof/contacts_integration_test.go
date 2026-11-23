//go:build integration

package actionproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func newRealContactProofFixture(t *testing.T, claimed bool) realProofFixture {
	t.Helper()
	f := newRealMFAEnrollmentProofFixture(t, claimed)
	var role string
	if err := f.runtime.QueryRow(f.ctx, "SELECT current_user").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "GRANT SELECT,INSERT,DELETE ON contact_management_action_proofs TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	deps, policy := f.service.deps, f.service.policy
	deps.Codes = purposeCodes(t, f.client, f.delivery, true, true, contactcode.PurposeContactChange)
	var err error
	f.service, err = NewContacts(Config{BindingKey: bytes.Repeat([]byte{21}, 32), ContactIssuanceEnabled: true}, deps)
	if err != nil {
		t.Fatal(err)
	}
	f.service.SetAccountPolicy(policy)
	return f
}

func (f realProofFixture) issueContactProof(t *testing.T, action, target, channel string) (string, time.Time) {
	t.Helper()
	handle, expires, err := f.service.ContactChallenge(f.ctx, f.sess, testSecret, channel, action, target, "203.0.113.8")
	if err != nil {
		t.Fatal("contact challenge failed", err)
	}
	proof, deadline, err := f.service.ContactVerify(f.ctx, f.sess, handle, f.delivery.lastCode(), action)
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("contact proof failed or extended original deadline", err)
	}
	return proof, deadline
}

func TestContactProofSQLFrozenTargetsAndProviderFreeFinal(t *testing.T) {
	for _, actionTarget := range [][2]string{{"contact_change", "email"}, {"contact_change", "phone"}, {"contact_remove", "phone"}, {"contact_remove", "email"}} {
		for _, channel := range []string{"email", "sms"} {
			t.Run(actionTarget[0]+"/"+actionTarget[1]+"/"+channel, func(t *testing.T) {
				f := newRealContactProofFixture(t, true)
				if actionTarget[0] == "contact_remove" && actionTarget[1] == "email" {
					if channel == "email" {
						if _, _, err := f.service.ContactChallenge(f.ctx, f.sess, testSecret, channel, actionTarget[0], actionTarget[1], "203.0.113.8"); err != ErrEmailRemovalUnavailable || f.delivery.calls != 0 {
							t.Fatal("present-email operation gate dispatched", err)
						}
						return
					}
					// Truly absent primary email supports authorized no-op removal.
					if _, err := f.pool.Exec(f.ctx, "UPDATE users SET email=NULL WHERE id=$1", f.user.ID); err != nil {
						t.Fatal(err)
					}
				}
				f.sess.IdleExpiry = time.Now().UTC().Add(40 * time.Second).Truncate(time.Millisecond)
				proof, deadline := f.issueContactProof(t, actionTarget[0], actionTarget[1], channel)
				if !deadline.Equal(f.sess.IdleExpiry) {
					t.Fatal("captured original session limit ignored")
				}
				tx, guard := f.lockedMFAProof(t)
				otherAction, otherTarget := "contact_change", "email"
				if actionTarget[0] == otherAction {
					otherAction = "contact_remove"
				}
				if actionTarget[1] == otherTarget {
					otherTarget = "phone"
				}
				if _, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, otherAction, actionTarget[1], guard); err != ErrInvalid && err != ErrEmailRemovalUnavailable {
					t.Fatal("cross-action proof consumed", err)
				}
				if _, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, actionTarget[0], otherTarget, guard); err != ErrInvalid && err != ErrEmailRemovalUnavailable {
					t.Fatal("cross-target proof consumed", err)
				}
				auth, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, actionTarget[0], actionTarget[1], guard)
				if err != nil || !auth.ExpiresAt.Equal(deadline) || auth.Action != actionTarget[0] || auth.Target != actionTarget[1] || auth.Channel != channel {
					t.Fatal("SQL frozen context/deadline lost", err)
				}
				if _, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, actionTarget[0], actionTarget[1], guard); err != ErrInvalid {
					t.Fatal("single-use proof replayed", err)
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				deps := f.service.deps
				deps.Codes, deps.Limiter = nil, nil
				reader, err := NewContacts(Config{BindingKey: f.service.key}, deps)
				if err != nil {
					t.Fatal(err)
				}
				reader.SetAccountPolicy(f.service.policy)
				var role string
				if err := f.runtime.QueryRow(f.ctx, "SELECT current_user").Scan(&role); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(f.ctx, "REVOKE SELECT ON contact_management_action_proofs FROM "+pgx.Identifier{role}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				tx, guard = f.lockedMFAProof(t)
				for range 2 {
					if err := reader.ValidateContactTx(f.ctx, tx, f.sess, auth, guard); err != nil {
						t.Fatal("final validator read spent proof/provider or reacquired locks", err)
					}
				}
				if err := tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestContactProofSQLTruthfulEmailOTPAndReaderShutdown(t *testing.T) {
	f := newRealContactProofFixture(t, true)
	verifiedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	blob, err := contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, "email", *f.user.Email, contactproof.EmailOTP, verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: "email", EvidenceEncrypted: blob}); err != nil {
		t.Fatal(err)
	}
	handle, deadline, err := f.service.ContactChallenge(f.ctx, f.sess, testSecret, "email", "contact_change", "phone", "203.0.113.8")
	if err != nil {
		t.Fatal("truthful email OTP evidence could not select current old contact", err)
	}
	store, err := contactcode.NewRedisStore(f.client)
	if err != nil {
		t.Fatal(err)
	}
	deps := f.service.deps
	deps.Codes, err = contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{3}, 32)}, store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewContacts(Config{BindingKey: f.service.key}, deps)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetAccountPolicy(f.service.policy)
	proof, expires, err := reader.ContactVerify(f.ctx, f.sess, handle, f.delivery.lastCode(), "contact_change")
	if err != nil || !expires.Equal(deadline) || !capability(proof) {
		t.Fatal("sending-off finite proof reader rejected inventoried code", err)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE contact_management_action_proofs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if count, err := reader.CleanupExpiredContacts(f.ctx, 1); err != nil || count != 1 {
		t.Fatal("finite proof cleanup failed", count, err)
	}
	evidence, err := contactproof.Read(f.ctx, db.New(f.runtime), f.service.deps.Cipher, f.user.ID, "email")
	if err != nil || evidence == nil || evidence.Method != contactproof.EmailOTP || !evidence.VerifiedAt.Equal(verifiedAt) {
		t.Fatal("durable method/time reader was coupled to pending cleanup/provider", err)
	}
}

func TestContactProofSQLRollbackAndOneConcurrentStart(t *testing.T) {
	f := newRealContactProofFixture(t, true)
	proof, _ := f.issueContactProof(t, "contact_change", "phone", "email")
	tx, guard := f.lockedMFAProof(t)
	if _, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, "contact_change", "phone", guard); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			tx, err := f.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				results <- err
				return
			}
			defer rollback(ctx, tx)
			guard, err := f.service.policy.Guard(ctx, tx)
			if err == nil {
				err = pglock.LockAccount(ctx, tx, f.user.ID)
			}
			if err == nil {
				_, err = db.New(tx).GetUserByIDForUpdate(ctx, f.user.ID)
			}
			if err == nil {
				_, err = f.service.ConsumeContactStartTx(ctx, tx, f.sess, proof, "contact_change", "phone", guard)
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			results <- err
		})
	}
	workers.Wait()
	close(results)
	winners, refused := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrInvalid) {
			refused++
		} else {
			t.Fatal("concurrent exact SQL start failed unexpectedly", err)
		}
	}
	digest := sha256.Sum256([]byte(proof))
	var remaining int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_management_action_proofs WHERE digest=$1", digest[:]).Scan(&remaining); err != nil || remaining != 0 || winners != 1 || refused != 1 {
		t.Fatal("rollback restoration or concurrent one-use semantics failed", err)
	}
}

func TestContactProofSQLPolicyAndCurrentEvidenceRefusals(t *testing.T) {
	for _, scenario := range []string{"username-missing", "configured-totp", "role", "stale-version", "replaced-evidence", "corrupt-evidence"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealContactProofFixture(t, scenario != "username-missing")
			if scenario == "username-missing" {
				if _, _, err := f.service.ContactChallenge(f.ctx, f.sess, testSecret, "email", "contact_change", "phone", "203.0.113.8"); err != ErrUnauthorized || f.delivery.calls != 0 {
					t.Fatal("missing admitted username earned fallback", err)
				}
				return
			}
			proof, _ := f.issueContactProof(t, "contact_change", "phone", "email")
			tx, guard := f.lockedMFAProof(t)
			auth, err := f.service.ConsumeContactStartTx(f.ctx, tx, f.sess, proof, "contact_change", "phone", guard)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "configured-totp":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET mfa_totp_secret_encrypted=$2 WHERE id=$1", f.user.ID, []byte("configured"))
			case "role":
				_, err = f.pool.Exec(f.ctx, "INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles LIMIT 1", f.user.ID)
			case "stale-version":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
			case "replaced-evidence":
				blob, sealErr := contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, "email", *f.user.Email, contactproof.EmailOTP, time.Now().UTC().Add(-time.Second))
				if sealErr != nil {
					t.Fatal(sealErr)
				}
				err = db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: "email", EvidenceEncrypted: blob})
			case "corrupt-evidence":
				err = db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: "email", EvidenceEncrypted: bytes.Repeat([]byte{0}, 100)})
			}
			if err != nil {
				t.Fatal(err)
			}
			tx, guard = f.lockedMFAProof(t)
			if err := f.service.ValidateContactTx(f.ctx, tx, f.sess, auth, guard); err != ErrUnauthorized {
				t.Fatal("final frozen authority accepted stale policy/evidence", err)
			}
		})
	}
}

func TestContactProofSQLLostCommitAcknowledgementDoesNotPublish(t *testing.T) {
	f := newRealContactProofFixture(t, true)
	challenge, _, err := f.service.ContactChallenge(f.ctx, f.sess, testSecret, "email", "contact_change", "phone", "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	f.service.deps.DB = commitUnknownDB{f.runtime}
	if proof, expiry, err := f.service.ContactVerify(f.ctx, f.sess, challenge, f.delivery.lastCode(), "contact_change"); proof != "" || !expiry.IsZero() || err != ErrOutcomeUnknown {
		t.Fatal("lost SQL acknowledgement published tentative authority", err)
	}
	if _, _, err := f.service.ContactVerify(f.ctx, f.sess, challenge, f.delivery.lastCode(), "contact_change"); err != contactcode.ErrNoActiveCode {
		t.Fatal("lost commit restored spent OTP", err)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM contact_management_action_proofs").Scan(&count); err != nil || count != 1 || f.delivery.calls != 1 {
		t.Fatal("actual committed proof missing or provider retried", err)
	}
}
