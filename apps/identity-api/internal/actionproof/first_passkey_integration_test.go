//go:build integration

package actionproof

import (
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

func (f realProofFixture) issueFirstPasskey(t *testing.T, channel string) (string, time.Time) {
	t.Helper()
	handle, deadline, err := f.service.ChallengeFirstPasskey(f.ctx, f.sess, testSecret, channel, "203.0.113.8")
	if err != nil || !capability(handle) {
		t.Fatal("real first-passkey challenge failed", err)
	}
	proof, expires, err := f.service.VerifyFirstPasskey(f.ctx, f.sess, handle, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("real first-passkey proof lost original expiry", err)
	}
	return proof, expires
}

func (f realProofFixture) firstStartTx(t *testing.T) pgx.Tx {
	t.Helper()
	tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if err := pglock.LockAccount(f.ctx, tx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestFirstPasskeyOriginalExpiryCallerRollbackAndConcurrentStartIntegration(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newRealProofFixtureFor(t, contactcode.PurposeFirstPasskey)
			proof, deadline := f.issueFirstPasskey(t, channel)
			digest := sha256.Sum256([]byte(proof))
			var storedDeadline time.Time
			if err := f.pool.QueryRow(f.ctx, "SELECT expires_at FROM first_passkey_enrollment_action_proofs WHERE proof_digest=$1", digest[:]).Scan(&storedDeadline); err != nil || !storedDeadline.Equal(deadline) {
				t.Fatal("SQL expiry was restamped", err)
			}
			for range 2 {
				if err := f.service.CheckFirstPasskey(f.ctx, f.sess, proof); err != nil {
					t.Fatal(err)
				}
			}
			tx := f.firstStartTx(t)
			frozen, err := f.service.ConsumeFirstPasskeyStartTx(f.ctx, tx, f.sess, proof)
			if err != nil || !frozen.ExpiresAt.Equal(deadline) || frozen.Channel != channel || len(frozen.ContactBinding) != 32 {
				t.Fatal("consumer lost SQL original authority", err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.service.CheckFirstPasskey(f.ctx, f.sess, proof); err != nil {
				t.Fatal("caller rollback did not roll back DELETE", err)
			}
			results := make(chan error, 8)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
					if err != nil {
						results <- err
						return
					}
					defer func() { _ = tx.Rollback(context.Background()) }()
					if err = pglock.LockAccount(f.ctx, tx, f.user.ID); err == nil {
						_, err = db.New(tx).GetUserByIDForUpdate(f.ctx, f.user.ID)
					}
					if err == nil {
						_, err = f.service.ConsumeFirstPasskeyStartTx(f.ctx, tx, f.sess, proof)
					}
					if err == nil {
						err = tx.Commit(f.ctx)
					}
					results <- err
				})
			}
			wg.Wait()
			close(results)
			wins := 0
			for err := range results {
				if err == nil {
					wins++
				} else if !errors.Is(err, ErrInvalid) {
					t.Fatal("unexpected concurrent start outcome", err)
				}
			}
			if wins != 1 {
				t.Fatal("concurrent start had other than one committed DELETE")
			}
			tx = f.firstStartTx(t)
			for range 2 {
				if err := f.service.ValidateFirstPasskeyTx(f.ctx, tx, f.sess, frozen); err != nil {
					t.Fatal("read-only final required spent SQL proof", err)
				}
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.service.CheckFirstPasskey(f.ctx, f.sess, proof); err != ErrInvalid {
				t.Fatal("committed proof remained reusable")
			}
		})
	}
}

func TestFirstPasskeyFinalContactPolicyAndCurrentDeadlineIntegration(t *testing.T) {
	for _, scenario := range []string{"contact-time", "password", "passkey", "mfa", "role", "version", "deadline"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealProofFixtureFor(t, contactcode.PurposeFirstPasskey)
			proof, _ := f.issueFirstPasskey(t, "email")
			tx := f.firstStartTx(t)
			frozen, err := f.service.ConsumeFirstPasskeyStartTx(f.ctx, tx, f.sess, proof)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "contact-time":
				blob, err := contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, contactproof.Email, *f.user.Email, contactproof.EmailLink, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				err = db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: contactproof.Email, EvidenceEncrypted: blob})
				if err != nil {
					t.Fatal(err)
				}
			case "password":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET password_hash='unsupported' WHERE id=$1", f.user.ID)
			case "passkey":
				_, err = f.pool.Exec(f.ctx, "INSERT INTO webauthn_credentials(user_id,id,public_key,attestation_type,aaguid,sign_count,name) VALUES($1,$2,$3,'none','00000000-0000-0000-0000-000000000000',0,'fixture')", f.user.ID, []byte("first-proof-policy-key"), []byte("fixture-public-key"))
			case "mfa":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", f.user.ID)
			case "role":
				_, err = f.pool.Exec(f.ctx, "INSERT INTO user_roles(user_id,role_id) VALUES($1,'support')", f.user.ID)
			case "version":
				_, err = f.pool.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
			case "deadline":
				frozen.ExpiresAt = time.Now().Add(20 * time.Millisecond)
				time.Sleep(30 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			tx = f.firstStartTx(t)
			if err := f.service.ValidateFirstPasskeyTx(f.ctx, tx, f.sess, frozen); err != ErrUnauthorized {
				t.Fatal("final accepted changed policy/contact or stale current clock", err)
			}
		})
	}
}

func TestFirstPasskeyDigestPrivilegesCleanupAndCascadeIntegration(t *testing.T) {
	f := newRealProofFixtureFor(t, contactcode.PurposeFirstPasskey)
	proof, _ := f.issueFirstPasskey(t, "email")
	var selectOK, insertOK, deleteOK, updateOK, truncateOK, public, raw bool
	if err := f.runtime.QueryRow(f.ctx, "SELECT has_table_privilege(current_user,'first_passkey_enrollment_action_proofs','SELECT'),has_table_privilege(current_user,'first_passkey_enrollment_action_proofs','INSERT'),has_table_privilege(current_user,'first_passkey_enrollment_action_proofs','DELETE'),has_any_column_privilege(current_user,'first_passkey_enrollment_action_proofs','UPDATE'),has_table_privilege(current_user,'first_passkey_enrollment_action_proofs','TRUNCATE')").Scan(&selectOK, &insertOK, &deleteOK, &updateOK, &truncateOK); err != nil || !selectOK || !insertOK || !deleteOK || updateOK || truncateOK {
		t.Fatal("first proof grants exceeded SELECT/INSERT/DELETE", err)
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.table_privileges WHERE table_name='first_passkey_enrollment_action_proofs' AND grantee='PUBLIC'),EXISTS(SELECT 1 FROM first_passkey_enrollment_action_proofs WHERE proof_digest=convert_to($1,'UTF8'))", proof).Scan(&public, &raw); err != nil || public || raw {
		t.Fatal("PUBLIC/raw proof persisted", err)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE first_passkey_enrollment_action_proofs SET action='password_change'"); err == nil {
		t.Fatal("first proof accepted another purpose")
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE first_passkey_enrollment_action_proofs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO first_passkey_enrollment_action_proofs SELECT sha256(proof_digest),user_id,session_id,jkt,auth_version,action,channel,contact_binding,created_at,expires_at FROM first_passkey_enrollment_action_proofs"); err != nil {
		t.Fatal(err)
	}
	if count, err := f.service.CleanupExpiredFirstPasskey(f.ctx, 1); err != nil || count != 1 {
		t.Fatal("cleanup exceeded its bounded batch", err)
	}
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM users WHERE id=$1", f.user.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM first_passkey_enrollment_action_proofs").Scan(&count); err != nil || count != 0 {
		t.Fatal("account purge retained proof binding", err)
	}
}
