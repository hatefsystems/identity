//go:build integration

package actionproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

func newRealMFAEnrollmentProofFixture(t *testing.T) realProofFixture {
	t.Helper()
	f := newRealProofFixtureFor(t, contactcode.PurposeMFAEnrollment)
	// This admitted authority exists only inside the run-owned fixture database.
	normalizer, err := username.New(username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1, Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}, `[\x{0621}-\x{06CC}]+`, bytes.Repeat([]byte{0x71}, 32), "mfa-proof-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	a := normalizer.Authority()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, []any{a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact()}},
		{`INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, []any{a.KeyID, a.KeyVerifier[:]}},
		{`UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, []any{a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:]}},
	} {
		if _, err := f.pool.Exec(f.ctx, statement.sql, statement.args...); err != nil {
			t.Fatal("install run-owned MFA proof username authority failed", err)
		}
	}
	var runtimeRole string
	if err := f.runtime.QueryRow(f.ctx, "SELECT current_user").Scan(&runtimeRole); err != nil {
		t.Fatal(err)
	}
	role := pgx.Identifier{runtimeRole}.Sanitize()
	for _, grant := range []string{
		"GRANT SELECT ON username_active_policy,username_policy_artifacts,username_lookup_keys TO ",
		"GRANT UPDATE(singleton) ON username_active_policy TO ",
	} {
		if _, err := f.pool.Exec(f.ctx, grant+role); err != nil {
			t.Fatal("grant restricted MFA proof username reads failed", err)
		}
	}
	names, err := username.NewStore(f.pool, f.service.deps.Cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	value, err := normalizer.Normalize("\u0645\u0627\u0644\u06a9")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(f.ctx, tx)
	if err := names.Assign(f.ctx, tx, f.user.ID, f.user.AuthVersion, value); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	names, err = username.NewStore(f.runtime, f.service.deps.Cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	f.service.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: names})
	return f
}

func (f realProofFixture) issueMFAEnrollment(t *testing.T, channel string) (string, time.Time) {
	t.Helper()
	challenge, deadline, err := f.service.ChallengeMFAEnrollment(f.ctx, f.sess, testSecret, channel, "203.0.113.8")
	if err != nil || !capability(challenge) {
		t.Fatal("MFA enrollment challenge failed", err)
	}
	proof, expires, err := f.service.VerifyMFAEnrollment(f.ctx, f.sess, challenge, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("MFA enrollment proof lost original deadline", err)
	}
	return proof, expires
}

func (f realProofFixture) lockedMFAProof(t *testing.T) (pgx.Tx, username.GuardAuthority) {
	t.Helper()
	tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rollback(context.Background(), tx) })
	authority, err := f.service.policy.Guard(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(f.ctx, tx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
		t.Fatal(err)
	}
	return tx, authority
}

func TestMFAEnrollmentProofRealChannelsFrozenStartAndDisabledReader(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newRealMFAEnrollmentProofFixture(t)
			proof, deadline := f.issueMFAEnrollment(t, channel)
			digest := sha256.Sum256([]byte(proof))
			var stored time.Time
			if err := f.pool.QueryRow(f.ctx, "SELECT expires_at FROM mfa_enrollment_action_proofs WHERE proof_digest=$1", digest[:]).Scan(&stored); err != nil || !stored.Equal(deadline) {
				t.Fatal("SQL restamped original proof deadline", err)
			}
			tx, guard := f.lockedMFAProof(t)
			if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != ErrInvalid {
				t.Fatal("MFA proof authorized deletion", err)
			}
			if err := f.service.ConsumePasswordChangeTx(f.ctx, tx, f.sess, proof); err != ErrInvalid {
				t.Fatal("MFA proof authorized password change", err)
			}
			if _, err := f.service.ConsumeFirstPasskeyStartTx(f.ctx, tx, f.sess, proof); err != ErrInvalid {
				t.Fatal("MFA proof authorized passkey enrollment", err)
			}
			authorization, err := f.service.ConsumeMFAEnrollmentStartTx(f.ctx, tx, f.sess, proof, guard)
			if err != nil || !authorization.ExpiresAt.Equal(deadline) || authorization.Channel != channel || len(authorization.ContactBinding) != 32 {
				t.Fatal("start lost frozen SQL authorization", err)
			}
			if _, err := f.service.ConsumeMFAEnrollmentStartTx(f.ctx, tx, f.sess, proof, guard); err != ErrInvalid {
				t.Fatal("proof started twice", err)
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			deps := f.service.deps
			deps.Codes, deps.Limiter = nil, nil
			reader, err := NewMFAEnrollment(Config{BindingKey: f.service.key}, deps)
			if err != nil {
				t.Fatal("disabled reader required provider", err)
			}
			reader.SetAccountPolicy(f.service.policy)
			var role string
			if err := f.runtime.QueryRow(f.ctx, "SELECT current_user").Scan(&role); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Exec(f.ctx, "REVOKE SELECT ON mfa_enrollment_action_proofs FROM "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			tx, guard = f.lockedMFAProof(t)
			for range 2 {
				if err := reader.ValidateMFAEnrollmentTx(f.ctx, tx, f.sess, authorization, guard); err != nil {
					t.Fatal("final required spent proof/provider or mutated state", err)
				}
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMFAEnrollmentProofRealPolicyAndCurrentBindingRefusals(t *testing.T) {
	for _, scenario := range []string{"login-off", "password", "username-missing", "username-stale", "mfa-flag", "mfa-secret", "role", "passkey", "contact", "contact-time", "version", "foreign-session", "foreign-jkt"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealMFAEnrollmentProofFixture(t)
			proof, deadline := f.issueMFAEnrollment(t, "email")
			digest := sha256.Sum256([]byte(proof))
			var binding []byte
			if err := f.pool.QueryRow(f.ctx, "SELECT contact_binding FROM mfa_enrollment_action_proofs WHERE proof_digest=$1", digest[:]).Scan(&binding); err != nil {
				t.Fatal(err)
			}
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			sess := f.sess
			switch scenario {
			case "login-off":
				policy := f.service.policy
				policy.PasswordLoginEnabled = false
				f.service.SetAccountPolicy(policy)
			case "password":
				exec("UPDATE users SET password_hash='unsupported' WHERE id=$1", f.user.ID)
			case "username-missing":
				exec("UPDATE users SET username_key=NULL,username_details_encrypted=NULL,username_policy_id=NULL,username_policy_fingerprint=NULL,username_policy_epoch=NULL,username_lookup_key_id=NULL WHERE id=$1", f.user.ID)
			case "username-stale":
				exec("UPDATE username_active_policy SET epoch=epoch+1 WHERE singleton")
			case "mfa-flag":
				exec("UPDATE users SET is_mfa_enabled=true WHERE id=$1", f.user.ID)
			case "mfa-secret":
				exec("UPDATE users SET mfa_totp_secret_encrypted=$2 WHERE id=$1", f.user.ID, []byte("configured-active-secret"))
			case "role":
				exec("INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles LIMIT 1", f.user.ID)
			case "passkey":
				_, err := db.New(f.pool).CreateWebauthnCredential(f.ctx, db.CreateWebauthnCredentialParams{ID: []byte("proof-passkey"), UserID: f.user.ID, PublicKey: []byte("test-public-key")})
				if err != nil {
					t.Fatal(err)
				}
			case "contact":
				exec("DELETE FROM contact_verification_evidence WHERE user_id=$1 AND channel='email'", f.user.ID)
			case "contact-time":
				blob, err := contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, contactproof.Email, *f.user.Email, contactproof.EmailLink, time.Now().UTC().Add(-20*time.Second))
				if err != nil {
					t.Fatal(err)
				}
				if err := db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: contactproof.Email, EvidenceEncrypted: blob}); err != nil {
					t.Fatal(err)
				}
			case "version":
				exec("UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
			case "foreign-session":
				sess.ID = uuid.NewString()
			case "foreign-jkt":
				sess.DPoPJKT = testCapability(7)
			}
			tx, guard := f.lockedMFAProof(t)
			if _, err := f.service.ConsumeMFAEnrollmentStartTx(f.ctx, tx, sess, proof, guard); !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrUnavailable) {
				t.Fatal("stale/ineligible enrollment start accepted", err)
			}
			if err := f.service.ValidateMFAEnrollmentTx(f.ctx, tx, sess, MFAEnrollmentAuthorization{deadline, "email", binding}, guard); !errors.Is(err, ErrUnauthorized) && !errors.Is(err, ErrUnavailable) {
				t.Fatal("stale/ineligible final authorization accepted", err)
			}
			rollback(f.ctx, tx)
			var count int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM mfa_enrollment_action_proofs WHERE proof_digest=$1", digest[:]).Scan(&count); err != nil || count != 1 {
				t.Fatal("rejected authority spent a valid proof", err)
			}
		})
	}
}

func TestMFAEnrollmentProofRealRollbackAndConcurrentSingleStart(t *testing.T) {
	for _, scenario := range []string{"insert", "lost-commit-ack"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealMFAEnrollmentProofFixture(t)
			challenge, _, err := f.service.ChallengeMFAEnrollment(f.ctx, f.sess, testSecret, "email", "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			wantRows := 0
			if scenario == "insert" {
				var role string
				if err := f.runtime.QueryRow(f.ctx, "SELECT current_user").Scan(&role); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(f.ctx, "REVOKE INSERT ON mfa_enrollment_action_proofs FROM "+pgx.Identifier{role}.Sanitize()); err != nil {
					t.Fatal(err)
				}
			} else {
				f.service.deps.DB = commitUnknownDB{f.runtime}
				wantRows = 1 // Actual commit succeeded; only its acknowledgement is lost.
			}
			if proof, expires, err := f.service.VerifyMFAEnrollment(f.ctx, f.sess, challenge, f.delivery.lastCode()); proof != "" || !expires.IsZero() || err != ErrOutcomeUnknown {
				t.Fatal("uncertain issuance published authority", err)
			}
			if _, _, err := f.service.VerifyMFAEnrollment(f.ctx, f.sess, challenge, f.delivery.lastCode()); err != contactcode.ErrNoActiveCode {
				t.Fatal("uncertain issuance restored spent OTP", err)
			}
			var rows int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM mfa_enrollment_action_proofs").Scan(&rows); err != nil || rows != wantRows || f.delivery.calls != 1 {
				t.Fatal("uncertain issuance retried or misstated SQL commit", err)
			}
		})
	}
	f := newRealMFAEnrollmentProofFixture(t)
	proof, deadline := f.issueMFAEnrollment(t, "email")
	tx, guard := f.lockedMFAProof(t)
	if _, err := f.service.ConsumeMFAEnrollmentStartTx(f.ctx, tx, f.sess, proof, guard); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES($1)", f.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				results <- err
				return
			}
			defer rollback(f.ctx, tx)
			guard, err := f.service.policy.Guard(f.ctx, tx)
			if err == nil {
				err = pglock.LockAccount(f.ctx, tx, f.user.ID)
			}
			if err == nil {
				_, err = db.New(tx).GetUserByIDForUpdate(f.ctx, f.user.ID)
			}
			var authorization MFAEnrollmentAuthorization
			if err == nil {
				authorization, err = f.service.ConsumeMFAEnrollmentStartTx(f.ctx, tx, f.sess, proof, guard)
			}
			if err == nil && !authorization.ExpiresAt.Equal(deadline) {
				err = errors.New("deadline changed")
			}
			if err == nil {
				_, err = tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES($1)", f.user.ID)
			}
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			results <- err
		})
	}
	workers.Wait()
	close(results)
	winners, rejected := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, ErrInvalid) {
			rejected++
		} else {
			t.Fatal("concurrent start failed unexpectedly", err)
		}
	}
	var actions, proofs int
	if err := f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM proof_test_actions),(SELECT count(*) FROM mfa_enrollment_action_proofs)").Scan(&actions, &proofs); err != nil || winners != 1 || rejected != 1 || actions != 1 || proofs != 0 {
		t.Fatal("proof/action rollback or single-start atomicity failed", winners, rejected, actions, proofs, err)
	}
}

func TestMFAEnrollmentProofRealRestrictedGrantsAndBoundedCleanup(t *testing.T) {
	f := newRealMFAEnrollmentProofFixture(t)
	proof, _ := f.issueMFAEnrollment(t, "email")
	var selectOK, insertOK, deleteOK, updateOK, truncateOK bool
	if err := f.runtime.QueryRow(f.ctx, "SELECT has_table_privilege(current_user,'mfa_enrollment_action_proofs','SELECT'),has_table_privilege(current_user,'mfa_enrollment_action_proofs','INSERT'),has_table_privilege(current_user,'mfa_enrollment_action_proofs','DELETE'),has_any_column_privilege(current_user,'mfa_enrollment_action_proofs','UPDATE'),has_table_privilege(current_user,'mfa_enrollment_action_proofs','TRUNCATE')").Scan(&selectOK, &insertOK, &deleteOK, &updateOK, &truncateOK); err != nil || !selectOK || !insertOK || !deleteOK || updateOK || truncateOK {
		t.Fatal("MFA proof runtime privileges widened", err)
	}
	var public, plaintext bool
	if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.table_privileges WHERE table_name='mfa_enrollment_action_proofs' AND grantee='PUBLIC'),EXISTS(SELECT 1 FROM mfa_enrollment_action_proofs WHERE proof_digest=convert_to($1,'UTF8'))", proof).Scan(&public, &plaintext); err != nil || public || plaintext {
		t.Fatal("proof table exposed raw authority or PUBLIC privilege", err)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE mfa_enrollment_action_proofs SET action='password_change'"); err == nil {
		t.Fatal("schema accepted another action purpose")
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE mfa_enrollment_action_proofs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO mfa_enrollment_action_proofs SELECT sha256(proof_digest),user_id,session_id,jkt,auth_version,action,channel,contact_binding,created_at,expires_at FROM mfa_enrollment_action_proofs"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if rows, err := f.service.CleanupExpiredMFAEnrollment(f.ctx, 1); err != nil || rows != 1 {
			t.Fatal("cleanup failed bounded reclamation", rows, err)
		}
	}
	if rows, err := f.service.CleanupExpiredMFAEnrollment(f.ctx, 1); err != nil || rows != 0 {
		t.Fatal("cleanup was not idempotent", rows, err)
	}
}

func TestMFAEnrollmentPendingSQLAllOrNoneMetadata(t *testing.T) {
	f := newRealMFAEnrollmentProofFixture(t)
	for _, metadata := range []string{
		"NULL,NULL,NULL,NULL,NULL",
		"0,'" + f.sess.DPoPJKT + "','webauthn_uv',NULL,NULL",
		"0,'" + f.sess.DPoPJKT + "','password_contact','email',decode(repeat('ab',32),'hex')",
		"0,'" + f.sess.DPoPJKT + "','password_contact','sms',decode(repeat('ab',32),'hex')",
	} {
		if _, err := f.pool.Exec(f.ctx, "INSERT INTO mfa_totp_enrollments(user_id,session_id,purpose,secret_encrypted,expires_at,auth_version,jkt,authorization_method,channel,contact_binding) VALUES($1,$2,'maintenance',$3,clock_timestamp()+interval '1 minute',"+metadata+")", f.user.ID, uuid.MustParse(f.sess.ID), []byte("encrypted-pending-fixture")); err != nil {
			t.Fatal("schema rejected complete or absent metadata", err)
		}
	}
	for _, metadata := range []string{
		"0,NULL,NULL,NULL,NULL", "NULL,NULL,NULL,'email',NULL",
		"-1,'" + f.sess.DPoPJKT + "','webauthn_uv',NULL,NULL",
		"0,'short','webauthn_uv',NULL,NULL",
		"0,'" + f.sess.DPoPJKT + "',NULL,NULL,NULL",
		"0,'" + f.sess.DPoPJKT + "','otp',NULL,NULL",
		"0,'" + f.sess.DPoPJKT + "','webauthn_uv','email',NULL",
		"0,'" + f.sess.DPoPJKT + "','password_contact',NULL,decode(repeat('ab',32),'hex')",
		"0,'" + f.sess.DPoPJKT + "','password_contact','unknown',decode(repeat('ab',32),'hex')",
		"0,'" + f.sess.DPoPJKT + "','password_contact','email',NULL",
		"0,'" + f.sess.DPoPJKT + "','password_contact','email',decode(repeat('ab',31),'hex')",
	} {
		if _, err := f.pool.Exec(f.ctx, "INSERT INTO mfa_totp_enrollments(user_id,session_id,purpose,secret_encrypted,expires_at,auth_version,jkt,authorization_method,channel,contact_binding) VALUES($1,$2,'maintenance',$3,clock_timestamp()+interval '1 minute',"+metadata+")", f.user.ID, uuid.MustParse(f.sess.ID), []byte("encrypted-pending-fixture")); err == nil {
			t.Fatal("schema accepted partial or invalid metadata", strings.Split(metadata, ",")[0])
		}
	}
}
