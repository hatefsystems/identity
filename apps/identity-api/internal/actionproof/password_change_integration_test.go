//go:build integration

package actionproof

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func (f realProofFixture) issuePasswordChange(t *testing.T, channel string) (string, time.Time) {
	t.Helper()
	handle, deadline, err := f.service.ChallengePasswordChange(f.ctx, f.sess, testSecret, channel, "203.0.113.8")
	if err != nil {
		t.Fatal("real password-change challenge failed", err)
	}
	proof, expires, err := f.service.VerifyPasswordChange(f.ctx, f.sess, handle, f.delivery.lastCode())
	if err != nil || !capability(proof) || !expires.Equal(deadline) {
		t.Fatal("real password-change issuance failed or restamped deadline", err)
	}
	return proof, expires
}

func TestPasswordChangeEmailSMSPreflightRollbackAndNoopIntegration(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newRealPasswordChangeFixture(t)
			proof, deadline := f.issuePasswordChange(t, channel)
			var storedDeadline time.Time
			if err := f.pool.QueryRow(f.ctx, "SELECT expires_at FROM password_change_action_proofs").Scan(&storedDeadline); err != nil || !storedDeadline.Equal(deadline) {
				t.Fatal("proof persisted a new rather than original deadline")
			}
			// An account writer can hold both locks throughout preflight. No lock
			// or consumption is permitted until the later mutation transaction.
			writer, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(f.ctx) }()
			if err := pglock.LockAccount(f.ctx, writer, f.user.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.New(writer).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := f.service.CheckPasswordChange(f.ctx, f.sess, proof); err != nil {
					t.Fatal("non-consuming preflight blocked or failed", err)
				}
			}
			if err := writer.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := f.service.ConsumeTx(f.ctx, tx, f.sess, proof); err != ErrInvalid {
				t.Fatal("password-change SQL proof authorized deletion", err)
			}
			if err := f.service.ConsumePasswordChangeTx(f.ctx, tx, f.sess, proof); err != nil {
				t.Fatal("valid proof did not consume in caller transaction", err)
			}
			if _, err := tx.Exec(f.ctx, "INSERT INTO proof_test_actions(user_id) VALUES ($1)", f.user.ID); err != nil {
				t.Fatal(err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.service.CheckPasswordChange(f.ctx, f.sess, proof); err != nil {
				t.Fatal("rollback did not restore proof", err)
			}
			var actions int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM proof_test_actions").Scan(&actions); err != nil || actions != 0 {
				t.Fatal("rollback partially committed associated action")
			}
			tx, err = f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.service.ConsumePasswordChangeTx(f.ctx, tx, f.sess, proof); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := f.service.CheckPasswordChange(f.ctx, f.sess, proof); err != ErrInvalid {
				t.Fatal("authorized no-op proof survived commit", err)
			}
			current, err := db.New(f.pool).GetUserByID(f.ctx, f.user.ID)
			if err != nil || current.AuthVersion != f.user.AuthVersion || *current.PasswordHash != *f.user.PasswordHash {
				t.Fatal("proof-only no-op changed verifier or earned version")
			}
			live, err := f.sessions.LookupByID(f.ctx, f.sess.UserID, f.sess.ID)
			if err != nil || live != f.sess {
				t.Fatal("proof-only no-op changed live session")
			}
		})
	}
}

func TestPasswordChangeConsumerRechecksAfterLockWaitIntegration(t *testing.T) {
	for _, scenario := range []string{"expiry", "version", "contact"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRealPasswordChangeFixture(t)
			proof, _ := f.issuePasswordChange(t, "email")
			writer, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(f.ctx) }()
			if err := pglock.LockAccount(f.ctx, writer, f.user.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.New(writer).GetUserByIDForUpdate(f.ctx, f.user.ID); err != nil {
				t.Fatal(err)
			}
			if scenario == "expiry" {
				if _, err := writer.Exec(f.ctx, "UPDATE password_change_action_proofs SET expires_at=clock_timestamp()+interval '50 milliseconds'"); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan error, 1)
			go func() {
				tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					result <- err
					return
				}
				defer func() { _ = tx.Rollback(f.ctx) }()
				result <- f.service.ConsumePasswordChangeTx(f.ctx, tx, f.sess, proof)
			}()
			select {
			case err := <-result:
				t.Fatal("consumer failed to wait for account mutex", err)
			case <-time.After(80 * time.Millisecond):
			}
			want := ErrUnauthorized
			switch scenario {
			case "expiry":
				want = ErrInvalid
			case "version":
				_, err = writer.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", f.user.ID)
			case "contact":
				var evidence []byte
				evidence, err = contactproof.Seal(f.ctx, f.service.deps.Cipher, f.user.ID, contactproof.Email, *f.user.Email, contactproof.EmailLink, time.Now().UTC().Add(-20*time.Second))
				if err == nil {
					err = db.New(writer).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: f.user.ID, Channel: contactproof.Email, EvidenceEncrypted: evidence})
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != want {
				t.Fatal("consumer retained pre-lock snapshot or transaction-start deadline", err)
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM password_change_action_proofs").Scan(&count); err != nil || count != 1 {
				t.Fatal("rejected consumer consumed proof")
			}
		})
	}
}

func TestPasswordChangeConcurrentConsumersAndUnknownIssuanceIntegration(t *testing.T) {
	f := newRealPasswordChangeFixture(t)
	proof, _ := f.issuePasswordChange(t, "email")
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			tx, err := f.runtime.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				results <- err
				return
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := f.service.ConsumePasswordChangeTx(f.ctx, tx, f.sess, proof); err != nil {
				results <- err
				return
			}
			results <- tx.Commit(f.ctx)
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if err != ErrInvalid {
			t.Fatal("concurrent password-change consumption failed unexpectedly", err)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent password-change consumers had multiple winners")
	}
	f = newRealPasswordChangeFixture(t)
	handle, _, err := f.service.ChallengePasswordChange(f.ctx, f.sess, testSecret, "email", "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	f.service.deps.DB = commitUnknownDB{f.runtime}
	if proof, deadline, err := f.service.VerifyPasswordChange(f.ctx, f.sess, handle, f.delivery.lastCode()); proof != "" || !deadline.IsZero() || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal("unknown SQL commit exposed password-change capability")
	}
	if _, _, err := f.service.VerifyPasswordChange(f.ctx, f.sess, handle, f.delivery.lastCode()); err != contactcode.ErrNoActiveCode {
		t.Fatal("unknown SQL commit restored consumed OTP")
	}
}

func TestPasswordChangeProofSchemaGrantsCleanupAndForwardOnlyIntegration(t *testing.T) {
	f := newRealPasswordChangeFixture(t)
	proof, _ := f.issuePasswordChange(t, "email")
	var update, truncate, public, raw bool
	if err := f.runtime.QueryRow(f.ctx, "SELECT has_any_column_privilege(current_user,'password_change_action_proofs','UPDATE'),has_table_privilege(current_user,'password_change_action_proofs','TRUNCATE')").Scan(&update, &truncate); err != nil || update || truncate {
		t.Fatal("password-change runtime can restamp or truncate proofs")
	}
	if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.table_privileges WHERE table_name='password_change_action_proofs' AND grantee='PUBLIC'),EXISTS(SELECT 1 FROM password_change_action_proofs WHERE proof_digest=convert_to($1,'UTF8'))", proof).Scan(&public, &raw); err != nil || public || raw {
		t.Fatal("password-change table granted PUBLIC or stored raw handles")
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE password_change_action_proofs SET action='account_deletion'"); err == nil {
		t.Fatal("password-change table accepted deletion purpose")
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO account_deletion_action_proofs SELECT proof_digest,user_id,session_id,jkt,auth_version,action,channel,contact_binding,created_at,expires_at FROM password_change_action_proofs"); err == nil {
		t.Fatal("deletion-only constraint accepted password-change purpose")
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE password_change_action_proofs SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "INSERT INTO password_change_action_proofs SELECT sha256(proof_digest),user_id,session_id,jkt,auth_version,action,channel,contact_binding,created_at,expires_at FROM password_change_action_proofs"); err != nil {
		t.Fatal(err)
	}
	if rows, err := f.service.CleanupExpiredPasswordChange(f.ctx, 1); err != nil || rows != 1 {
		t.Fatal("password-change cleanup exceeded bounded batch", err)
	}
	if rows, err := f.service.CleanupExpiredPasswordChange(f.ctx, 1000); err != nil || rows != 1 {
		t.Fatal("password-change cleanup failed to reclaim remaining row", err)
	}
	sqlDB := stdlib.OpenDB(*f.pool.Config().ConnConfig)
	defer func() { _ = sqlDB.Close() }()
	provider, err := migrate.NewProvider(sqlDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ApplyVersion(f.ctx, 8, false); err == nil {
		t.Fatal("password-change proof migration allowed rollback")
	}
	if version, err := provider.GetDBVersion(f.ctx); err != nil || version != 11 {
		t.Fatal("forward-only refusal changed password-change lineage")
	}
}
