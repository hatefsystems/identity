//go:build integration

package registration

import (
	"bytes"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func TestRegistrationCreationProofAtomicAndReplayTimeIntegration(t *testing.T) {
	ctx, pool := registrationDatabase(t)
	namespace := registrationUsernameNamespace(ctx, t, pool)
	s, authority, _ := registrationReadyBirth(ctx, t, pool, namespace, fixtureUsername, "+989123456789")
	before, err := s.deps.Store.Get(ctx, authority.AttemptID, authority.Capability, authority.JKT)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"fixture-credential"}`)
	if result, err := s.Complete(ctx, authority, body); err != nil || result.State != "completed" {
		t.Fatal("birth failed", err)
	}
	receipt, err := s.deps.Store.Get(ctx, authority.AttemptID, authority.Capability, authority.JKT)
	if err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	id := receipt.Record.ResultUserID.UUID
	rows := map[string][]byte{}
	for _, channel := range []string{contactproof.Email, contactproof.Phone} {
		e, err := contactproof.Read(ctx, q, s.deps.Encryptor, id, channel)
		at, destination := before.Record.EmailVerifiedAt.Time, before.Details.Email
		if channel == contactproof.Phone {
			at, destination = before.Record.PhoneVerifiedAt.Time, before.Details.Phone
		}
		if err != nil || e == nil || e.Destination != destination || !e.VerifiedAt.Equal(at) {
			t.Fatal("account creation lost exact proof/time", err)
		}
		row, err := q.GetCurrentContactEvidence(ctx, db.GetCurrentContactEvidenceParams{UserID: id, Channel: channel})
		if err != nil || bytes.Contains(row.EvidenceEncrypted, []byte(destination)) {
			t.Fatal("proof unprotected", err)
		}
		rows[channel] = bytes.Clone(row.EvidenceEncrypted)
	}
	s.now = func() time.Time { return time.Now().Add(time.Minute) }
	if result, err := s.Complete(ctx, authority, body); err != nil || result.State != "completed" {
		t.Fatal("receipt replay failed", err)
	}
	for channel, original := range rows {
		row, err := q.GetCurrentContactEvidence(ctx, db.GetCurrentContactEvidenceParams{UserID: id, Channel: channel})
		if err != nil || !bytes.Equal(row.EvidenceEncrypted, original) {
			t.Fatal("replay rewrote evidence or verification time", err)
		}
	}
}

func TestRegistrationCreationFailureRollsBackEvidenceIntegration(t *testing.T) {
	for _, failure := range []string{"evidence", "receipt"} {
		t.Run(failure, func(t *testing.T) {
			ctx, pool := registrationDatabase(t)
			namespace := registrationUsernameNamespace(ctx, t, pool)
			s, authority, _ := registrationReadyBirth(ctx, t, pool, namespace, fixtureUsername, "+989123456789")
			// Fixed fixture trigger name in this newly owned disposable database.
			registrationExec(ctx, t, pool, `CREATE FUNCTION reject_birth_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'birth fixture failure'; END $$`)
			if failure == "evidence" {
				registrationExec(ctx, t, pool, `CREATE TRIGGER reject_birth BEFORE INSERT ON contact_verification_evidence FOR EACH ROW EXECUTE FUNCTION reject_birth_evidence()`)
			} else {
				registrationExec(ctx, t, pool, `CREATE TRIGGER reject_birth BEFORE UPDATE ON registration_attempts FOR EACH ROW WHEN (NEW.state='completed') EXECUTE FUNCTION reject_birth_evidence()`)
			}
			if _, err := s.Complete(ctx, authority, []byte(`{"id":"fixture-credential"}`)); err == nil {
				t.Fatal("failure committed account")
			}
			var users, proofs, outbox, credentials int
			if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM contact_verification_evidence),(SELECT count(*) FROM event_outbox),(SELECT count(*) FROM webauthn_credentials)`).Scan(&users, &proofs, &outbox, &credentials); err != nil || users != 0 || proofs != 0 || outbox != 0 || credentials != 0 {
				t.Fatal("failed birth left partial account/evidence", err)
			}
		})
	}
}
