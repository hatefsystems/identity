//go:build integration

package profile

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func putEmailProof(t *testing.T, f profileDatabase, id uuid.UUID, destination string) []byte {
	t.Helper()
	blob, err := contactproof.Seal(f.ctx, f.service.cipher, id, contactproof.Email, destination, contactproof.EmailLink, time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.New(f.pool).PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: id, Channel: contactproof.Email, EvidenceEncrypted: blob}); err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestOptionalEmailStorageAndEvidenceNoBackfillIntegration(t *testing.T) {
	f := newProfileDatabase(t)
	q := db.New(f.pool)
	for range 2 {
		u, err := q.CreateUser(f.ctx, db.CreateUserParams{Status: "active"})
		if err != nil {
			t.Fatal("NULL email blocked or uniqueness fabricated", err)
		}
		p, err := f.service.Get(f.ctx, u.ID, u.AuthVersion)
		if err != nil || p.Email != nil || p.EmailVerifiedAt != nil {
			t.Fatal("absent email/evidence misrepresented", err)
		}
	}
	if _, err := q.CreateUser(f.ctx, db.CreateUserParams{Email: new(""), Status: "active"}); err == nil {
		t.Fatal("storage accepted empty email")
	}
	u := profileUser(t, f)
	p, err := f.service.Get(f.ctx, u.ID, u.AuthVersion)
	if err != nil || p.Email == nil || p.EmailVerifiedAt != nil {
		t.Fatal("active populated email inferred verified", err)
	}
	putEmailProof(t, f, u.ID, *u.Email)
	p, err = f.service.Get(f.ctx, u.ID, u.AuthVersion)
	if err != nil || p.EmailVerifiedAt == nil {
		t.Fatal("exact protected evidence did not verify", err)
	}
}

func TestContactEvidenceCrossAccountDestinationAndABARollbackIntegration(t *testing.T) {
	f := newProfileDatabase(t)
	u, other := profileUser(t, f), profileUser(t, f)
	q := db.New(f.pool)
	blob := putEmailProof(t, f, u.ID, *u.Email)
	if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: other.ID, Channel: contactproof.Email, EvidenceEncrypted: blob}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Get(f.ctx, other.ID, other.AuthVersion); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-account substituted proof verified")
	}
	putEmailProof(t, f, u.ID, "different@example.test")
	if _, err := f.service.Get(f.ctx, u.ID, u.AuthVersion); !errors.Is(err, ErrUnavailable) {
		t.Fatal("destination B evidence verified A")
	}
	putEmailProof(t, f, u.ID, *u.Email)
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE users SET email=$2 WHERE id=$1`, u.ID, "b@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE users SET email=$2 WHERE id=$1`, u.ID, u.Email); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	p, err := f.service.Get(f.ctx, u.ID, u.AuthVersion)
	if err != nil || p.EmailVerifiedAt != nil {
		t.Fatal("A->B->A revived historical proof", err)
	}
	putEmailProof(t, f, u.ID, *u.Email)
	tx, err = f.pool.BeginTx(f.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `UPDATE users SET email=NULL WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	p, err = f.service.Get(f.ctx, u.ID, u.AuthVersion)
	if err != nil || p.EmailVerifiedAt == nil {
		t.Fatal("rolled-back change invalidated committed proof", err)
	}
	profileExec(t, f, `UPDATE users SET email=NULL WHERE id=$1`, u.ID)
	p, err = f.service.Get(f.ctx, u.ID, u.AuthVersion)
	if err != nil || p.Email != nil || p.EmailVerifiedAt != nil {
		t.Fatal("removal retained evidence", err)
	}
}

func TestPhoneEvidenceProtectedReplacementInvalidatesIntegration(t *testing.T) {
	f := newProfileDatabase(t)
	u := profileUser(t, f)
	q := db.New(f.pool)
	phone := "+989123456789"
	encrypted, err := f.service.cipher.Encrypt(f.ctx, []byte(phone))
	if err != nil {
		t.Fatal(err)
	}
	index := "test-index"
	if _, err := q.SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: encrypted, PhoneBlindIndex: &index}); err != nil {
		t.Fatal(err)
	}
	blob, err := contactproof.Seal(f.ctx, f.service.cipher, u.ID, contactproof.Phone, phone, contactproof.SMSOTP, time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.PutContactVerificationEvidence(f.ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: contactproof.Phone, EvidenceEncrypted: blob}); err != nil {
		t.Fatal(err)
	}
	if e, err := contactproof.Read(f.ctx, q, f.service.cipher, u.ID, contactproof.Phone); err != nil || e == nil {
		t.Fatal("exact phone proof unavailable", err)
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.service.cipher.Encrypt(f.ctx, []byte("+989123456780"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: second, PhoneBlindIndex: &index}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(tx).SetUserPhone(f.ctx, db.SetUserPhoneParams{ID: u.ID, PhoneEncrypted: encrypted, PhoneBlindIndex: &index}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if e, err := contactproof.Read(f.ctx, q, f.service.cipher, u.ID, contactproof.Phone); err != nil || e != nil {
		t.Fatal("phone A->B->A reused historical proof", err)
	}
}
