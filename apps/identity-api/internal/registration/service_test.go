package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type signupLimiter struct {
	keys   []string
	denyAt int
	err    error
}

func (l *signupLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	return l.denyAt != len(l.keys), l.err
}

type signupPhone struct {
	sends, consumes int
	id              string
	err             error
}

func (p *signupPhone) SendSignupCode(context.Context, uuid.UUID, string, string, string, time.Time) (string, error) {
	p.sends++
	return p.id, p.err
}
func (p *signupPhone) ConsumeSignupCode(context.Context, uuid.UUID, string, string, string, string) error {
	p.consumes++
	return p.err
}

type signupPasskey struct {
	calls      int
	err        error
	onVerify   func()
	credential db.CreateWebauthnCredentialParams
}

func (p *signupPasskey) BeginSignup(context.Context, string, []byte, string, time.Time) (*protocol.CredentialCreation, json.RawMessage, error) {
	p.calls++
	return &protocol.CredentialCreation{}, json.RawMessage(`{"purpose":"registration"}`), p.err
}
func (p *signupPasskey) VerifySignup(context.Context, string, []byte, string, json.RawMessage, []byte) (db.CreateWebauthnCredentialParams, error) {
	p.calls++
	if p.onVerify != nil {
		p.onVerify()
	}
	return p.credential, p.err
}

type signupIndexer struct{}

func (signupIndexer) Compute(s string) string { return digest(s) }

type valueRow struct {
	value any
	err   error
}

func (r valueRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	value := reflect.ValueOf(r.value)
	for i := range dest {
		if value.Kind() == reflect.Struct {
			reflect.ValueOf(dest[i]).Elem().Set(value.Field(i))
		} else {
			reflect.ValueOf(dest[i]).Elem().Set(value)
		}
	}
	return nil
}

func signupFixture(t *testing.T) (*Service, Authority, *testDatabase, *testTx, *signupPasskey, *signupPhone, *recordingMail) {
	t.Helper()
	store, attempt, capability := pendingFixture(t)
	now := store.now()
	attempt.Record.EmailTokenIssuedAt = timestamp(now.Add(-30 * time.Second))
	attempt.Record.EmailTokenExpiresAt = timestamp(now.Add(9 * time.Minute))
	attempt.Record.EmailVerifiedAt = timestamp(now.Add(-20 * time.Second))
	attempt.Record.PhoneVerifiedAt = timestamp(now.Add(-10 * time.Second))
	id := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	ref, _ := verificationReference(id)
	attempt.Record.SmsVerificationRef = uuid.NullUUID{UUID: ref, Valid: true}
	attempt.Record.ChallengeRevision = 1
	attempt.Record.PasskeyCreatedAt = timestamp(now)
	attempt.Record.PasskeyExpiresAt = timestamp(now.Add(PasskeyLifetime))
	attempt.Details.Ceremony = json.RawMessage(`{"purpose":"registration"}`)
	attempt.Details.CeremonyRevision = 1
	attempt.Record.DetailsEncrypted, _ = store.seal(t.Context(), attempt.Details)
	tx := &testTx{record: attempt.Record, affected: 1, failures: map[string]error{}}
	database := &testDatabase{read: attempt.Record, txs: []*testTx{tx}}
	store.database = database
	mail := &recordingMail{}
	email, _ := NewEmail(EmailConfig{From: "identity@example.com", PublicOrigin: "https://identity.example.com"}, mail)
	passkey := &signupPasskey{credential: db.CreateWebauthnCredentialParams{ID: []byte{1}, PublicKey: []byte{2}, UserVerified: true, UserPresent: true}}
	phone := &signupPhone{id: id}
	service, err := NewService(Deps{Store: store, Database: database, Email: email, Phone: phone, WebAuthn: passkey, Encryptor: store.cipher, Indexer: signupIndexer{}, Limiter: &signupLimiter{}, GlobalDailyLimit: 10, EmailHourlyLimit: 5})
	if err != nil {
		t.Fatal(err)
	}
	service.now = store.now
	user := db.User{ID: uuid.New(), Email: attempt.Details.Email, Status: "active"}
	tx.onQuery = func(name string, args []any) pgx.Row {
		if err := tx.failures[name]; err != nil {
			return valueRow{err: err}
		}
		switch name {
		case "CreateUser":
			return valueRow{value: user}
		case "AdvanceUserLifecycleRevision":
			return valueRow{value: int64(1)}
		case "CreateWebauthnCredential":
			return valueRow{value: db.WebauthnCredential{ID: []byte{1}, UserID: user.ID}}
		case "CompleteRegistrationAttempt":
			r := tx.record
			r.State = "completed"
			r.DetailsEncrypted = nil
			r.EmailTokenHash = nil
			r.EmailTokenIssuedAt.Valid = false
			r.EmailTokenExpiresAt.Valid = false
			r.SmsVerificationRef = uuid.NullUUID{}
			r.PasskeyCreatedAt.Valid = false
			r.PasskeyExpiresAt.Valid = false
			r.TerminalAt = timestamp(now)
			r.ReceiptExpiresAt = timestamp(now.Add(ReceiptLifetime))
			r.CompletionFingerprint = args[2].([]byte)
			r.ResultUserID = args[3].(uuid.NullUUID)
			return registrationRow{record: r}
		default:
			return registrationRow{record: tx.record}
		}
	}
	return service, Authority{attempt.Record.ID, capability, attempt.Record.Jkt}, database, tx, passkey, phone, mail
}

func TestSignupAtomicBirthWriteOrderAndFailureIsolation(t *testing.T) {
	for _, failure := range []string{"", "CreateUser", "AdvanceUserLifecycleRevision", "InsertLifecycleEvent", "SetWebauthnUserHandle", "CreateWebauthnCredential", "SetUserPhone", "CompleteRegistrationAttempt", "commit"} {
		t.Run("failure_"+failure, func(t *testing.T) {
			s, a, _, tx, _, _, _ := signupFixture(t)
			if failure != "" {
				tx.failures[failure] = errors.New("private@example.com secret SQL")
			}
			result, err := s.Complete(t.Context(), a, []byte(`{"id":"credential"}`))
			if failure == "" {
				if err != nil || result.State != "completed" || result.Next != "login" || tx.commits != 1 {
					t.Fatalf("complete: %v", err)
				}
				want := []string{"CreateUser", "AdvanceUserLifecycleRevision", "InsertLifecycleEvent", "SetWebauthnUserHandle", "CreateWebauthnCredential", "SetUserPhone", "CompleteRegistrationAttempt"}
				last := -1
				for _, op := range want {
					index := -1
					for i, name := range tx.ops {
						if name == op {
							index = i
							break
						}
					}
					if index <= last {
						t.Fatalf("wrong birth order %v", tx.ops)
					}
					last = index
				}
			} else if err == nil || tx.commits != 0 || tx.rollbacks == 0 || strings.Contains(err.Error(), "secret") || result.State != "" {
				t.Fatal("failed birth leaked state/diagnostic or committed")
			}
		})
	}
}
func TestSignupCompletionLockedSnapshotAndReplay(t *testing.T) {
	t.Run("revision changed outside lock", func(t *testing.T) {
		s, a, _, tx, p, _, _ := signupFixture(t)
		p.onVerify = func() { tx.record.RowRevision++ }
		if _, err := s.Complete(t.Context(), a, []byte(`{"id":"credential"}`)); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		for _, op := range tx.ops {
			if op == "CreateUser" {
				t.Fatal("stale ceremony created user")
			}
		}
	})
	t.Run("identical durable receipt", func(t *testing.T) {
		s, a, d, _, p, _, _ := signupFixture(t)
		body := []byte(`{"id":"credential"}`)
		fingerprint, _ := completionFingerprint(body)
		r := d.read
		r.State = "completed"
		r.DetailsEncrypted = nil
		r.EmailTokenHash = nil
		r.EmailTokenIssuedAt.Valid = false
		r.EmailTokenExpiresAt.Valid = false
		r.SmsVerificationRef = uuid.NullUUID{}
		r.PasskeyCreatedAt.Valid = false
		r.PasskeyExpiresAt.Valid = false
		r.TerminalAt = timestamp(s.now())
		r.ReceiptExpiresAt = timestamp(s.now().Add(ReceiptLifetime))
		r.CompletionFingerprint = fingerprint
		r.ResultUserID = uuid.NullUUID{UUID: uuid.New(), Valid: true}
		d.read = r
		if result, err := s.Complete(t.Context(), a, body); err != nil || result.Next != "login" || p.calls != 0 || d.begins != 0 {
			t.Fatal("receipt repeated birth or crypto")
		}
		if _, err := s.Complete(t.Context(), a, []byte(`{"id":"changed"}`)); !errors.Is(err, ErrConflict) {
			t.Fatal("changed completion accepted")
		}
	})
}
func TestSignupUnprovenContactsAndAdmissionNeverAllocateUser(t *testing.T) {
	for _, proof := range []string{"email", "phone", "expiry", "binding"} {
		t.Run(proof, func(t *testing.T) {
			s, a, d, tx, p, _, _ := signupFixture(t)
			switch proof {
			case "email":
				d.read.EmailVerifiedAt.Valid = false
				d.read.PhoneVerifiedAt.Valid = false
				d.read.SmsVerificationRef = uuid.NullUUID{}
				d.read.PasskeyCreatedAt.Valid = false
				d.read.PasskeyExpiresAt.Valid = false
			case "phone":
				d.read.PhoneVerifiedAt.Valid = false
				d.read.PasskeyCreatedAt.Valid = false
				d.read.PasskeyExpiresAt.Valid = false
			case "expiry":
				s.now = func() time.Time { return d.read.EmailTokenExpiresAt.Time }
				s.deps.Store.now = s.now
			case "binding":
				a.JKT = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
			}
			if _, err := s.Complete(t.Context(), a, []byte(`{"id":"credential"}`)); err == nil || d.begins != 0 || p.calls != 0 || tx.commits != 0 {
				t.Fatal("unproven signup progressed")
			}
		})
	}
	for budget := 1; budget <= 4; budget++ {
		s, a, d, _, _, _, _ := signupFixture(t)
		l := &signupLimiter{denyAt: budget}
		s.deps.Limiter = l
		if _, err := s.Start(t.Context(), "Person@EXAMPLE.COM", "+989123456789", a.JKT, "203.0.113.9"); !errors.Is(err, ErrRateLimited) || d.begins != 0 {
			t.Fatal("admission allocated before budgets")
		}
		for _, key := range l.keys {
			if strings.Contains(key, "person@") || strings.Contains(key, "+989") {
				t.Fatal("admission key retained contacts")
			}
		}
	}
}
func TestSignupPhoneConsumedSQLFailureRequiresNewProof(t *testing.T) {
	s, a, d, tx, _, phone, _ := signupFixture(t)
	d.read.PhoneVerifiedAt.Valid = false
	d.read.PasskeyCreatedAt.Valid = false
	d.read.PasskeyExpiresAt.Valid = false
	details := Details{}
	plain, _ := s.deps.Store.cipher.Decrypt(t.Context(), d.read.DetailsEncrypted)
	_ = json.Unmarshal(plain, &details)
	details.Ceremony = nil
	details.CeremonyRevision = 0
	d.read.DetailsEncrypted, _ = s.deps.Store.seal(t.Context(), details)
	tx.record = d.read
	tx.failures["SaveRegistrationAttempt"] = errors.New("SQL failed after Redis consumption")
	if err := s.VerifyPhone(t.Context(), a, phone.id, "000123"); !errors.Is(err, ErrRestartRequired) || phone.consumes != 1 || phone.sends != 0 || tx.commits != 0 {
		t.Fatal("consumed proof resurrected or reported success")
	}
}
func TestSignupDatabaseConflictsAreSanitized(t *testing.T) {
	s, a, _, tx, _, _, _ := signupFixture(t)
	tx.failures["CreateUser"] = &pgconn.PgError{Code: "23505", Detail: "private@example.com"}
	if _, err := s.Complete(t.Context(), a, []byte(`{"id":"credential"}`)); !errors.Is(err, ErrConflict) || strings.Contains(err.Error(), "private") {
		t.Fatal(err)
	}
}

func TestSignupEmailCommitBeforeSendAndResendPreservesAbsoluteDeadline(t *testing.T) {
	s, a, d, tx, _, _, mail := signupFixture(t)
	expires := d.read.ExpiresAt.Time
	tx.onQuery = func(name string, args []any) pgx.Row {
		if name == "SaveRegistrationAttempt" {
			r := tx.record
			r.DetailsEncrypted = bytes.Clone(args[0].([]byte))
			r.EmailTokenHash = bytes.Clone(args[1].([]byte))
			r.EmailTokenIssuedAt = args[2].(pgtype.Timestamptz)
			r.EmailTokenExpiresAt = args[3].(pgtype.Timestamptz)
			r.EmailVerifiedAt = args[4].(pgtype.Timestamptz)
			r.SmsVerificationRef = args[5].(uuid.NullUUID)
			r.PhoneVerifiedAt = args[6].(pgtype.Timestamptz)
			r.ChallengeRevision = args[7].(int64)
			r.PasskeyCreatedAt = args[8].(pgtype.Timestamptz)
			r.PasskeyExpiresAt = args[9].(pgtype.Timestamptz)
			r.RowRevision++
			tx.record = r
			d.read = r
			return registrationRow{record: r}
		}
		return registrationRow{record: tx.record}
	}
	mail.before = func() {
		if tx.commits != 1 {
			t.Error("SMTP sent before token hash SQL commit")
		}
	}
	if err := s.ResendEmail(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	if !d.read.ExpiresAt.Time.Equal(expires) || d.read.EmailVerifiedAt.Valid || d.read.PhoneVerifiedAt.Valid || d.read.SmsVerificationRef.Valid || d.read.PasskeyExpiresAt.Valid || len(d.read.EmailTokenHash) != 32 || d.read.RowRevision != 1 {
		t.Fatal("resend extended lifetime or kept stale proofs/ceremony")
	}
	if bytes.Contains(d.read.DetailsEncrypted, a.Capability) || bytes.Contains(mail.message, a.Capability) {
		t.Fatal("capability stored/sent in email")
	}
	if d.read.EmailTokenExpiresAt.Time.After(s.now().Add(EmailLifetime)) {
		t.Fatal("resend token clock unbounded")
	}
	mail.err = errors.New("provider private failure")
	tx.commits = 0
	d.begins = 0
	if err := s.ResendEmail(t.Context(), a); !errors.Is(err, ErrSendFailed) || d.read.EmailVerifiedAt.Valid || tx.commits != 1 {
		t.Fatal("send failure claimed ownership or undid committed token")
	}
}

func TestSignupConstructorAndUnsupportedMobileFailBeforeAllocation(t *testing.T) {
	s, a, d, _, _, _, _ := signupFixture(t)
	var phone *signupPhone
	deps := s.deps
	deps.Phone = phone
	if _, err := NewService(deps); err == nil {
		t.Fatal("typed nil phone admitted")
	}
	var mail *recordingMail
	if _, err := NewEmail(EmailConfig{From: "identity@example.com", PublicOrigin: "https://identity.example.com"}, mail); err == nil {
		t.Fatal("typed nil sender admitted")
	}
	for _, phone := range []string{"+12025550123", "+982112345678", "bad"} {
		if _, err := s.Start(t.Context(), "person@example.com", phone, a.JKT, "203.0.113.9"); !errors.Is(err, ErrInvalid) || d.begins != 0 {
			t.Fatal("unsupported mobile allocated pending PII")
		}
	}
}
