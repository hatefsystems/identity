package smsotp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type userTestDatabase struct {
	db.DBTX
	tx       *userTestTx
	beginErr error
}

func (d *userTestDatabase) BeginTx(_ context.Context, opt pgx.TxOptions) (pgx.Tx, error) {
	if opt.IsoLevel != pgx.ReadCommitted {
		return nil, errPrivate
	}
	return d.tx, d.beginErr
}

type userTestRow struct {
	values []any
	err    error
}

func (r userTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}

type userTestTx struct {
	pgx.Tx
	status           string
	version          int64
	deleted          pgtype.Timestamptz
	fail             string
	count            int64
	steps            []string
	commits          int
	rollbackDetached bool
	phone            []byte
	index            *string
	email            *string
	evidence         map[string][]byte
}

func (tx *userTestTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	step := "lock"
	if strings.Contains(sql, "SetUserPhoneIfAuthorized") {
		step = "set"
	} else if strings.Contains(sql, "PutContactVerificationEvidence") {
		step = "evidence"
	} else if strings.Contains(sql, "RemoveUserPhoneIfAuthorized") {
		step = "remove"
	} else if strings.Contains(sql, "RevokeUserCredentials") {
		step = "revoke"
	}
	tx.steps = append(tx.steps, step)
	if tx.fail == step {
		return pgconn.CommandTag{}, errPrivate
	}
	if step == "set" && args[3] != tx.version || step == "remove" && args[1] != tx.version {
		return pgconn.CommandTag{}, errPrivate
	}
	return pgconn.NewCommandTag("UPDATE " + map[int64]string{0: "0", 1: "1", 2: "2"}[tx.count]), nil
}
func (tx *userTestTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	step := "read"
	if strings.Contains(sql, "GetCurrentContactEvidence") {
		step = "read_" + args[0].(string)
	}
	tx.steps = append(tx.steps, step)
	if tx.fail == step {
		return userTestRow{err: errPrivate}
	}
	if tx.fail == "missing" {
		return userTestRow{err: pgx.ErrNoRows}
	}
	if step != "read" {
		return userTestRow{values: []any{args[1].(uuid.UUID), tx.email, tx.phone, tx.evidence[args[0].(string)]}}
	}
	u := db.User{ID: args[0].(uuid.UUID), Status: tx.status, DeletedAt: tx.deleted, AuthVersion: tx.version, PhoneEncrypted: tx.phone, PhoneBlindIndex: tx.index, Email: tx.email}
	value := reflect.ValueOf(u)
	values := make([]any, value.NumField())
	for i := range values {
		values[i] = value.Field(i).Interface()
	}
	return userTestRow{values: values}
}
func (tx *userTestTx) Commit(context.Context) error {
	tx.commits++
	if tx.fail == "commit" {
		return errPrivate
	}
	return nil
}
func (tx *userTestTx) Rollback(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	tx.rollbackDetached = ok && ctx.Err() == nil && time.Until(deadline) <= 5*time.Second
	return nil
}
func userStoreFixture(t *testing.T) (*PostgresUserStore, *userTestTx) {
	t.Helper()
	tx := &userTestTx{status: "active", version: 7, count: 1, evidence: map[string][]byte{}}
	s, err := NewUserStore(&userTestDatabase{tx: tx}, smsTestCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	return s, tx
}
func smsTestCipher(t *testing.T) *envelope.Encryptor {
	t.Helper()
	provider, err := kms.NewMockProvider([]byte(strings.Repeat("k", 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}
func smsTestProof(t *testing.T, cipher contactproof.Cipher, id uuid.UUID, channel, destination string) []byte {
	t.Helper()
	method := contactproof.SMSOTP
	if channel == contactproof.Email {
		method = contactproof.EmailLink
	}
	proof, err := contactproof.Seal(context.Background(), cipher, id, channel, destination, method, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func smsTestEncrypted(t *testing.T, cipher contactproof.Cipher, phone string) []byte {
	t.Helper()
	blob, err := cipher.Encrypt(context.Background(), []byte(phone))
	if err != nil {
		t.Fatal(err)
	}
	return blob
}
func TestSMSPostgresStoreRequiresTransactionDatabase(t *testing.T) {
	if _, err := NewUserStore(nil); err == nil {
		t.Fatal("nil DB accepted")
	}
	var d *userTestDatabase
	if _, err := NewUserStore(d); err == nil {
		t.Fatal("typed nil DB accepted")
	}
	database := &userTestDatabase{}
	var cipher *envelope.Encryptor
	for _, ciphers := range [][]contactproof.Cipher{{nil}, {cipher}, {smsTestCipher(t), smsTestCipher(t)}} {
		if _, err := NewUserStore(database, ciphers...); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid cipher injection accepted")
		}
	}
	if _, err := NewUserStore(database); err != nil {
		t.Fatal("optional cipher construction queried database")
	}
}
func TestSMSPostgresStoreLocksBeforeFencedConditionalWrite(t *testing.T) {
	for _, remove := range []bool{false, true} {
		s, tx := userStoreFixture(t)
		id := uuid.New()
		var err error
		if remove {
			_, err = s.RemovePhoneIfCurrent(context.Background(), id, 7)
		} else {
			err = s.SetPhoneIfCurrent(context.Background(), id, 7, smsTestEncrypted(t, s.cipher, testPhone), "index", smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone))
		}
		wantSteps := 6
		if remove {
			wantSteps = 5
		}
		if err != nil || len(tx.steps) != wantSteps || tx.steps[0] != "lock" || tx.steps[1] != "read" || tx.commits != 1 || !tx.rollbackDetached {
			t.Fatalf("unfenced ordering: %v %+v", err, tx)
		}
	}
}
func TestSMSPostgresStoreStaleInactiveAndFailureHaveNoWrite(t *testing.T) {
	for _, failure := range []string{"stale", "inactive", "deleted", "missing", "lock", "read"} {
		t.Run(failure, func(t *testing.T) {
			s, tx := userStoreFixture(t)
			switch failure {
			case "stale":
				tx.version++
			case "inactive":
				tx.status = "suspended"
			case "deleted":
				tx.deleted.Valid = true
			default:
				tx.fail = failure
			}
			id := uuid.New()
			err := s.SetPhoneIfCurrent(context.Background(), id, 7, smsTestEncrypted(t, s.cipher, testPhone), "index", smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone))
			if err == nil || tx.commits != 0 || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe failure: %v", err)
			}
			for _, step := range tx.steps {
				if step == "set" || step == "remove" {
					t.Fatal("invalid authority wrote")
				}
			}
		})
	}
}
func TestSMSPostgresRemovalCountAndCommitFailures(t *testing.T) {
	s, tx := userStoreFixture(t)
	tx.count = 0
	changed, err := s.RemovePhoneIfCurrent(context.Background(), uuid.New(), 7)
	if changed || err != nil || tx.commits != 1 {
		t.Fatal("no-op removal claims event")
	}
	if strings.Contains(strings.Join(tx.steps, ","), "revoke") {
		t.Fatal("absent phone removal revoked authority")
	}
	for _, failure := range []string{"set", "evidence", "revoke", "remove", "commit"} {
		s, tx := userStoreFixture(t)
		tx.fail = failure
		var changed bool
		var err error
		if failure == "set" || failure == "evidence" {
			id := uuid.New()
			err = s.SetPhoneIfCurrent(context.Background(), id, 7, smsTestEncrypted(t, s.cipher, testPhone), "index", smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone))
		} else {
			changed, err = s.RemovePhoneIfCurrent(context.Background(), uuid.New(), 7)
		}
		if changed || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") {
			t.Fatal("failed/unknown commit claims change")
		}
	}
}

func TestSMSPhoneRemovalRequiresExactVerifiedEmail(t *testing.T) {
	for _, condition := range []string{"unknown", "verified_email", "populated_email", "no_email", "wrong_email", "bad_phone", "phone_dependency", "email_dependency", "missing_cipher"} {
		t.Run(condition, func(t *testing.T) {
			s, tx := userStoreFixture(t)
			id := uuid.New()
			tx.phone = smsTestEncrypted(t, s.cipher, testPhone)
			tx.email = new("current@example.invalid")
			if condition != "unknown" {
				tx.evidence[contactproof.Phone] = smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone)
			}
			switch condition {
			case "verified_email":
				tx.evidence[contactproof.Email] = smsTestProof(t, s.cipher, id, contactproof.Email, *tx.email)
			case "no_email":
				tx.email = nil
			case "wrong_email":
				tx.evidence[contactproof.Email] = smsTestProof(t, s.cipher, id, contactproof.Email, "old@example.invalid")
			case "bad_phone":
				tx.evidence[contactproof.Phone][len(tx.evidence[contactproof.Phone])-1] ^= 1
			case "phone_dependency":
				tx.fail = "read_phone"
			case "email_dependency":
				tx.fail = "read_email"
			case "missing_cipher":
				s.cipher = nil
			}
			changed, err := s.RemovePhoneIfCurrent(context.Background(), id, 7)
			if condition == "unknown" || condition == "verified_email" {
				if err != nil || !changed || strings.Count(strings.Join(tx.steps, ","), "revoke") != 1 {
					t.Fatalf("authorized removal not revoked once: %v %v", err, tx.steps)
				}
				return
			}
			want := ErrUnavailable
			if condition == "populated_email" || condition == "no_email" {
				want = accountpolicy.ErrLastVerifiedContact
			}
			if changed || !errors.Is(err, want) || tx.commits != 0 {
				t.Fatalf("rejected removal result: %v %v", changed, err)
			}
			for _, step := range tx.steps {
				if step == "remove" || step == "revoke" {
					t.Fatal("rejected removal wrote or revoked")
				}
			}
		})
	}
}

func TestSMSPhoneReplacementEvidenceBindingAndUnknownRepair(t *testing.T) {
	for _, condition := range []string{"repair", "new_phone", "same", "evidence_change", "different_phone", "different_account", "different_channel", "tampered", "invalid_phone", "missing_cipher", "read_dependency"} {
		t.Run(condition, func(t *testing.T) {
			s, tx := userStoreFixture(t)
			id := uuid.New()
			encrypted := smsTestEncrypted(t, s.cipher, testPhone)
			proof := smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone)
			tx.phone, tx.index = encrypted, new("index")
			tx.evidence[contactproof.Phone] = []byte("unknown provenance")
			switch condition {
			case "same":
				tx.evidence[contactproof.Phone] = proof
			case "evidence_change":
				tx.evidence[contactproof.Phone] = smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone)
			case "new_phone":
				tx.phone = smsTestEncrypted(t, s.cipher, "+15550102020")
			case "different_phone":
				proof = smsTestProof(t, s.cipher, id, contactproof.Phone, "+15550102020")
			case "different_account":
				proof = smsTestProof(t, s.cipher, uuid.New(), contactproof.Phone, testPhone)
			case "different_channel":
				proof = smsTestProof(t, s.cipher, id, contactproof.Email, "current@example.invalid")
			case "tampered":
				proof[len(proof)-1] ^= 1
			case "invalid_phone":
				encrypted = []byte("not an authenticated envelope")
			case "missing_cipher":
				s.cipher = nil
			case "read_dependency":
				tx.fail = "read_phone"
			}
			err := s.SetPhoneIfCurrent(context.Background(), id, 7, encrypted, "index", proof)
			if condition == "repair" || condition == "new_phone" || condition == "evidence_change" || condition == "same" {
				want := 1
				if condition == "same" {
					want = 0
				}
				if err != nil || tx.commits != 1 || strings.Count(strings.Join(tx.steps, ","), "revoke") != want {
					t.Fatalf("replacement result: %v %v", err, tx.steps)
				}
				return
			}
			if !errors.Is(err, ErrUnavailable) || tx.commits != 0 {
				t.Fatalf("invalid evidence accepted: %v", err)
			}
			for _, step := range tx.steps {
				if step == "set" || step == "evidence" || step == "revoke" {
					t.Fatal("invalid replacement wrote or revoked")
				}
			}
		})
	}
}

func TestSMSPhoneCommittedMarkerExcludesNoopRejectionAndRollback(t *testing.T) {
	for _, operation := range []string{"replace", "same", "remove", "absent", "reject", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			s, tx := userStoreFixture(t)
			id := uuid.New()
			encrypted := smsTestEncrypted(t, s.cipher, testPhone)
			proof := smsTestProof(t, s.cipher, id, contactproof.Phone, testPhone)
			tx.phone, tx.index = encrypted, new("index")
			if operation == "same" || operation == "reject" {
				tx.evidence[contactproof.Phone] = proof
			}
			if operation == "absent" {
				tx.phone, tx.index, tx.count = nil, nil, 0
			}
			if operation == "rollback" {
				tx.fail = "commit"
			}
			codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			issue := httptest.NewRecorder()
			current, err := manager.Issue(issue, session.IssueParams{UserID: id.String(), AuthVersion: 7, AuthVersionSet: true})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			for _, cookie := range issue.Result().Cookies() {
				r.AddCookie(cookie)
			}
			r = r.WithContext(session.WithSession(r.Context(), current))
			w := httptest.NewRecorder()
			manager.TrackActivity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if operation == "replace" || operation == "same" {
					err = s.SetPhoneIfCurrent(r.Context(), id, 7, encrypted, "index", proof)
				} else {
					_, err = s.RemovePhoneIfCurrent(r.Context(), id, 7)
				}
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(w, r)
			marked := w.Header().Get(session.HeaderAuthInvalidated) == "true"
			wantMarked := operation == "replace" || operation == "remove"
			if marked != wantMarked {
				t.Fatal("committed marker did not match actual phone change")
			}
			wantStatus := http.StatusNoContent
			if operation == "reject" || operation == "rollback" {
				wantStatus = http.StatusInternalServerError
			}
			if w.Code != wantStatus {
				t.Fatalf("phone mutation status %d, want %d", w.Code, wantStatus)
			}
		})
	}
}
