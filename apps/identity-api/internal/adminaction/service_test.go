package adminaction

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

type fakeBeginner struct {
	txs   []*fakeTx
	calls int
	err   error
}

func (f *fakeBeginner) Begin(context.Context) (pgx.Tx, error) {
	if f.err != nil {
		return nil, f.err
	}
	tx := f.txs[f.calls]
	f.calls++
	return tx, nil
}

type statement struct {
	sql  string
	args []any
}
type fakeTx struct {
	pgx.Tx
	executed         []statement
	queryRows        [][]any
	execErr          string
	commitErr        error
	commits          int
	rollbacks        int
	rollbackCanceled bool
	readCommitted    bool
}

func (f *fakeTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if sql == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED" {
		f.readCommitted = true
		return pgconn.CommandTag{}, nil
	}
	f.executed = append(f.executed, statement{sql, args})
	if f.execErr != "" && strings.Contains(sql, f.execErr) {
		return pgconn.CommandTag{}, errors.New("secret database input must not leak")
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (f *fakeTx) Commit(context.Context) error { f.commits++; return f.commitErr }
func (f *fakeTx) Rollback(ctx context.Context) error {
	f.rollbacks++
	f.rollbackCanceled = ctx.Err() != nil
	return nil
}
func (f *fakeTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.executed = append(f.executed, statement{sql, args})
	return &fakeRows{values: f.queryRows}, nil
}

type fakeRows struct {
	pgx.Rows
	values [][]any
	pos    int
}

func (r *fakeRows) Next() bool { return r.pos < len(r.values) }
func (r *fakeRows) Scan(dest ...any) error {
	for i, value := range r.values[r.pos] {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	r.pos++
	return nil
}
func (r *fakeRows) Close()     {}
func (r *fakeRows) Err() error { return nil }

type fakeEncryptor struct {
	plaintext []byte
	err       error
}

func (f *fakeEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	f.plaintext = append([]byte(nil), plaintext...)
	if f.err != nil {
		return nil, f.err
	}
	return []byte("authenticated-ciphertext"), nil
}

func testService(t *testing.T, tx *fakeTx) (*Service, *fakeEncryptor) {
	t.Helper()
	enc := &fakeEncryptor{}
	s, err := New(&fakeBeginner{txs: []*fakeTx{tx}}, enc, "identity.audit.logs", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return s, enc
}

func testEvent() audit.Event {
	return audit.Event{EventType: audit.EventAdminUserStatusChanged, ActionStatus: audit.StatusSuccess, ActorID: uuid.New(), ActorSPIFFEID: audit.APIActorSPIFFEID}
}

func TestNewRequiresExplicitRetentionAndExactSubject(t *testing.T) {
	for _, retention := range []time.Duration{0, -1, time.Nanosecond} {
		if _, err := New(&fakeBeginner{}, &fakeEncryptor{}, "identity.audit.logs", retention); err == nil {
			t.Fatal("accepted unapproved/invalid retention")
		}
	}
	for _, subject := range []string{"", "identity.user.deleted", "identity.audit.*", "identity.audit.>", "identity..audit", "identity.audit.\nlogs"} {
		if _, err := New(&fakeBeginner{}, &fakeEncryptor{}, subject, time.Hour); err == nil {
			t.Fatalf("accepted subject %q", subject)
		}
	}
}

func TestUnsupportedHTTPMethodsCanBeAuditedWithoutRawURLs(t *testing.T) {
	for _, method := range []string{"HEAD", "OPTIONS", "TRACE", "CONNECT"} {
		event := testEvent()
		event.ActionStatus = audit.StatusFailure
		event.Payload = map[string]any{"operation": method + " /api/v1/admin/*", "method": method, "http_status": 405}
		if _, err := sanitizedEvent(event, uuid.New()); err != nil {
			t.Fatalf("cannot record %s denial: %v", method, err)
		}
		event.Payload["operation"] = method + " /api/v1/admin/private@example.test"
		if _, err := sanitizedEvent(event, uuid.New()); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("raw path accepted for %s", method)
		}
	}
}

func TestSetEventPreservesRequestDefaults(t *testing.T) {
	actor := uuid.New()
	op := &Operation{Event: audit.Event{ActorID: actor, ActorSPIFFEID: audit.APIActorSPIFFEID, ClientIP: "192.0.2.1", UserAgent: "test-agent", Payload: map[string]any{"http_status": 200}}}
	ctx := WithContext(context.Background(), op)
	SetEvent(ctx, audit.Event{EventType: audit.EventAdminAuditLogsQueried, ActorID: uuid.New(), ClientIP: "192.0.2.2", Payload: map[string]any{"result_count": 3}, Security: &audit.SecurityContext{}})
	if op.Event.ActorID != actor || op.Event.ClientIP != "192.0.2.1" || op.Event.UserAgent != "test-agent" || op.Event.ActorSPIFFEID != audit.APIActorSPIFFEID {
		t.Fatal("request defaults erased or overwritten")
	}
	if op.Event.Payload["http_status"] != 200 || op.Event.Payload["result_count"] != 3 || op.Event.Security != nil {
		t.Fatal("merge/security invariant failed")
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unexpected operation")
	}
	if err := SetDetails(context.Background(), "reason"); !errors.Is(err, ErrNoOperation) {
		t.Fatal(err)
	}
}

func TestCommitAtomicallyStoresEncryptedContextAndCanonicalEnvelope(t *testing.T) {
	tx := &fakeTx{}
	s, enc := testService(t, tx)
	op, err := s.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	op.occurredAt = time.Date(2026, 9, 18, 2, 3, 4, 987654321, time.FixedZone("offset", 3600)).UTC().Truncate(time.Microsecond)
	subject := uuid.New()
	op.Event = testEvent()
	op.Event.SubjectID = &subject
	op.Event.Security = &audit.SecurityContext{AccountRef: subject}
	op.Event.Payload = map[string]any{"reason": "sealed narrative", "email": "private@example.test", "blind_index": strings.Repeat("a", 64), "result_count": 2}
	if err := SetDetails(WithContext(context.Background(), op), map[string]string{"reason": "sealed narrative"}); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !tx.readCommitted || tx.commits != 1 || tx.rollbacks != 0 || len(tx.executed) != 2 {
		t.Fatalf("transaction sequence %#v", tx)
	}
	if !strings.Contains(tx.executed[0].sql, "InsertAdminActionContext") || !strings.Contains(tx.executed[1].sql, "InsertAdminActionOutbox") {
		t.Fatal("missing atomic writes")
	}
	if tx.executed[0].args[1] != (uuid.NullUUID{UUID: subject, Valid: true}) {
		t.Fatal("restricted account reference lost")
	}
	if string(tx.executed[0].args[2].([]byte)) != "authenticated-ciphertext" || !strings.Contains(string(enc.plaintext), op.ID.String()) {
		t.Fatal("context not encrypted/bound to action")
	}
	var env audit.Envelope
	payload := tx.executed[1].args[2].(string)
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatal(err)
	}
	if env.EventID != op.ID || env.Security != nil || env.SubjectID != "" || env.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatal("wire identity/class/time invariant failed")
	}
	if strings.Contains(payload, "sealed narrative") || strings.Contains(payload, "private@example.test") || strings.Contains(payload, "blind_index") {
		t.Fatal("sensitive value escaped into outbox")
	}
	if !strings.Contains(env.Payload, op.ID.String()) {
		t.Fatal("opaque action reference absent")
	}
	if got := tx.executed[0].args[4].(pgtype.Timestamptz).Time.Sub(op.occurredAt); got != 24*time.Hour {
		t.Fatalf("retention=%v", got)
	}
	if err := op.Commit(context.Background()); !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal("duplicate commit was accepted")
	}
}

func TestCommitFailuresRollbackAndRedactErrors(t *testing.T) {
	for _, failure := range []string{"encryption", "InsertAdminActionContext", "InsertAdminActionOutbox", "commit", "details"} {
		t.Run(failure, func(t *testing.T) {
			tx := &fakeTx{}
			s, enc := testService(t, tx)
			op, _ := s.Begin(context.Background())
			op.Event = testEvent()
			ctx := WithContext(context.Background(), op)
			if err := SetDetails(ctx, map[string]string{"reason": "sensitive"}); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "encryption":
				enc.err = errors.New("sensitive KMS detail")
			case "commit":
				tx.commitErr = errors.New("sensitive commit detail")
			case "details":
				_ = SetDetails(ctx, make(chan int))
			default:
				tx.execErr = failure
			}
			err := op.Commit(ctx)
			if err == nil || strings.Contains(err.Error(), "sensitive") || tx.rollbacks != 1 {
				t.Fatalf("failure not closed/redacted: %v, rollbacks=%d", err, tx.rollbacks)
			}
			if failure != "commit" && tx.commits != 0 {
				t.Fatal("commit after failed durable write")
			}
		})
	}
}

func TestRecordUsesFreshTransactionAfterRollback(t *testing.T) {
	first, second := &fakeTx{}, &fakeTx{}
	b := &fakeBeginner{txs: []*fakeTx{first, second}}
	s, err := New(b, &fakeEncryptor{}, "identity.audit.logs", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, _ := s.Begin(context.Background())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := op.Rollback(canceled); err != nil {
		t.Fatal(err)
	}
	e := testEvent()
	e.ActionStatus = audit.StatusFailure
	if err := s.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if b.calls != 2 || first.commits != 0 || first.rollbackCanceled || second.commits != 1 {
		t.Fatal("failure attempt did not use fresh transaction")
	}
}

func TestMetadataSchemaRejectsSmugglingAndOmitsNarratives(t *testing.T) {
	for _, payload := range []map[string]any{
		{"result_count": "private@example.test"}, {"result_count": -1}, {"verified": "secret"},
		{"new_status": "raw narrative"}, {"fields": []string{"identity_blind_index"}}, {"response_digest": "email@example.test"},
		{"hold_id": "arbitrary narrative"}, {"start_time": "case name"},
	} {
		e := testEvent()
		e.Payload = payload
		if _, err := sanitizedEvent(e, uuid.New()); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("accepted %#v", payload)
		}
	}
	e := testEvent()
	e.Payload = map[string]any{"reason": make(chan int), "requesting_authority": "court", "case_reference": "case", "blind_index": "index", "account_ref": uuid.New()}
	clean, err := sanitizedEvent(e, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Payload) != 1 {
		t.Fatalf("forbidden payload keys survived: %#v", clean.Payload)
	}
}
