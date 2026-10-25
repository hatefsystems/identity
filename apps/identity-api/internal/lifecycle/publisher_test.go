package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

var errRuntimePrivate = errors.New("private database/broker input user:secret@example.test")

type runtimeStatement struct {
	name string
	args []any
}

type runtimeTx struct {
	pgx.Tx
	queries         map[string][]db.EventOutbox
	row             db.EventOutbox
	backlog         []any
	fail            map[string]error
	affected        map[string]int64
	statements      []runtimeStatement
	onStatement     func(string)
	commitErr       error
	commits         int
	rollbacks       int
	readCommitted   bool
	rollbackBounded bool
	rollbackActive  bool
}

func runtimeQueryName(sql string) string {
	if strings.Contains(sql, "pg_advisory_xact_lock") {
		return "account_lock"
	}
	if strings.HasPrefix(sql, "SET TRANSACTION") {
		return "isolation"
	}
	return strings.Fields(sql)[2]
}

func (tx *runtimeTx) record(ctx context.Context, sql string, args []any) error {
	name := runtimeQueryName(sql)
	tx.statements = append(tx.statements, runtimeStatement{name: name, args: args})
	if name == "isolation" {
		tx.readCommitted = sql == "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
	}
	if tx.onStatement != nil {
		tx.onStatement(name)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tx.fail[name]
}

func (tx *runtimeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := tx.record(ctx, sql, args); err != nil {
		return pgconn.CommandTag{}, err
	}
	if n, ok := tx.affected[runtimeQueryName(sql)]; ok {
		return pgconn.NewCommandTag("UPDATE " + strconv.FormatInt(n, 10)), nil
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (tx *runtimeTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := tx.record(ctx, sql, args); err != nil {
		return nil, err
	}
	values := make([][]any, 0)
	for _, row := range tx.queries[runtimeQueryName(sql)] {
		values = append(values, runtimeOutboxValues(row))
	}
	return &runtimeRows{values: values}, nil
}

func (tx *runtimeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	err := tx.record(ctx, sql, args)
	values := runtimeOutboxValues(tx.row)
	if runtimeQueryName(sql) == "LifecycleBacklog" {
		values = tx.backlog
	}
	return &runtimeRow{values: values, err: err}
}

func (tx *runtimeTx) Commit(ctx context.Context) error {
	tx.commits++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return tx.commitErr
}

func (tx *runtimeTx) Rollback(ctx context.Context) error {
	tx.rollbacks++
	deadline, ok := ctx.Deadline()
	tx.rollbackBounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 5*time.Second
	tx.rollbackActive = ctx.Err() == nil
	return nil
}

func runtimeOutboxValues(row db.EventOutbox) []any {
	v := reflect.ValueOf(row)
	values := make([]any, v.NumField())
	for i := range values {
		values[i] = v.Field(i).Interface()
	}
	return values
}

type runtimeRow struct {
	values []any
	err    error
}

func (r *runtimeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("test row column mismatch")
	}
	for i, value := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

type runtimeRows struct {
	pgx.Rows
	values [][]any
	pos    int
}

func (r *runtimeRows) Next() bool {
	if r.pos == len(r.values) {
		return false
	}
	r.pos++
	return true
}
func (r *runtimeRows) Scan(dest ...any) error {
	return (&runtimeRow{values: r.values[r.pos-1]}).Scan(dest...)
}
func (*runtimeRows) Err() error { return nil }
func (*runtimeRows) Close()     {}

type runtimeDB struct {
	txs          []*runtimeTx
	calls        int
	err          error
	onBegin      func(int)
	beginContext context.Context
}

func (b *runtimeDB) Begin(ctx context.Context) (pgx.Tx, error) {
	b.calls++
	b.beginContext = ctx
	if b.onBegin != nil {
		b.onBegin(b.calls)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b.err != nil {
		return nil, b.err
	}
	if b.calls > len(b.txs) {
		return nil, errRuntimePrivate
	}
	return b.txs[b.calls-1], nil
}

type runtimeBeginTxDB struct {
	runtimeDB
	options []pgx.TxOptions
}

func (b *runtimeBeginTxDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	b.options = append(b.options, opts)
	return b.Begin(ctx)
}

type runtimePubResult struct {
	ack *jetstream.PubAck
	err error
}

type runtimePublisher struct {
	results   []runtimePubResult
	messages  []*nats.Msg
	onPublish func(context.Context, *nats.Msg)
	block     bool
}

func (js *runtimePublisher) PublishMsg(ctx context.Context, msg *nats.Msg, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	copyMessage := *msg
	copyMessage.Data = append([]byte(nil), msg.Data...)
	copyMessage.Header = make(nats.Header, len(msg.Header))
	for name, values := range msg.Header {
		copyMessage.Header[name] = append([]string(nil), values...)
	}
	js.messages = append(js.messages, &copyMessage)
	if js.onPublish != nil {
		js.onPublish(ctx, msg)
	}
	if js.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if len(js.results) >= len(js.messages) {
		result := js.results[len(js.messages)-1]
		return result.ack, result.err
	}
	return &jetstream.PubAck{Stream: "IDENTITY_USERS", Sequence: 42}, nil
}

func queuedLifecycle(t *testing.T, legacy bool) db.EventOutbox {
	t.Helper()
	created := time.Date(2026, 10, 15, 12, 0, 0, 123456000, time.UTC)
	id, userID := uuid.New(), uuid.New()
	revision := int64(7)
	row := db.EventOutbox{ID: id, Subject: SubjectUpdated, CreatedAt: pgtype.Timestamptz{Time: created, Valid: true},
		NextAttemptAt: pgtype.Timestamptz{Time: created, Valid: true}, LifecycleUserID: uuid.NullUUID{UUID: userID, Valid: true}, LifecycleRevision: &revision}
	if legacy {
		row.Subject, row.Payload = SubjectDeleted, `{"user_id":"`+userID.String()+`"}`
		row.LifecycleUserID, row.LifecycleRevision = uuid.NullUUID{}, nil
		return row
	}
	event, err := NewEvent(id, userID, revision, row.Subject, "active", []string{"status"}, created)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := MarshalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	row.Payload = string(payload)
	return row
}

func runtimeBatch(rows ...db.EventOutbox) *runtimeTx {
	tx := &runtimeTx{queries: map[string][]db.EventOutbox{}, fail: map[string]error{}, affected: map[string]int64{}}
	for _, row := range rows {
		name := "ClaimLifecycleEvents"
		if !row.LifecycleUserID.Valid && row.LifecycleRevision == nil {
			name = "ClaimLegacyLifecycleEvents"
		}
		tx.queries[name] = append(tx.queries[name], row)
	}
	return tx
}

func runtimeHasStatement(tx *runtimeTx, name string) bool {
	for _, s := range tx.statements {
		if s.name == name {
			return true
		}
	}
	return false
}

func TestPublisherRequiresExpectedStreamAcknowledgementBeforeMark(t *testing.T) {
	for _, mode := range []string{"acked", "duplicate", "broker error", "nil ack", "empty stream", "wrong stream", "zero sequence", "ack and error", "invalid envelope", "mark failure", "mark zero", "retry failure", "retry zero", "commit failure"} {
		t.Run(mode, func(t *testing.T) {
			row := queuedLifecycle(t, false)
			tx := runtimeBatch(row)
			result := runtimePubResult{ack: &jetstream.PubAck{Stream: "IDENTITY_USERS", Sequence: 1}}
			switch mode {
			case "duplicate":
				result.ack.Duplicate = true
			case "broker error", "ack and error":
				result.err = errRuntimePrivate
			case "nil ack":
				result.ack = nil
			case "empty stream":
				result.ack.Stream = ""
			case "wrong stream":
				result.ack.Stream = "IDENTITY_AUDIT"
			case "zero sequence":
				result.ack.Sequence = 0
			case "invalid envelope":
				tx.queries["ClaimLifecycleEvents"][0].ID = uuid.New()
			case "mark failure":
				tx.fail["MarkLifecyclePublished"] = errRuntimePrivate
			case "mark zero":
				tx.affected["MarkLifecyclePublished"] = 0
			case "retry failure", "retry zero":
				result.err = errRuntimePrivate
				if mode == "retry failure" {
					tx.fail["RetryLifecycleEvent"] = errRuntimePrivate
				} else {
					tx.affected["RetryLifecycleEvent"] = 0
				}
			case "commit failure":
				tx.commitErr = errRuntimePrivate
			}
			js := &runtimePublisher{results: []runtimePubResult{result}, onPublish: func(ctx context.Context, msg *nats.Msg) {
				if runtimeHasStatement(tx, "MarkLifecyclePublished") || tx.commits != 0 {
					t.Fatal("bookkeeping preceded acknowledgement")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second || msg.Subject != row.Subject ||
					msg.Header.Get(jetstream.MsgIDHeader) != row.ID.String() || msg.Header.Get(jetstream.ExpectedStreamHeader) != "IDENTITY_USERS" {
					t.Fatal("publish identity, expected stream or timeout missing")
				}
			}}
			p, err := NewPublisher(&runtimeDB{txs: []*runtimeTx{tx}}, js, "IDENTITY_USERS", PublisherConfig{})
			if err != nil {
				t.Fatal(err)
			}
			n, err := p.RunOnce(context.Background())
			if mode == "acked" || mode == "duplicate" {
				if err != nil || n != 1 || tx.commits != 1 || !runtimeHasStatement(tx, "MarkLifecyclePublished") {
					t.Fatalf("ack not committed: %d %v", n, err)
				}
			} else if err == nil || n != 0 || strings.Contains(err.Error(), "private") {
				t.Fatalf("failure not retained/redacted: %d %v", n, err)
			}
			if mode == "invalid envelope" && len(js.messages) != 0 {
				t.Fatal("invalid row sent to broker")
			}
			if !tx.readCommitted || !tx.rollbackActive || !tx.rollbackBounded {
				t.Fatal("transaction isolation or bounded rollback missing")
			}
			for _, statement := range tx.statements {
				if statement.name == "RetryLifecycleEvent" {
					foundCode := false
					for _, arg := range statement.args {
						if code, ok := arg.(*string); ok {
							foundCode = *code == "invalid_envelope" || *code == "publish_unacknowledged"
						}
					}
					if !foundCode {
						t.Fatal("retry reason was not a fixed sanitized code")
					}
				}
			}
		})
	}
}

func TestPublisherPoisonDoesNotBlockUnrelatedAccounts(t *testing.T) {
	poison, good, unavailable := queuedLifecycle(t, false), queuedLifecycle(t, false), queuedLifecycle(t, false)
	poison.Payload = `{"private":"do not disclose"}`
	unavailable.Attempts = math.MaxInt32
	tx := runtimeBatch(poison, good, unavailable)
	js := &runtimePublisher{results: []runtimePubResult{
		{ack: &jetstream.PubAck{Stream: "IDENTITY_USERS", Sequence: 1}}, {err: errRuntimePrivate},
	}}
	p, _ := NewPublisher(&runtimeDB{txs: []*runtimeTx{tx}}, js, "IDENTITY_USERS", PublisherConfig{})
	before := time.Now()
	n, err := p.RunOnce(context.Background())
	if n != 1 || !errors.Is(err, ErrPublish) || len(js.messages) != 2 || tx.commits != 1 {
		t.Fatalf("unrelated progress lost: %d %v", n, err)
	}
	var retries int
	for _, s := range tx.statements {
		if s.name != "RetryLifecycleEvent" {
			continue
		}
		retries++
		for _, arg := range s.args {
			if stamp, ok := arg.(pgtype.Timestamptz); ok {
				if !stamp.Valid || stamp.Time.Before(before.Add(time.Second-time.Millisecond)) || stamp.Time.After(time.Now().Add(256*time.Second)) {
					t.Fatal("retry deadline is not finite and bounded")
				}
			}
		}
	}
	if retries != 2 {
		t.Fatal("poison or unacknowledged intent was discarded")
	}
}

func TestPublisherUncertainCommitReplaysStableIdentity(t *testing.T) {
	for _, mode := range []string{"v1", "v2", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			legacy := mode == "legacy"
			row := queuedLifecycle(t, legacy)
			if mode == "v2" {
				event, err := NewDisplayNameEvent(row.ID, row.LifecycleUserID.UUID, *row.LifecycleRevision, "active", row.CreatedAt.Time)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := MarshalEvent(event)
				if err != nil {
					t.Fatal(err)
				}
				row.Payload = string(payload)
			}
			first, second := runtimeBatch(row), runtimeBatch(row)
			first.commitErr = errRuntimePrivate
			js := &runtimePublisher{}
			p, _ := NewPublisher(&runtimeDB{txs: []*runtimeTx{first, second}}, js, "IDENTITY_USERS", PublisherConfig{})
			if n, err := p.RunOnce(context.Background()); n != 0 || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("uncertain commit hidden: %d %v", n, err)
			}
			if n, err := p.RunOnce(context.Background()); n != 1 || err != nil {
				t.Fatalf("recovery failed: %d %v", n, err)
			}
			if len(js.messages) != 2 || !bytes.Equal(js.messages[0].Data, js.messages[1].Data) || !reflect.DeepEqual(js.messages[0].Header, js.messages[1].Header) {
				t.Fatal("uncertain commit changed message identity or body")
			}
			for _, msg := range js.messages {
				event, err := UnmarshalEvent(msg.Data)
				if err != nil || event.EventId != row.ID.String() || !event.OccurredAt.AsTime().Equal(row.CreatedAt.Time) || (event.Revision == nil) != legacy {
					t.Fatalf("stored envelope boundary lost: %v", err)
				}
				wantVersion := uint32(SchemaVersion)
				if mode == "v2" {
					wantVersion = SchemaVersionV2
				}
				if event.SchemaVersion != wantVersion || !legacy && !bytes.Equal(msg.Data, []byte(row.Payload)) {
					t.Fatal("publication rewrote the stored lifecycle version/payload")
				}
			}
		})
	}
}

func TestPublisherSharesBatchBoundAndAlternatesLegacyPriority(t *testing.T) {
	newRow, legacy := queuedLifecycle(t, false), queuedLifecycle(t, true)
	first, second := runtimeBatch(newRow, legacy), runtimeBatch(newRow, legacy)
	js := &runtimePublisher{}
	p, _ := NewPublisher(&runtimeDB{txs: []*runtimeTx{first, second}}, js, "IDENTITY_USERS", PublisherConfig{BatchSize: 1})
	for _, tx := range []*runtimeTx{first, second} {
		if n, err := p.RunOnce(context.Background()); n != 1 || err != nil {
			t.Fatalf("bounded lane failed: %d %v", n, err)
		}
		var claims int
		for _, s := range tx.statements {
			if strings.HasPrefix(s.name, "Claim") {
				claims++
				if s.args[0] != int32(1) {
					t.Fatal("batch bound missing")
				}
			}
		}
		if claims != 1 {
			t.Fatal("claimed beyond shared batch budget")
		}
	}
	if js.messages[0].Subject != SubjectUpdated || js.messages[1].Subject != SubjectDeleted {
		t.Fatal("legacy lane starved")
	}
	tx := runtimeBatch(newRow, legacy, queuedLifecycle(t, true))
	p, _ = NewPublisher(&runtimeDB{txs: []*runtimeTx{tx}}, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{BatchSize: 3})
	if n, err := p.RunOnce(context.Background()); n != 3 || err != nil {
		t.Fatalf("shared lane budget failed: %d %v", n, err)
	}
	for _, s := range tx.statements {
		if s.name == "ClaimLegacyLifecycleEvents" && s.args[0] != int32(2) {
			t.Fatal("legacy scan did not use remaining budget")
		}
	}
}

func TestDecodeOutboxEventStrictRowAndLegacyBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*db.EventOutbox){
		"admin":            func(r *db.EventOutbox) { r.AdminAction = true },
		"zero id":          func(r *db.EventOutbox) { r.ID = uuid.Nil },
		"mismatched id":    func(r *db.EventOutbox) { r.ID = uuid.New() },
		"mismatched user":  func(r *db.EventOutbox) { r.LifecycleUserID.UUID = uuid.New() },
		"missing user":     func(r *db.EventOutbox) { r.LifecycleUserID.Valid = false },
		"nil user":         func(r *db.EventOutbox) { r.LifecycleUserID.UUID = uuid.Nil },
		"missing revision": func(r *db.EventOutbox) { r.LifecycleRevision = nil },
		"wrong revision":   func(r *db.EventOutbox) { n := int64(8); r.LifecycleRevision = &n },
		"zero revision":    func(r *db.EventOutbox) { n := int64(0); r.LifecycleRevision = &n },
		"negative rev":     func(r *db.EventOutbox) { n := int64(-1); r.LifecycleRevision = &n },
		"wrong subject":    func(r *db.EventOutbox) { r.Subject = SubjectDeleted },
		"unknown subject":  func(r *db.EventOutbox) { r.Subject = "identity.user.private" },
		"absent time":      func(r *db.EventOutbox) { r.CreatedAt.Valid = false },
		"zero time":        func(r *db.EventOutbox) { r.CreatedAt.Time = time.Time{} },
		"infinite time":    func(r *db.EventOutbox) { r.CreatedAt.InfinityModifier = pgtype.Infinity },
		"wrong time":       func(r *db.EventOutbox) { r.CreatedAt.Time = r.CreatedAt.Time.Add(time.Microsecond) },
		"oversized":        func(r *db.EventOutbox) { r.Payload = strings.Repeat("x", MaxMessageBytes+1) },
		"empty":            func(r *db.EventOutbox) { r.Payload = "" },
		"legacy new meta":  func(r *db.EventOutbox) { r.Payload = `{"user_id":"` + r.LifecycleUserID.UUID.String() + `"}` },
		"new without meta": func(r *db.EventOutbox) { r.LifecycleUserID, r.LifecycleRevision = uuid.NullUUID{}, nil },
	} {
		t.Run(name, func(t *testing.T) {
			row := queuedLifecycle(t, false)
			mutate(&row)
			if payload, id, err := decodeOutboxEvent(row); !errors.Is(err, ErrInvalidEvent) || payload != nil || id != uuid.Nil {
				t.Fatalf("invalid row accepted or leaked: %v", err)
			}
		})
	}
	legacy := queuedLifecycle(t, true)
	id := "ecf132b8-8b12-4baa-9c0e-f976e56d9b9b"
	for _, payload := range []string{
		`{}`, `null`, `[]`, `{"user_id":null}`, `{"user_id":123}`, `{"UserId":"` + id + `"}`,
		`{"user_id":"` + id + `","email":"private@example.test"}`,
		`{"user_id":"` + id + `","user_id":"` + id + `"}`,
		`{"user_id":"` + id + `"}{}`, `{"user_id":"` + id + `"} true`,
		`{"user_id":"00000000-0000-0000-0000-000000000000"}`, `{"user_id":"not-an-id"}`,
		`{"user_id":"` + strings.ToUpper(id) + `"}`, `{"user_id":"urn:uuid:` + id + `"}`,
	} {
		legacy.Payload = payload
		if _, _, err := decodeOutboxEvent(legacy); !errors.Is(err, ErrInvalidEvent) {
			t.Fatalf("malformed legacy object accepted: %v", err)
		}
	}
	legacy = queuedLifecycle(t, true)
	legacy.CreatedAt.Time = legacy.CreatedAt.Time.In(time.FixedZone("source", 3600)).Add(123 * time.Nanosecond)
	payload, userID, err := decodeOutboxEvent(legacy)
	if err != nil {
		t.Fatal(err)
	}
	event, err := UnmarshalEvent(payload)
	if err != nil || event.UserId != userID.String() || event.Revision != nil || event.Status != nil || len(event.ChangedFields) != 0 ||
		!event.OccurredAt.AsTime().Equal(legacy.CreatedAt.Time.UTC().Truncate(time.Microsecond)) {
		t.Fatal("legacy adaptation manufactured profile data/revision or lost stored time")
	}
	for _, subject := range []string{SubjectCreated, SubjectUpdated, SubjectSuspended, "identity.audit.logs"} {
		legacy.Subject = subject
		if _, _, err := decodeOutboxEvent(legacy); !errors.Is(err, ErrInvalidEvent) {
			t.Fatal("metadata-free non-deletion accepted as legacy")
		}
	}
}

func TestPublisherCancellationAndPublishTimeout(t *testing.T) {
	for _, mode := range []string{"before begin", "during publish", "batch timeout", "publish timeout"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tx := runtimeBatch(queuedLifecycle(t, false), queuedLifecycle(t, false))
				b := &runtimeDB{txs: []*runtimeTx{tx}}
				js := &runtimePublisher{}
				cfg := DefaultPublisherConfig()
				switch mode {
				case "before begin":
					cancel()
				case "during publish":
					js.onPublish = func(context.Context, *nats.Msg) { cancel() }
				case "batch timeout":
					cfg.PublishTimeout, cfg.BatchTimeout, js.block = time.Millisecond, time.Millisecond, true
					js.onPublish = func(context.Context, *nats.Msg) { <-b.beginContext.Done() }
				case "publish timeout":
					cfg.PublishTimeout, js.block = time.Millisecond, true
				}
				p, _ := NewPublisher(b, js, "IDENTITY_USERS", cfg)
				n, err := p.RunOnce(ctx)
				if err == nil || n != 0 {
					t.Fatalf("canceled work reported success: %d %v", n, err)
				}
				if mode == "before begin" {
					if b.calls != 0 {
						t.Fatal("canceled worker claimed work")
					}
					return
				}
				if !tx.rollbackBounded || !tx.rollbackActive || tx.rollbacks != 1 {
					t.Fatal("canceled batch did not use bounded uncanceled rollback")
				}
				if mode == "publish timeout" {
					if !errors.Is(err, ErrPublish) || !runtimeHasStatement(tx, "RetryLifecycleEvent") || tx.commits != 1 || len(js.messages) != 2 {
						t.Fatal("per-message timeout did not retain work and progress through batch")
					}
				} else if tx.commits != 0 || len(js.messages) > 1 || runtimeHasStatement(tx, "MarkLifecyclePublished") ||
					mode == "during publish" && (len(js.messages) != 1 || runtimeHasStatement(tx, "RetryLifecycleEvent")) ||
					mode == "batch timeout" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("batch cancellation allowed new publication/bookkeeping: err=%v commits=%d messages=%d retry=%v mark=%v", err, tx.commits, len(js.messages), runtimeHasStatement(tx, "RetryLifecycleEvent"), runtimeHasStatement(tx, "MarkLifecyclePublished"))
				}
			})
		})
	}
}

func TestPublisherDatabaseFailuresAndReadCommitted(t *testing.T) {
	for _, operation := range []string{"begin", "isolation", "ClaimLifecycleEvents", "ClaimLegacyLifecycleEvents"} {
		t.Run(operation, func(t *testing.T) {
			tx := runtimeBatch()
			tx.fail[operation] = errRuntimePrivate
			b := &runtimeDB{txs: []*runtimeTx{tx}}
			if operation == "begin" {
				b.err = errRuntimePrivate
			}
			js := &runtimePublisher{}
			p, _ := NewPublisher(b, js, "IDENTITY_USERS", PublisherConfig{})
			if n, err := p.RunOnce(context.Background()); n != 0 || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") || len(js.messages) != 0 {
				t.Fatalf("DB failure unsafe: %d %v", n, err)
			}
			if operation != "begin" && (!tx.rollbackBounded || !tx.rollbackActive) {
				t.Fatal("failed transaction not released")
			}
		})
	}
	b := &runtimeBeginTxDB{runtimeDB: runtimeDB{txs: []*runtimeTx{runtimeBatch()}}}
	p, _ := NewPublisher(b, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{})
	if _, err := p.RunOnce(context.Background()); err != nil || len(b.options) != 1 || b.options[0].IsoLevel != pgx.ReadCommitted || runtimeHasStatement(b.txs[0], "isolation") {
		t.Fatalf("BeginTx isolation not used: %v", err)
	}
}

func TestPublisherOutageCommitsRetriesBeforeBatchDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rows := make([]db.EventOutbox, 10)
		for i := range rows {
			rows[i] = queuedLifecycle(t, false)
		}
		tx := runtimeBatch(rows...)
		js := &runtimePublisher{block: true}
		p, _ := NewPublisher(&runtimeDB{txs: []*runtimeTx{tx}}, js, "IDENTITY_USERS", PublisherConfig{BatchSize: 10})
		start := time.Now()
		n, err := p.RunOnce(context.Background())
		if n != 0 || !errors.Is(err, ErrPublish) || tx.commits != 1 || len(js.messages) != 5 || time.Since(start) != 25*time.Second {
			t.Fatalf("outage rolled back retries instead of yielding a bounded batch: n=%d err=%v commits=%d attempts=%d duration=%v", n, err, tx.commits, len(js.messages), time.Since(start))
		}
		var retries int
		for _, statement := range tx.statements {
			if statement.name == "RetryLifecycleEvent" {
				retries++
			}
		}
		if retries != len(js.messages) {
			t.Fatal("attempted intent was not scheduled for a persisted retry")
		}
	})
}

func TestPublisherBacklogAndRunLogsContainOnlyAggregates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	row := queuedLifecycle(t, false)
	row.Payload = `{"private":"private body user@example.test"}`
	delivery := runtimeBatch(row)
	backlog := &runtimeTx{backlog: []any{int64(2), pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}, int64(9), int64(1)}}
	b := &runtimeDB{txs: []*runtimeTx{delivery, backlog}, onBegin: func(n int) {
		if n == 3 {
			cancel()
		}
	}}
	p, _ := NewPublisher(b, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{PollInterval: time.Millisecond})
	var logs bytes.Buffer
	if err := p.RunUntilDone(ctx, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"pending":2`, `"attempts":9`, `"invalid":1`, `"oldest_age_seconds":`, `"reason":"invalid_envelope"`, `"published":0`} {
		if !strings.Contains(logs.String(), required) {
			t.Fatalf("missing aggregate diagnostic %s", required)
		}
	}
	for _, secret := range []string{row.ID.String(), row.LifecycleUserID.UUID.String(), "private", "user@example.test", row.Payload} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("logs disclosed row identity, payload or raw error")
		}
	}
	for _, future := range []bool{false, true} {
		oldest := pgtype.Timestamptz{}
		if future {
			oldest = pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}
		}
		tx := &runtimeTx{backlog: []any{int64(0), oldest, int64(0), int64(0)}}
		p, _ := NewPublisher(&runtimeDB{txs: []*runtimeTx{tx}}, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{})
		if b, err := p.Backlog(context.Background()); err != nil || b.OldestAge != 0 || tx.commits != 0 || !tx.readCommitted || !tx.rollbackBounded {
			t.Fatalf("backlog is not bounded, read-only, or age-clamped: %+v %v", b, err)
		}
	}
	p, _ = NewPublisher(&runtimeDB{err: errRuntimePrivate}, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{})
	if err := p.RunUntilDone(ctx, nil); err != nil {
		t.Fatal("already canceled loop should be a graceful stop")
	}
	if _, err := p.Backlog(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backlog failure was not sanitized: %v", err)
	}
}

func TestPublisherConfigAndRetrySaturation(t *testing.T) {
	for attempts, want := range map[int32]time.Duration{-1: time.Second, 0: time.Second, 1: 2 * time.Second, 8: 256 * time.Second, 9: 256 * time.Second, math.MaxInt32: 256 * time.Second} {
		if got := retryDelay(attempts); got != want {
			t.Fatalf("retryDelay(%d)=%v want %v", attempts, got, want)
		}
	}
	for _, cfg := range []PublisherConfig{
		{BatchSize: -1}, {BatchSize: 201}, {PublishTimeout: -1}, {PublishTimeout: time.Nanosecond},
		{PublishTimeout: 61 * time.Second}, {BatchTimeout: -1}, {BatchTimeout: 6 * time.Minute},
		{PublishTimeout: 10 * time.Second, BatchTimeout: time.Second}, {PollInterval: -1},
		{PollInterval: time.Nanosecond}, {PollInterval: 61 * time.Second},
	} {
		if _, err := NewPublisher(&runtimeDB{}, &runtimePublisher{}, "IDENTITY_USERS", cfg); err == nil {
			t.Fatalf("unbounded configuration accepted: %+v", cfg)
		}
	}
	if _, err := NewPublisher(nil, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{}); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := NewPublisher(&runtimeDB{}, nil, "IDENTITY_USERS", PublisherConfig{}); err == nil {
		t.Fatal("nil broker accepted")
	}
	if _, err := NewPublisher(&runtimeDB{}, &runtimePublisher{}, "identity.user.>", PublisherConfig{}); err == nil {
		t.Fatal("invalid stream accepted")
	}
	p, err := NewPublisher(&runtimeDB{}, &runtimePublisher{}, "IDENTITY_USERS", PublisherConfig{})
	if err != nil || p.cfg != DefaultPublisherConfig() || p.cfg.Validate() != nil {
		t.Fatal("publisher defaults changed")
	}
}
