package adminaction

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

type fakePublisher struct {
	ack      *jetstream.PubAck
	err      error
	payloads [][]byte
	before   func()
}

func (f *fakePublisher) Publish(_ context.Context, _ string, payload []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	if f.before != nil {
		f.before()
	}
	f.payloads = append(f.payloads, append([]byte(nil), payload...))
	return f.ack, f.err
}

func queuedEnvelope(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	env, err := audit.NewEnvelope(testEvent(), id, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return id, string(b)
}

func TestPublisherRequiresAcknowledgementBeforeDelivered(t *testing.T) {
	id, payload := queuedEnvelope(t)
	for _, mode := range []string{"acked", "error", "nil_ack", "empty_ack", "commit_failure", "mark_failure", "invalid_envelope", "invalid_actor"} {
		t.Run(mode, func(t *testing.T) {
			tx := &fakeTx{queryRows: [][]any{{id, payload, int32(0)}}}
			js := &fakePublisher{ack: &jetstream.PubAck{Stream: "AUDIT", Sequence: 1}}
			js.before = func() {
				if tx.commits != 0 || len(tx.executed) != 1 {
					t.Fatal("delivery was marked before PubAck")
				}
			}
			switch mode {
			case "error":
				js.err = errors.New("broker private payload")
			case "nil_ack":
				js.ack = nil
			case "empty_ack":
				js.ack = &jetstream.PubAck{}
			case "commit_failure":
				tx.commitErr = errors.New("commit failed")
			case "mark_failure":
				tx.execErr = "MarkAdminActionPublished"
			case "invalid_envelope":
				tx.queryRows[0][0] = uuid.New()
			case "invalid_actor":
				var env audit.Envelope
				if err := json.Unmarshal([]byte(payload), &env); err != nil {
					t.Fatal(err)
				}
				env.ActorID = "sensitive@example.test"
				raw, err := json.Marshal(env)
				if err != nil {
					t.Fatal(err)
				}
				tx.queryRows[0][1] = string(raw)
			}
			p, err := NewPublisher(&fakeBeginner{txs: []*fakeTx{tx}}, js, "identity.audit.logs", PublisherConfig{})
			if err != nil {
				t.Fatal(err)
			}
			n, err := p.RunOnce(context.Background())
			if mode == "acked" {
				if err != nil || n != 1 || !strings.Contains(tx.executed[1].sql, "MarkAdminActionPublished") {
					t.Fatalf("ack not persisted: %d %v", n, err)
				}
			} else {
				if err == nil || n != 0 {
					t.Fatalf("unacknowledged/failed transaction reported success: %d %v", n, err)
				}
				if mode != "commit_failure" && mode != "mark_failure" {
					if !strings.Contains(tx.executed[1].sql, "RetryAdminActionOutbox") {
						t.Fatal("failure not scheduled for retry")
					}
					if strings.Contains(*tx.executed[1].args[1].(*string), "private") {
						t.Fatal("raw transport error leaked")
					}
				}
			}
			if (mode == "invalid_envelope" || mode == "invalid_actor") && len(js.payloads) != 0 {
				t.Fatal("invalid envelope published")
			}
		})
	}
}

type delayedPublisher struct {
	delay  time.Duration
	calls  uint64
	failAt uint64
}

func (p *delayedPublisher) Publish(ctx context.Context, _ string, _ []byte, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	p.calls++
	timer := time.NewTimer(p.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
	}
	if p.calls == p.failAt {
		return nil, errors.New("sensitive broker failure")
	}
	return &jetstream.PubAck{Stream: "AUDIT", Sequence: p.calls}, nil
}

type publisherBeginnerFunc func(context.Context) (pgx.Tx, error)

func (f publisherBeginnerFunc) Begin(ctx context.Context) (pgx.Tx, error) { return f(ctx) }

// Unlike the ordinary SQL fake, reject bookkeeping and commit after deadline.
type publisherBudgetTx struct {
	*fakeTx
	commitRemaining time.Duration
}

func (tx *publisherBudgetTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if err := ctx.Err(); err != nil {
		return pgconn.CommandTag{}, err
	}
	return tx.fakeTx.Exec(ctx, sql, args...)
}
func (tx *publisherBudgetTx) Commit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	tx.commitRemaining = time.Until(deadline)
	return tx.fakeTx.Commit(ctx)
}

func TestPublisherPersistsAttemptedOutcomesBeforeBudget(t *testing.T) {
	for failAt, failCall := range []uint64{0, 1, 2} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			tx := &publisherBudgetTx{fakeTx: &fakeTx{}}
			var ids []uuid.UUID
			for range 4 {
				id, payload := queuedEnvelope(t)
				tx.queryRows = append(tx.queryRows, []any{id, payload, int32(0)})
				ids = append(ids, id)
			}
			js := &delayedPublisher{delay: 90 * time.Millisecond, failAt: failCall}
			p, err := NewPublisher(publisherBeginnerFunc(func(context.Context) (pgx.Tx, error) { return tx, nil }), js, "identity.audit.logs", PublisherConfig{BatchTimeout: 260 * time.Millisecond, PublishTimeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			n, err := p.RunOnce(context.Background())
			want := 2
			if failAt != 0 {
				want = 1
			}
			if n != want || (failAt == 0 && err != nil) || (failAt != 0 && !errors.Is(err, ErrPublish)) {
				t.Fatalf("attempted results: n=%d err=%v", n, err)
			}
			if js.calls != 2 || tx.commits != 1 || tx.commitRemaining <= 0 || len(tx.executed) != 3 {
				t.Fatal("batch exhausted commit budget or attempted extra claimed rows")
			}
			for i, statement := range tx.executed[1:] {
				if i+1 == failAt {
					if !strings.Contains(statement.sql, "RetryAdminActionOutbox") || *statement.args[1].(*string) != "publish_unacknowledged" || statement.args[2] != ids[i] {
						t.Fatal("failed attempt not durably scheduled with sanitized reason")
					}
				} else if !strings.Contains(statement.sql, "MarkAdminActionPublished") || statement.args[0] != ids[i] {
					t.Fatal("delayed success not durably marked")
				}
			}
		})
	}
}

func TestPublisherFirstAttemptReservesCommitTime(t *testing.T) {
	id, payload := queuedEnvelope(t)
	tx := &publisherBudgetTx{fakeTx: &fakeTx{queryRows: [][]any{{id, payload, int32(0)}}}}
	js := &delayedPublisher{delay: time.Second}
	p, err := NewPublisher(publisherBeginnerFunc(func(context.Context) (pgx.Tx, error) { return tx, nil }), js, "identity.audit.logs", PublisherConfig{BatchTimeout: 500 * time.Millisecond, PublishTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := p.RunOnce(context.Background()); n != 0 || !errors.Is(err, ErrPublish) {
		t.Fatalf("timed-out first publish: %d %v", n, err)
	}
	if js.calls != 1 || tx.commits != 1 || tx.commitRemaining <= 0 || !strings.Contains(tx.executed[1].sql, "RetryAdminActionOutbox") {
		t.Fatal("first publish consumed commit reserve")
	}
}

func TestPublisherDoesNotStartWithoutCommitBudget(t *testing.T) {
	id, payload := queuedEnvelope(t)
	tx := &publisherBudgetTx{fakeTx: &fakeTx{queryRows: [][]any{{id, payload, int32(0)}}}}
	js := &delayedPublisher{}
	p, err := NewPublisher(publisherBeginnerFunc(func(context.Context) (pgx.Tx, error) { return tx, nil }), js, "identity.audit.logs", PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if n, err := p.RunOnce(ctx); n != 0 || err != nil {
		t.Fatalf("unused claims: %d %v", n, err)
	}
	if js.calls != 0 || tx.commits != 1 || len(tx.executed) != 1 {
		t.Fatal("publish started without commit budget or altered unattempted row")
	}
}

func TestPublisherCrashRetryUsesStableEnvelope(t *testing.T) {
	id, payload := queuedEnvelope(t)
	first := &fakeTx{queryRows: [][]any{{id, payload, int32(0)}}, commitErr: errors.New("commit unknown")}
	second := &fakeTx{queryRows: [][]any{{id, payload, int32(0)}}}
	js := &fakePublisher{ack: &jetstream.PubAck{Stream: "AUDIT", Sequence: 42}}
	p, err := NewPublisher(&fakeBeginner{txs: []*fakeTx{first, second}}, js, "identity.audit.logs", PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.RunOnce(context.Background()); err == nil {
		t.Fatal("commit failure hidden")
	}
	if n, err := p.RunOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("retry failed: %d %v", n, err)
	}
	if len(js.payloads) != 2 || string(js.payloads[0]) != string(js.payloads[1]) {
		t.Fatal("retry changed envelope identity/time/payload")
	}
}

func TestPublisherBoundsAndBackoff(t *testing.T) {
	for _, cfg := range []PublisherConfig{{BatchSize: -1}, {BatchSize: 201}, {PublishTimeout: -1}, {PublishTimeout: 10 * time.Second, BatchTimeout: time.Second}, {PollInterval: -1}} {
		if _, err := NewPublisher(&fakeBeginner{}, &fakePublisher{}, "identity.audit.logs", cfg); err == nil {
			t.Fatalf("accepted invalid config %#v", cfg)
		}
	}
	if retryDelay(0) != time.Second || retryDelay(1) != 2*time.Second || retryDelay(1000) != 256*time.Second || retryDelay(-1) != time.Second {
		t.Fatal("retry backoff not bounded")
	}
}
