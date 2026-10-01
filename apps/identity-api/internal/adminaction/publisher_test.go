package adminaction

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	for _, mode := range []string{"acked", "error", "nil_ack", "empty_ack", "commit_failure", "mark_failure", "invalid_envelope"} {
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
			if mode == "invalid_envelope" && len(js.payloads) != 0 {
				t.Fatal("invalid envelope published")
			}
		})
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
