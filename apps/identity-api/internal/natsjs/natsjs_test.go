package natsjs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// TestRedeliveryBackOffStartsAtAckWait pins the invariant that cost us a silently
// broken consumer: nats-server overwrites AckWait with BackOff[0] instead of treating
// them as independent settings. A ladder whose first rung is shorter than the
// configured ack deadline therefore shortens that deadline without any error, and the
// server starts redelivering batches the signer is still legitimately accumulating.
func TestRedeliveryBackOffStartsAtAckWait(t *testing.T) {
	t.Parallel()

	for _, ackWait := range []time.Duration{
		time.Second,
		30 * time.Second,
		60 * time.Second,
		5 * time.Minute,
	} {
		t.Run(ackWait.String(), func(t *testing.T) {
			t.Parallel()

			backoff := redeliveryBackOff(ackWait)
			if len(backoff) == 0 {
				t.Fatal("redeliveryBackOff returned no intervals; JetStream would fall back to a bare AckWait ladder")
			}
			// The load-bearing assertion: BackOff[0] becomes the effective AckWait.
			if backoff[0] != ackWait {
				t.Errorf("backoff[0] = %s, want %s (server derives the ack deadline from it)", backoff[0], ackWait)
			}
			for i, interval := range backoff {
				if interval < ackWait {
					t.Errorf("backoff[%d] = %s is shorter than ack wait %s; redelivery would race the signer's own batch", i, interval, ackWait)
				}
			}
			// Monotonic: the point of the ladder is to give a saturated database
			// progressively more room, never less.
			for i := 1; i < len(backoff); i++ {
				if backoff[i] <= backoff[i-1] {
					t.Errorf("backoff[%d] = %s is not greater than backoff[%d] = %s", i, backoff[i], i-1, backoff[i-1])
				}
			}
		})
	}
}

func TestConnectRequiresURL(t *testing.T) {
	t.Parallel()

	nc, js, err := Connect(context.Background(), "", "test", nil)
	if err == nil {
		if nc != nil {
			nc.Close()
		}
		t.Fatal("Connect with an empty url returned no error")
	}
	if nc != nil || js != nil {
		t.Error("Connect returned a non-nil connection or JetStream context alongside an error")
	}
	if !strings.Contains(err.Error(), "url is required") {
		t.Errorf("error = %q, want it to mention the missing url", err)
	}
}

// TestEnsureStreamValidation covers the guards that must reject a misconfigured
// stream before it reaches CreateOrUpdateStream, which is authoritative and would
// otherwise rewrite the live stream's limits.
func TestEnsureStreamValidation(t *testing.T) {
	t.Parallel()

	valid := StreamOptions{
		Name:       "IDENTITY_AUDIT",
		Subjects:   []string{"identity.audit.>"},
		MaxBytes:   1 << 20,
		Duplicates: 2 * time.Minute,
	}

	tests := []struct {
		name    string
		mutate  func(*StreamOptions)
		wantMsg string
	}{
		{
			name:    "empty name",
			mutate:  func(o *StreamOptions) { o.Name = "" },
			wantMsg: "stream name is required",
		},
		{
			name:    "no subjects",
			mutate:  func(o *StreamOptions) { o.Subjects = nil },
			wantMsg: "stream subjects are required",
		},
		{
			name:    "zero max bytes",
			mutate:  func(o *StreamOptions) { o.MaxBytes = 0 },
			wantMsg: "max bytes must be positive",
		},
		{
			name:    "negative max bytes",
			mutate:  func(o *StreamOptions) { o.MaxBytes = -1 },
			wantMsg: "max bytes must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := valid
			opts.Subjects = append([]string(nil), valid.Subjects...)
			tc.mutate(&opts)

			// A nil JetStream context is rejected first, so these cases are driven
			// through a non-nil sentinel to prove the field guards themselves fire.
			stream, err := EnsureStream(context.Background(), stubJetStream{}, opts)
			if err == nil {
				t.Fatalf("EnsureStream(%+v) returned no error", opts)
			}
			if stream != nil {
				t.Error("EnsureStream returned a non-nil stream alongside an error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestEnsureStreamRequiresJetStream(t *testing.T) {
	t.Parallel()

	_, err := EnsureStream(context.Background(), nil, StreamOptions{
		Name:     "IDENTITY_AUDIT",
		Subjects: []string{"identity.audit.>"},
		MaxBytes: 1 << 20,
	})
	if err == nil {
		t.Fatal("EnsureStream with a nil JetStream context returned no error")
	}
	if !strings.Contains(err.Error(), "jetstream context is required") {
		t.Errorf("error = %q, want it to mention the missing jetstream context", err)
	}
}

// TestEnsureConsumerValidation covers the consumer guards, including AckWait, which
// is validated rather than defaulted because it is also the base of the redelivery
// ladder.
func TestEnsureConsumerValidation(t *testing.T) {
	t.Parallel()

	valid := ConsumerOptions{
		Durable:       "audit-signer",
		FilterSubject: "identity.audit.logs",
		AckWait:       60 * time.Second,
		MaxAckPending: 2000,
		MaxDeliver:    5,
	}

	tests := []struct {
		name    string
		mutate  func(*ConsumerOptions)
		wantMsg string
	}{
		{
			name:    "empty durable",
			mutate:  func(o *ConsumerOptions) { o.Durable = "" },
			wantMsg: "durable consumer name is required",
		},
		{
			name:    "zero max ack pending",
			mutate:  func(o *ConsumerOptions) { o.MaxAckPending = 0 },
			wantMsg: "max ack pending must be positive",
		},
		{
			name:    "negative max ack pending",
			mutate:  func(o *ConsumerOptions) { o.MaxAckPending = -5 },
			wantMsg: "max ack pending must be positive",
		},
		{
			name:    "zero max deliver",
			mutate:  func(o *ConsumerOptions) { o.MaxDeliver = 0 },
			wantMsg: "max deliver must be positive",
		},
		{
			name:    "negative max deliver",
			mutate:  func(o *ConsumerOptions) { o.MaxDeliver = -1 },
			wantMsg: "max deliver must be positive",
		},
		{
			name:    "zero ack wait",
			mutate:  func(o *ConsumerOptions) { o.AckWait = 0 },
			wantMsg: "ack wait must be positive",
		},
		{
			name:    "negative ack wait",
			mutate:  func(o *ConsumerOptions) { o.AckWait = -time.Second },
			wantMsg: "ack wait must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := valid
			tc.mutate(&opts)

			consumer, err := EnsureConsumer(context.Background(), stubJetStream{}, "IDENTITY_AUDIT", opts)
			if err == nil {
				t.Fatalf("EnsureConsumer(%+v) returned no error", opts)
			}
			if consumer != nil {
				t.Error("EnsureConsumer returned a non-nil consumer alongside an error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantMsg)
			}
		})
	}
}

func TestEnsureConsumerRequiresJetStreamAndStream(t *testing.T) {
	t.Parallel()

	opts := ConsumerOptions{
		Durable:       "audit-signer",
		FilterSubject: "identity.audit.logs",
		AckWait:       60 * time.Second,
		MaxAckPending: 2000,
		MaxDeliver:    5,
	}

	if _, err := EnsureConsumer(context.Background(), nil, "IDENTITY_AUDIT", opts); err == nil {
		t.Error("EnsureConsumer with a nil JetStream context returned no error")
	} else if !strings.Contains(err.Error(), "jetstream context is required") {
		t.Errorf("error = %q, want it to mention the missing jetstream context", err)
	}

	if _, err := EnsureConsumer(context.Background(), stubJetStream{}, "", opts); err == nil {
		t.Error("EnsureConsumer with an empty stream name returned no error")
	} else if !strings.Contains(err.Error(), "stream name is required") {
		t.Errorf("error = %q, want it to mention the missing stream name", err)
	}
}

// errStubJetStream is returned by every stubJetStream method the Ensure* functions
// could reach. The validation tests must fail before any of them is called, so seeing
// this error in a failure message means a guard did not fire.
var errStubJetStream = errors.New("natsjs test: stub JetStream method called; a validation guard did not fire")

// stubJetStream is a non-nil jetstream.JetStream used to prove the field-level guards
// in EnsureStream and EnsureConsumer fire on their own, rather than being masked by
// the nil-context check that runs first.
//
// The interface is embedded so the stub keeps compiling as nats.go grows methods;
// only the two the Ensure* functions can reach are implemented. Any other call
// dereferences the nil embedded interface and panics, which is the desired outcome:
// these tests must never touch a real server.
type stubJetStream struct {
	jetstream.JetStream
}

func (stubJetStream) CreateOrUpdateStream(context.Context, jetstream.StreamConfig) (jetstream.Stream, error) {
	return nil, errStubJetStream
}

func (stubJetStream) CreateOrUpdateConsumer(context.Context, string, jetstream.ConsumerConfig) (jetstream.Consumer, error) {
	return nil, errStubJetStream
}
