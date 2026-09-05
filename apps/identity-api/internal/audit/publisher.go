package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
)

// JetStreamRecorder is the Task 5.2 Recorder: it publishes envelopes to a NATS
// JetStream subject that the single-threaded signing consumer drains.
//
// # Why Record is asynchronous
//
// Record is called from inside request handlers, on the success path of operations
// that have already committed. A synchronous publish would put a network round-trip
// — and, worse, a NATS outage — on the critical path of logging in, disabling MFA, or
// issuing a token. Refusing or stalling a business operation because the audit
// transport is unavailable is itself a compliance failure: the operation is lawful
// and already done, and the correct response to a transport outage is an alert, not a
// user-visible error. So Record hands the envelope to a bounded channel and returns.
//
// # What happens when that is not enough
//
// The channel is bounded, so a sustained outage must eventually shed load. Nothing is
// dropped quietly: a full buffer or a terminal publish failure emits a single
// slog.Error containing the entire envelope JSON tagged with
// AuditTransportFailureMarker, so the event survives in the container log and is
// recoverable by hand. That is why Event.Payload's "no raw PII" rule is load-bearing
// rather than belt-and-braces — this path writes payload values, not just their keys.
type JetStreamRecorder struct {
	js      jetstream.JetStream
	subject string
	logger  *slog.Logger

	// buf carries envelopes from callers to the publishing goroutine.
	buf chan Envelope
	// stallWait bounds how long an individual async publish may wait for a free
	// slot in the client's pending window before failing.
	stallWait time.Duration

	// closeOnce guards Close so a double shutdown cannot close buf twice.
	closeOnce sync.Once
	// done is closed by the publishing goroutine when it has finished draining.
	done chan struct{}

	// newID and now are seams for deterministic tests.
	newID func() uuid.UUID
	now   func() time.Time

	mu      sync.Mutex
	dropped uint64
}

// AuditTransportFailureMarker tags every log line that carries an audit event which
// did not make it onto the stream. Alerting keys off this exact string, and the
// presence of any such line means the tamper-evident ledger is incomplete for that
// event, so it is an operational incident rather than a warning to be tuned out.
const AuditTransportFailureMarker = "audit_transport_failure"

// defaultPublishStallWait bounds an individual async publish's wait for a free
// pending slot. It is short by design: the point of the bounded buffer is to fail
// loudly and quickly under sustained backpressure, not to queue for minutes and then
// dump a large batch of events into the log at once.
const defaultPublishStallWait = 2 * time.Second

// RecorderOption configures a JetStreamRecorder.
type RecorderOption func(*JetStreamRecorder)

// WithRecorderClock overrides the occurrence-time source for deterministic tests.
func WithRecorderClock(now func() time.Time) RecorderOption {
	return func(r *JetStreamRecorder) {
		if now != nil {
			r.now = now
		}
	}
}

// WithRecorderIDs overrides event-id generation for deterministic tests.
func WithRecorderIDs(newID func() uuid.UUID) RecorderOption {
	return func(r *JetStreamRecorder) {
		if newID != nil {
			r.newID = newID
		}
	}
}

// WithPublishStallWait overrides how long one async publish waits for a free
// pending slot.
func WithPublishStallWait(d time.Duration) RecorderOption {
	return func(r *JetStreamRecorder) {
		if d > 0 {
			r.stallWait = d
		}
	}
}

// NewJetStreamRecorder constructs a JetStreamRecorder and starts its publishing
// goroutine. The caller must invoke Close during shutdown to drain it.
//
// bufferSize must be positive: a zero-capacity channel would make Record's
// non-blocking send fail whenever the publisher goroutine is momentarily busy,
// converting normal operation into a stream of transport-failure log lines.
func NewJetStreamRecorder(js jetstream.JetStream, subject string, bufferSize int, logger *slog.Logger, opts ...RecorderOption) (*JetStreamRecorder, error) {
	if js == nil {
		return nil, errors.New("audit: jetstream context is required")
	}
	if subject == "" {
		return nil, errors.New("audit: publish subject is required")
	}
	if bufferSize <= 0 {
		return nil, fmt.Errorf("audit: publish buffer size must be positive, got %d", bufferSize)
	}
	if logger == nil {
		logger = slog.Default()
	}

	r := &JetStreamRecorder{
		js:        js,
		subject:   subject,
		logger:    logger,
		buf:       make(chan Envelope, bufferSize),
		stallWait: defaultPublishStallWait,
		done:      make(chan struct{}),
		newID:     uuid.New,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}

	go r.run()
	return r, nil
}

// Record implements Recorder.
//
// It returns an error only for an envelope that could not be constructed at all (an
// unmarshallable payload), and even then the failure has already been logged. It
// never returns a transport error, because there is nothing a handler could usefully
// do with one: see the type doc.
func (r *JetStreamRecorder) Record(_ context.Context, e Event) error {
	env, err := NewEnvelope(e, r.newID(), r.now())
	if err != nil {
		// Nothing publishable exists, so fall back to what is known about the event.
		r.logger.Error("audit: build event envelope",
			slog.String("marker", AuditTransportFailureMarker),
			slog.String("reason", "payload_not_serializable"),
			slog.String("event_type", e.EventType),
			slog.String("action_status", e.ActionStatus),
			slog.String("error", err.Error()))
		r.countDrop()
		return err
	}

	select {
	case r.buf <- env:
		return nil
	default:
		// Buffer full: shed the event loudly rather than blocking the handler.
		r.fallback(env, "publish_buffer_full", nil)
		return nil
	}
}

// run is the single publishing goroutine. Publishing from one goroutine keeps the
// per-event ordering a caller would expect and means the client's async pending
// window is the only concurrency control needed.
func (r *JetStreamRecorder) run() {
	defer close(r.done)
	for env := range r.buf {
		r.publish(env)
	}
}

// publish sends one envelope and waits for its acknowledgement.
//
// It waits on the ack future rather than firing and forgetting: an unacknowledged
// publish is an event that is not in the stream, and the whole point of the fallback
// path is that such an event still lands somewhere durable. Serializing on the ack
// costs throughput that this workload does not need — the buffer absorbs bursts, and
// the signer batches on the other side.
func (r *JetStreamRecorder) publish(env Envelope) {
	data, err := json.Marshal(env)
	if err != nil {
		// Envelope fields are all plain scalars, so this is unreachable in practice;
		// it is handled rather than ignored so the event is still recoverable.
		r.fallback(env, "envelope_not_serializable", err)
		return
	}

	// WithMsgID engages JetStream's publisher-side duplicate window, which
	// suppresses the retry-after-timeout duplicate. It is not sufficient on its own —
	// the window is finite and the consumer is at-least-once — so the signer also
	// filters ids that are already persisted.
	future, err := r.js.PublishAsync(r.subject, data,
		jetstream.WithMsgID(env.EventID.String()),
		jetstream.WithStallWait(r.stallWait))
	if err != nil {
		r.fallback(env, "publish_rejected", err)
		return
	}

	select {
	case <-future.Ok():
	case ackErr := <-future.Err():
		r.fallback(env, "publish_not_acknowledged", ackErr)
	}
}

// fallback is the last-resort durability path: one structured error line carrying
// the whole envelope, including payload values, so the event can be reconstructed
// from the container log.
func (r *JetStreamRecorder) fallback(env Envelope, reason string, cause error) {
	r.countDrop()

	encoded, err := json.Marshal(env)
	if err != nil {
		// Degrade to the identifying fields rather than losing the event entirely.
		r.logger.Error("audit: event not published and envelope not serializable",
			slog.String("marker", AuditTransportFailureMarker),
			slog.String("reason", reason),
			slog.String("event_id", env.EventID.String()),
			slog.String("event_type", env.EventType),
			slog.String("action_status", env.ActionStatus))
		return
	}

	attrs := []any{
		slog.String("marker", AuditTransportFailureMarker),
		slog.String("reason", reason),
		slog.String("event_id", env.EventID.String()),
		slog.String("event_type", env.EventType),
		slog.String("subject", r.subject),
		slog.String("envelope", string(encoded)),
	}
	if cause != nil {
		attrs = append(attrs, slog.String("error", cause.Error()))
	}
	r.logger.Error("audit: event not published; recorded to log for manual recovery", attrs...)
}

// countDrop increments the shed-event counter.
func (r *JetStreamRecorder) countDrop() {
	r.mu.Lock()
	r.dropped++
	r.mu.Unlock()
}

// Dropped reports how many events took the fallback path over this process's
// lifetime. It backs the shutdown summary and is the number an operator needs when
// deciding whether a log-recovery replay is required. Any value above zero means the
// ledger has gaps.
func (r *JetStreamRecorder) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// Close drains the buffer, waits for outstanding acknowledgements, and reports how
// many events were shed.
//
// It must run *after* the HTTP server has stopped accepting requests: draining first
// would discard the audit events of the requests still in flight.
//
// A ctx deadline hit here is returned as an error rather than swallowed, because the
// undrained remainder is exactly the set of audit events that were lost on shutdown —
// the operator needs to know.
func (r *JetStreamRecorder) Close(ctx context.Context) error {
	r.closeOnce.Do(func() { close(r.buf) })

	select {
	case <-r.done:
	case <-ctx.Done():
		return fmt.Errorf("audit: shutdown timed out with %d envelopes still buffered: %w",
			len(r.buf), ctx.Err())
	}

	// The goroutine has stopped publishing; every ack it was waiting on has already
	// resolved, so this only guards against acks issued by a direct js user.
	select {
	case <-r.js.PublishAsyncComplete():
	case <-ctx.Done():
		return fmt.Errorf("audit: shutdown timed out with %d publishes unacknowledged: %w",
			r.js.PublishAsyncPending(), ctx.Err())
	}

	if dropped := r.Dropped(); dropped > 0 {
		r.logger.Error("audit: events were not published during this process lifetime",
			slog.String("marker", AuditTransportFailureMarker),
			slog.Uint64("dropped_events", dropped))
	}
	return nil
}
