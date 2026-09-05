// Package natsjs owns the NATS connection and the JetStream stream/consumer
// definitions for the audit pipeline.
//
// It is a separate package from internal/audit so that provisioning is separable
// from publishing. Only the signing worker calls the Ensure* functions; the API
// process connects and publishes and never declares topology. That asymmetry is
// deliberate: CreateOrUpdateStream is authoritative, so an API instance rolled out
// with a stale or misconfigured value would silently rewrite the stream's limits
// underneath the worker. One writer of the definition, many publishers.
package natsjs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// StreamOptions is the audit stream's shape.
type StreamOptions struct {
	// Name is the stream name, e.g. IDENTITY_AUDIT.
	Name string
	// Subjects are the subjects bound to the stream. A wildcard is used so future
	// audit subjects do not need a topology change.
	Subjects []string
	// MaxBytes caps on-disk size. It is required: see the Discard note in
	// EnsureStream.
	MaxBytes int64
	// Duplicates is the publisher-side duplicate-suppression window keyed on
	// Nats-Msg-Id.
	Duplicates time.Duration
}

// ConsumerOptions is the signing consumer's shape.
type ConsumerOptions struct {
	// Durable is the consumer name. It must be durable: an ephemeral consumer would
	// lose its ack state on restart and re-deliver the entire stream.
	Durable string
	// FilterSubject narrows delivery to the audit subject.
	FilterSubject string
	// AckWait is how long the server waits for an ack before redelivering. It must
	// comfortably exceed the time to hash and COPY one full batch. It is also the
	// base of the redelivery ladder (see redeliveryBackOff), because nats-server
	// derives the effective ack deadline from BackOff[0].
	AckWait time.Duration
	// MaxAckPending bounds in-flight unacked messages.
	MaxAckPending int
	// MaxDeliver bounds redelivery attempts before the consumer quarantines the
	// message.
	MaxDeliver int
}

// redeliveryBackOff staggers redelivery of a batch the signer could not commit,
// giving a database that is failing over or saturated time to recover instead of
// spinning at AckWait.
//
// The first interval MUST equal ackWait, and every interval MUST be >= ackWait.
// nats-server does not treat BackOff and AckWait as independent knobs: when BackOff
// is set it overwrites AckWait with BackOff[0]. A hardcoded ladder starting below
// AckWait therefore silently shortens the ack deadline, and the server begins
// redelivering messages that the signer is still legitimately holding while it
// accumulates a batch (up to FlushInterval, or BatchTimeout on a slow commit). Those
// redeliveries burn MaxDeliver attempts on healthy traffic, and once exhausted the
// message is quarantined — dropping audit records, which for an append-only chain is
// the one failure mode that must never happen. Deriving the ladder from ackWait keeps
// the deadline the caller asked for.
//
// The slice is shorter than a typical MaxDeliver on purpose: JetStream reuses the
// final interval for all remaining attempts, so this expresses "back off to a
// multiple of the ack deadline and stay there".
func redeliveryBackOff(ackWait time.Duration) []time.Duration {
	return []time.Duration{
		ackWait,
		2 * ackWait,
		4 * ackWait,
		8 * ackWait,
	}
}

// Connect dials NATS and returns both the raw connection and a JetStream context.
//
// The connection is configured to retry forever rather than to give up. For the API
// process a permanent reconnect loop is strictly better than a dead client: the
// publisher's fallback path keeps events in the log while NATS is away, and the
// pipeline resumes by itself once it returns. For the signer, exiting on a blip
// would just hand the same decision to the orchestrator's restart policy.
//
// The caller owns the returned connection and must Drain or Close it.
func Connect(ctx context.Context, url, name string, logger *slog.Logger) (*nats.Conn, jetstream.JetStream, error) {
	if url == "" {
		return nil, nil, errors.New("natsjs: url is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := []nats.Option{
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.ReconnectJitter(500*time.Millisecond, 2*time.Second),
		// Reconnect buffering is disabled: a publish that lands in the client's
		// in-memory reconnect buffer looks successful but is lost if the process
		// exits before reconnecting. Failing the publish routes it into the audit
		// publisher's log fallback, which is recoverable.
		nats.ReconnectBufSize(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			attrs := []any{slog.String("nats_name", name)}
			if err != nil {
				attrs = append(attrs, slog.String("error", err.Error()))
			}
			logger.Error("natsjs: disconnected from NATS; audit transport is degraded", attrs...)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Warn("natsjs: reconnected to NATS",
				slog.String("nats_name", name),
				slog.String("url", nc.ConnectedUrl()))
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			logger.Warn("natsjs: NATS connection closed", slog.String("nats_name", name))
		}),
		nats.ErrorHandler(func(_ *nats.Conn, sub *nats.Subscription, err error) {
			attrs := []any{slog.String("nats_name", name), slog.String("error", err.Error())}
			if sub != nil {
				attrs = append(attrs, slog.String("subject", sub.Subject))
			}
			logger.Error("natsjs: asynchronous NATS error", attrs...)
		}),
	}

	// Bound only the initial dial: after that the reconnect loop takes over, and the
	// request context typically outlives startup.
	if deadline, ok := ctx.Deadline(); ok {
		if wait := time.Until(deadline); wait > 0 {
			opts = append(opts, nats.Timeout(wait))
		}
	}

	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("natsjs: connect to NATS: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("natsjs: create JetStream context: %w", err)
	}
	return nc, js, nil
}

// EnsureStream idempotently creates or updates the audit stream.
//
// Design notes, each of which is a correctness choice rather than a default:
//
//   - Retention is WorkQueue: a record is removed once the signer acks it, because
//     PostgreSQL is the durable ledger and the stream is only a hand-off buffer.
//   - There is deliberately no MaxAge. Under WorkQueue retention MaxAge deletes
//     un-acked messages once they are old enough, which for this stream means
//     silently destroying audit records during any signer outage longer than the
//     window. Age-based expiry is exactly the failure mode a tamper-evident ledger
//     must not have.
//   - Discard is DiscardNew, so a full stream rejects the *publish* instead of
//     evicting the oldest un-processed record. The rejection surfaces in the
//     publisher's fallback log, which is loud and recoverable; eviction would be
//     silent and permanent. This is also why MaxBytes is required: with an unbounded
//     stream the disk fills and the server's behaviour, not ours, decides what is
//     lost.
//   - Storage is File: memory storage loses the backlog on a NATS restart.
//   - Replicas is 1 because the MVP runs a single NATS node (see the ClickHouse
//     exclusion in the same MVP resource budget). This is the pipeline's one
//     accepted single point of failure, and it is mitigated by the publisher's log
//     fallback rather than hidden.
func EnsureStream(ctx context.Context, js jetstream.JetStream, opts StreamOptions) (jetstream.Stream, error) {
	if js == nil {
		return nil, errors.New("natsjs: jetstream context is required")
	}
	if opts.Name == "" {
		return nil, errors.New("natsjs: stream name is required")
	}
	if len(opts.Subjects) == 0 {
		return nil, errors.New("natsjs: stream subjects are required")
	}
	if opts.MaxBytes <= 0 {
		return nil, fmt.Errorf("natsjs: stream max bytes must be positive, got %d", opts.MaxBytes)
	}

	cfg := jetstream.StreamConfig{
		Name:        opts.Name,
		Description: "Identity audit and security events awaiting cryptographic signing (Task 5.2)",
		Subjects:    opts.Subjects,
		Retention:   jetstream.WorkQueuePolicy,
		Storage:     jetstream.FileStorage,
		Discard:     jetstream.DiscardNew,
		MaxBytes:    opts.MaxBytes,
		Duplicates:  opts.Duplicates,
		Replicas:    1,
		// The stream is a hand-off buffer, not an archive: nothing should be able to
		// remove records except the consumer acking them.
		DenyDelete: true,
		DenyPurge:  true,
	}

	stream, err := js.CreateOrUpdateStream(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("natsjs: create or update stream %q: %w", opts.Name, err)
	}
	return stream, nil
}

// EnsureConsumer idempotently creates or updates the signing consumer.
//
// It is a pull consumer with explicit acks: the signer decides when it is ready for
// the next batch (it must hold the chain tip and one database transaction), which a
// push consumer's server-driven delivery cannot express.
func EnsureConsumer(ctx context.Context, js jetstream.JetStream, streamName string, opts ConsumerOptions) (jetstream.Consumer, error) {
	if js == nil {
		return nil, errors.New("natsjs: jetstream context is required")
	}
	if streamName == "" {
		return nil, errors.New("natsjs: stream name is required")
	}
	if opts.Durable == "" {
		return nil, errors.New("natsjs: durable consumer name is required")
	}
	if opts.MaxAckPending <= 0 {
		return nil, fmt.Errorf("natsjs: max ack pending must be positive, got %d", opts.MaxAckPending)
	}
	if opts.MaxDeliver <= 0 {
		return nil, fmt.Errorf("natsjs: max deliver must be positive, got %d", opts.MaxDeliver)
	}
	// Validated rather than defaulted: AckWait doubles as the base of the redelivery
	// ladder below, so a zero value would hand nats-server a zero-length ack deadline.
	if opts.AckWait <= 0 {
		return nil, fmt.Errorf("natsjs: ack wait must be positive, got %s", opts.AckWait)
	}

	cfg := jetstream.ConsumerConfig{
		Durable:       opts.Durable,
		Name:          opts.Durable,
		Description:   "Single-threaded audit chain signer; sole writer of both hash chains",
		FilterSubject: opts.FilterSubject,
		// DeliverAll: on first start the signer must consume the whole backlog. Any
		// other start policy would skip records that were published before it existed.
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       opts.AckWait,
		MaxDeliver:    opts.MaxDeliver,
		BackOff:       redeliveryBackOff(opts.AckWait),
		MaxAckPending: opts.MaxAckPending,
		ReplayPolicy:  jetstream.ReplayInstantPolicy,
		// InactiveThreshold is left unset so the durable consumer — and with it the
		// backlog position — survives an arbitrarily long signer outage.
	}

	consumer, err := js.CreateOrUpdateConsumer(ctx, streamName, cfg)
	if err != nil {
		return nil, fmt.Errorf("natsjs: create or update consumer %q on stream %q: %w", opts.Durable, streamName, err)
	}
	return consumer, nil
}
