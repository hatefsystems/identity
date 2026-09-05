package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
)

// AuditConfig holds the asynchronous audit pipeline's transport and batching
// policy (Task 5.2): where events are published, how the signing worker drains
// them, and how long ledger rows must be retained.
//
// Nothing here is secret. The one genuinely sensitive input to the pipeline is the
// blind-index pepper, which stays in CryptoConfig because the signing worker is the
// only process that needs it.
type AuditConfig struct {
	// NATSURL is the NATS server URL. It is required outside development; an empty
	// value in development selects the LogRecorder fallback so the service still
	// boots with no message bus running.
	NATSURL string

	// StreamName is the JetStream stream holding unsigned events.
	StreamName string
	// Subject is the subject events are published to. It must live under
	// StreamSubjectPattern, or publishes would land on no stream at all.
	Subject string
	// ConsumerName is the durable pull consumer the signing worker binds to.
	// Changing it starts a *new* consumer at the beginning of the stream, which is a
	// deliberate replay, not a rename.
	ConsumerName string

	// PublishBuffer is the depth of the publisher's in-process channel. It is the
	// burst absorber between request handlers and the network: once it is full,
	// events take the log-fallback path rather than blocking the handler.
	PublishBuffer int

	// BatchSize is how many messages the signer pulls and COPYs at once.
	BatchSize int
	// FlushInterval bounds how long a partially filled batch waits, so a quiet
	// system still persists events promptly instead of holding them until BatchSize
	// is reached.
	FlushInterval time.Duration

	// StreamMaxBytes caps the stream's on-disk size. It is a hard requirement of the
	// DiscardNew policy: a bounded stream rejects publishes (loudly, into the log
	// fallback) instead of letting the server decide what to evict.
	StreamMaxBytes int64
	// DuplicateWindow is JetStream's publisher-side duplicate-suppression window,
	// keyed on the event id carried as Nats-Msg-Id.
	//
	// It is intentionally not environment-tunable. It only needs to outlive a
	// publish retry, and the durable protection against duplicates is the signer's
	// pre-COPY existence filter — so exposing this would offer a knob that looks like
	// it controls correctness while the real guarantee lives elsewhere.
	DuplicateWindow time.Duration

	// AckWait is how long JetStream waits for an ack before redelivering. It must
	// exceed the time to hash and COPY one full batch, or the server will redeliver
	// work that is still committing.
	AckWait time.Duration
	// MaxDeliver bounds redelivery attempts. On the final failure the signer
	// quarantines the message: it writes a synthesized audit record describing the
	// loss and then terminates the original.
	MaxDeliver int

	// LedgerRetention sets security_event_ledger.retain_until relative to each
	// event's occurrence time.
	LedgerRetention time.Duration
}

// StreamSubjectPattern is the subject space bound to the audit stream. A wildcard
// is used so a future audit subject needs no topology change, while still keeping
// unrelated traffic (identity.user.*, Task 6.3) on its own stream.
const StreamSubjectPattern = "identity.audit.>"

// auditSubjectPrefix is the literal portion of StreamSubjectPattern that a
// configured subject must start with.
const auditSubjectPrefix = "identity.audit."

// Environment variable names for the audit pipeline.
const (
	EnvNATSURL                 = "NATS_URL"
	EnvAuditStreamName         = "AUDIT_STREAM_NAME"
	EnvAuditSubject            = "AUDIT_SUBJECT"
	EnvAuditConsumerName       = "AUDIT_CONSUMER_NAME"
	EnvAuditPublishBuffer      = "AUDIT_PUBLISH_BUFFER"
	EnvAuditBatchSize          = "AUDIT_BATCH_SIZE"
	EnvAuditFlushInterval      = "AUDIT_FLUSH_INTERVAL"
	EnvAuditStreamMaxBytes     = "AUDIT_STREAM_MAX_BYTES"
	EnvAuditAckWait            = "AUDIT_ACK_WAIT"
	EnvAuditMaxDeliver         = "AUDIT_MAX_DELIVER"
	EnvSecurityLedgerRetention = "SECURITY_LEDGER_RETENTION"
)

// Audit pipeline defaults. The batch size and flush interval come from
// docs/data-architecture.md §4.2 ("every 5s or 1000 records").
const (
	defaultAuditStreamName      = "IDENTITY_AUDIT"
	defaultAuditSubject         = "identity.audit.logs"
	defaultAuditConsumerName    = "audit-signer"
	defaultAuditPublishBuffer   = 4096
	defaultAuditBatchSize       = 1000
	defaultAuditFlushInterval   = 5 * time.Second
	defaultAuditStreamMaxBytes  = int64(512 << 20) // 512 MiB
	defaultAuditDuplicateWindow = 2 * time.Minute
	defaultAuditAckWait         = 60 * time.Second
	defaultAuditMaxDeliver      = 5

	// defaultSecurityLedgerRetention is ~12 months, the midpoint of the mandated
	// range.
	defaultSecurityLedgerRetention = 8760 * time.Hour
	// MinSecurityLedgerRetention and MaxSecurityLedgerRetention bracket the legally
	// defensible retention window for security events: 6 to 18 months
	// (docs/compliance-and-data-governance.md §3, §7).
	//
	// Both ends are enforced because both are compliance failures, in opposite
	// directions. Too short destroys evidence the platform is obliged to be able to
	// produce; too long keeps request-linkable data past its lawful purpose, which is
	// a data-minimisation violation rather than a harmless surplus. Neither is a
	// performance tunable, so neither is silently clamped.
	MinSecurityLedgerRetention = 4320 * time.Hour  // ~6 months
	MaxSecurityLedgerRetention = 13140 * time.Hour // ~18 months
)

// HasNATS reports whether a message bus is configured. When false the caller must
// fall back to audit.LogRecorder; LoadAudit guarantees this can only happen in
// development.
func (c AuditConfig) HasNATS() bool { return c.NATSURL != "" }

// StreamSubjects returns the subject list for the stream definition.
func (c AuditConfig) StreamSubjects() []string { return []string{StreamSubjectPattern} }

// MaxAckPending is the consumer's in-flight limit: two batches' worth, so the
// server can stage the next batch while the current one commits without ever
// letting more than that go un-acked.
//
// It is derived rather than configured because the only correct value is a function
// of BatchSize — a smaller number would stall the consumer mid-batch, and a larger
// one buys nothing for a single-threaded writer.
func (c AuditConfig) MaxAckPending() int { return 2 * c.BatchSize }

// LoadAudit builds an AuditConfig from environment variables, applying the
// documented defaults and failing fast on a malformed or out-of-policy value.
//
// environment is used for exactly one decision: whether a missing NATS_URL is a
// development convenience or a misconfiguration. Everything else is identical
// across environments, because an audit pipeline that batches or retains
// differently in staging is not a rehearsal of production.
func LoadAudit(environment string) (AuditConfig, error) {
	cfg := AuditConfig{
		NATSURL:         strings.TrimSpace(getEnv(EnvNATSURL, "")),
		StreamName:      getEnv(EnvAuditStreamName, defaultAuditStreamName),
		Subject:         getEnv(EnvAuditSubject, defaultAuditSubject),
		ConsumerName:    getEnv(EnvAuditConsumerName, defaultAuditConsumerName),
		DuplicateWindow: defaultAuditDuplicateWindow,
	}

	isDev := environment == "development"
	if cfg.NATSURL == "" && !isDev {
		return AuditConfig{}, fmt.Errorf("config: %s is required outside development", EnvNATSURL)
	}

	if !strings.HasPrefix(cfg.Subject, auditSubjectPrefix) {
		// Publishing outside the stream's subject space would make every event fail
		// with "no responders" and route straight to the log fallback — a working
		// service with an empty ledger, which is the worst possible failure mode here.
		return AuditConfig{}, fmt.Errorf(
			"config: %s %q must start with %q so it is bound to the %s stream",
			EnvAuditSubject, cfg.Subject, auditSubjectPrefix, StreamSubjectPattern)
	}

	var err error
	if cfg.PublishBuffer, err = getEnvPositiveInt(
		EnvAuditPublishBuffer, defaultAuditPublishBuffer); err != nil {
		return AuditConfig{}, err
	}
	if cfg.BatchSize, err = getEnvPositiveInt(EnvAuditBatchSize, defaultAuditBatchSize); err != nil {
		return AuditConfig{}, err
	}
	if cfg.FlushInterval, err = getEnvDuration(
		EnvAuditFlushInterval, defaultAuditFlushInterval); err != nil {
		return AuditConfig{}, err
	}
	if cfg.StreamMaxBytes, err = getEnvPositiveInt64(
		EnvAuditStreamMaxBytes, defaultAuditStreamMaxBytes); err != nil {
		return AuditConfig{}, err
	}
	if cfg.AckWait, err = getEnvDuration(EnvAuditAckWait, defaultAuditAckWait); err != nil {
		return AuditConfig{}, err
	}
	if cfg.MaxDeliver, err = getEnvPositiveInt(EnvAuditMaxDeliver, defaultAuditMaxDeliver); err != nil {
		return AuditConfig{}, err
	}
	if cfg.LedgerRetention, err = getEnvDuration(
		EnvSecurityLedgerRetention, defaultSecurityLedgerRetention); err != nil {
		return AuditConfig{}, err
	}
	if cfg.LedgerRetention < MinSecurityLedgerRetention || cfg.LedgerRetention > MaxSecurityLedgerRetention {
		return AuditConfig{}, fmt.Errorf(
			"config: %s %v is outside the mandated %v-%v retention window",
			EnvSecurityLedgerRetention, cfg.LedgerRetention,
			MinSecurityLedgerRetention, MaxSecurityLedgerRetention)
	}

	// AckWait must cover a batch's whole life: the time it spends waiting to fill
	// (up to FlushInterval) plus the time it spends committing (bounded by
	// signer.BatchTimeout). Below that sum the server redelivers batches that are
	// still in flight, which manifests as duplicate work and a stalling consumer
	// rather than as a configuration error — so it is rejected here instead.
	if minAckWait := cfg.FlushInterval + signer.BatchTimeout; cfg.AckWait <= minAckWait {
		return AuditConfig{}, fmt.Errorf(
			"config: %s %v must exceed %s + signer batch timeout (%v) so an in-flight batch is not redelivered",
			EnvAuditAckWait, cfg.AckWait, EnvAuditFlushInterval, minAckWait)
	}

	return cfg, nil
}

// getEnvPositiveInt64 parses a positive 64-bit integer environment variable,
// returning fallback when unset/empty and an error when the value is unparseable or
// not positive. It exists because byte-size limits do not fit the int-width
// assumption of getEnvPositiveInt on 32-bit builds.
func getEnvPositiveInt64(key string, fallback int64) (int64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s %q: %w", key, raw, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("config: %s %d must be positive", key, v)
	}
	return v, nil
}
