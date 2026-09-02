// Package audit is the seam through which security-relevant events leave the
// application. It exists so a caller can record "what happened" without knowing
// where the record eventually lands.
//
// Task 5.1 ships one implementation, LogRecorder, which writes structured slog
// lines. Task 5.2 replaces it with a NATS JetStream publisher feeding the
// single-threaded signing consumer that owns mvp_audit_logs and
// security_event_ledger. Both sit behind Recorder, so no call site changes.
//
// # Two invariants Task 5.2 must not break
//
// 1. A Recorder MUST NOT compute or persist a chain_hash.
//
// The ledger's tamper evidence is chain_hash(N) = SHA-256(chain_hash(N-1) ||
// serialize(record(N))). That recurrence is only well defined if exactly one
// writer assigns positions in the chain. Recorders are called from HTTP handlers
// and from the purge worker — concurrently, in separate processes — so any
// chain_hash they computed would be racing over the same predecessor and the
// ledger would stop verifying. Only 5.2's single-threaded signing consumer may
// compute it. Everything upstream of that consumer emits unchained events.
//
// 2. Task 5.2's canonical serialize(record) MUST exclude user_id.
//
// mvp_audit_logs.user_id is ON DELETE SET NULL (migration 00001), and Task 5.1's
// hard-delete is what triggers it: after a subject is purged, every audit row that
// referenced them has user_id = NULL while the rest of the row is byte-identical.
// If user_id were inside the hashed serialization, the stored chain_hash would no
// longer match the recomputed one for those rows, so
// ListAuditLogsForChainVerification would report tampering for every purged
// subject — turning a correct GDPR erasure into a permanent integrity alarm.
// Attribution after deletion is the security_event_ledger's job (it has no FK to
// users and stores a stable account_ref), not the chained payload's.
package audit

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// Event types emitted by the GDPR privacy flows (Task 5.1). They are dotted,
// lowercase, and namespaced by subsystem so the ledger can be filtered by prefix.
const (
	// EventDeletionRequested records an accepted "Right to be Forgotten" request:
	// the account is now pending_deletion and the grace window has opened.
	EventDeletionRequested = "privacy.deletion.requested"
	// EventDeletionReclaimed records a successful reclaim inside the grace window.
	EventDeletionReclaimed = "privacy.deletion.reclaimed"
	// EventDeletionReclaimFailed records a reclaim attempt that failed its factor
	// check, including the attempt that exhausts the cap and retires the request.
	EventDeletionReclaimFailed = "privacy.deletion.reclaim_failed"
	// EventDeletionPurged records a committed hard delete.
	EventDeletionPurged = "privacy.deletion.purged"
	// EventDeletionSkippedLegalHold records a subject the purge worker left in
	// place because an active Legal Hold outranks the retention timer
	// (compliance-and-data-governance.md §6).
	EventDeletionSkippedLegalHold = "privacy.deletion.skipped_legal_hold"
	// EventDeletionPurgeFailed records a subject the purge worker could not decide
	// on — most importantly a Legal Hold check that errored. The worker skips
	// rather than purges, so this event is the only trace of that decision.
	EventDeletionPurgeFailed = "privacy.deletion.purge_failed"
)

// Action statuses. They mirror mvp_audit_logs.action_status, which is a free-text
// VARCHAR, so pinning the vocabulary here keeps queries over it meaningful.
const (
	// StatusSuccess marks an operation that completed as intended.
	StatusSuccess = "success"
	// StatusFailure marks an operation that was refused or could not complete.
	StatusFailure = "failure"
)

// SystemActorSPIFFEID identifies an event raised by a background worker rather
// than by a request-bound user or service call. The purge worker has no SPIFFE
// identity of its own yet (it is a CronJob, not a mesh workload), so it declares
// itself explicitly instead of leaving actor_spiffe_id empty and indistinguishable
// from a missing value.
const SystemActorSPIFFEID = "system://identity/purge-worker"

// Event is one security-relevant occurrence, shaped to match the columns of
// mvp_audit_logs so the Task 5.2 consumer can persist it without a translation
// layer. It deliberately has no chain_hash field: see the package doc.
type Event struct {
	// EventType is the dotted event name, e.g. EventDeletionPurged.
	EventType string
	// ActionStatus is StatusSuccess or StatusFailure.
	ActionStatus string
	// ActorID is who performed the action. For a self-service request it is the
	// subject's own ID; for a background worker it is uuid.Nil.
	ActorID uuid.UUID
	// ActorSPIFFEID identifies the calling workload. Background workers use
	// SystemActorSPIFFEID.
	ActorSPIFFEID string
	// SubjectID is the account the action was performed *on*, when that differs
	// from the actor or when the actor is a worker. It is a pointer because
	// mvp_audit_logs.user_id is nullable, and because a hard delete's event must
	// survive the row it points at (ON DELETE SET NULL).
	SubjectID *uuid.UUID
	// ClientIP is the resolved client address, or empty for a worker.
	ClientIP string
	// UserAgent is the client device string, or empty for a worker.
	UserAgent string
	// Payload carries event-specific, PII-masked context. It must never contain a
	// token, a passcode, an email address, a phone number, or any other Class A
	// value: these records outlive the account (see the package doc), so anything
	// put here escapes the "Right to be Forgotten" erasure entirely.
	Payload map[string]any
}

// Recorder persists an audit Event.
//
// Implementations must not fail the caller's business operation: an audit
// transport being down is a monitoring problem, whereas refusing to complete a
// deletion because of it would be a compliance failure. Callers therefore log a
// Record error and continue.
type Recorder interface {
	Record(ctx context.Context, e Event) error
}

// LogRecorder is a Recorder that writes structured slog lines, mirroring
// smsotp.LogSender. It is the Task 5.1 implementation and remains useful for
// development and for the purge worker's own stdout trail after Task 5.2 lands.
//
// Like LogSender it is redaction-first: it emits the event's shape and the
// payload keys, never the payload values, so a caller that accidentally puts a
// token or an email address into Payload cannot leak it through the log. That is
// belt-and-braces on top of the Event.Payload contract, not a licence to ignore
// it — the Task 5.2 publisher will forward values verbatim.
type LogRecorder struct {
	logger *slog.Logger
}

// NewLogRecorder constructs a LogRecorder. A nil logger falls back to
// slog.Default.
func NewLogRecorder(logger *slog.Logger) *LogRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogRecorder{logger: logger}
}

// Record implements Recorder by emitting one structured line per event.
//
// Only non-sensitive identifiers are logged: the event type and status, the actor
// and subject UUIDs (which are internal primary keys, never public identifiers),
// and the *names* of the payload fields. Client IP and user agent are omitted
// entirely — they are request-linkable data whose home is the ledger, not the
// process log.
func (r *LogRecorder) Record(_ context.Context, e Event) error {
	attrs := []any{
		slog.String("event_type", e.EventType),
		slog.String("action_status", e.ActionStatus),
		slog.String("actor_spiffe_id", e.ActorSPIFFEID),
	}
	if e.ActorID != uuid.Nil {
		attrs = append(attrs, slog.String("actor_id", e.ActorID.String()))
	}
	if e.SubjectID != nil {
		attrs = append(attrs, slog.String("subject_id", e.SubjectID.String()))
	}
	if len(e.Payload) > 0 {
		attrs = append(attrs, slog.Any("payload_fields", payloadFields(e.Payload)))
	}
	r.logger.Info("audit event recorded (payload values redacted)", attrs...)
	return nil
}

// payloadFields returns the sorted key names of a payload so a log line reports
// which context was attached without reproducing any of it.
func payloadFields(payload map[string]any) []string {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

// sortStrings is an insertion sort over the handful of payload keys an event
// carries. It avoids pulling in "sort" for a slice that is never longer than a
// few entries, and keeps the log line's field order deterministic so log-based
// assertions and diffing stay stable.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
