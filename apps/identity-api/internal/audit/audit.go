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

// Event types emitted by the authentication and OAuth surfaces (Task 5.2). Every
// one of these is a security-relevant state change or a failed attempt at one, so
// each has an instrumented call site in internal/server.
//
// The ones listed in LedgerEventTypes must additionally carry Event.Security.
const (
	// EventLoginSucceeded records a completed WebAuthn assertion.
	EventLoginSucceeded = "auth.login.succeeded"
	// EventLoginFailed records a rejected authentication attempt. It frequently
	// has no resolvable account (unknown handle, malformed assertion), which is
	// why it is audit-only — see the LedgerEventTypes doc.
	EventLoginFailed = "auth.login.failed"

	// EventWebAuthnCredentialRegistered records a new passkey bound to an account.
	// Adding an authenticator is a permanent expansion of who can log in, so it is
	// ledgered.
	EventWebAuthnCredentialRegistered = "auth.webauthn.credential.registered" // #nosec G101 -- Public event name, not a credential.
	// EventWebAuthnCredentialDeleted records a passkey removal.
	EventWebAuthnCredentialDeleted = "auth.webauthn.credential.deleted" // #nosec G101 -- Public event name, not a credential.

	// EventMFATOTPEnabled records enrolment completion: TOTP is now required.
	EventMFATOTPEnabled = "auth.mfa.totp.enabled"
	// EventMFATOTPDisabled records MFA teardown, a security *downgrade* and one of
	// the highest-value events in the ledger.
	EventMFATOTPDisabled = "auth.mfa.totp.disabled"
	// EventMFAVerifyFailed records a rejected TOTP code.
	EventMFAVerifyFailed = "auth.mfa.verify_failed"

	// EventRecoveryCodeGenerated records a freshly minted recovery-code batch,
	// which invalidates every previously issued code.
	EventRecoveryCodeGenerated = "auth.recovery_code.generated"
	// EventRecoveryCodeConsumed records a single-use recovery code being spent.
	EventRecoveryCodeConsumed = "auth.recovery_code.consumed"
	// EventRecoveryCodeVerifyFailed records a rejected recovery code.
	EventRecoveryCodeVerifyFailed = "auth.recovery_code.verify_failed"

	// EventPhoneVerified records a phone number bound to the account as a factor.
	EventPhoneVerified = "auth.phone.verified"
	// EventPhoneRemoved records that binding being torn down.
	EventPhoneRemoved = "auth.phone.removed"

	// EventStepUpGranted records a successful step-up, which unlocks the
	// sensitive-operation endpoints for a bounded window.
	EventStepUpGranted = "auth.stepup.granted"
	// EventStepUpDenied records a refused step-up attempt.
	EventStepUpDenied = "auth.stepup.denied"

	// EventSessionLoggedOut records a user-initiated logout. Audit-only: ending
	// one's own session grants nothing and is not attribution evidence.
	EventSessionLoggedOut = "auth.session.logged_out"
	// EventSessionRevoked records a specific session being revoked.
	EventSessionRevoked = "auth.session.revoked"

	// EventTokenIssued records a successful token grant. Ledgered because
	// "which client held which scopes for this account, and when" is exactly the
	// question a lawful inquiry asks (threat-modeling.md R2).
	EventTokenIssued = "oauth.token.issued" // #nosec G101 -- Public event name, not a credential.
	// EventTokenDenied records a rejected token request.
	EventTokenDenied = "oauth.token.denied" // #nosec G101 -- Public event name, not a credential.

	// EventRTRBreach records a refresh-token-rotation replay: a used refresh token
	// was presented again, which means it leaked. The whole family is revoked.
	EventRTRBreach = "security.rtr_breach"
)

// EventGRPCAccessDenied records a rejected workload authentication or method
// authorization check. It is audit-only: a service identity is not an account.
const EventGRPCAccessDenied = "grpc.access.denied"

// Event types emitted by the audit pipeline about itself (Task 5.2).
const (
	// EventPipelineUndecodable records a stream message the signing consumer could
	// not decode. The signer synthesizes this record, chains it normally, and only
	// then discards the original, so the loss is itself in the tamper-evident log
	// rather than being a silent gap.
	EventPipelineUndecodable = "audit.pipeline.undecodable"
)

// Event types emitted by the administrative and lawful-request surfaces
// (Task 5.3, docs/api-design.md §1.7).
//
// Every one of these is Class C — administrative and lawful-request handling
// (docs/compliance-and-data-governance.md §8). None of them may ever be added
// to LedgerEventTypes, and TestAdminAndLegalEventsAreNeverLedgered enforces
// that. The reason is structural rather than stylistic:
// security_event_ledger.account_ref is the *subject* of an event, but for these
// events the account that matters is the *actor* — the administrator. Ledgering
// one would file an admin's action under the subject's attribution history and
// let it survive that subject's erasure, which is precisely backwards.
//
// Payloads carry only opaque action/hold references, outcomes, status changes,
// and bounded disclosure scope. Legal narratives belong in restricted encrypted
// context, not here. Raw identities and reusable identity blind indexes must
// never enter these long-lived Class C payloads.
const (
	// EventAdminUserStatusChanged records a moderator moving an account between
	// active, suspended, and banned.
	EventAdminUserStatusChanged = "admin.user.status_changed"
	// EventAdminRoleAssigned records a role grant. This is privilege escalation
	// by definition and is the event most worth alerting on.
	EventAdminRoleAssigned = "admin.role.assigned"
	// EventAdminAuditLogsQueried records a DPO reading the audit
	// log. Reading the tamper-evident log is itself an auditable act; without
	// this, the one surface that observes everything would observe nothing about
	// its own use.
	EventAdminAuditLogsQueried = "admin.audit_logs.queried"
	// EventAdminChainVerified records a chain-verification run. It must carry
	// verified, checked, and broken_at_seq: a detected break is the single
	// highest-severity signal this system produces, and it belongs in the
	// tamper-evident log itself rather than only in an HTTP response the caller
	// is free to discard.
	EventAdminChainVerified = "admin.chain.verified"
	// EventAdminAccessDenied records a rejected authorization check on an admin
	// route. Raised by rbac.RequirePermission on every 403; it is the tripwire
	// for a compromised or over-curious admin account.
	EventAdminAccessDenied = "admin.access.denied"

	// EventLegalHoldApplied records a Legal Hold being placed on an account_ref.
	EventLegalHoldApplied = "legal.hold.applied"
	// EventLegalHoldReleased records a hold being lifted, which re-exposes the
	// subject to every retention timer the hold was suspending.
	EventLegalHoldReleased = "legal.hold.released"
	// EventLegalPreservationRecorded records a freeze-before-order preservation
	// request (compliance §8), implemented as an immediate hold.
	EventLegalPreservationRecorded = "legal.preservation.recorded"
	// EventLegalInquiryLookup records a blind-index attribution lookup. The
	// payload carries bounded disclosure scope, never the identifier or index.
	EventLegalInquiryLookup = "legal.inquiry.lookup"
	// EventLegalLedgerPurged records a bounded Class B maintenance commit.
	EventLegalLedgerPurged = "legal.ledger.purged"
	// EventLegalLedgerPurgeSkipped records an aggregate held/ineligible outcome.
	EventLegalLedgerPurgeSkipped = "legal.ledger.purge_skipped"
)

// LedgerEventTypes is the declared set of event types that MUST carry
// Event.Security, i.e. that must produce a security_event_ledger row in addition
// to the mvp_audit_logs row. Membership is what makes an event survive account
// deletion, so it is a compliance statement, not a convenience.
//
// Failures are deliberately absent even when their success counterpart is present.
// security_event_ledger.account_ref is NOT NULL and must always be users.id, and a
// failed attempt frequently has no resolvable account: an unknown WebAuthn handle,
// a bad client_id, a malformed assertion. Inventing an account_ref to satisfy the
// column would fabricate attribution evidence, and skipping only the unresolvable
// subset would make ledger coverage depend on how the attempt happened to fail.
// Failures are therefore recorded as audit rows whose payload carries the
// non-identifying facts (identifier_present, ip_subnet, reason) instead.
//
// The signer treats a mismatch in either direction as an error worth logging: a
// member arriving without Security, or Security arriving with a nil AccountRef.
// Neither is silently dropped — see internal/audit/signer.
var LedgerEventTypes = map[string]struct{}{
	EventLoginSucceeded:               {},
	EventWebAuthnCredentialRegistered: {},
	EventWebAuthnCredentialDeleted:    {},
	EventMFATOTPEnabled:               {},
	EventMFATOTPDisabled:              {},
	EventRecoveryCodeGenerated:        {},
	EventRecoveryCodeConsumed:         {},
	EventPhoneVerified:                {},
	EventPhoneRemoved:                 {},
	EventStepUpGranted:                {},
	EventTokenIssued:                  {},
	EventRTRBreach:                    {},
}

// IsLedgerEventType reports whether an event type must carry Security.
func IsLedgerEventType(eventType string) bool {
	_, ok := LedgerEventTypes[eventType]
	return ok
}

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

// SignerActorSPIFFEID identifies records the audit signing worker raises about the
// pipeline itself (EventPipelineUndecodable). It is distinct from
// SystemActorSPIFFEID so a self-report by the signer can never be confused with a
// purge decision when reading the ledger.
const SignerActorSPIFFEID = "system://identity/audit-signer"

// LedgerRetentionActorSPIFFEID separates Class B expiry from account deletion.
const LedgerRetentionActorSPIFFEID = "system://identity/security-ledger-purge"

// APIActorSPIFFEID identifies events raised by the identity API process while
// serving a request. ActorID carries the authenticated user; this states which
// workload asserted it.
const APIActorSPIFFEID = "system://identity/identity-api"

// SecurityContext marks an Event as a Class B security event and carries the
// attributes that exist only on security_event_ledger.
//
// A non-nil value is the call site's explicit declaration that this action must
// remain attributable after the account is erased (threat-modeling.md R2). That is
// a deliberate, auditable choice, which is why it is a typed struct rather than
// well-known Payload keys: a typo in a map key would silently destroy attribution
// evidence with no compile-time signal.
//
// It must never carry raw PII. The producer captures identity_blind_index before
// asynchronous publication while attribution material is available. The signer
// retains live-account lookup only for older queued envelopes and degraded capture.
type SecurityContext struct {
	// AccountRef is the subject of the event and is always users.id (tasks.md:54).
	// It is required: security_event_ledger.account_ref is NOT NULL, and it is the
	// join key legal holds and lawful-inquiry lookups use, so any other derivation
	// would decouple holds from the rows they are meant to freeze.
	AccountRef uuid.UUID
	// ClientID is the OAuth client involved, when the event happened through one.
	ClientID string
	// Scope is the granted scope string, for token events.
	Scope string
	// DeviceFingerprint is the caller-supplied device identifier, when present.
	DeviceFingerprint string
	// IdentityBlindIndex is captured synchronously, never copied to Payload.
	IdentityBlindIndex *string
}

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
	//
	// Task 5.2 makes this load-bearing rather than belt-and-braces: the JetStream
	// publisher forwards payload *values* verbatim, and its transport-failure
	// fallback writes them to the process log.
	Payload map[string]any
	// Security, when non-nil, declares this a Class B security event that must also
	// be written to security_event_ledger and must survive account deletion. Nil
	// means audit-only. See SecurityContext and LedgerEventTypes.
	Security *SecurityContext
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
