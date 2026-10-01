package audit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// envelopeTestEvent returns a fully populated Event including a security context.
func envelopeTestEvent() (Event, uuid.UUID, uuid.UUID) {
	actor := uuid.MustParse("6f1d3c2b-0000-4000-8000-000000000002")
	subject := uuid.MustParse("6f1d3c2b-0000-4000-8000-000000000003")
	return Event{
		EventType:     EventLoginSucceeded,
		ActionStatus:  StatusSuccess,
		ActorID:       actor,
		ActorSPIFFEID: APIActorSPIFFEID,
		SubjectID:     &subject,
		ClientIP:      "203.0.113.5",
		UserAgent:     "Mozilla/5.0",
		Payload:       map[string]any{"method": "webauthn", "uv": true},
		Security: &SecurityContext{
			AccountRef:        subject,
			ClientID:          "search-engine",
			Scope:             "openid profile",
			DeviceFingerprint: "device-1",
		},
	}, actor, subject
}

func TestNewEnvelopeStampsSchemaVersionAndUTC(t *testing.T) {
	t.Parallel()

	tehran := time.FixedZone("+0330", int((3*time.Hour + 30*time.Minute).Seconds()))
	e, _, _ := envelopeTestEvent()
	id := uuid.New()

	env, err := NewEnvelope(e, id, fixedTime.In(tehran))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	if env.SchemaVersion != EnvelopeSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", env.SchemaVersion, EnvelopeSchemaVersion)
	}
	if env.EventID != id {
		t.Errorf("EventID = %s, want %s", env.EventID, id)
	}
	// UTC at construction, not at hashing: the signer chains whatever it decodes, so
	// normalizing later would leave the stored timestamp and the hashed one in
	// different zones.
	if env.OccurredAt.Location() != time.UTC {
		t.Errorf("OccurredAt location = %s, want UTC", env.OccurredAt.Location())
	}
	if !env.OccurredAt.Equal(NormalizeChainTime(fixedTime)) {
		t.Errorf("OccurredAt = %s, want PostgreSQL precision %s", env.OccurredAt, NormalizeChainTime(fixedTime))
	}
}

// TestNewEnvelopeMarshalsPayloadExactlyOnce pins the "hash what you store" rule: the
// publisher renders the payload to text here, and both the stored column and the
// hashed bytes use that exact string. A consumer-side re-marshal could reorder keys
// and break verification with no code change.
func TestNewEnvelopeMarshalsPayloadExactlyOnce(t *testing.T) {
	t.Parallel()

	e, _, _ := envelopeTestEvent()
	env, err := NewEnvelope(e, uuid.New(), fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(env.Payload), &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if decoded["method"] != "webauthn" || decoded["uv"] != true {
		t.Errorf("payload = %s, want the caller's map", env.Payload)
	}
	if env.AuditRecord().Payload != env.Payload {
		t.Error("AuditRecord re-rendered the payload; the hashed bytes must be the stored bytes")
	}
}

// TestNewEnvelopeEmptyPayloadIsJSONObject keeps the NOT NULL payload column a valid
// object so payload-key queries need no null guard.
func TestNewEnvelopeEmptyPayloadIsJSONObject(t *testing.T) {
	t.Parallel()

	env, err := NewEnvelope(Event{EventType: EventSessionLoggedOut}, uuid.New(), fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.Payload != emptyPayload {
		t.Errorf("Payload = %q, want %q", env.Payload, emptyPayload)
	}
}

// TestNewEnvelopeReportsUnserializablePayload covers the loud-failure contract: a
// payload that cannot be marshalled is reported so the publisher can route it to the
// transport-failure log, never silently dropped.
func TestNewEnvelopeReportsUnserializablePayload(t *testing.T) {
	t.Parallel()

	_, err := NewEnvelope(Event{
		EventType: EventLoginFailed,
		Payload:   map[string]any{"unserializable": make(chan int)},
	}, uuid.New(), fixedTime)
	if err == nil {
		t.Fatal("NewEnvelope accepted an unmarshallable payload; the event would be dropped without a trace")
	}
}

func TestNewEnvelopeCopiesSecurityContext(t *testing.T) {
	t.Parallel()

	e, _, subject := envelopeTestEvent()
	env, err := NewEnvelope(e, uuid.New(), fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.Security == nil {
		t.Fatal("Security is nil; the event would never produce a ledger row")
	}
	if env.Security.AccountRef != subject.String() {
		t.Errorf("AccountRef = %q, want %q", env.Security.AccountRef, subject)
	}
	if env.Security.ClientID != "search-engine" || env.Security.Scope != "openid profile" || env.Security.DeviceFingerprint != "device-1" {
		t.Errorf("security context not copied verbatim: %+v", env.Security)
	}
}

// TestNewEnvelopeOmitsAbsentSubjectAndSecurity keeps "audit-only" distinguishable
// from "security event with a broken account reference" on the wire.
func TestNewEnvelopeOmitsAbsentSubjectAndSecurity(t *testing.T) {
	t.Parallel()

	env, err := NewEnvelope(Event{EventType: EventLoginFailed}, uuid.New(), fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.SubjectID != "" {
		t.Errorf("SubjectID = %q, want empty", env.SubjectID)
	}
	if env.Security != nil {
		t.Errorf("Security = %+v, want nil", env.Security)
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, absent := range []string{`"subject_id"`, `"security"`} {
		if bytes.Contains(encoded, []byte(absent)) {
			t.Errorf("wire form %s contains %s; an absent value must not decode as a present-but-zero one", encoded, absent)
		}
	}
}

// TestEnvelopeSurvivesJSONRoundTripForHashing is the publisher/signer contract the
// Dockerfile relies on when it ships both processes in one image: whatever the signer
// decodes off the stream must hash to the same digest the publisher described.
func TestEnvelopeSurvivesJSONRoundTripForHashing(t *testing.T) {
	t.Parallel()

	e, _, _ := envelopeTestEvent()
	env, err := NewEnvelope(e, uuid.New(), fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	encoded, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded Envelope
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	want := ChainHash(GenesisChainHash, SerializeAudit(env.AuditRecord()))
	got := ChainHash(GenesisChainHash, SerializeAudit(decoded.AuditRecord()))
	if got != want {
		t.Errorf("chain hash after a JSON round trip = %q, want %q; the signer would write a hash the publisher's record does not verify against", got, want)
	}
}

// TestAuditRecordExcludesSubjectID is the GDPR invariant from the package doc, tested
// at the level where it can actually regress. mvp_audit_logs.user_id is
// ON DELETE SET NULL, so a hard delete rewrites it to NULL while the rest of the row
// stays byte-identical. If it were hashed, every purged subject's rows would fail
// verification forever — a correct erasure presenting as permanent tampering.
func TestAuditRecordExcludesSubjectID(t *testing.T) {
	t.Parallel()

	e, _, _ := envelopeTestEvent()
	id := uuid.New()

	withSubject, err := NewEnvelope(e, id, fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	// The same event after the subject was purged: user_id is now NULL.
	purged := e
	purged.SubjectID = nil
	afterPurge, err := NewEnvelope(purged, id, fixedTime)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	before := ChainHash(GenesisChainHash, SerializeAudit(withSubject.AuditRecord()))
	after := ChainHash(GenesisChainHash, SerializeAudit(afterPurge.AuditRecord()))
	if before != after {
		t.Errorf("chain hash changed when user_id was nulled (%q -> %q); a GDPR hard delete would make every audit row of that subject report tampering", before, after)
	}
}

// TestLedgerEventTypesAreDeclaredConsistently guards the compliance statement in
// LedgerEventTypes: membership is what makes an event survive account deletion.
func TestLedgerEventTypesAreDeclaredConsistently(t *testing.T) {
	t.Parallel()

	// Every event the task text names as security-relevant and attributable.
	for _, eventType := range []string{
		EventLoginSucceeded,
		EventTokenIssued,
		EventRTRBreach,
		EventMFATOTPEnabled,
		EventMFATOTPDisabled,
		EventWebAuthnCredentialRegistered,
		EventWebAuthnCredentialDeleted,
	} {
		if !IsLedgerEventType(eventType) {
			t.Errorf("%s is not a ledger event type; it would not survive account deletion", eventType)
		}
	}

	// Failures stay out: security_event_ledger.account_ref is NOT NULL and a failed
	// attempt frequently has no resolvable account, so including them would either
	// fabricate attribution or make coverage depend on how the attempt failed.
	for _, eventType := range []string{
		EventLoginFailed,
		EventTokenDenied,
		EventMFAVerifyFailed,
		EventStepUpDenied,
		EventRecoveryCodeVerifyFailed,
		EventPipelineUndecodable,
	} {
		if IsLedgerEventType(eventType) {
			t.Errorf("%s is declared as a ledger event type, but it can occur without a resolvable account_ref", eventType)
		}
	}

	if IsLedgerEventType("auth.does.not.exist") {
		t.Error("an unknown event type was reported as a ledger event type")
	}
}
