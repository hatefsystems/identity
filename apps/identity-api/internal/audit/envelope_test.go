package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEnvelopeAdmissionStorageRepresentation(t *testing.T) {
	e, _, _ := envelopeTestEvent()
	base, err := NewEnvelope(e, uuid.New(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Envelope)
		want   error
	}{
		{"valid", func(*Envelope) {}, nil},
		{"zero_actor", func(e *Envelope) { e.ActorID = uuid.Nil.String() }, nil},
		{"zero_references", func(e *Envelope) { e.SubjectID = uuid.Nil.String(); e.Security.AccountRef = uuid.Nil.String() }, nil},
		{"missing_actor", func(e *Envelope) { e.ActorID = "" }, ErrEnvelopeActor},
		{"uppercase_actor", func(e *Envelope) { e.ActorID = strings.ToUpper(e.ActorID) }, ErrEnvelopeActor},
		{"compact_actor", func(e *Envelope) { e.ActorID = strings.ReplaceAll(e.ActorID, "-", "") }, ErrEnvelopeActor},
		{"urn_actor", func(e *Envelope) { e.ActorID = "urn:uuid:" + e.ActorID }, ErrEnvelopeActor},
		{"invalid_actor", func(e *Envelope) { e.ActorID = "private@example.test" }, ErrEnvelopeActor},
		{"invalid_subject", func(e *Envelope) { e.SubjectID = "secret-token" }, ErrEnvelopeReference},
		{"uppercase_account", func(e *Envelope) { e.Security.AccountRef = strings.ToUpper(e.ActorID) }, ErrEnvelopeReference},
		{"missing_account", func(e *Envelope) { e.Security.AccountRef = "" }, ErrEnvelopeReference},
		{"zero_id", func(e *Envelope) { e.EventID = uuid.Nil }, ErrEnvelopeEventID},
		{"schema", func(e *Envelope) { e.SchemaVersion-- }, ErrEnvelopeSchema},
		{"missing_time", func(e *Envelope) { e.OccurredAt = time.Time{} }, ErrEnvelopeTime},
		{"year_zero", func(e *Envelope) { e.OccurredAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrEnvelopeTime},
		{"year_overflow", func(e *Envelope) { e.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrEnvelopeTime},
		{"index_generation", func(e *Envelope) { e.Security.BlindIndexVersion = -1 }, ErrEnvelopeIndex},
		{"index_short", func(e *Envelope) { s := "abcd"; e.Security.IdentityBlindIndex = &s }, ErrEnvelopeIndex},
		{"index_uppercase", func(e *Envelope) { s := strings.Repeat("A", 64); e.Security.IdentityBlindIndex = &s }, ErrEnvelopeIndex},
		{"index_nonhex", func(e *Envelope) { s := strings.Repeat("g", 64); e.Security.IdentityBlindIndex = &s }, ErrEnvelopeIndex},
		{"generation_without_capture", func(e *Envelope) { e.Security.BlindIndexVersion = 32767 }, nil},
		{"varchar_character_limits", func(e *Envelope) {
			e.ActorSPIFFEID = strings.Repeat("\u0627", 255)
			e.EventType = strings.Repeat("e", 100)
			e.ActionStatus = strings.Repeat("s", 50)
			e.ClientIP = strings.Repeat("i", 50)
			e.Security.ClientID = strings.Repeat("c", 100)
			e.Security.DeviceFingerprint = strings.Repeat("f", 128)
		}, nil},
		{"spiffe_overflow", func(e *Envelope) { e.ActorSPIFFEID = strings.Repeat("s", 256) }, ErrEnvelopeText},
		{"event_overflow", func(e *Envelope) { e.EventType = strings.Repeat("e", 101) }, ErrEnvelopeText},
		{"event_missing", func(e *Envelope) { e.EventType = "" }, ErrEnvelopeText},
		{"status_overflow", func(e *Envelope) { e.ActionStatus = strings.Repeat("s", 51) }, ErrEnvelopeText},
		{"ip_overflow", func(e *Envelope) { e.ClientIP = strings.Repeat("i", 51) }, ErrEnvelopeText},
		{"agent_overflow", func(e *Envelope) { e.UserAgent = strings.Repeat("a", 8193) }, ErrEnvelopeText},
		{"client_overflow", func(e *Envelope) { e.Security.ClientID = strings.Repeat("c", 101) }, ErrEnvelopeText},
		{"fingerprint_overflow", func(e *Envelope) { e.Security.DeviceFingerprint = strings.Repeat("f", 129) }, ErrEnvelopeText},
		{"scope_overflow", func(e *Envelope) { e.Security.Scope = strings.Repeat("s", 8193) }, ErrEnvelopeText},
		{"payload_overflow", func(e *Envelope) { e.Payload = strings.Repeat("p", MaxEnvelopeBytes+1) }, ErrEnvelopeText},
		{"nul_payload", func(e *Envelope) { e.Payload = "private\x00@example.test" }, ErrEnvelopeText},
		{"nul_actor_spiffe", func(e *Envelope) { e.ActorSPIFFEID = "spiffe://audit\x00" }, ErrEnvelopeText},
		{"nul_event", func(e *Envelope) { e.EventType += "\x00" }, ErrEnvelopeText},
		{"nul_status", func(e *Envelope) { e.ActionStatus += "\x00" }, ErrEnvelopeText},
		{"nul_ip", func(e *Envelope) { e.ClientIP += "\x00" }, ErrEnvelopeText},
		{"nul_agent", func(e *Envelope) { e.UserAgent += "\x00" }, ErrEnvelopeText},
		{"nul_client", func(e *Envelope) { e.Security.ClientID += "\x00" }, ErrEnvelopeText},
		{"nul_fingerprint", func(e *Envelope) { e.Security.DeviceFingerprint += "\x00" }, ErrEnvelopeText},
		{"nul_scope", func(e *Envelope) { e.Security.Scope += "\x00" }, ErrEnvelopeText},
		{"invalid_utf8", func(e *Envelope) { e.UserAgent = string([]byte{0xff}) }, ErrEnvelopeText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base
			security := *base.Security
			env.Security = &security
			tc.change(&env)
			before, _ := SerializeAudit(env.AuditRecord())
			if got := env.Validate(); !errors.Is(got, tc.want) {
				t.Fatalf("Validate = %v, want %v", got, tc.want)
			}
			after, _ := SerializeAudit(env.AuditRecord())
			if !bytes.Equal(before, after) {
				t.Fatal("admission rewrote canonical bytes")
			}
		})
	}
}

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

	want := ChainAudit(Genesis(), mustLeafAudit(t, env.AuditRecord()))
	got := ChainAudit(Genesis(), mustLeafAudit(t, decoded.AuditRecord()))
	if got != want {
		t.Errorf("chain digest after a JSON round trip = %s, want %s; the signer would write a digest the publisher's record does not verify against", got.Hex(), want.Hex())
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

	before := ChainAudit(Genesis(), mustLeafAudit(t, withSubject.AuditRecord()))
	after := ChainAudit(Genesis(), mustLeafAudit(t, afterPurge.AuditRecord()))
	if before != after {
		t.Errorf("chain digest changed when user_id was nulled (%s -> %s); a GDPR hard delete would make every audit row of that subject report tampering", before.Hex(), after.Hex())
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
