package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// EnvelopeSchemaVersion is the wire-format version carried on every published
// envelope.
//
// It is explicit so a future field change can be handled by the consumer rather
// than by a coordinated deploy: JetStream holds a backlog, so during any rollout
// the signer will decode messages produced by the previous release. A consumer that
// sees a version it does not know must quarantine, never guess.
//
// Version 2 accompanies the chain/payload split: EnvelopeSecurity carries
// BlindIndexVersion, and the signer computes leaf digests rather than hashing a
// record directly into the chain. A v1 envelope is not forward-decodable into v2
// because its security context cannot state which pepper generation applied, so
// the signer quarantines it rather than defaulting the version and signing a claim
// the producer never made.
const EnvelopeSchemaVersion = 2

// MaxEnvelopeBytes bounds intake before JSON allocation. TEXT fields have separate
// resource bounds; VARCHAR limits below count characters, as PostgreSQL does.
const MaxEnvelopeBytes = 1024 * 1024

// Envelope admission errors are fixed reason codes, safe for quarantine evidence.
var (
	ErrEnvelopeSchema    = errors.New("unsupported_schema")
	ErrEnvelopeEventID   = errors.New("invalid_event_id")
	ErrEnvelopeActor     = errors.New("invalid_actor_id")
	ErrEnvelopeReference = errors.New("invalid_reference")
	ErrEnvelopeText      = errors.New("invalid_text")
	ErrEnvelopeTime      = errors.New("invalid_timestamp")
	ErrEnvelopeIndex     = errors.New("invalid_blind_index")
)

// Envelope is the JSON message published to the audit subject.
//
// It is a separate type from Event on purpose. Event is the ergonomic call-site
// shape (map payload, pointer subject); Envelope is a wire contract that is
// persisted in a stream and must stay decodable by a different process at a
// different version. Reusing Event would make every convenience change to the
// call-site API a breaking change to stored messages.
type Envelope struct {
	// EventID is assigned by the publisher and is simultaneously the JetStream
	// Nats-Msg-Id and the primary key of the resulting row. Because both target
	// tables are append-only with UPDATE/DELETE revoked, a duplicate row is
	// permanent and uncorrectable — so at-least-once delivery is made idempotent by
	// this id rather than by anything the database could undo.
	EventID uuid.UUID `json:"event_id"`
	// SchemaVersion is EnvelopeSchemaVersion at publish time.
	SchemaVersion int `json:"schema_version"`
	// OccurredAt is the publisher's clock reading for the event and becomes the row
	// timestamp. It is the event's occurrence time, deliberately not its persistence
	// time: DPO time-range queries must stay correct when the signer is running a
	// backlog. Chain *position* comes from the seq column instead, precisely because
	// this value is not monotonic across publishers.
	OccurredAt time.Time `json:"occurred_at"`

	EventType     string `json:"event_type"`
	ActionStatus  string `json:"action_status"`
	ActorID       string `json:"actor_id"`
	ActorSPIFFEID string `json:"actor_spiffe_id"`
	// SubjectID is the account acted upon, empty when there is none. It becomes
	// mvp_audit_logs.user_id, which is nullable and ON DELETE SET NULL.
	SubjectID string `json:"subject_id,omitempty"`
	ClientIP  string `json:"client_ip"`
	UserAgent string `json:"user_agent"`
	// Payload is pre-serialized JSON stored as TEXT. The publisher marshals the caller's
	// map exactly once, here, so the bytes that get hashed are the bytes that get
	// stored; a consumer-side re-marshal could reorder keys and break verification.
	Payload string `json:"payload"`
	// Security is non-nil for Class B events and drives the ledger row. See
	// SecurityContext.
	Security *EnvelopeSecurity `json:"security,omitempty"`
}

// EnvelopeSecurity is the wire form of SecurityContext. AccountRef is a string so
// an absent value decodes as "" rather than as uuid.Nil-that-might-be-real, letting
// the signer distinguish "not a security event" from "security event with a broken
// account reference".
type EnvelopeSecurity struct {
	AccountRef        string `json:"account_ref"`
	ClientID          string `json:"client_id,omitempty"`
	Scope             string `json:"scope,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	// IdentityBlindIndex is the producer-captured attribution index. It stays
	// optional: when the pepper is unavailable the signer falls back to a live
	// lookup, and a purged subject legitimately yields NULL.
	IdentityBlindIndex *string `json:"identity_blind_index,omitempty"`
	// BlindIndexVersion names the pepper generation that produced
	// IdentityBlindIndex, and is hashed into the ledger body unconditionally.
	//
	// It is not omitempty: version 0 is a meaningful value (the pre-rotation
	// generation), and omitting it would make "generation 0" and "unstated"
	// indistinguishable on the wire — which is exactly the ambiguity that makes a
	// pepper unrotatable.
	BlindIndexVersion int16 `json:"blind_index_version"`
}

// Validate checks the admitted v2 representation without rewriting any field.
// In particular, hashing actor text and then storing a parsed UUID is safe only
// when that text already equals the database's canonical UUID representation.
func (e Envelope) Validate() error {
	if e.SchemaVersion != EnvelopeSchemaVersion {
		return ErrEnvelopeSchema
	}
	if e.EventID == uuid.Nil {
		return ErrEnvelopeEventID
	}
	if !canonicalEnvelopeUUID(e.ActorID) {
		return ErrEnvelopeActor
	}
	if e.SubjectID != "" && !canonicalEnvelopeUUID(e.SubjectID) {
		return ErrEnvelopeReference
	}
	if e.OccurredAt.IsZero() || e.OccurredAt.UTC().Year() < 1 || e.OccurredAt.UTC().Year() > 9999 {
		return ErrEnvelopeTime
	}
	for _, field := range []struct {
		value string
		limit int
	}{
		{e.ActorSPIFFEID, 255}, {e.EventType, 100}, {e.ActionStatus, 50}, {e.ClientIP, 50},
		{e.UserAgent, 8192}, {e.Payload, MaxEnvelopeBytes},
	} {
		if !validEnvelopeText(field.value, field.limit) {
			return ErrEnvelopeText
		}
	}
	if e.EventType == "" {
		return ErrEnvelopeText
	}
	if security := e.Security; security != nil {
		if !canonicalEnvelopeUUID(security.AccountRef) {
			return ErrEnvelopeReference
		}
		for _, field := range []struct {
			value string
			limit int
		}{
			{security.ClientID, 100}, {security.DeviceFingerprint, 128}, {security.Scope, 8192},
		} {
			if !validEnvelopeText(field.value, field.limit) {
				return ErrEnvelopeText
			}
		}
		if security.BlindIndexVersion < 0 {
			return ErrEnvelopeIndex
		}
		if index := security.IdentityBlindIndex; index != nil {
			if len(*index) != ChainHashHexLen || strings.Trim(*index, "0123456789abcdef") != "" {
				return ErrEnvelopeIndex
			}
		}
	}
	return nil
}

func canonicalEnvelopeUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && value == id.String()
}

func validEnvelopeText(value string, limit int) bool {
	return len(value) <= MaxEnvelopeBytes && utf8.ValidString(value) &&
		!strings.ContainsRune(value, 0) && utf8.RuneCountInString(value) <= limit
}

// emptyPayload is the JSON text used when an event carries no context. The column
// is NOT NULL, and "{}" keeps it a valid JSON object so payload-key queries do not
// need a null guard.
const emptyPayload = "{}"

// NewEnvelope builds the wire message for an Event, assigning the event id and the
// occurrence timestamp.
//
// A payload that cannot be marshalled is reported rather than dropped: the caller
// (the publisher) routes the failure into the loud transport-failure path, because a
// silently discarded audit event is exactly the outcome this pipeline exists to
// prevent.
func NewEnvelope(e Event, eventID uuid.UUID, occurredAt time.Time) (Envelope, error) {
	payload := emptyPayload
	if len(e.Payload) > 0 {
		encoded, err := json.Marshal(e.Payload)
		if err != nil {
			return Envelope{}, fmt.Errorf("audit: marshal payload for %q: %w", e.EventType, err)
		}
		payload = string(encoded)
	}

	env := Envelope{
		EventID:       eventID,
		SchemaVersion: EnvelopeSchemaVersion,
		OccurredAt:    NormalizeChainTime(occurredAt),
		EventType:     e.EventType,
		ActionStatus:  e.ActionStatus,
		ActorID:       e.ActorID.String(),
		ActorSPIFFEID: e.ActorSPIFFEID,
		ClientIP:      e.ClientIP,
		UserAgent:     e.UserAgent,
		Payload:       payload,
	}
	if e.SubjectID != nil {
		env.SubjectID = e.SubjectID.String()
	}
	if e.Security != nil && IsLedgerEventType(e.EventType) {
		env.Security = &EnvelopeSecurity{
			AccountRef:        e.Security.AccountRef.String(),
			ClientID:          e.Security.ClientID,
			Scope:             e.Security.Scope,
			DeviceFingerprint: e.Security.DeviceFingerprint,
			BlindIndexVersion: e.Security.BlindIndexVersion,
		}
		if e.Security.IdentityBlindIndex != nil {
			index := *e.Security.IdentityBlindIndex
			env.Security.IdentityBlindIndex = &index
		}
	}
	return env, nil
}

// AuditRecord projects the envelope onto the chained mvp_audit_logs fields.
// SubjectID is intentionally not part of the result: see AuditRecord's doc.
func (e Envelope) AuditRecord() AuditRecord {
	return AuditRecord{
		ID:            e.EventID.String(),
		ActorID:       e.ActorID,
		ActorSPIFFEID: e.ActorSPIFFEID,
		EventType:     e.EventType,
		ActionStatus:  e.ActionStatus,
		ClientIP:      e.ClientIP,
		UserAgent:     e.UserAgent,
		Payload:       e.Payload,
		Timestamp:     e.OccurredAt,
	}
}
