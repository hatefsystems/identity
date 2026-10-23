// Package lifecycle defines metadata-only, revisioned account notifications.
package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

// SubjectCreated, SubjectUpdated, SubjectSuspended and SubjectDeleted are the
// supported account lifecycle subjects.
const (
	SubjectCreated   = "identity.user.created"
	SubjectUpdated   = "identity.user.updated"
	SubjectSuspended = "identity.user.suspended"
	SubjectDeleted   = "identity.user.deleted"
	SchemaVersion    = 1
	MaxMessageBytes  = 16 * 1024
)

// ErrInvalidEvent denotes an invalid envelope without exposing its contents.
var ErrInvalidEvent = errors.New("lifecycle: invalid event")

// NewEvent captures a new intent with caller-assigned, stable identifiers and
// time. Revision must fit a positive PostgreSQL bigint, including for deletion.
// The caller must persist the event in the same transaction as the mutation.
func NewEvent(id, userID uuid.UUID, revision int64, subject, status string, changedFields []string, occurredAt time.Time) (*identityv1.UserLifecycleEvent, error) {
	if revision <= 0 {
		return nil, fmt.Errorf("%w: revision must be positive", ErrInvalidEvent)
	}
	rev := uint64(revision)
	event := &identityv1.UserLifecycleEvent{
		SchemaVersion: SchemaVersion,
		EventId:       id.String(),
		EventType:     subject,
		UserId:        userID.String(),
		OccurredAt:    timestamppb.New(occurredAt.UTC()),
		Revision:      &rev,
		ChangedFields: changedFields,
	}
	switch status {
	case "":
	case "active":
		event.Status = identityv1.UserStatus_USER_STATUS_ACTIVE.Enum()
	case "pending_verification":
		event.Status = identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION.Enum()
	case "suspended":
		event.Status = identityv1.UserStatus_USER_STATUS_SUSPENDED.Enum()
	case "pending_deletion":
		event.Status = identityv1.UserStatus_USER_STATUS_PENDING_DELETION.Enum()
	case "banned":
		event.Status = identityv1.UserStatus_USER_STATUS_BANNED.Enum()
	default:
		return nil, fmt.Errorf("%w: unknown status", ErrInvalidEvent)
	}
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	event.ChangedFields = append([]string(nil), changedFields...)
	return event, nil
}

// MarshalEvent validates and encodes the bounded, metadata-only ProtoJSON
// contract. An explicitly constructed legacy deletion may omit its revision;
// new intents must use NewEvent and cannot omit it.
func MarshalEvent(event *identityv1.UserLifecycleEvent) ([]byte, error) {
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot encode ProtoJSON", ErrInvalidEvent)
	}
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: message too large", ErrInvalidEvent)
	}
	return data, nil
}

// UnmarshalEvent accepts only the versioned envelope, not the historical
// {"user_id":...} payload. Legacy outbox adaptation belongs at the row boundary.
func UnmarshalEvent(data []byte) (*identityv1.UserLifecycleEvent, error) {
	if len(data) == 0 || len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: invalid message size", ErrInvalidEvent)
	}
	event := new(identityv1.UserLifecycleEvent)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false, RecursionLimit: 8}).Unmarshal(data, event); err != nil {
		// Protobuf errors may quote unknown keys or values containing PII.
		return nil, fmt.Errorf("%w: malformed ProtoJSON", ErrInvalidEvent)
	}
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	if !validEventJSON(data, event) {
		return nil, fmt.Errorf("%w: invalid ProtoJSON representation", ErrInvalidEvent)
	}
	return event, nil
}

func validateEvent(event *identityv1.UserLifecycleEvent) error {
	if event == nil || event.SchemaVersion != SchemaVersion || len(event.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidEvent)
	}
	for _, raw := range []string{event.EventId, event.UserId} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || raw != id.String() {
			return fmt.Errorf("%w: noncanonical or zero UUID", ErrInvalidEvent)
		}
	}
	if event.OccurredAt.CheckValid() != nil || event.OccurredAt.AsTime().IsZero() || len(event.OccurredAt.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("%w: invalid occurrence time", ErrInvalidEvent)
	}
	if event.Revision == nil && event.EventType != SubjectDeleted ||
		event.Revision != nil && (event.GetRevision() == 0 || event.GetRevision() > math.MaxInt64) {
		return fmt.Errorf("%w: invalid revision", ErrInvalidEvent)
	}
	if event.EventType == SubjectDeleted {
		if event.Status != nil || len(event.ChangedFields) != 0 {
			return fmt.Errorf("%w: deletion must omit profile metadata", ErrInvalidEvent)
		}
		return nil
	}
	if event.Status == nil {
		return fmt.Errorf("%w: status required", ErrInvalidEvent)
	}
	switch event.GetStatus() {
	case identityv1.UserStatus_USER_STATUS_ACTIVE, identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION,
		identityv1.UserStatus_USER_STATUS_SUSPENDED, identityv1.UserStatus_USER_STATUS_PENDING_DELETION,
		identityv1.UserStatus_USER_STATUS_BANNED:
	default:
		return fmt.Errorf("%w: unknown status", ErrInvalidEvent)
	}
	if len(event.ChangedFields) == 0 || len(event.ChangedFields) > 2 {
		return fmt.Errorf("%w: invalid changed fields", ErrInvalidEvent)
	}
	var changedStatus, changedEmail bool
	for _, field := range event.ChangedFields {
		switch {
		case field == "status" && !changedStatus:
			changedStatus = true
		case field == "email" && !changedEmail:
			changedEmail = true
		default:
			return fmt.Errorf("%w: unknown or duplicate changed field", ErrInvalidEvent)
		}
	}
	switch event.EventType {
	case SubjectCreated:
		if (event.GetStatus() != identityv1.UserStatus_USER_STATUS_ACTIVE && event.GetStatus() != identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION) || !changedStatus || !changedEmail {
			return fmt.Errorf("%w: invalid creation metadata", ErrInvalidEvent)
		}
	case SubjectSuspended:
		if event.GetStatus() != identityv1.UserStatus_USER_STATUS_SUSPENDED || !changedStatus || changedEmail {
			return fmt.Errorf("%w: invalid suspension metadata", ErrInvalidEvent)
		}
	case SubjectUpdated:
		if changedStatus && event.GetStatus() == identityv1.UserStatus_USER_STATUS_SUSPENDED {
			return fmt.Errorf("%w: suspension requires its own event type", ErrInvalidEvent)
		}
	default:
		return fmt.Errorf("%w: unknown event type", ErrInvalidEvent)
	}
	return nil
}

// ProtoJSON handles syntax, types, and duplicate fields. This bounded second
// pass also excludes accepted reader aliases/numeric enums, explicit nulls, and
// duplicate null keys, so every accepted row follows the writer's wire format.
func validEventJSON(data []byte, event *identityv1.UserLifecycleEvent) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	fields := event.ProtoReflect().Descriptor().Fields()
	var seen uint64
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		name, ok := token.(string)
		if !ok {
			return false
		}
		field := fields.ByName(protoreflect.Name(name))
		if field == nil || field.Number() > 63 {
			return false
		}
		bit := uint64(1) << field.Number()
		if seen&bit != 0 {
			return false
		}
		seen |= bit
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) {
			return false
		}
		if event.EventType == SubjectDeleted && (name == "status" || name == "changed_fields") {
			return false
		}
		switch name {
		case "schema_version":
			if string(raw) != strconv.Itoa(SchemaVersion) {
				return false
			}
		case "revision", "status", "occurred_at":
			var value string
			if err := json.Unmarshal(raw, &value); err != nil {
				return false
			}
			if name == "revision" && value != strconv.FormatUint(event.GetRevision(), 10) ||
				name == "status" && value != event.GetStatus().String() ||
				name == "occurred_at" && !strings.HasSuffix(value, "Z") {
				return false
			}
		}
	}
	_, err := decoder.Token()
	return err == nil
}
