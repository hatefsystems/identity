package lifecycle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

const (
	wireEventID = "ecf132b8-8b12-4baa-9c0e-f976e56d9b9b"
	wireUserID  = "039e55cf-04e1-4453-a3a9-6967d6f16e8a"
	wireUpdated = `{"schema_version":1,"event_id":"` + wireEventID + `","event_type":"identity.user.updated","user_id":"` + wireUserID + `","occurred_at":"2026-10-15T12:00:00.123456789Z","revision":"7","status":"USER_STATUS_ACTIVE","changed_fields":["status"]}`
	wireDeleted = `{"schema_version":1,"event_id":"` + wireEventID + `","event_type":"identity.user.deleted","user_id":"` + wireUserID + `","occurred_at":"2026-10-15T12:00:00.123456789Z","revision":"7"}`
)

func wireTime() time.Time {
	return time.Date(2026, time.October, 15, 12, 0, 0, 123456789, time.UTC)
}

func updatedEvent(t *testing.T) *identityv1.UserLifecycleEvent {
	t.Helper()
	event, err := lifecycle.NewEvent(uuid.MustParse(wireEventID), uuid.MustParse(wireUserID), 7,
		lifecycle.SubjectUpdated, "active", []string{"status"}, wireTime())
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func compactEventJSON(t *testing.T, data []byte) string {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		t.Fatal(err)
	}
	return compact.String()
}

func TestUserLifecycleEventWireContract(t *testing.T) {
	if lifecycle.SchemaVersion != 1 || lifecycle.MaxMessageBytes != 16*1024 ||
		lifecycle.SubjectCreated != "identity.user.created" || lifecycle.SubjectUpdated != "identity.user.updated" ||
		lifecycle.SubjectSuspended != "identity.user.suspended" || lifecycle.SubjectDeleted != "identity.user.deleted" {
		t.Fatal("lifecycle contract constants changed")
	}
	descriptor := (&identityv1.UserLifecycleEvent{}).ProtoReflect().Descriptor()
	fields := []struct {
		name     protoreflect.Name
		kind     protoreflect.Kind
		presence bool
		list     bool
	}{
		{"schema_version", protoreflect.Uint32Kind, false, false},
		{"event_id", protoreflect.StringKind, false, false},
		{"event_type", protoreflect.StringKind, false, false},
		{"user_id", protoreflect.StringKind, false, false},
		{"occurred_at", protoreflect.MessageKind, true, false},
		{"revision", protoreflect.Uint64Kind, true, false},
		{"status", protoreflect.EnumKind, true, false},
		{"changed_fields", protoreflect.StringKind, false, true},
	}
	if descriptor.FullName() != "hatef.identity.v1.UserLifecycleEvent" || descriptor.Fields().Len() != len(fields) {
		t.Fatal("lifecycle envelope changed without a contract review")
	}
	for i, want := range fields {
		field := descriptor.Fields().ByName(want.name)
		if field == nil || field.Number() != protoreflect.FieldNumber(i+1) || field.Kind() != want.kind ||
			field.HasPresence() != want.presence || field.IsList() != want.list || field.IsMap() {
			t.Fatalf("wire field %s changed its number, type, or presence", want.name)
		}
	}
	if descriptor.Fields().ByName("occurred_at").Message().FullName() != "google.protobuf.Timestamp" ||
		descriptor.Fields().ByName("status").Enum().FullName() != "hatef.identity.v1.UserStatus" ||
		!descriptor.Fields().ByName("revision").HasOptionalKeyword() || !descriptor.Fields().ByName("status").HasOptionalKeyword() {
		t.Fatal("timestamp or optional revision/status contract changed")
	}
}

func TestNewEventRoundTripsEverySupportedTransition(t *testing.T) {
	for _, tc := range []struct {
		name, subject, status string
		fields                []string
		wantStatus            identityv1.UserStatus
	}{
		{"created active", lifecycle.SubjectCreated, "active", []string{"status", "email"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
		{"created pending", lifecycle.SubjectCreated, "pending_verification", []string{"email", "status"}, identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION},
		{"reactivated", lifecycle.SubjectUpdated, "active", []string{"status"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
		{"banned", lifecycle.SubjectUpdated, "banned", []string{"status"}, identityv1.UserStatus_USER_STATUS_BANNED},
		{"pending deletion", lifecycle.SubjectUpdated, "pending_deletion", []string{"status"}, identityv1.UserStatus_USER_STATUS_PENDING_DELETION},
		{"pending verification", lifecycle.SubjectUpdated, "pending_verification", []string{"status"}, identityv1.UserStatus_USER_STATUS_PENDING_VERIFICATION},
		{"email", lifecycle.SubjectUpdated, "active", []string{"email"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
		{"redacted email", lifecycle.SubjectUpdated, "suspended", []string{"email"}, identityv1.UserStatus_USER_STATUS_SUSPENDED},
		{"status and email", lifecycle.SubjectUpdated, "active", []string{"email", "status"}, identityv1.UserStatus_USER_STATUS_ACTIVE},
		{"suspended", lifecycle.SubjectSuspended, "suspended", []string{"status"}, identityv1.UserStatus_USER_STATUS_SUSPENDED},
		{"deleted", lifecycle.SubjectDeleted, "", nil, identityv1.UserStatus_USER_STATUS_UNSPECIFIED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			occurredAt := wireTime().In(time.FixedZone("source", 3*60*60+30*60))
			event, err := lifecycle.NewEvent(uuid.MustParse(wireEventID), uuid.MustParse(wireUserID), 7, tc.subject, tc.status, tc.fields, occurredAt)
			if err != nil {
				t.Fatal(err)
			}
			if event.SchemaVersion != lifecycle.SchemaVersion || event.EventId != wireEventID || event.UserId != wireUserID ||
				event.EventType != tc.subject || event.Revision == nil || event.GetRevision() != 7 || event.GetStatus() != tc.wantStatus ||
				!event.OccurredAt.AsTime().Equal(occurredAt) || event.OccurredAt.AsTime().Location() != time.UTC {
				t.Fatalf("new event changed captured metadata: %v", event)
			}
			if (event.Status == nil) != (tc.subject == lifecycle.SubjectDeleted) {
				t.Fatal("status presence does not distinguish deletion")
			}
			encoded, err := lifecycle.MarshalEvent(event)
			if err != nil || len(encoded) > lifecycle.MaxMessageBytes {
				t.Fatalf("MarshalEvent: %v", err)
			}
			decoded, err := lifecycle.UnmarshalEvent(encoded)
			if err != nil || !proto.Equal(event, decoded) {
				t.Fatalf("ProtoJSON lost metadata: %v", err)
			}
			binary, err := proto.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var fromBinary identityv1.UserLifecycleEvent
			if err := proto.Unmarshal(binary, &fromBinary); err != nil || !proto.Equal(event, &fromBinary) {
				t.Fatalf("protobuf wire roundtrip lost metadata: %v", err)
			}
			if len(tc.fields) != 0 {
				original := event.ChangedFields[0]
				tc.fields[0] = "private@example.invalid"
				if event.ChangedFields[0] != original {
					t.Fatal("caller mutation changed captured field metadata")
				}
			}
		})
	}
}

func TestEventGoldenProtoJSON(t *testing.T) {
	for _, raw := range []string{wireUpdated, wireDeleted, strings.Replace(wireDeleted, `,"revision":"7"`, "", 1)} {
		event, err := lifecycle.UnmarshalEvent([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := lifecycle.MarshalEvent(event)
		if err != nil || compactEventJSON(t, encoded) != raw {
			t.Fatalf("metadata-only snake_case golden changed: %s, %v", encoded, err)
		}
		if event.EventType == lifecycle.SubjectDeleted && (event.Status != nil || len(event.ChangedFields) != 0 ||
			bytes.Contains(encoded, []byte(`"status"`)) || bytes.Contains(encoded, []byte(`"changed_fields"`))) {
			t.Fatal("deletion exposed profile metadata")
		}
	}
}

func TestEventRevisionPrecisionAndLegacyAbsence(t *testing.T) {
	for _, revision := range []int64{1, 1<<53 + 1, math.MaxInt64} {
		event, err := lifecycle.NewEvent(uuid.MustParse(wireEventID), uuid.MustParse(wireUserID), revision,
			lifecycle.SubjectDeleted, "", nil, wireTime())
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := lifecycle.MarshalEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Revision string `json:"revision"`
		}
		if err := json.Unmarshal(encoded, &wire); err != nil || wire.Revision != strconv.FormatInt(revision, 10) {
			t.Fatalf("revision is not an exact JSON decimal string: %s, %v", encoded, err)
		}
		decoded, err := lifecycle.UnmarshalEvent(encoded)
		if err != nil || decoded.Revision == nil || strconv.FormatUint(decoded.GetRevision(), 10) != wire.Revision {
			t.Fatalf("revision lost precision: %v", err)
		}
	}
	legacy := updatedEvent(t)
	legacy.EventType, legacy.Revision, legacy.Status, legacy.ChangedFields = lifecycle.SubjectDeleted, nil, nil, nil
	encoded, err := lifecycle.MarshalEvent(legacy)
	if err != nil || bytes.Contains(encoded, []byte(`"revision"`)) {
		t.Fatalf("legacy tombstone acquired an invented revision: %s, %v", encoded, err)
	}
	decoded, err := lifecycle.UnmarshalEvent(encoded)
	if err != nil || decoded.Revision != nil || !proto.Equal(legacy, decoded) {
		t.Fatalf("legacy revision absence was not preserved: %v", err)
	}
	for _, subject := range []string{lifecycle.SubjectCreated, lifecycle.SubjectUpdated, lifecycle.SubjectSuspended, lifecycle.SubjectDeleted} {
		if event, err := lifecycle.NewEvent(uuid.MustParse(wireEventID), uuid.MustParse(wireUserID), 0, subject, "", nil, wireTime()); event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
			t.Fatalf("NewEvent allowed missing revision for %s: %v", subject, err)
		}
	}
}

func TestNewEventRejectsInvalidInput(t *testing.T) {
	type input struct {
		id, userID uuid.UUID
		revision   int64
		subject    string
		status     string
		fields     []string
		at         time.Time
	}
	for _, tc := range []struct {
		name   string
		change func(*input)
	}{
		{"zero event ID", func(in *input) { in.id = uuid.Nil }},
		{"zero user ID", func(in *input) { in.userID = uuid.Nil }},
		{"zero revision", func(in *input) { in.revision = 0 }},
		{"negative revision", func(in *input) { in.revision = -1 }},
		{"minimum signed revision", func(in *input) { in.revision = math.MinInt64 }},
		{"zero time", func(in *input) { in.at = time.Time{} }},
		{"time before protobuf range", func(in *input) { in.at = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"time after protobuf range", func(in *input) { in.at = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"empty subject", func(in *input) { in.subject = "" }},
		{"unknown subject", func(in *input) { in.subject = "identity.user.password_changed" }},
		{"missing status", func(in *input) { in.status = "" }},
		{"unknown status", func(in *input) { in.status = "private@example.invalid" }},
		{"enum name as DB status", func(in *input) { in.status = "USER_STATUS_ACTIVE" }},
		{"uppercase DB status", func(in *input) { in.status = "ACTIVE" }},
		{"empty fields", func(in *input) { in.fields = nil }},
		{"raw email field", func(in *input) { in.fields = []string{"private@example.invalid"} }},
		{"credential field", func(in *input) { in.fields = []string{"password_hash"} }},
		{"duplicate fields", func(in *input) { in.fields = []string{"status", "status"} }},
		{"too many fields", func(in *input) { in.fields = []string{"status", "email", "status"} }},
		{"creation of banned account", func(in *input) {
			in.subject, in.status, in.fields = lifecycle.SubjectCreated, "banned", []string{"status", "email"}
		}},
		{"deletion with profile data", func(in *input) { in.subject = lifecycle.SubjectDeleted }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := input{uuid.MustParse(wireEventID), uuid.MustParse(wireUserID), 7, lifecycle.SubjectUpdated, "active", []string{"status"}, wireTime()}
			tc.change(&in)
			event, err := lifecycle.NewEvent(in.id, in.userID, in.revision, in.subject, in.status, in.fields, in.at)
			if event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
				t.Fatalf("invalid input accepted: %v, %v", event, err)
			}
			if strings.Contains(err.Error(), "private@example.invalid") || strings.Contains(err.Error(), wireUserID) {
				t.Fatal("invalid input leaked in error")
			}
		})
	}
}

func TestMarshalEventRejectsInvalidMetadata(t *testing.T) {
	if encoded, err := lifecycle.MarshalEvent(nil); encoded != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatalf("nil envelope accepted: %v", err)
	}
	cases := []struct {
		name   string
		change func(*identityv1.UserLifecycleEvent)
	}{
		{"zero schema", func(e *identityv1.UserLifecycleEvent) { e.SchemaVersion = 0 }},
		{"unknown schema", func(e *identityv1.UserLifecycleEvent) { e.SchemaVersion = 2 }},
		{"unknown protobuf field", func(e *identityv1.UserLifecycleEvent) { e.ProtoReflect().SetUnknown([]byte{0x48, 0x01}) }},
		{"missing time", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt = nil }},
		{"zero time", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt = timestamppb.New(time.Time{}) }},
		{"time below minimum", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt.Seconds = -62135596801 }},
		{"time above maximum", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt.Seconds = 253402300800 }},
		{"negative nanoseconds", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt.Nanos = -1 }},
		{"overflowing nanoseconds", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt.Nanos = 1e9 }},
		{"unknown timestamp field", func(e *identityv1.UserLifecycleEvent) { e.OccurredAt.ProtoReflect().SetUnknown([]byte{0x18, 0x01}) }},
		{"missing revision", func(e *identityv1.UserLifecycleEvent) { e.Revision = nil }},
		{"zero revision", func(e *identityv1.UserLifecycleEvent) { e.Revision = proto.Uint64(0) }},
		{"unsigned revision beyond DB range", func(e *identityv1.UserLifecycleEvent) { e.Revision = proto.Uint64(math.MaxInt64 + 1) }},
		{"maximum unsigned revision", func(e *identityv1.UserLifecycleEvent) { e.Revision = proto.Uint64(math.MaxUint64) }},
		{"missing status", func(e *identityv1.UserLifecycleEvent) { e.Status = nil }},
		{"unspecified status", func(e *identityv1.UserLifecycleEvent) {
			e.Status = identityv1.UserStatus_USER_STATUS_UNSPECIFIED.Enum()
		}},
		{"unknown status", func(e *identityv1.UserLifecycleEvent) { e.Status = identityv1.UserStatus(99).Enum() }},
		{"negative status", func(e *identityv1.UserLifecycleEvent) { e.Status = identityv1.UserStatus(-1).Enum() }},
		{"empty fields", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = nil }},
		{"empty field name", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{""} }},
		{"duplicate status", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"status", "status"} }},
		{"duplicate email", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"email", "email"} }},
		{"too many fields", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"status", "email", "email"} }},
		{"oversized field", func(e *identityv1.UserLifecycleEvent) {
			e.ChangedFields = []string{strings.Repeat("x", lifecycle.MaxMessageBytes+1)}
		}},
		{"PII field value", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"private@example.invalid"} }},
		{"credential field", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"mfa_totp_secret_encrypted"} }},
		{"moderation narrative", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"reason"} }},
		{"case-folded field", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{"Email"} }},
		{"padded field", func(e *identityv1.UserLifecycleEvent) { e.ChangedFields = []string{" status"} }},
		{"unknown subject", func(e *identityv1.UserLifecycleEvent) { e.EventType = "audit.user.updated" }},
		{"wildcard subject", func(e *identityv1.UserLifecycleEvent) { e.EventType = "identity.user.*" }},
		{"creation omits email", func(e *identityv1.UserLifecycleEvent) { e.EventType = lifecycle.SubjectCreated }},
		{"creation omits status change", func(e *identityv1.UserLifecycleEvent) {
			e.EventType, e.ChangedFields = lifecycle.SubjectCreated, []string{"email"}
		}},
		{"suspension with active status", func(e *identityv1.UserLifecycleEvent) { e.EventType = lifecycle.SubjectSuspended }},
		{"suspension without status change", func(e *identityv1.UserLifecycleEvent) {
			e.EventType, e.Status, e.ChangedFields = lifecycle.SubjectSuspended, identityv1.UserStatus_USER_STATUS_SUSPENDED.Enum(), []string{"email"}
		}},
		{"suspension with email change", func(e *identityv1.UserLifecycleEvent) {
			e.EventType, e.Status, e.ChangedFields = lifecycle.SubjectSuspended, identityv1.UserStatus_USER_STATUS_SUSPENDED.Enum(), []string{"status", "email"}
		}},
		{"suspension mislabeled update", func(e *identityv1.UserLifecycleEvent) { e.Status = identityv1.UserStatus_USER_STATUS_SUSPENDED.Enum() }},
		{"deletion with status", func(e *identityv1.UserLifecycleEvent) { e.EventType, e.ChangedFields = lifecycle.SubjectDeleted, nil }},
		{"deletion with unspecified status", func(e *identityv1.UserLifecycleEvent) {
			e.EventType, e.Status, e.ChangedFields = lifecycle.SubjectDeleted, identityv1.UserStatus_USER_STATUS_UNSPECIFIED.Enum(), nil
		}},
		{"deletion with fields", func(e *identityv1.UserLifecycleEvent) { e.EventType, e.Status = lifecycle.SubjectDeleted, nil }},
	}
	for _, status := range []identityv1.UserStatus{identityv1.UserStatus_USER_STATUS_SUSPENDED, identityv1.UserStatus_USER_STATUS_BANNED, identityv1.UserStatus_USER_STATUS_PENDING_DELETION} {
		cases = append(cases, struct {
			name   string
			change func(*identityv1.UserLifecycleEvent)
		}{"invalid initial status " + status.String(), func(e *identityv1.UserLifecycleEvent) {
			e.EventType, e.Status, e.ChangedFields = lifecycle.SubjectCreated, status.Enum(), []string{"status", "email"}
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := updatedEvent(t)
			tc.change(event)
			encoded, err := lifecycle.MarshalEvent(event)
			if encoded != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
				t.Fatalf("invalid metadata encoded: %s, %v", encoded, err)
			}
			if strings.Contains(err.Error(), "private@example.invalid") || strings.Contains(err.Error(), wireEventID) || strings.Contains(err.Error(), wireUserID) {
				t.Fatal("invalid metadata leaked in error")
			}
		})
	}
}

func TestEventUUIDsMustBeCanonicalAndNonzero(t *testing.T) {
	for _, field := range []string{"event_id", "user_id"} {
		for _, raw := range []string{"", "not-a-uuid", uuid.Nil.String(), strings.ToUpper(wireUserID), strings.ReplaceAll(wireUserID, "-", ""),
			"urn:uuid:" + wireUserID, "{" + wireUserID + "}", " " + wireUserID, wireUserID + "\n"} {
			t.Run(field+"/"+raw, func(t *testing.T) {
				event := updatedEvent(t)
				if field == "event_id" {
					event.EventId = raw
				} else {
					event.UserId = raw
				}
				if encoded, err := lifecycle.MarshalEvent(event); encoded != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
					t.Fatalf("noncanonical UUID encoded: %v", err)
				}
				quoted, err := json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				old := wireUserID
				if field == "event_id" {
					old = wireEventID
				}
				wire := strings.Replace(wireUpdated, `"`+old+`"`, string(quoted), 1)
				if decoded, err := lifecycle.UnmarshalEvent([]byte(wire)); decoded != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
					t.Fatalf("noncanonical UUID decoded: %v", err)
				}
			})
		}
	}
}

func TestUnmarshalEventRejectsInvalidWire(t *testing.T) {
	replace := func(old, value string) string { return strings.Replace(wireUpdated, old, value, 1) }
	appendField := func(field string) string { return strings.TrimSuffix(wireUpdated, "}") + "," + field + "}" }
	for _, tc := range []struct {
		name, raw string
	}{
		{"empty", ""}, {"whitespace", " \n\t"}, {"empty object", "{}"}, {"null", "null"}, {"array", "[]"},
		{"string", `"event"`}, {"truncated", wireUpdated[:len(wireUpdated)-1]}, {"trailing JSON", wireUpdated + "{}"},
		{"invalid UTF8", appendField("\"email\":\"\xff\"")}, {"BOM", "\xef\xbb\xbf" + wireUpdated},
		{"legacy payload at wrong boundary", `{"user_id":"` + wireUserID + `"}`},
		{"unknown schema", replace(`"schema_version":1`, `"schema_version":2`)},
		{"missing schema", replace(`"schema_version":1,`, "")},
		{"null schema", replace(`"schema_version":1`, `"schema_version":null`)},
		{"quoted schema", replace(`"schema_version":1`, `"schema_version":"1"`)},
		{"fractional schema", replace(`"schema_version":1`, `"schema_version":1.0`)},
		{"zero revision", replace(`"revision":"7"`, `"revision":"0"`)},
		{"missing revision", replace(`,"revision":"7"`, "")},
		{"null revision", replace(`"revision":"7"`, `"revision":null`)},
		{"negative revision", replace(`"revision":"7"`, `"revision":"-1"`)},
		{"unsigned-only revision", replace(`"revision":"7"`, `"revision":"9223372036854775808"`)},
		{"overflowing revision", replace(`"revision":"7"`, `"revision":"18446744073709551616"`)},
		{"numeric revision", replace(`"revision":"7"`, `"revision":7`)},
		{"fractional revision", replace(`"revision":"7"`, `"revision":7.5`)},
		{"scientific revision", replace(`"revision":"7"`, `"revision":"7e0"`)},
		{"padded revision", replace(`"revision":"7"`, `"revision":"07"`)},
		{"signed revision", replace(`"revision":"7"`, `"revision":"+7"`)},
		{"missing time", replace(`,"occurred_at":"2026-10-15T12:00:00.123456789Z"`, "")},
		{"null time", replace(`"2026-10-15T12:00:00.123456789Z"`, "null")},
		{"zero time", replace(`"2026-10-15T12:00:00.123456789Z"`, `"0001-01-01T00:00:00Z"`)},
		{"invalid time", replace(`"2026-10-15T12:00:00.123456789Z"`, `"private@example.invalid"`)},
		{"timestamp object", replace(`"2026-10-15T12:00:00.123456789Z"`, `{"seconds":1}`)},
		{"offset timestamp", replace(`"2026-10-15T12:00:00.123456789Z"`, `"2026-10-15T12:00:00.123456789+00:00"`)},
		{"leap second", replace(`"2026-10-15T12:00:00.123456789Z"`, `"2026-10-15T12:00:60Z"`)},
		{"excess timestamp precision", replace(`"2026-10-15T12:00:00.123456789Z"`, `"2026-10-15T12:00:00.1234567891Z"`)},
		{"unknown status", replace(`"USER_STATUS_ACTIVE"`, `"USER_STATUS_FUTURE"`)},
		{"unspecified status", replace(`"USER_STATUS_ACTIVE"`, `"USER_STATUS_UNSPECIFIED"`)},
		{"numeric status", replace(`"USER_STATUS_ACTIVE"`, "1")},
		{"unknown numeric status", replace(`"USER_STATUS_ACTIVE"`, "99")},
		{"database status", replace(`"USER_STATUS_ACTIVE"`, `"active"`)},
		{"null status", replace(`"USER_STATUS_ACTIVE"`, "null")},
		{"missing status", replace(`,"status":"USER_STATUS_ACTIVE"`, "")},
		{"unknown subject", replace(`"identity.user.updated"`, `"identity.user.credentials_changed"`)},
		{"creation missing email", replace(`"identity.user.updated"`, `"identity.user.created"`)},
		{"suspension with active status", replace(`"identity.user.updated"`, `"identity.user.suspended"`)},
		{"suspension mislabeled update", replace(`"USER_STATUS_ACTIVE"`, `"USER_STATUS_SUSPENDED"`)},
		{"empty fields", replace(`["status"]`, "[]")},
		{"null fields", replace(`["status"]`, "null")},
		{"missing fields", replace(`,"changed_fields":["status"]`, "")},
		{"duplicate fields", replace(`["status"]`, `["status","status"]`)},
		{"too many fields", replace(`["status"]`, `["status","email","status"]`)},
		{"numeric field", replace(`["status"]`, "[1]")},
		{"null field", replace(`["status"]`, "[null]")},
		{"generic field map", replace(`["status"]`, `{"email":"private@example.invalid"}`)},
		{"raw PII field value", replace(`["status"]`, `["private@example.invalid"]`)},
		{"credential field", replace(`["status"]`, `["webauthn_user_handle"]`)},
		{"unknown email property", appendField(`"email":"private@example.invalid"`)},
		{"unknown reason property", appendField(`"reason":"sensitive moderation narrative"`)},
		{"generic payload", appendField(`"payload":{"email":"private@example.invalid"}`)},
		{"deeply nested payload", appendField(`"payload":` + strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32))},
		{"duplicate schema", appendField(`"schema_version":1`)},
		{"duplicate ID", appendField(`"event_id":"` + wireEventID + `"`)},
		{"duplicate escaped ID", appendField(`"event_\u0069d":"` + wireEventID + `"`)},
		{"duplicate ID alias", appendField(`"eventId":"` + wireEventID + `"`)},
		{"duplicate revision", appendField(`"revision":"7"`)},
		{"duplicate revision null first", replace(`"revision":"7"`, `"revision":null,"revision":"7"`)},
		{"duplicate revision null last", appendField(`"revision":null`)},
		{"duplicate repeated field", appendField(`"changed_fields":["email"]`)},
		{"duplicate fields null first", replace(`"changed_fields":["status"]`, `"changed_fields":null,"changed_fields":["status"]`)},
		{"deleted explicit null revision", strings.Replace(wireDeleted, `"revision":"7"`, `"revision":null`, 1)},
		{"deleted explicit zero revision", strings.Replace(wireDeleted, `"revision":"7"`, `"revision":"0"`, 1)},
		{"deleted explicit null status", strings.TrimSuffix(wireDeleted, "}") + `,"status":null}`},
		{"deleted explicit null fields", strings.TrimSuffix(wireDeleted, "}") + `,"changed_fields":null}`},
		{"deleted explicit empty fields", strings.TrimSuffix(wireDeleted, "}") + `,"changed_fields":[]}`},
		{"oversized", strings.Repeat(" ", lifecycle.MaxMessageBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, err := lifecycle.UnmarshalEvent([]byte(tc.raw))
			if event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
				t.Fatalf("invalid wire accepted: %v, %v", event, err)
			}
			for _, sensitive := range []string{"private@example.invalid", "sensitive moderation narrative", "webauthn_user_handle", wireEventID, wireUserID} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatal("wire decoder error exposed untrusted content")
				}
			}
		})
	}
	for _, names := range [][2]string{{"schema_version", "schemaVersion"}, {"event_id", "eventId"}, {"event_type", "eventType"},
		{"user_id", "userId"}, {"occurred_at", "occurredAt"}, {"changed_fields", "changedFields"}} {
		t.Run("reader alias "+names[1], func(t *testing.T) {
			raw := replace(`"`+names[0]+`"`, `"`+names[1]+`"`)
			if event, err := lifecycle.UnmarshalEvent([]byte(raw)); event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
				t.Fatalf("non-proto field alias accepted: %v", err)
			}
		})
	}
}

func TestUnmarshalEventMessageSizeBoundaryAndWhitespace(t *testing.T) {
	// PostgreSQL jsonb may reorder keys and add whitespace; neither is semantic.
	reordered := `{"revision":"7", "changed_fields":["status"], "status":"USER_STATUS_ACTIVE", "occurred_at":"2026-10-15T12:00:00.123456789Z", "user_id":"` + wireUserID + `", "event_type":"identity.user.updated", "event_id":"` + wireEventID + `", "schema_version":1}`
	for _, raw := range []string{wireUpdated, reordered, "\n\t" + wireUpdated + " \r\n", wireUpdated + strings.Repeat(" ", lifecycle.MaxMessageBytes-len(wireUpdated))} {
		event, err := lifecycle.UnmarshalEvent([]byte(raw))
		if err != nil || !proto.Equal(event, updatedEvent(t)) {
			t.Fatalf("valid bounded metadata rejected: %v", err)
		}
	}
	oversized := wireUpdated + strings.Repeat(" ", lifecycle.MaxMessageBytes-len(wireUpdated)+1)
	if event, err := lifecycle.UnmarshalEvent([]byte(oversized)); event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatalf("oversized valid JSON accepted: %v", err)
	}
}

func FuzzUnmarshalEvent(f *testing.F) {
	for _, seed := range []string{wireUpdated, wireDeleted, strings.Replace(wireDeleted, `,"revision":"7"`, "", 1), "{}", "null",
		`{"user_id":"` + wireUserID + `"}`, strings.Repeat("[", 32), strings.Repeat(" ", lifecycle.MaxMessageBytes+1)} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		event, err := lifecycle.UnmarshalEvent(data)
		if err != nil {
			if event != nil || !errors.Is(err, lifecycle.ErrInvalidEvent) {
				t.Fatal("failed decoding returned data or an unclassified error")
			}
			return
		}
		encoded, err := lifecycle.MarshalEvent(event)
		if err != nil || len(encoded) > lifecycle.MaxMessageBytes {
			t.Fatalf("decoder admitted an unencodable envelope: %v", err)
		}
		roundtrip, err := lifecycle.UnmarshalEvent(encoded)
		if err != nil || !proto.Equal(event, roundtrip) {
			t.Fatalf("accepted event did not roundtrip: %v", err)
		}
	})
}
