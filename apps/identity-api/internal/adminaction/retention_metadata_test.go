package adminaction

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

func TestRetentionMetadataBoundedAndClassC(t *testing.T) {
	id := uuid.New()
	event, err := sanitizedEvent(audit.Event{
		EventType: audit.EventLegalLedgerPurged, ActionStatus: audit.StatusSuccess,
		Security: &audit.SecurityContext{AccountRef: id}, SubjectID: &id,
		Payload: map[string]any{
			"operation_id": id, "cutoff": time.Now(), "considered_count": 5000,
			"deleted_count": 4999, "held_count": 1, "dry_run": false, "outcome": "purged",
			"account_ref": id.String(), "source_event_id": uuid.New().String(), "checkpoint_history": "forbidden",
		},
	}, id)
	if err != nil {
		t.Fatal(err)
	}
	if event.Security != nil || event.SubjectID != nil {
		t.Fatal("maintenance metadata must be Class C only")
	}
	for _, key := range []string{"account_ref", "source_event_id", "checkpoint_history"} {
		if _, ok := event.Payload[key]; ok {
			t.Fatalf("metadata leaked %s", key)
		}
	}
	for _, key := range []string{"considered_count", "deleted_count", "held_count", "would_delete"} {
		for _, value := range []any{-1, 5001, "account identifier"} {
			_, err := sanitizedEvent(audit.Event{EventType: audit.EventLegalLedgerPurged, ActionStatus: audit.StatusSuccess,
				Payload: map[string]any{key: value}}, id)
			if err == nil {
				t.Fatalf("accepted invalid %s=%v", key, value)
			}
		}
	}
}
