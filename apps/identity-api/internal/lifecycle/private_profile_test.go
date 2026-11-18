package lifecycle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

func TestPrivateProfileIntentCoarseStrictV2(t *testing.T) {
	store := &intentStore{revision: 9007199254740993}
	next, err := lifecycle.EnqueuePrivateProfileChange(t.Context(), store, uuid.New(), "active")
	if err != nil || next != 9007199254740994 || store.advances != 1 || len(store.rows) != 1 {
		t.Fatal("private update must allocate one exact revision and durable intent")
	}
	event, err := lifecycle.UnmarshalEvent([]byte(store.rows[0].Payload))
	if err != nil || event.SchemaVersion != 2 || event.EventType != lifecycle.SubjectUpdated || len(event.ChangedFields) != 1 || event.ChangedFields[0] != "private_profile" {
		t.Fatal("private intent not coarse v2 update")
	}
	for _, mode := range []string{"v1", "creation", "suspension", "duplicate", "individual field", "mixed", "inactive"} {
		copyEvent, err := lifecycle.UnmarshalEvent([]byte(store.rows[0].Payload))
		if err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "v1":
			copyEvent.SchemaVersion = 1
		case "creation":
			copyEvent.EventType = lifecycle.SubjectCreated
		case "suspension":
			copyEvent.EventType = lifecycle.SubjectSuspended
		case "duplicate":
			copyEvent.ChangedFields = []string{"private_profile", "private_profile"}
		case "individual field":
			copyEvent.ChangedFields = []string{"given_name"}
		case "mixed":
			copyEvent.ChangedFields = []string{"private_profile", "email"}
		case "inactive":
			copyEvent.Status = nil
		}
		if _, err := lifecycle.MarshalEvent(copyEvent); !errors.Is(err, lifecycle.ErrInvalidEvent) {
			t.Fatal("invalid private marker metadata accepted")
		}
	}
	for _, store := range []*intentStore{{advance: errors.New("secret data")}, {insert: errors.New("secret data")}} {
		if _, err := lifecycle.EnqueuePrivateProfileChange(t.Context(), store, uuid.New(), "active"); !errors.Is(err, lifecycle.ErrEnqueue) || strings.Contains(err.Error(), "secret") {
			t.Fatal("private enqueue failure hidden or leaked")
		}
	}
	for _, status := range []string{"banned", "suspended", "pending_verification", "pending_deletion", ""} {
		store := &intentStore{}
		if _, err := lifecycle.EnqueuePrivateProfileChange(t.Context(), store, uuid.New(), status); !errors.Is(err, lifecycle.ErrInvalidEvent) || store.advances != 0 {
			t.Fatal("ineligible private intent accepted")
		}
	}
}
