package lifecycle_test

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

type intentStore struct {
	revision int64
	advances int
	rows     []db.InsertLifecycleEventParams
	advance  error
	insert   error
}

func (s *intentStore) AdvanceUserLifecycleRevision(context.Context, uuid.UUID) (int64, error) {
	s.advances++
	if s.advance != nil {
		return 0, s.advance
	}
	s.revision++
	return s.revision, nil
}

func (s *intentStore) InsertLifecycleEvent(_ context.Context, row db.InsertLifecycleEventParams) error {
	if s.insert != nil {
		return s.insert
	}
	s.rows = append(s.rows, row)
	return nil
}

func TestEnqueueStatusTransitions(t *testing.T) {
	for _, tc := range []struct{ before, after, subject string }{
		{"active", "suspended", lifecycle.SubjectSuspended},
		{"banned", "suspended", lifecycle.SubjectSuspended},
		{"active", "banned", lifecycle.SubjectUpdated},
		{"suspended", "active", lifecycle.SubjectUpdated},
		{"active", "pending_deletion", lifecycle.SubjectUpdated},
		{"pending_deletion", "active", lifecycle.SubjectUpdated},
		{"pending_verification", "active", lifecycle.SubjectUpdated},
	} {
		t.Run(tc.before+"_to_"+tc.after, func(t *testing.T) {
			store := &intentStore{revision: 8}
			id := uuid.New()
			if err := lifecycle.EnqueueStatusChange(context.Background(), store, id, tc.before, tc.after); err != nil {
				t.Fatal(err)
			}
			if store.advances != 1 || len(store.rows) != 1 {
				t.Fatal("logical transition must allocate exactly one revision and intent")
			}
			row := store.rows[0]
			event, err := lifecycle.UnmarshalEvent([]byte(row.Payload))
			if err != nil {
				t.Fatal(err)
			}
			if row.Subject != tc.subject || event.EventType != tc.subject || event.UserId != id.String() ||
				event.EventId != row.ID.String() || !row.LifecycleUserID.Valid || row.LifecycleUserID.UUID != id ||
				row.LifecycleRevision == nil || *row.LifecycleRevision != 9 || event.GetRevision() != 9 {
				t.Fatal("intent identity/revision differs from indexed metadata")
			}
			if !row.CreatedAt.Valid || row.CreatedAt.Time.Nanosecond()%1000 != 0 ||
				!event.OccurredAt.AsTime().Equal(row.CreatedAt.Time) || time.Since(row.CreatedAt.Time) > time.Minute {
				t.Fatal("event time must be captured once at PostgreSQL precision")
			}
			if len(event.ChangedFields) != 1 || event.ChangedFields[0] != "status" {
				t.Fatal("status mutation described unrelated profile fields")
			}
		})
	}
}

func TestSameStatusDoesNotAllocateRevisionOrEvent(t *testing.T) {
	for _, status := range []string{"active", "suspended", "banned", "pending_deletion", "pending_verification"} {
		store := &intentStore{revision: 7}
		if err := lifecycle.EnqueueStatusChange(context.Background(), store, uuid.New(), status, status); err != nil {
			t.Fatal(err)
		}
		if store.advances != 0 || len(store.rows) != 0 || store.revision != 7 {
			t.Fatal("same-status security invalidation became a lifecycle transition")
		}
	}
}

func TestEnqueueDeletionIsTerminalAndDoesNotUpdateRemovedUser(t *testing.T) {
	store := &intentStore{revision: 4}
	id := uuid.New()
	if err := lifecycle.EnqueueDeletion(context.Background(), store, id, 4); err != nil {
		t.Fatal(err)
	}
	if store.advances != 0 || len(store.rows) != 1 {
		t.Fatal("deletion must use the locked pre-delete revision without updating users")
	}
	event, err := lifecycle.UnmarshalEvent([]byte(store.rows[0].Payload))
	if err != nil || event.EventType != lifecycle.SubjectDeleted || event.GetRevision() != 5 ||
		event.UserId != id.String() || event.Status != nil || len(event.ChangedFields) != 0 {
		t.Fatalf("invalid tombstone: %v", err)
	}
	for _, revision := range []int64{-1, math.MaxInt64} {
		store.rows = nil
		if err := lifecycle.EnqueueDeletion(context.Background(), store, id, revision); !errors.Is(err, lifecycle.ErrInvalidEvent) || len(store.rows) != 0 {
			t.Fatal("invalid or overflowing deletion revision accepted")
		}
	}
}

func TestEnqueueFailuresAreRequiredAndSanitized(t *testing.T) {
	private := errors.New("private@example.invalid postgres://user:secret@host")
	for _, store := range []*intentStore{{advance: private}, {insert: private}} {
		err := lifecycle.EnqueueStatusChange(context.Background(), store, uuid.New(), "active", "banned")
		if !errors.Is(err, lifecycle.ErrEnqueue) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
			t.Fatal("persistence failure was hidden or disclosed database error contents")
		}
	}
	if err := lifecycle.EnqueueDeletion(context.Background(), &intentStore{insert: private}, uuid.New(), 0); !errors.Is(err, lifecycle.ErrEnqueue) {
		t.Fatal("terminal intent failure must abort deletion")
	}
	if err := lifecycle.EnqueueStatusChange(context.Background(), nil, uuid.New(), "active", "banned"); !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatal("nil status store accepted")
	}
	if err := lifecycle.EnqueueDeletion(context.Background(), nil, uuid.New(), 0); !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatal("nil deletion store accepted")
	}
	if _, err := lifecycle.CreateUser(context.Background(), nil, db.CreateUserParams{Status: "active"}); !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatal("creation accepted without a caller-owned transaction")
	}
}
