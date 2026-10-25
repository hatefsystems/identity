package lifecycle_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

var (
	errContractReconcile = errors.New("consumer baseline requires reconciliation")
	errContractRetry     = errors.New("profile dependency must be retried")
)

// This is an executable consumer contract, not a production client. The JSON
// round trip models restarting from a locally committed projection/checkpoint.
type contractProjection struct {
	Revision    uint64
	Visible     bool
	Terminal    bool
	ClassA      string
	DisplayName string
	ClassB      string
	Scrubs      int
	Refreshes   int
}

type contractStore struct {
	StreamIdentity string
	Checkpoint     uint64
	Seen           map[string]bool
	Users          map[string]contractProjection
}

func contractBaseline() *contractStore {
	return &contractStore{
		StreamIdentity: "IDENTITY_USERS/2026-10-22T00:00:00Z",
		Seen:           map[string]bool{}, Users: map[string]contractProjection{},
	}
}

func (s *contractStore) resume(identity string, first uint64, consumerExists bool) error {
	if !consumerExists || s.StreamIdentity == "" || identity != s.StreamIdentity || first > s.Checkpoint+1 {
		return errContractReconcile
	}
	return nil
}

func (s *contractStore) refresh(user string, triggeringRevision uint64, snapshot *identityv1.GetInternalUserInfoResponse) error {
	current := s.Users[user]
	if current.Terminal || triggeringRevision < current.Revision {
		return nil
	}
	if snapshot == nil { // NotFound is reversible unavailability, not erasure.
		current.Revision, current.Visible = triggeringRevision, false
	} else {
		if snapshot.UserId != user || snapshot.LifecycleRevision < triggeringRevision || snapshot.LifecycleRevision < current.Revision {
			return errContractRetry
		}
		current.Revision, current.Visible = snapshot.LifecycleRevision, true
		current.DisplayName = snapshot.DisplayName
	}
	current.Refreshes++
	s.Users[user] = current
	return nil
}

func (s *contractStore) consume(identity string, sequence uint64, payload []byte, resolve func() (*identityv1.GetInternalUserInfoResponse, error)) error {
	event, err := lifecycle.UnmarshalEvent(payload)
	if err != nil || s.StreamIdentity == "" || identity != s.StreamIdentity {
		return errContractReconcile
	}
	if sequence <= s.Checkpoint {
		if s.Seen[event.EventId] {
			return nil
		}
		return errContractReconcile
	}
	if sequence != s.Checkpoint+1 {
		return errContractReconcile
	}
	current := s.Users[event.UserId]
	if !s.Seen[event.EventId] && !current.Terminal {
		if event.EventType == lifecycle.SubjectDeleted {
			current.Terminal, current.Visible, current.ClassA = true, false, ""
			current.DisplayName = ""
			current.Revision = max(current.Revision, event.GetRevision())
			current.Scrubs++
			s.Users[event.UserId] = current
		} else if event.GetRevision() > current.Revision {
			snapshot, err := resolve()
			if err != nil {
				return errContractRetry
			}
			if err := s.refresh(event.UserId, event.GetRevision(), snapshot); err != nil {
				return err
			}
		}
	}
	// In a real consumer these three writes share one durable local transaction;
	// only its successful commit permits the subsequent broker acknowledgement.
	s.Seen[event.EventId] = true
	s.Checkpoint = sequence
	return nil
}

func TestConsumerContractMixedVersionsAndLegacyNameErasure(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "revisioned deletion", true: "legacy tombstone"}[legacy], func(t *testing.T) {
			s, user := contractBaseline(), uuid.New()
			s.Users[user.String()] = contractProjection{ClassB: "retained evidence"}
			named, err := lifecycle.NewDisplayNameEvent(uuid.New(), user, 2, "active", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			events := []*identityv1.UserLifecycleEvent{contractEvent(t, user, 1, lifecycle.SubjectCreated), named,
				contractEvent(t, user, 3, lifecycle.SubjectSuspended), contractEvent(t, user, 4, lifecycle.SubjectUpdated)}
			for i, event := range events {
				name := "Private shared name"
				if event.EventType == lifecycle.SubjectSuspended {
					name = ""
				}
				if err := s.consume(s.StreamIdentity, uint64(i+1), contractPayload(t, event), func() (*identityv1.GetInternalUserInfoResponse, error) {
					return &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: event.GetRevision(), DisplayName: name}, nil
				}); err != nil || s.Users[user.String()].DisplayName != name {
					t.Fatalf("mixed-version refresh failed: %v", err)
				}
				s = reloadContract(t, s)
			}
			if err := s.consume(s.StreamIdentity, 5, contractPayload(t, named), nil); err != nil || s.Users[user.String()].Revision != 4 || s.Users[user.String()].Refreshes != 4 {
				t.Fatal("old v2 replay repeated or regressed profile refresh")
			}
			deleted := contractEvent(t, user, 5, lifecycle.SubjectDeleted)
			if legacy {
				deleted.Revision = nil
			}
			if err := s.consume(s.StreamIdentity, 6, contractPayload(t, deleted), nil); err != nil {
				t.Fatal(err)
			}
			s = reloadContract(t, s)
			future, err := lifecycle.NewDisplayNameEvent(uuid.New(), user, 99, "active", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			for i, event := range []*identityv1.UserLifecycleEvent{named, future, deleted} {
				if err := s.consume(s.StreamIdentity, uint64(7+i), contractPayload(t, event), nil); err != nil {
					t.Fatal(err)
				}
			}
			projection := s.Users[user.String()]
			if !projection.Terminal || projection.Visible || projection.DisplayName != "" || projection.Scrubs != 1 || projection.ClassB != "retained evidence" || projection.Refreshes != 4 {
				t.Fatal("mixed-version replay resurrected name or erased retained evidence")
			}
		})
	}
}

func contractEvent(t *testing.T, user uuid.UUID, revision int64, subject string) *identityv1.UserLifecycleEvent {
	t.Helper()
	status, fields := "active", []string{"status"}
	switch subject {
	case lifecycle.SubjectCreated:
		fields = []string{"email", "status"}
	case lifecycle.SubjectSuspended:
		status = "suspended"
	case lifecycle.SubjectDeleted:
		status, fields = "", nil
	}
	event, err := lifecycle.NewEvent(uuid.New(), user, revision, subject, status, fields, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func contractPayload(t *testing.T, event *identityv1.UserLifecycleEvent) []byte {
	t.Helper()
	payload, err := lifecycle.MarshalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func reloadContract(t *testing.T, s *contractStore) *contractStore {
	t.Helper()
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := new(contractStore)
	if err := json.Unmarshal(encoded, reloaded); err != nil {
		t.Fatal(err)
	}
	return reloaded
}

func TestConsumerContractDurableReplayAndTerminalProtection(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "revisioned", true: "legacy"}[legacy], func(t *testing.T) {
			s := contractBaseline()
			user := uuid.New()
			s.Users[user.String()] = contractProjection{ClassA: "application profile", ClassB: "protected evidence"}
			created := contractEvent(t, user, 1, lifecycle.SubjectCreated)
			resolveCalls := 0
			resolve := func() (*identityv1.GetInternalUserInfoResponse, error) {
				resolveCalls++
				return &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: 1}, nil
			}
			if err := s.consume(s.StreamIdentity, 1, contractPayload(t, created), resolve); err != nil {
				t.Fatal(err)
			}
			// A new broker sequence models republication after its finite dedup
			// window; the stable ID survives our local process restart indefinitely.
			s = reloadContract(t, s)
			if err := s.consume(s.StreamIdentity, 2, contractPayload(t, created), resolve); err != nil || resolveCalls != 1 {
				t.Fatalf("stable-ID replay had effects: calls=%d err=%v", resolveCalls, err)
			}
			duplicateRevision := contractEvent(t, user, 1, lifecycle.SubjectUpdated)
			if err := s.consume(s.StreamIdentity, 3, contractPayload(t, duplicateRevision), resolve); err != nil || resolveCalls != 1 {
				t.Fatalf("revision replay had effects: calls=%d err=%v", resolveCalls, err)
			}
			deleted := contractEvent(t, user, 3, lifecycle.SubjectDeleted)
			if legacy {
				deleted.Revision = nil
			}
			if err := s.consume(s.StreamIdentity, 4, contractPayload(t, deleted), nil); err != nil {
				t.Fatal(err)
			}
			s = reloadContract(t, s)
			for i, event := range []*identityv1.UserLifecycleEvent{deleted, contractEvent(t, user, 2, lifecycle.SubjectUpdated), contractEvent(t, user, 99, lifecycle.SubjectUpdated)} {
				if err := s.consume(s.StreamIdentity, uint64(5+i), contractPayload(t, event), resolve); err != nil {
					t.Fatal(err)
				}
			}
			projection := s.Users[user.String()]
			if !projection.Terminal || projection.Visible || projection.ClassA != "" || projection.ClassB != "protected evidence" || projection.Scrubs != 1 || resolveCalls != 1 {
				t.Fatalf("replay resurrected or erased protected state: %+v calls=%d", projection, resolveCalls)
			}
		})
	}
}

func TestConsumerContractRPCSnapshotAndLateNotFound(t *testing.T) {
	for _, lateNotFound := range []bool{false, true} {
		t.Run(map[bool]string{false: "late stale snapshot", true: "late NotFound"}[lateNotFound], func(t *testing.T) {
			s, user := contractBaseline(), uuid.New()
			event := contractEvent(t, user, 3, lifecycle.SubjectUpdated)
			resolve := func() (*identityv1.GetInternalUserInfoResponse, error) {
				// A newer RPC refresh commits while this older request is in flight.
				if err := s.refresh(user.String(), 4, &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: 8}); err != nil {
					t.Fatal(err)
				}
				if lateNotFound {
					return nil, nil
				}
				return &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: 3}, nil
			}
			if err := s.consume(s.StreamIdentity, 1, contractPayload(t, event), resolve); err != nil {
				t.Fatal(err)
			}
			if got := s.Users[user.String()]; got.Revision != 8 || !got.Visible || got.Refreshes != 1 || s.Checkpoint != 1 {
				t.Fatalf("late response overwrote newer snapshot: %+v", got)
			}
		})
	}

	s, user := contractBaseline(), uuid.New()
	s.Users[user.String()] = contractProjection{Revision: 1, Visible: true, ClassA: "application profile", ClassB: "protected evidence"}
	event := contractEvent(t, user, 2, lifecycle.SubjectUpdated)
	payload := contractPayload(t, event)
	for _, resolver := range []func() (*identityv1.GetInternalUserInfoResponse, error){
		func() (*identityv1.GetInternalUserInfoResponse, error) { return nil, errContractRetry },
		func() (*identityv1.GetInternalUserInfoResponse, error) {
			return &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: 1}, nil
		},
	} {
		if err := s.consume(s.StreamIdentity, 1, payload, resolver); !errors.Is(err, errContractRetry) || s.Checkpoint != 0 || s.Seen[event.EventId] || s.Users[user.String()].Revision != 1 {
			t.Fatalf("failed dependency/stale RPC was acknowledged: err=%v state=%+v", err, s)
		}
	}
	if err := s.consume(s.StreamIdentity, 1, payload, func() (*identityv1.GetInternalUserInfoResponse, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if got := s.Users[user.String()]; got.Visible || got.Terminal || got.ClassA == "" || got.ClassB == "" || got.Scrubs != 0 || got.Revision != 2 || s.Checkpoint != 1 {
		t.Fatalf("NotFound erased state or failed to checkpoint temporary invalidation: %+v", got)
	}
	reclaimed := contractEvent(t, user, 3, lifecycle.SubjectUpdated)
	if err := s.consume(s.StreamIdentity, 2, contractPayload(t, reclaimed), func() (*identityv1.GetInternalUserInfoResponse, error) {
		return &identityv1.GetInternalUserInfoResponse{UserId: user.String(), LifecycleRevision: 7}, nil
	}); err != nil || !s.Users[user.String()].Visible || s.Users[user.String()].Revision != 7 {
		t.Fatalf("reclaim/newer RPC did not advance reversible state: %v", err)
	}
}

func TestConsumerContractRequiresReconciledHistory(t *testing.T) {
	s, user := contractBaseline(), uuid.New()
	event := contractEvent(t, user, 1, lifecycle.SubjectCreated)
	payload := contractPayload(t, event)
	unknown := proto.Clone(event).(*identityv1.UserLifecycleEvent)
	unknown.SchemaVersion = 3
	// A future writer is outside today's strict MarshalEvent contract.
	var wire map[string]any
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	wire["schema_version"] = unknown.SchemaVersion
	unknownPayload, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, identity string
		sequence       uint64
		payload        []byte
	}{
		{"unknown schema", s.StreamIdentity, 1, unknownPayload},
		{"recreated stream", "IDENTITY_USERS/2026-10-23T00:00:00Z", 1, payload},
		{"sequence gap", s.StreamIdentity, 3, payload},
		{"truncated bootstrap", s.StreamIdentity, 500, payload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.consume(tc.identity, tc.sequence, tc.payload, nil); !errors.Is(err, errContractReconcile) || s.Checkpoint != 0 || len(s.Seen) != 0 || len(s.Users) != 0 {
				t.Fatalf("untrusted history advanced baseline: %v %+v", err, s)
			}
		})
	}
	for _, tc := range []struct {
		identity string
		first    uint64
		exists   bool
	}{
		{s.StreamIdentity, 1, false},
		{s.StreamIdentity, 2, true},
		{"recreated", 1, true},
	} {
		if err := s.resume(tc.identity, tc.first, tc.exists); !errors.Is(err, errContractReconcile) {
			t.Fatalf("missing consumer/reset/expired history accepted: %v", err)
		}
	}
	s.StreamIdentity = ""
	if err := s.consume("new stream", 1, payload, nil); !errors.Is(err, errContractReconcile) {
		t.Fatal("fresh consumer silently treated retained messages as a complete inventory")
	}
}
