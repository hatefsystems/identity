package session

import (
	"testing"
	"time"
)

// newFixedStore returns a MemoryStore whose clock is pinned to *at, so tests
// can advance time deterministically by reassigning the pointed-to value.
func newFixedStore(at *time.Time) *MemoryStore {
	s := NewMemoryStore()
	s.now = func() time.Time { return *at }
	return s
}

// liveSession builds a session that is well within both deadlines relative to
// base, owned by userID with the given public id.
func liveSession(base time.Time, userID, id string) Session {
	return Session{
		ID:             id,
		UserID:         userID,
		CreatedAt:      base,
		LastSeenAt:     base,
		AbsoluteExpiry: base.Add(24 * time.Hour),
		IdleExpiry:     base.Add(2 * time.Hour),
	}
}

func TestMemoryCreateAndGet(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	want := liveSession(base, "user-1", "sess-1")
	if err := store.Create("hash-1", want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get("hash-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.UserID != want.UserID {
		t.Fatalf("Get returned %+v, want %+v", got, want)
	}
}

func TestMemoryGetUnknown(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if _, err := store.Get("missing"); err != ErrSessionNotFound {
		t.Fatalf("Get(missing) error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemoryGetExpiredByIdle(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-1", liveSession(base, "user-1", "sess-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Advance past the idle deadline but before the absolute deadline.
	now = base.Add(3 * time.Hour)
	if _, err := store.Get("hash-1"); err != ErrSessionNotFound {
		t.Fatalf("Get after idle expiry error = %v, want ErrSessionNotFound", err)
	}
	// The lapsed entry must have been reclaimed from the user index too.
	sessions, err := store.ListForUser("user-1")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected expired session reclaimed, got %d", len(sessions))
	}
}

func TestMemoryGetExpiredByAbsolute(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	s := liveSession(base, "user-1", "sess-1")
	// Keep idle sliding, but the absolute ceiling still kills it.
	s.IdleExpiry = base.Add(24 * time.Hour)
	if err := store.Create("hash-1", s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	now = base.Add(25 * time.Hour)
	if _, err := store.Get("hash-1"); err != ErrSessionNotFound {
		t.Fatalf("Get after absolute expiry error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemoryTouchSlidesIdle(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-1", liveSession(base, "user-1", "sess-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	now = base.Add(1 * time.Hour)
	newIdle := now.Add(2 * time.Hour)
	if err := store.Touch("hash-1", newIdle); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	got, err := store.Get("hash-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.IdleExpiry.Equal(newIdle) {
		t.Fatalf("IdleExpiry = %v, want %v", got.IdleExpiry, newIdle)
	}
	if !got.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v", got.LastSeenAt, now)
	}
}

func TestMemoryTouchUnknown(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)
	if err := store.Touch("missing", now.Add(time.Hour)); err != ErrSessionNotFound {
		t.Fatalf("Touch(missing) error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemoryDeleteIdempotent(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-1", liveSession(base, "user-1", "sess-1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Delete("hash-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Deleting again is not an error.
	if err := store.Delete("hash-1"); err != nil {
		t.Fatalf("Delete (second): %v", err)
	}
	if _, err := store.Get("hash-1"); err != ErrSessionNotFound {
		t.Fatalf("Get after delete error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemoryListForUserNewestFirst(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	older := liveSession(base, "user-1", "old")
	newer := liveSession(base.Add(time.Minute), "user-1", "new")
	if err := store.Create("hash-old", older); err != nil {
		t.Fatalf("Create old: %v", err)
	}
	if err := store.Create("hash-new", newer); err != nil {
		t.Fatalf("Create new: %v", err)
	}

	sessions, err := store.ListForUser("user-1")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("ListForUser returned %d sessions, want 2", len(sessions))
	}
	if sessions[0].ID != "new" || sessions[1].ID != "old" {
		t.Fatalf("ListForUser order = [%s, %s], want [new, old]", sessions[0].ID, sessions[1].ID)
	}
}

func TestMemoryListForUserScoped(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-a", liveSession(base, "user-1", "a")); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	if err := store.Create("hash-b", liveSession(base, "user-2", "b")); err != nil {
		t.Fatalf("Create b: %v", err)
	}

	sessions, err := store.ListForUser("user-1")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != "a" {
		t.Fatalf("ListForUser(user-1) = %+v, want only session a", sessions)
	}
}

func TestMemoryDeleteForUserScoping(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-a", liveSession(base, "user-1", "sess-a")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A different user cannot revoke user-1's session.
	removed, err := store.DeleteForUser("user-2", "sess-a")
	if err != nil {
		t.Fatalf("DeleteForUser: %v", err)
	}
	if removed {
		t.Fatal("DeleteForUser allowed a foreign user to revoke a session")
	}

	// The owner can.
	removed, err = store.DeleteForUser("user-1", "sess-a")
	if err != nil {
		t.Fatalf("DeleteForUser: %v", err)
	}
	if !removed {
		t.Fatal("DeleteForUser did not remove the owner's session")
	}

	// Revoking an unknown id reports not-removed.
	removed, err = store.DeleteForUser("user-1", "sess-a")
	if err != nil {
		t.Fatalf("DeleteForUser: %v", err)
	}
	if removed {
		t.Fatal("DeleteForUser reported removal of an already-deleted session")
	}
}

func TestMemoryDeleteAllForUser(t *testing.T) {
	base := time.Now()
	now := base
	store := newFixedStore(&now)

	if err := store.Create("hash-a", liveSession(base, "user-1", "a")); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	if err := store.Create("hash-b", liveSession(base, "user-1", "b")); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if err := store.Create("hash-c", liveSession(base, "user-2", "c")); err != nil {
		t.Fatalf("Create c: %v", err)
	}

	if err := store.DeleteAllForUser("user-1"); err != nil {
		t.Fatalf("DeleteAllForUser: %v", err)
	}

	sessions, err := store.ListForUser("user-1")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("user-1 still has %d sessions after DeleteAllForUser", len(sessions))
	}

	// user-2 is untouched.
	other, err := store.ListForUser("user-2")
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(other) != 1 {
		t.Fatalf("user-2 has %d sessions, want 1 (bulk revoke leaked across users)", len(other))
	}
}
