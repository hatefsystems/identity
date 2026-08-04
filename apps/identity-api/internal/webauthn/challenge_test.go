package webauthn

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// newFixedChallengeStore builds a MemoryChallengeStore whose clock is pinned to
// *now, so expiry can be triggered by advancing the variable rather than
// sleeping (mirrors the session package's fixed-clock test pattern).
func newFixedChallengeStore(now *time.Time) *MemoryChallengeStore {
	s := NewMemoryChallengeStore()
	s.now = func() time.Time { return *now }
	return s
}

// newPendingChallenge builds a minimal PendingChallenge for store-level tests.
func newPendingChallenge(challenge string, userRef uuid.UUID, expires time.Time) PendingChallenge {
	return PendingChallenge{
		Session: gowebauthn.SessionData{
			Challenge:      challenge,
			RelyingPartyID: "localhost",
			UserID:         []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		UserRef: userRef,
		Expires: expires,
	}
}

func TestMemoryChallengeStoreSaveTakeRoundTrip(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newFixedChallengeStore(&now)

	userRef := uuid.New()
	want := newPendingChallenge("chal-round-trip", userRef, now.Add(5*time.Minute))
	if err := store.Save(want.Session.Challenge, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Take("chal-round-trip")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.UserRef != userRef {
		t.Errorf("UserRef = %v, want %v", got.UserRef, userRef)
	}
	if got.Session.Challenge != want.Session.Challenge {
		t.Errorf("Session.Challenge = %q, want %q", got.Session.Challenge, want.Session.Challenge)
	}
	if got.Session.RelyingPartyID != "localhost" {
		t.Errorf("Session.RelyingPartyID = %q, want %q", got.Session.RelyingPartyID, "localhost")
	}
	if string(got.Session.UserID) != string(want.Session.UserID) {
		t.Errorf("Session.UserID = %x, want %x", got.Session.UserID, want.Session.UserID)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("Expires = %v, want %v", got.Expires, want.Expires)
	}
}

// TestMemoryChallengeStoreTakeIsSingleUse is the replay guard: a challenge is
// consumed on read, so a captured authenticator response can never be replayed.
func TestMemoryChallengeStoreTakeIsSingleUse(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newFixedChallengeStore(&now)

	pc := newPendingChallenge("chal-once", uuid.New(), now.Add(time.Minute))
	if err := store.Save(pc.Session.Challenge, pc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := store.Take("chal-once"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	if _, err := store.Take("chal-once"); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("second Take error = %v, want %v", err, ErrChallengeNotFound)
	}
}

func TestMemoryChallengeStoreTakeUnknown(t *testing.T) {
	store := NewMemoryChallengeStore()

	if _, err := store.Take("never-issued"); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Take error = %v, want %v", err, ErrChallengeNotFound)
	}
}

func TestMemoryChallengeStoreTakeExpired(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newFixedChallengeStore(&now)

	pc := newPendingChallenge("chal-expired", uuid.New(), now.Add(5*time.Minute))
	if err := store.Save(pc.Session.Challenge, pc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Exactly at the expiry instant the challenge is still valid (After is
	// strict), one nanosecond later it is not.
	now = pc.Expires
	if err := store.Save(pc.Session.Challenge, pc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.Take("chal-expired"); err != nil {
		t.Fatalf("Take at expiry instant: %v", err)
	}

	if err := store.Save(pc.Session.Challenge, pc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	now = pc.Expires.Add(time.Nanosecond)
	if _, err := store.Take("chal-expired"); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("Take after expiry error = %v, want %v", err, ErrChallengeExpired)
	}

	// The lapsed entry is reclaimed, so a retry reports it as unknown.
	if _, err := store.Take("chal-expired"); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Take after expiry sweep error = %v, want %v", err, ErrChallengeNotFound)
	}
}

// TestMemoryChallengeStoreTakeIsAtomic hammers a single saved challenge from
// many goroutines and asserts exactly one of them wins, which is the property
// the replay guard depends on under concurrency.
func TestMemoryChallengeStoreTakeIsAtomic(t *testing.T) {
	store := NewMemoryChallengeStore()
	pc := newPendingChallenge("chal-race", uuid.New(), time.Now().Add(time.Minute))
	if err := store.Save(pc.Session.Challenge, pc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	const goroutines = 32
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := store.Take("chal-race"); err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if winners != 1 {
		t.Fatalf("successful Take count = %d, want 1", winners)
	}
}

// TestMemoryChallengeStoreIsolatesChallenges proves entries do not interfere:
// consuming one leaves the others intact.
func TestMemoryChallengeStoreIsolatesChallenges(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	store := newFixedChallengeStore(&now)

	for _, c := range []string{"a", "b", "c"} {
		if err := store.Save(c, newPendingChallenge(c, uuid.New(), now.Add(time.Minute))); err != nil {
			t.Fatalf("Save(%q): %v", c, err)
		}
	}

	if _, err := store.Take("b"); err != nil {
		t.Fatalf("Take(b): %v", err)
	}
	for _, c := range []string{"a", "c"} {
		if _, err := store.Take(c); err != nil {
			t.Errorf("Take(%q) after unrelated Take: %v", c, err)
		}
	}
}

// TestMemoryChallengeStoreImplementsInterface is a compile-time assertion that
// the in-memory store stays substitutable for a future Redis-backed one.
func TestMemoryChallengeStoreImplementsInterface(_ *testing.T) {
	var _ ChallengeStore = (*MemoryChallengeStore)(nil)
}
