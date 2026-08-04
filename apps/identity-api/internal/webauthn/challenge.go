package webauthn

import (
	"sync"
	"time"

	"github.com/google/uuid"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// PendingChallenge is the server-side state stored between the Begin and Finish
// steps of a WebAuthn ceremony. It bundles the library's SessionData (challenge,
// RP ID, allowed credential IDs, user verification requirement) with the owning
// user's real UUID and an expiry instant so a challenge can never be replayed
// after its short TTL.
//
// The WebAuthn SessionData embeds the CSPRNG-generated 64-bit user handle as its
// UserID (never the account UUID); UserRef carries the real primary key so the
// Finish step can load the account and issue a session without re-deriving it
// from the anonymised handle.
type PendingChallenge struct {
	// Session is the go-webauthn SessionData produced by BeginRegistration /
	// BeginLogin and required verbatim by CreateCredential / ValidateLogin.
	Session gowebauthn.SessionData
	// UserRef is the owning account's real UUID primary key.
	UserRef uuid.UUID
	// Expires is the absolute instant after which the challenge is rejected.
	Expires time.Time
}

// ChallengeStore persists pending WebAuthn ceremonies keyed by the base64url
// challenge string. The challenge is returned to the client inside the Begin
// response's options and echoed back — inside the signed clientDataJSON — on
// Finish, which lets the verifier locate the matching SessionData without a
// separate flow identifier in the request body.
//
// Following the pattern of session.Store, this is an interface with an
// in-memory implementation for the single-node MVP; a Redis-backed store
// (key webauthn:challenge:{challenge}, short TTL per
// docs/data-architecture.md §3.1) can replace it later without touching the
// service. Implementations must be safe for concurrent use and must consume a
// challenge on read (Take) so it can be used at most once.
type ChallengeStore interface {
	// Save stores pc under the given challenge string.
	Save(challenge string, pc PendingChallenge) error
	// Take atomically returns and removes the pending challenge for the given
	// challenge string. It reports ErrChallengeNotFound when the challenge is
	// unknown or already consumed, and ErrChallengeExpired when it existed but
	// its TTL had lapsed (the entry is reclaimed either way).
	Take(challenge string) (PendingChallenge, error)
}

// MemoryChallengeStore is a thread-safe, in-memory ChallengeStore for the
// single-node MVP, mirroring session.MemoryStore. Expiry is enforced lazily on
// read; the clock is injectable so tests are deterministic.
type MemoryChallengeStore struct {
	mu sync.Mutex
	// byChallenge maps the base64url challenge string to its pending ceremony.
	byChallenge map[string]PendingChallenge
	// now is injectable so expiry behavior is deterministic in tests.
	now func() time.Time
}

// NewMemoryChallengeStore constructs an empty MemoryChallengeStore.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{
		byChallenge: make(map[string]PendingChallenge),
		now:         time.Now,
	}
}

// Save implements ChallengeStore.
func (m *MemoryChallengeStore) Save(challenge string, pc PendingChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byChallenge[challenge] = pc
	return nil
}

// Take implements ChallengeStore. It removes the entry on every path (hit,
// miss-after-expiry) so a challenge is single-use and lapsed entries are
// reclaimed, mirroring Redis TTL + GETDEL semantics.
func (m *MemoryChallengeStore) Take(challenge string) (PendingChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pc, ok := m.byChallenge[challenge]
	if !ok {
		return PendingChallenge{}, ErrChallengeNotFound
	}
	delete(m.byChallenge, challenge)
	if m.now().After(pc.Expires) {
		return PendingChallenge{}, ErrChallengeExpired
	}
	return pc, nil
}
