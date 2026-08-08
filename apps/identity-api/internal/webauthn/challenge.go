package webauthn

import (
	"sync"
	"time"

	"github.com/google/uuid"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Flow identifies which ceremony a pending challenge was issued for. The
// verifier for each flow asserts the tag before doing any work, so a challenge
// minted by one Begin step can never be redeemed by a different Finish step
// (e.g. a registration challenge replayed into the login verifier). The
// clientDataJSON ceremony type gives the same guarantee inside the library for
// the create/get split, but the tag also separates the three *login* variants,
// which the spec cannot distinguish for us.
type Flow uint8

const (
	// FlowRegistration is an attestation ceremony for an authenticated account.
	FlowRegistration Flow = iota
	// FlowLoginNamed is a user-named assertion ceremony: allowCredentials is
	// populated from the named account's registered credentials.
	FlowLoginNamed
	// FlowLoginDiscoverable is a usernameless assertion ceremony: the
	// allowCredentials list is empty and the authenticator selects the identity,
	// returning it as the userHandle. This is the primary secure login path
	// (docs/architecture.md "User Harvesting & Timing Attack Defenses").
	FlowLoginDiscoverable
	// FlowLoginMock is a decoy assertion ceremony handed to a user-named login
	// attempt for an identity that cannot log in. It is never completable; its
	// only purpose is to be byte-indistinguishable from FlowLoginNamed so the
	// endpoint cannot be used to enumerate accounts.
	FlowLoginMock
)

// String implements fmt.Stringer for log and error messages.
func (f Flow) String() string {
	switch f {
	case FlowRegistration:
		return "registration"
	case FlowLoginNamed:
		return "login_named"
	case FlowLoginDiscoverable:
		return "login_discoverable"
	case FlowLoginMock:
		return "login_mock"
	default:
		return "unknown"
	}
}

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
	// UserRef is the owning account's real UUID primary key. It is uuid.Nil for
	// FlowLoginDiscoverable (the identity is unknown until the assertion
	// arrives) and for FlowLoginMock (there is no identity at all).
	UserRef uuid.UUID
	// Flow records which ceremony issued this challenge; the matching Finish
	// step rejects any other value.
	Flow Flow
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

// defaultMaxPendingChallenges bounds how many ceremonies the in-memory store
// holds at once. The login options endpoint is unauthenticated and, since Task
// 4.3, issues a stored challenge for the discoverable flow and a *mock* one for
// unknown identities, so an attacker can mint entries without owning an account.
// Expiry alone does not bound memory (entries are only reclaimed when read),
// hence a hard cap: past it, already-lapsed entries are swept and otherwise the
// nearest-to-expiring entry is evicted, degrading into "some in-flight logins
// must be retried" rather than an OOM. Task 4.5's Redis rate limiting is the
// upstream fix; this is the backstop, and it is another reason a Redis-backed
// store (with native TTL reaping) is the production target.
const defaultMaxPendingChallenges = 10000

// MemoryChallengeStore is a thread-safe, in-memory ChallengeStore for the
// single-node MVP, mirroring session.MemoryStore. Expiry is enforced lazily on
// read; the clock is injectable so tests are deterministic.
type MemoryChallengeStore struct {
	mu sync.Mutex
	// byChallenge maps the base64url challenge string to its pending ceremony.
	byChallenge map[string]PendingChallenge
	// maxEntries caps the map size; zero disables the cap.
	maxEntries int
	// now is injectable so expiry behavior is deterministic in tests.
	now func() time.Time
}

// NewMemoryChallengeStore constructs an empty MemoryChallengeStore with the
// default capacity bound.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{
		byChallenge: make(map[string]PendingChallenge),
		maxEntries:  defaultMaxPendingChallenges,
		now:         time.Now,
	}
}

// Save implements ChallengeStore. When the store is at capacity it first sweeps
// entries whose TTL has already lapsed — usually enough, since challenges are
// short-lived — and only if that frees nothing does it evict the entry closest
// to expiring.
func (m *MemoryChallengeStore) Save(challenge string, pc PendingChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.maxEntries > 0 && len(m.byChallenge) >= m.maxEntries {
		if _, replacing := m.byChallenge[challenge]; !replacing {
			m.evictLocked()
		}
	}

	m.byChallenge[challenge] = pc
	return nil
}

// evictLocked frees at least one slot. The caller must hold m.mu.
func (m *MemoryChallengeStore) evictLocked() {
	now := m.now()

	swept := false
	for key, entry := range m.byChallenge {
		if now.After(entry.Expires) {
			delete(m.byChallenge, key)
			swept = true
		}
	}
	if swept {
		return
	}

	// Everything is still live, so drop whichever entry has the least remaining
	// validity: it is the one a legitimate user is least likely to still be able
	// to complete.
	var (
		oldestKey string
		oldest    time.Time
		found     bool
	)
	for key, entry := range m.byChallenge {
		if !found || entry.Expires.Before(oldest) {
			oldestKey, oldest, found = key, entry.Expires, true
		}
	}
	if found {
		delete(m.byChallenge, oldestKey)
	}
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
