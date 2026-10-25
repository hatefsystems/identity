package webauthn

import (
	"context"
	"encoding/json"
	"strings"
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
	// FlowStepUp is a re-authentication ceremony for an account the caller
	// already holds a live session for (Task 4.7). It differs from every login
	// flow in two ways: userVerification is "required" rather than the
	// configured default, and completing it grants no session — it only proves a
	// strong factor was re-presented, which internal/stepup turns into a
	// short-lived ACR grant. Tagging it separately is what stops a step-up
	// challenge being redeemed at the login verifier (where it would mint a
	// session) or a login challenge being redeemed for a step-up grant (where it
	// would bypass the UV requirement).
	FlowStepUp
	// FlowRecoveryRegistration is a UV-required passkey registration started
	// from a restricted recovery-enrollment session.
	FlowRecoveryRegistration
	// FlowReclaim is a UV-required assertion presented to cancel a pending
	// account deletion (Task 5.1). It is the one ceremony that operates on an
	// account webauthn.isLoginEligible refuses — a pending_deletion account —
	// which is exactly why it must be tagged separately: a reclaim challenge
	// redeemed at the login verifier would mint a session for an account that is
	// suspended from every service, and a login challenge redeemed here would
	// bypass the UV requirement the reclaim ceremony rests on. Completing it
	// grants no session at all; internal/privacy turns it into a status change.
	FlowReclaim
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
	case FlowStepUp:
		return "step_up"
	case FlowRecoveryRegistration:
		return "recovery_registration"
	case FlowReclaim:
		return "reclaim"
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
	// Named ceremonies pin a version; usernameless ceremonies pin a global
	// epoch so a ban/reactivation during the challenge cannot be overlooked.
	AuthVersion int64 `json:"auth_version,string"`
	AuthEpoch   int64 `json:"auth_epoch,string"`
	// Session is the go-webauthn SessionData produced by BeginRegistration /
	// BeginLogin and required verbatim by CreateCredential / ValidateLogin.
	Session gowebauthn.SessionData
	// UserRef is the owning account's real UUID primary key. It is uuid.Nil for
	// FlowLoginDiscoverable (the identity is unknown until the assertion
	// arrives) and for FlowLoginMock (there is no identity at all).
	UserRef uuid.UUID
	// SessionID binds authenticated ceremonies to the exact server-side
	// session that started them. Login ceremonies leave it empty.
	SessionID string
	// DPoPJKT is the verified browser key at ceremony start. It is mandatory
	// for login and checked before consuming state, never taken from the body.
	DPoPJKT string
	// Name is frozen at ordinary registration start, not supplied at verification.
	Name string
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
// Implementations must atomically check the expected binding before consuming
// state. A failed binding check must not burn another ceremony. Redis is the
// production authority; memory storage is only for isolated tests/development.
type ChallengeStore interface {
	// Save rejects collisions with live challenges instead of replacing them.
	Save(ctx context.Context, challenge string, pc PendingChallenge) error
	// Take has one winner for an exact binding match. Missing/expired state
	// requires a new ceremony; dependency failures never fall back locally.
	Take(ctx context.Context, challenge string, binding ChallengeBinding) (PendingChallenge, error)
}

// ChallengeBinding describes the authority of the completing request. Only the
// login endpoint accepts multiple flows: the identity is then challenge-owned
// (named login) or signature-resolved (discoverable), not caller-selected.
// Every other flow requires an exact account and session/deletion-request ID.
type ChallengeBinding struct {
	Flows     []Flow
	UserRef   uuid.UUID
	SessionID string
	DPoPJKT   string
}

// MaxChallengeTTL is the configured ceremony lifetime ceiling.
const (
	MaxChallengeTTL          = 15 * time.Minute
	maxChallengeBytes        = 64 << 10
	maxChallengeKeyBytes     = 256
	maxChallengeBindingBytes = 256
)

func isLoginFlow(flow Flow) bool {
	return flow == FlowLoginNamed || flow == FlowLoginDiscoverable || flow == FlowLoginMock
}

func (b ChallengeBinding) validate() error {
	if len(b.Flows) == 0 || len(b.Flows) > 3 {
		return ErrChallengeFlowMismatch
	}
	login := isLoginFlow(b.Flows[0])
	for _, flow := range b.Flows {
		if flow > FlowReclaim || isLoginFlow(flow) != login || (!login && len(b.Flows) != 1) {
			return ErrChallengeFlowMismatch
		}
	}
	if len(b.SessionID) > maxChallengeBindingBytes || len(b.DPoPJKT) > maxChallengeBindingBytes {
		return ErrChallengeNotFound
	}
	if login {
		if b.UserRef != uuid.Nil || b.SessionID != "" || strings.TrimSpace(b.DPoPJKT) == "" {
			return ErrChallengeNotFound
		}
	} else if b.UserRef == uuid.Nil || b.SessionID == "" {
		return ErrChallengeNotFound
	}
	return nil
}

func (b ChallengeBinding) matches(pc PendingChallenge) error {
	found := false
	for _, flow := range b.Flows {
		found = found || flow == pc.Flow
	}
	if !found {
		return ErrChallengeFlowMismatch
	}
	if (!isLoginFlow(pc.Flow) && pc.UserRef != b.UserRef) || pc.SessionID != b.SessionID || pc.DPoPJKT != b.DPoPJKT {
		return ErrChallengeNotFound
	}
	return nil
}

func validatePendingChallenge(challenge string, pc PendingChallenge) error {
	if challenge == "" || len(challenge) > maxChallengeKeyBytes || pc.Session.Challenge != challenge || pc.Flow > FlowReclaim ||
		pc.Expires.IsZero() || pc.AuthVersion < 0 || pc.AuthEpoch < 0 ||
		len(pc.SessionID) > maxChallengeBindingBytes || len(pc.DPoPJKT) > maxChallengeBindingBytes || len(pc.Name) > 320 {
		return ErrInvalidChallenge
	}
	if isLoginFlow(pc.Flow) {
		if pc.SessionID != "" || strings.TrimSpace(pc.DPoPJKT) == "" ||
			(pc.Flow == FlowLoginNamed && pc.UserRef == uuid.Nil) ||
			(pc.Flow != FlowLoginNamed && pc.UserRef != uuid.Nil) {
			return ErrInvalidChallenge
		}
	} else if pc.UserRef == uuid.Nil || pc.SessionID == "" {
		return ErrInvalidChallenge
	}
	if pc.Flow != FlowRegistration && pc.Name != "" {
		return ErrInvalidChallenge
	}
	return nil
}

func encodePendingChallenge(challenge string, pc PendingChallenge, now time.Time) ([]byte, time.Duration, error) {
	if err := validatePendingChallenge(challenge, pc); err != nil {
		return nil, 0, err
	}
	ttl := pc.Expires.Sub(now)
	if ttl < time.Millisecond {
		return nil, 0, ErrChallengeExpired
	}
	if ttl > MaxChallengeTTL {
		return nil, 0, ErrInvalidChallenge
	}
	data, err := json.Marshal(pc)
	if err != nil || len(data) > maxChallengeBytes {
		return nil, 0, ErrInvalidChallenge
	}
	return data, ttl, nil
}

func decodePendingChallenge(challenge string, data []byte) (PendingChallenge, error) {
	var pc PendingChallenge
	if len(data) == 0 || len(data) > maxChallengeBytes || json.Unmarshal(data, &pc) != nil {
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	if validatePendingChallenge(challenge, pc) != nil {
		return PendingChallenge{}, ErrChallengeStoreUnavailable
	}
	return pc, nil
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
func (m *MemoryChallengeStore) Save(ctx context.Context, challenge string, pc PendingChallenge) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, _, err := encodePendingChallenge(challenge, pc, m.now())
	if err != nil {
		return err
	}
	// Detach slices/maps just as Redis serialization does. Callers cannot mutate
	// a pending flow or its allowed credentials after a successful Save.
	pc, err = decodePendingChallenge(challenge, data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous, exists := m.byChallenge[challenge]; exists {
		if m.now().Before(previous.Expires) {
			return ErrChallengeConflict
		}
		delete(m.byChallenge, challenge)
	}

	if m.maxEntries > 0 && len(m.byChallenge) >= m.maxEntries {
		m.evictLocked()
	}

	m.byChallenge[challenge] = pc
	return nil
}

// evictLocked frees at least one slot. The caller must hold m.mu.
func (m *MemoryChallengeStore) evictLocked() {
	now := m.now()

	swept := false
	for key, entry := range m.byChallenge {
		if !now.Before(entry.Expires) {
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

// Take implements ChallengeStore. Binding mismatches intentionally leave
// the challenge live; expiry is still terminal and reclaims the entry.
func (m *MemoryChallengeStore) Take(ctx context.Context, challenge string, binding ChallengeBinding) (PendingChallenge, error) {
	if err := ctx.Err(); err != nil {
		return PendingChallenge{}, err
	}
	if err := binding.validate(); err != nil {
		return PendingChallenge{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return PendingChallenge{}, err
	}
	pc, ok := m.byChallenge[challenge]
	if !ok {
		return PendingChallenge{}, ErrChallengeNotFound
	}
	if !m.now().Before(pc.Expires) {
		delete(m.byChallenge, challenge)
		return PendingChallenge{}, ErrChallengeExpired
	}
	if err := binding.matches(pc); err != nil {
		return PendingChallenge{}, err
	}
	delete(m.byChallenge, challenge)
	return pc, nil
}
