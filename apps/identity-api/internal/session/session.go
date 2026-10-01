// Package session implements stateful, server-side session management for the
// identity-api service. Sessions are the browser-facing counterpart to the
// OAuth/OIDC tokens: after a successful interactive authentication the server
// mints an opaque, high-entropy session token, stores the associated state
// server-side, and hands the client a hardened cookie (see cookie.go) that
// carries only the opaque token.
//
// Following the convention established by the token and DPoP packages, the
// backing store is defined as an interface with an in-memory implementation
// for the single-node MVP (memory.go). A Redis-backed implementation
// (key session:token:{token_hash}, Hash type, 24h TTL per
// docs/data-architecture.md §3.1) can be slotted in later behind the same
// interface without touching the manager or handlers.
//
// Secrets are never stored raw: the store is keyed by the SHA-256 digest of
// the session token (same technique as internal/oidc/token), so a dump of the
// store cannot be replayed against the service.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// tokenByteLen is the entropy of a generated session token: 256 bits from
// crypto/rand, matching the authorization-code / refresh-token strength.
const tokenByteLen = 32

// RecoveryEnrollmentTTL is the hard lifetime of a restricted recovery
// session. These sessions may only enroll one replacement UV passkey and can
// never authenticate normal account routes.
const RecoveryEnrollmentTTL = 10 * time.Minute

// Kind describes the authority carried by a server-side session.
type Kind string

const (
	// KindAuthenticated is a normal, fully authenticated browser session.
	KindAuthenticated Kind = "authenticated"
	// KindRecoveryEnrollment is a restricted session issued only after a
	// recovery code is consumed. It authorizes one replacement passkey.
	KindRecoveryEnrollment Kind = "recovery_enrollment"
)

// Store sentinel errors.
var (
	// ErrSessionNotFound indicates the session token is unknown, was revoked,
	// or has expired (idle or absolute).
	ErrSessionNotFound = errors.New("session: not found")
)

// Session is the server-side state bound to an issued session token. It mirrors
// the fields the Redis session hash is documented to hold in
// docs/data-architecture.md §3.1: user id, source IP, client device, and the
// DPoP key fingerprint when the session is sender-constrained.
type Session struct {
	// ID is a stable, non-secret public identifier for this session, safe to
	// expose to the owner for listing and targeted revocation
	// (GET/DELETE /api/v1/users/me/sessions). It is NOT the session token and
	// cannot be used to authenticate a request.
	ID string
	// Kind separates full authenticated sessions from deliberately restricted
	// recovery-enrollment sessions. Unknown and zero kinds are rejected.
	Kind Kind
	// UserID is the authenticated subject the session belongs to.
	UserID string
	// AuthVersion is captured by the authentication ceremony, never restamped.
	AuthVersion    int64
	AuthVersionSet bool
	// IP is the client source address captured at session creation.
	IP string
	// UserAgent identifies the client device/browser (data-architecture §3.1
	// "Client Device").
	UserAgent string
	// DPoPJKT is the JWK thumbprint of the DPoP key the session is bound to,
	// when sender-constrained (RFC 9449). Empty for bearer sessions.
	DPoPJKT string
	// CreatedAt is when the session was issued.
	CreatedAt time.Time
	// LastSeenAt is refreshed on each authenticated request (idle tracking).
	LastSeenAt time.Time
	// AbsoluteExpiry is the hard ceiling on session lifetime; it is never
	// extended, so a session always dies at CreatedAt+AbsoluteTTL regardless
	// of activity.
	AbsoluteExpiry time.Time
	// IdleExpiry slides forward on activity but is always clamped to
	// AbsoluteExpiry. A session lapses if it is idle past this instant.
	IdleExpiry time.Time
	// EnrollmentClaimed is an internal compare-and-set flag used to ensure a
	// recovery-enrollment session can persist at most one replacement factor.
	EnrollmentClaimed bool
}

// Store persists sessions keyed by the SHA-256 hash of the session token.
// Implementations must be safe for concurrent use.
type Store interface {
	// Create stores s under tokenHash. It overwrites any existing entry for
	// the same hash (hash collisions are cryptographically negligible).
	Create(tokenHash string, s Session) error
	// Get returns the session for tokenHash. Expired sessions (idle or
	// absolute) must be reported as ErrSessionNotFound and are eligible for
	// reclamation, mirroring Redis TTL semantics.
	Get(tokenHash string) (Session, error)
	// Touch slides the idle expiry of the session identified by tokenHash to
	// idleExpiry (already clamped to the absolute expiry by the caller). It is
	// a no-op returning ErrSessionNotFound when the session is gone.
	Touch(tokenHash string, idleExpiry time.Time) error
	// Delete removes the session identified by tokenHash. Deleting an unknown
	// session is not an error (idempotent logout).
	Delete(tokenHash string) error
	// ListForUser returns every live (non-expired) session belonging to
	// userID, ordered newest-first. It is the backing for
	// GET /api/v1/users/me/sessions.
	ListForUser(userID string) ([]Session, error)
	// DeleteForUser removes the session with the given public ID only when it
	// belongs to userID, and reports whether a session was removed. Scoping by
	// userID prevents one user revoking another's session.
	DeleteForUser(userID, sessionID string) (bool, error)
	// DeleteAllForUser removes every session belonging to userID. It backs the
	// "log out everywhere" action and the RTR breach response
	// (docs/architecture.md "Refresh Token Rotation").
	DeleteAllForUser(userID string) error
	// ClaimRecoveryEnrollment atomically claims the live restricted session
	// identified by its public ID. It returns false when the session is absent,
	// expired, the wrong kind, or was already claimed.
	ClaimRecoveryEnrollment(userID, sessionID string) (bool, error)
	// ReleaseRecoveryEnrollment releases a prior claim after a conclusively
	// failed enrollment ceremony so the caller may retry.
	ReleaseRecoveryEnrollment(userID, sessionID string) error
}

// NewToken generates a 256-bit random session token encoded as base64url, plus
// its SHA-256 hash used as the storage key so the raw token never rests in the
// store.
func NewToken() (token string, hash string, err error) {
	raw := make([]byte, tokenByteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("session: generate token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns the base64url-encoded SHA-256 digest of a session token,
// used as the storage key.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
