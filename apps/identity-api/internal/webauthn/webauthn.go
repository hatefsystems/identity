// Package webauthn implements the WebAuthn/FIDO2 passwordless registration and
// login ceremonies for the identity-api service (Task 4.2). It wraps the
// go-webauthn library with the platform's persistence layer and the specific
// security properties mandated by docs/architecture.md
// ("Phishing-Resistant WebAuthn / FIDO2"):
//
//   - Origin & RP ID binding: the Relying Party ID is pinned to a clean domain
//     (e.g. "identity.hatef.ir") and every ceremony verifies the authenticator
//     origin against the configured RPOrigins, enforced inside the library's
//     ParsedCredential*.Verify step.
//   - Signature counter auditing: on each assertion the incoming sign count must
//     strictly exceed the stored value; a non-increasing counter raises the
//     library's clone warning and the login is rejected as a possible cloned
//     authenticator.
//   - Anonymized user.id mapping: the WebAuthn user handle is a CSPRNG-generated
//     random 64-bit value (never the account UUID), persisted once and mapped
//     internally to the real user, preventing cross-RP identity correlation.
//
// Following the conventions of the session and token packages, the backing
// stores are defined as interfaces (satisfied by the generated *db.Queries and
// an in-memory challenge store for the single-node MVP) so a Redis-backed
// challenge store can be slotted in later without touching the service or
// handlers.
package webauthn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

// userHandleByteLen is the size of the WebAuthn user handle: a random 64-bit
// (8-byte) value generated with crypto/rand, per docs/architecture.md
// ("Anonymized user.id Mapping") and docs/api-design.md §1.3. It is well within
// the spec's 64-byte maximum for a user handle.
const userHandleByteLen = 8

// Config carries the Relying Party settings and ceremony policy for the
// WebAuthn service. Values originate from the environment (see
// config.LoadWebAuthn); nothing here is secret.
type Config struct {
	// RPID is the Relying Party ID: the effective domain of the IdP with no
	// scheme, port, or path (e.g. "identity.hatef.ir"). The authenticator binds
	// credentials to this value and it must be a registrable suffix of every
	// origin in RPOrigins.
	RPID string
	// RPDisplayName is a human-palatable Relying Party name shown by some
	// authenticators/platform UIs.
	RPDisplayName string
	// RPOrigins is the allow-list of fully-qualified origins permitted to run a
	// ceremony (e.g. "https://identity.hatef.ir"). At least one is required.
	RPOrigins []string
	// ChallengeTTL bounds how long a begin-issued challenge remains valid before
	// the matching verify must arrive; it must be positive.
	ChallengeTTL time.Duration
	// UserVerification sets the default userVerification requirement
	// ("required", "preferred", or "discouraged"); empty defaults to the
	// library's "preferred".
	UserVerification string
}

// Transacter opens database transactions for atomic ceremony commits.
// *pgxpool.Pool satisfies it.
type Transacter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Option configures optional behavior on a Service.
type Option func(*Service)

// WithTransacter sets a database transaction opener for atomic ceremony commits.
func WithTransacter(tx Transacter) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

// Service orchestrates the WebAuthn registration and login ceremonies over the
// persistence layer. Construct it with New; the zero value is not usable.
type Service struct {
	wa         *gowebauthn.WebAuthn
	users      UserStore
	creds      CredentialStore
	challenges ChallengeStore
	tx         Transacter
	// challengeTTL is the validity window stamped onto each pending ceremony.
	challengeTTL time.Duration
	// now is injectable so challenge-expiry math is deterministic in tests.
	now func() time.Time
}

// New constructs a Service from its configuration and backing stores. It fails
// fast on an incomplete configuration (missing RP ID, no origins, non-positive
// TTL, nil store) or an RP ID / origin set the underlying library rejects, so
// misconfiguration surfaces at startup rather than mid-ceremony.
func New(cfg Config, users UserStore, creds CredentialStore, challenges ChallengeStore, opts ...Option) (*Service, error) {
	if users == nil {
		return nil, errors.New("webauthn: user store is required")
	}
	if creds == nil {
		return nil, errors.New("webauthn: credential store is required")
	}
	if challenges == nil {
		return nil, errors.New("webauthn: challenge store is required")
	}
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RPID is required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("webauthn: at least one RP origin is required")
	}
	if cfg.ChallengeTTL <= 0 {
		return nil, fmt.Errorf("webauthn: challenge TTL must be positive, got %v", cfg.ChallengeTTL)
	}

	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                   cfg.RPID,
		RPDisplayName:          cfg.RPDisplayName,
		RPOrigins:              cfg.RPOrigins,
		AuthenticatorSelection: gowebauthn.SelectAuthenticator("", nil, cfg.UserVerification),
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: build relying party: %w", err)
	}

	svc := &Service{
		wa:           wa,
		users:        users,
		creds:        creds,
		challenges:   challenges,
		challengeTTL: cfg.ChallengeTTL,
		now:          time.Now,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

// newUserHandle generates a fresh CSPRNG 64-bit WebAuthn user handle.
func newUserHandle() ([]byte, error) {
	h := make([]byte, userHandleByteLen)
	if _, err := rand.Read(h); err != nil {
		return nil, fmt.Errorf("webauthn: generate user handle: %w", err)
	}
	return h, nil
}
