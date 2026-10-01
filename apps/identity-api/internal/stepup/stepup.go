// Package stepup implements the Step-up Authentication framework (Task 4.7):
// short-lived, single-use grants minted after the user re-asserts a strong
// factor, and required by the high-risk endpoints listed in
// docs/api-design.md (§1.3, §1.4, §1.5).
//
// A grant is a compact JWS signed by the same rotating keystore that signs
// access and ID tokens (internal/oidc/keys), carrying the authentication
// context class ACRStepUp. The format follows docs/architecture.md and
// docs/api-design.md, which describe "a short-lived token containing the ACR
// claim" — a claim is a JWT concept, and a signed grant is also verifiable by
// the internal token-validation RPC later without a round-trip to this service.
//
// Three properties make the grant safe, and all three are enforced in
// Service.Validate:
//
//   - Purpose binding. Access tokens, ID tokens, and grants are signed by the
//     same keys, and access tokens already use aud == iss (see
//     internal/oidc/token/service.go). The mandatory typ header
//     (token.TypStepUpToken) plus the acr claim is what stops an access token
//     being presented as a grant.
//   - Session binding. The sid claim pins the grant to the exact session that
//     earned it, so a grant captured from one session cannot be paired with
//     another session's cookie.
//   - Single use. A JWT cannot be revoked on its own, so the jti is consumed
//     through a ReplayGuard on first successful validation. This matches
//     docs/frontend-pages.md §5.3 ("Once executed, the state is cleared").
//
// Following the convention of the session, token, and DPoP packages, the
// replay guard is an interface with an in-memory implementation for the
// single-node MVP (replay.go). A Redis-backed guard (key stepup:jti:{jti},
// TTL equal to the grant lifetime per docs/data-architecture.md §3.1) can be
// slotted in later without touching the service, handlers, or middleware.
package stepup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// ACRStepUp is the Authentication Context Class Reference a step-up grant
// asserts (docs/architecture.md "Step-up Auth Context (ACR)",
// docs/api-design.md §1.3).
//
// It is deliberately a compile-time constant rather than configuration: it is a
// protocol identifier shared with clients, and a per-deployment value would
// invalidate in-flight grants during a rolling deploy for no benefit.
const ACRStepUp = "https://ref.hatef.ir/acr/stepup"

// HeaderStepUpAuth is the request header carrying a grant on a gated endpoint
// (docs/api-design.md §1.3-1.5).
const HeaderStepUpAuth = "X-Step-Up-Auth"

// Step-up method identifiers accepted by Service.Verify and reported by
// Service.Challenge.
const (
	// MethodWebAuthn is a WebAuthn assertion with user verification, the
	// phishing-resistant path (docs/architecture.md "User Presence (UP) vs.
	// User Verification (UV)").
	MethodWebAuthn = "webauthn"
	// MethodTOTP is an active TOTP passcode, the fallback for accounts whose
	// authenticator cannot perform user verification.
	MethodTOTP = "totp"
)

// Authentication Method Reference values recorded in the grant's amr claim
// (RFC 8176). Recovery codes are deliberately absent: they are a login bypass,
// so accepting one as a step-up factor would let a stolen code authorise the
// very operations the gate exists to protect (account deletion, regenerating
// the code batch, disabling MFA).
var (
	// amrWebAuthnUV describes a hardware-key assertion that performed user
	// verification: "hwk" (proof of possession of a hardware key) plus "user"
	// (the user was verified to the authenticator via PIN or biometric).
	amrWebAuthnUV = []string{"hwk", "user"}
	// amrTOTP describes a one-time-password factor.
	amrTOTP = []string{"otp"}
)

// maxTokenTTL is the hard ceiling on a grant's lifetime. Every document that
// mentions the window says "3-5 minutes" (docs/architecture.md,
// docs/api-design.md §1.3, docs/frontend-pages.md §5.3), so configuration may
// shorten it but never widen it past the published contract.
const maxTokenTTL = 5 * time.Minute

// DefaultTokenTTL is the grant lifetime applied when none is configured: the
// top of the documented 3-5 minute range, which is the most forgiving value a
// user completing a sensitive operation can be given.
const DefaultTokenTTL = 5 * time.Minute

// clockSkewLeeway bounds how far into the future an iat may sit before the
// grant is rejected. It absorbs small clock differences between the signing
// and validating process without creating a usable pre-dating window. Note
// there is no matching leeway on exp: expiry is enforced exactly.
const clockSkewLeeway = 5 * time.Second

// totpReplayWindow is how long a submitted TOTP passcode is remembered so it
// cannot mint a second grant.
//
// totp.ValidateCode accepts a code for the current step plus windowSteps on
// either side, so a single code stays valid for (2*windowSteps+1) periods. With
// the service default of one step and a 30-second period that is 90 seconds;
// remembering the code for that long covers its entire acceptance window
// without the stepup package needing to know which step actually matched.
const totpReplayWindow = 90 * time.Second

// KeyStore is the signing and verification surface a Service needs from the
// OIDC keystore. *keys.Manager satisfies it, so grants always follow the same
// active/next/previous rotation as access and ID tokens.
type KeyStore interface {
	// ActiveSigner returns the key currently used to sign new grants.
	ActiveSigner() *keys.SigningKey
	// VerificationKey resolves a key by kid across every rotation slot,
	// returning nil for an unknown kid.
	VerificationKey(kid string) *keys.SigningKey
}

// UserStore is the subset of the generated db.Queries the Service needs to
// decide which factors an account can present and to refuse an account that is
// no longer active. *db.Queries satisfies it.
type UserStore interface {
	// GetUserByID resolves a non-deleted account by its UUID primary key.
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
}

// PasskeyVerifier is the WebAuthn ceremony surface for the step-up flow.
// *webauthn.Service satisfies it.
//
// The user-verification requirement is enforced inside the implementation
// (both by the library, via the ceremony's userVerification: "required", and by
// an explicit flag assertion afterwards), so a nil error from FinishStepUp is
// itself the proof that a UV assertion was presented.
type PasskeyVerifier interface {
	// BeginStepUp issues a UV-required assertion ceremony for the account,
	// reporting ErrNoCredentials-equivalent domain errors when the account has
	// no passkey to assert.
	BeginStepUp(ctx context.Context, userID uuid.UUID, sessionID string) (*protocol.CredentialAssertion, error)
	// FinishStepUp verifies the assertion body against the pending step-up
	// ceremony for userID.
	FinishStepUp(ctx context.Context, userID uuid.UUID, sessionID string, body []byte) error
}

// TOTPVerifier is the TOTP surface for the step-up flow. *mfa.Service
// satisfies it.
type TOTPVerifier interface {
	// VerifyEnabledCode validates a passcode against the account's enabled TOTP
	// secret.
	VerifyEnabledCode(ctx context.Context, userID uuid.UUID, code string) error
}

// Config carries the step-up policy. Every field has a production-safe default
// (see New); nothing here is secret.
type Config struct {
	AccountState session.AccountState
	// Issuer is the OIDC issuer URL stamped into a grant's iss and aud claims
	// and required to match on validation. It is mandatory.
	Issuer string
	// TokenTTL is the grant lifetime. Zero selects DefaultTokenTTL; values
	// above maxTokenTTL are rejected.
	TokenTTL time.Duration
	// PerAccountPerMinute, PerAccountPerHour, and PerSubnetPerHour bound
	// verification attempts when a rate limiter is configured. The per-minute
	// account window is what makes a 6-digit TOTP code impractical to brute
	// force; the hourly windows bound sustained abuse.
	PerAccountPerMinute int
	PerAccountPerHour   int
	PerSubnetPerHour    int
}

// Step-up default policy values.
const (
	defaultPerAccountPerMinute = 5
	defaultPerAccountPerHour   = 20
	defaultPerSubnetPerHour    = 40
)

// Service mints and validates step-up grants and runs the challenge ceremony.
// Construct it with New; the zero value is not usable.
type Service struct {
	accounts session.AccountState
	keys     KeyStore
	users    UserStore
	passkeys PasskeyVerifier
	totp     TOTPVerifier
	guard    ReplayGuard
	limiter  ratelimit.Limiter

	issuer   string
	tokenTTL time.Duration

	perAccountPerMinute int
	perAccountPerHour   int
	perSubnetPerHour    int

	// now is injectable so lifetime and replay-window math is deterministic in
	// tests.
	now func() time.Time
}

// Option configures optional behaviour on a Service.
type Option func(*Service)

// WithRateLimiter attaches a sliding-window limiter so verification attempts
// are throttled per account and per subnet. When omitted the service applies no
// rate limiting, which keeps unit tests lightweight.
//
// In every non-development environment Redis is mandatory (see
// cmd/server/main.go buildRedisClient), so the limiter is always present in
// production.
func WithRateLimiter(l ratelimit.Limiter) Option {
	return func(s *Service) {
		s.limiter = l
	}
}

// WithClock overrides the time source. Tests inject a deterministic clock.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New constructs a Service from its configuration and collaborators.
//
// passkeys and totp are each optional, but at least one must be present: a
// service that can verify no factor could never mint a grant, so every gated
// endpoint behind it would be permanently unreachable. That is a configuration
// error worth failing at startup rather than discovering per request.
func New(
	cfg Config,
	keyStore KeyStore,
	users UserStore,
	passkeys PasskeyVerifier,
	totp TOTPVerifier,
	guard ReplayGuard,
	opts ...Option,
) (*Service, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("stepup: issuer is required")
	}
	if keyStore == nil {
		return nil, errors.New("stepup: key store is required")
	}
	if users == nil {
		return nil, errors.New("stepup: user store is required")
	}
	if guard == nil {
		return nil, errors.New("stepup: replay guard is required")
	}
	if passkeys == nil && totp == nil {
		return nil, errors.New("stepup: at least one of the passkey or TOTP verifier is required")
	}

	tokenTTL := cfg.TokenTTL
	if tokenTTL == 0 {
		tokenTTL = DefaultTokenTTL
	}
	if tokenTTL < 0 {
		return nil, fmt.Errorf("stepup: token TTL must be positive, got %v", tokenTTL)
	}
	if tokenTTL > maxTokenTTL {
		return nil, fmt.Errorf("stepup: token TTL %v exceeds the %v maximum", tokenTTL, maxTokenTTL)
	}

	svc := &Service{
		accounts:            cfg.AccountState,
		keys:                keyStore,
		users:               users,
		passkeys:            passkeys,
		totp:                totp,
		guard:               guard,
		issuer:              cfg.Issuer,
		tokenTTL:            tokenTTL,
		perAccountPerMinute: orDefaultInt(cfg.PerAccountPerMinute, defaultPerAccountPerMinute),
		perAccountPerHour:   orDefaultInt(cfg.PerAccountPerHour, defaultPerAccountPerHour),
		perSubnetPerHour:    orDefaultInt(cfg.PerSubnetPerHour, defaultPerSubnetPerHour),
		now:                 time.Now,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

// TokenTTL reports the configured grant lifetime so handlers can surface
// expires_in without duplicating the policy.
func (s *Service) TokenTTL() time.Duration { return s.tokenTTL }

// orDefaultInt returns v when positive, else fallback.
func orDefaultInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
