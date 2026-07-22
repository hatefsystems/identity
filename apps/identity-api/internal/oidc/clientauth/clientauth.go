// Package clientauth implements RFC 7523 private_key_jwt client authentication
// for the token endpoint. Confidential internal clients (the Search Engine and
// Email Service, docs/client-integration.md §2) authenticate by presenting a
// short-lived JWT client assertion signed with their private key; the platform
// verifies it against the client's pre-registered public keys (never a shared
// secret, per docs/architecture.md "Secure Client Authentication").
//
// The Authenticator satisfies token.ClientAuthenticator. It enforces the full
// RFC 7523 §3 profile:
//
//   - client_assertion_type is exactly the jwt-bearer URN;
//   - the assertion is a compact JWS signed with RS256 or ES256 only — "none"
//     and any HS* MAC are structurally rejected;
//   - iss == sub == a registered client_id (and, when present, the client_id
//     form parameter must agree);
//   - the signing key is selected by the assertion's "kid" header and must be
//     one of the client's registered public keys;
//   - aud equals the token endpoint URL (audience confusion defence);
//   - exp is present, unexpired, and no more than maxAssertionLifetime in the
//     future (a stolen assertion is useless for long);
//   - jti is present and single-use — a replayed jti is rejected via the
//     JTIReplayGuard.
package clientauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// AssertionType is the required value of the client_assertion_type parameter
// (RFC 7523 §2.2).
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// DefaultMaxAssertionLifetime bounds how far in the future an assertion's exp
// may sit. Assertions are meant to be ephemeral; a generous but firm ceiling
// limits the blast radius of a leaked assertion (docs/architecture.md).
const DefaultMaxAssertionLifetime = 5 * time.Minute

// clockSkewLeeway tolerates small clock differences between the client and the
// IdP when validating exp/iat so legitimate assertions are not rejected.
const clockSkewLeeway = 60 * time.Second

// Errors returned by Authenticate. They are deliberately specific to aid
// server-side logging and testing; the token endpoint collapses all of them
// into a single opaque invalid_client response so nothing leaks to callers.
var (
	ErrMissingAssertion       = errors.New("clientauth: missing client_assertion")
	ErrUnsupportedType        = errors.New("clientauth: unsupported client_assertion_type")
	ErrMalformedAssertion     = errors.New("clientauth: malformed client assertion")
	ErrUnsupportedAlg         = errors.New("clientauth: unsupported assertion algorithm")
	ErrIssuerSubjectMismatch  = errors.New("clientauth: assertion iss and sub must be equal")
	ErrClientIDMismatch       = errors.New("clientauth: client_id does not match assertion issuer")
	ErrUnknownKey             = errors.New("clientauth: no registered key matches the assertion kid")
	ErrBadAudience            = errors.New("clientauth: assertion audience does not match the token endpoint")
	ErrExpired                = errors.New("clientauth: assertion is expired")
	ErrExcessiveLifetime      = errors.New("clientauth: assertion exp is too far in the future")
	ErrMissingJTI             = errors.New("clientauth: assertion is missing jti")
	ErrReplay                 = errors.New("clientauth: assertion jti has already been used")
	ErrSignature              = errors.New("clientauth: assertion signature is invalid")
	ErrNotConfidentialClient  = errors.New("clientauth: client is not a private_key_jwt client")
	ErrInvalidAssertionClaims = errors.New("clientauth: invalid assertion claims")
)

// JTIReplayGuard provides single-use enforcement of assertion jti values. The
// in-memory implementation here backs the MVP; the interface is intentionally
// small so a Redis-backed guard (shared across instances) can replace it
// without touching the Authenticator.
type JTIReplayGuard interface {
	// Remember records jti as used until expiresAt and reports whether it was
	// previously unseen. It returns false when jti has already been recorded
	// (i.e. a replay). expiresAt lets the guard reclaim storage once the
	// assertion could no longer be valid anyway.
	Remember(ctx context.Context, jti string, expiresAt time.Time) (bool, error)
}

// assertionHeader is the protected JOSE header of a client assertion.
type assertionHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Authenticator verifies RFC 7523 private_key_jwt client assertions.
type Authenticator struct {
	registry    clients.Registry
	audience    string
	jti         JTIReplayGuard
	maxLifetime time.Duration
	now         func() time.Time
}

// Option customizes an Authenticator.
type Option func(*Authenticator)

// WithClock overrides the time source (tests inject a deterministic clock).
func WithClock(now func() time.Time) Option {
	return func(a *Authenticator) {
		if now != nil {
			a.now = now
		}
	}
}

// WithMaxAssertionLifetime overrides the exp ceiling.
func WithMaxAssertionLifetime(d time.Duration) Option {
	return func(a *Authenticator) {
		if d > 0 {
			a.maxLifetime = d
		}
	}
}

// New constructs an Authenticator. registry resolves clients by their id;
// audience is the exact token endpoint URL an assertion must target
// (issuer + "/oauth2/token"); guard enforces single-use jti values.
func New(registry clients.Registry, audience string, guard JTIReplayGuard, opts ...Option) (*Authenticator, error) {
	if registry == nil {
		return nil, errors.New("clientauth: registry is required")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("clientauth: audience is required")
	}
	if guard == nil {
		return nil, errors.New("clientauth: JTI replay guard is required")
	}
	a := &Authenticator{
		registry:    registry,
		audience:    audience,
		jti:         guard,
		maxLifetime: DefaultMaxAssertionLifetime,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Authenticate implements token.ClientAuthenticator. It resolves and verifies
// the requesting client from the client_assertion form parameters.
func (a *Authenticator) Authenticate(ctx context.Context, form url.Values) (clients.Client, error) {
	if got := form.Get("client_assertion_type"); got != AssertionType {
		return clients.Client{}, fmt.Errorf("%w: %q", ErrUnsupportedType, got)
	}
	assertion := form.Get("client_assertion")
	if assertion == "" {
		return clients.Client{}, ErrMissingAssertion
	}

	header, claims, signingInput, sig, err := parseAssertion(assertion)
	if err != nil {
		return clients.Client{}, err
	}

	// Algorithm allow-list: only asymmetric RS256/ES256. This rejects "none"
	// and every HS* MAC before any key lookup or crypto is attempted.
	if header.Alg != keys.AlgRS256 && header.Alg != keys.AlgES256 {
		return clients.Client{}, fmt.Errorf("%w: %q", ErrUnsupportedAlg, header.Alg)
	}
	if header.Kid == "" {
		return clients.Client{}, fmt.Errorf("%w: missing kid", ErrMalformedAssertion)
	}

	iss := stringClaim(claims, "iss")
	sub := stringClaim(claims, "sub")
	if iss == "" || sub == "" || iss != sub {
		return clients.Client{}, ErrIssuerSubjectMismatch
	}
	// When the client also sends client_id (allowed by RFC 6749), it must not
	// contradict the assertion's self-asserted identity.
	if cid := form.Get("client_id"); cid != "" && cid != iss {
		return clients.Client{}, ErrClientIDMismatch
	}

	client, err := a.registry.Lookup(iss)
	if err != nil {
		// Do not distinguish unknown client from other failures to callers,
		// but keep the specific cause for logging.
		return clients.Client{}, fmt.Errorf("clientauth: %w", err)
	}
	if client.IsPublic() {
		return clients.Client{}, ErrNotConfidentialClient
	}

	key, ok := client.PublicKey(header.Kid)
	if !ok {
		return clients.Client{}, fmt.Errorf("%w: kid %q", ErrUnknownKey, header.Kid)
	}
	// The registered key pins its own algorithm; the assertion header must
	// agree so an attacker cannot downgrade or cross-use a key.
	if key.Alg != header.Alg {
		return clients.Client{}, fmt.Errorf("%w: header %q, key %q", ErrUnsupportedAlg, header.Alg, key.Alg)
	}

	if err := keys.VerifyJWSSignature(header.Alg, key.Key, signingInput, sig); err != nil {
		return clients.Client{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}

	// Signature is valid: now enforce the temporal and audience claims.
	if err := a.validateClaims(ctx, claims); err != nil {
		return clients.Client{}, err
	}

	return client, nil
}

// validateClaims enforces aud, exp, and single-use jti once the signature has
// been verified.
func (a *Authenticator) validateClaims(ctx context.Context, claims map[string]any) error {
	if !audienceMatches(claims["aud"], a.audience) {
		return ErrBadAudience
	}

	now := a.now()
	exp, ok := timeClaim(claims, "exp")
	if !ok {
		return fmt.Errorf("%w: missing exp", ErrInvalidAssertionClaims)
	}
	if !now.Add(-clockSkewLeeway).Before(exp) {
		return ErrExpired
	}
	if exp.After(now.Add(a.maxLifetime + clockSkewLeeway)) {
		return ErrExcessiveLifetime
	}

	jti := stringClaim(claims, "jti")
	if jti == "" {
		return ErrMissingJTI
	}
	fresh, err := a.jti.Remember(ctx, jti, exp)
	if err != nil {
		return fmt.Errorf("clientauth: jti replay guard: %w", err)
	}
	if !fresh {
		return ErrReplay
	}
	return nil
}

// parseAssertion splits a compact JWS and decodes its header and claims,
// returning the raw signing input and signature for verification.
func parseAssertion(assertion string) (assertionHeader, map[string]any, string, []byte, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: expected 3 segments", ErrMalformedAssertion)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: bad header encoding", ErrMalformedAssertion)
	}
	var header assertionHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: bad header JSON", ErrMalformedAssertion)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: bad payload encoding", ErrMalformedAssertion)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: bad payload JSON", ErrMalformedAssertion)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return assertionHeader{}, nil, "", nil, fmt.Errorf("%w: bad signature encoding", ErrMalformedAssertion)
	}
	signingInput := parts[0] + "." + parts[1]
	return header, claims, signingInput, sig, nil
}

// stringClaim returns claims[name] when it is a string, else "".
func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// timeClaim interprets a NumericDate claim (seconds since the epoch, encoded
// as a JSON number) as a time.Time.
func timeClaim(claims map[string]any, name string) (time.Time, bool) {
	switch v := claims[name].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return time.Unix(n, 0), true
		}
	}
	return time.Time{}, false
}

// audienceMatches reports whether the JWT "aud" claim (a string or an array of
// strings per RFC 7519) contains want.
func audienceMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
