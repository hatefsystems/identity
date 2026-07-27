// Package dpop implements DPoP — Demonstrating Proof-of-Possession at the
// Application Layer (RFC 9449). It sender-constrains access and refresh tokens
// to a client-generated asymmetric key so that a stolen bearer token is
// useless without the matching private key (docs/architecture.md "DPoP",
// docs/threat-modeling.md I1).
//
// The package provides three cooperating pieces, mirroring the interface-driven
// style already used by internal/oidc/clientauth:
//
//   - ParseProof / Validator: parse a compact DPoP proof JWS, verify its
//     signature against the embedded public JWK, and validate the htm/htu/iat/
//     ath/nonce claims;
//   - ReplayGuard: single-use enforcement of the proof "jti" (docs: cached in
//     Redis for the 60s proof lifetime, key dpop:jti:{jti});
//   - NonceStore: the server-issued DPoP-Nonce lifecycle (RFC 9449 §8-9).
//
// Only the two asymmetric algorithms permitted platform-wide are accepted —
// ES256 and RS256; "none" and every HS* MAC are structurally rejected, reusing
// keys.VerifyJWSSignature so there is a single audited verification path.
package dpop

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// TypDPoP is the required JOSE "typ" header of a DPoP proof (RFC 9449 §4.2).
const TypDPoP = "dpop+jwt"

// DefaultProofMaxAge bounds how old a proof's iat may be. Proofs are meant to
// be created per-request and are short-lived; the platform caches the jti for
// this same window to catch replays (docs/data-architecture.md §3.1:
// dpop:jti:{jti} TTL 60s).
const DefaultProofMaxAge = 60 * time.Second

// clockSkewLeeway tolerates small clock differences between the client and the
// IdP when validating iat so legitimate proofs are not rejected.
const clockSkewLeeway = 5 * time.Second

// Errors returned by proof parsing and validation. They are deliberately
// specific to aid server-side logging and testing; transport layers collapse
// them into an opaque invalid_dpop_proof / use_dpop_nonce response so nothing
// leaks to callers.
var (
	ErrMissingProof   = errors.New("dpop: missing proof")
	ErrMalformedProof = errors.New("dpop: malformed proof")
	ErrUnsupportedAlg = errors.New("dpop: unsupported proof algorithm")
	ErrWrongType      = errors.New("dpop: proof typ header must be dpop+jwt")
	ErrMissingJWK     = errors.New("dpop: proof header is missing the public jwk")
	ErrPrivateJWK     = errors.New("dpop: proof jwk must not contain private key material")
	ErrJWKAlgMismatch = errors.New("dpop: proof jwk algorithm does not match the header alg")
	ErrSignature      = errors.New("dpop: proof signature is invalid")
	ErrMethodMismatch = errors.New("dpop: proof htm does not match the request method")
	ErrURIMismatch    = errors.New("dpop: proof htu does not match the request URI")
	ErrMissingIAT     = errors.New("dpop: proof is missing iat")
	ErrStaleProof     = errors.New("dpop: proof iat is outside the acceptance window")
	ErrMissingJTI     = errors.New("dpop: proof is missing jti")
	ErrReplay         = errors.New("dpop: proof jti has already been used")
	ErrMissingATH     = errors.New("dpop: proof is missing the access token hash (ath)")
	ErrATHMismatch    = errors.New("dpop: proof ath does not match the presented access token")
	ErrNonceRequired  = errors.New("dpop: a fresh DPoP-Nonce is required")
)

// Proof is a parsed, signature-verified DPoP proof. It carries the confirmation
// key thumbprint (JKT) used to sender-constrain issued tokens (cnf.jkt), plus
// the claims needed for binding and replay checks.
type Proof struct {
	// JKT is the RFC 7638 SHA-256 thumbprint (base64url) of the proof's public
	// JWK. It is the value bound into tokens as the cnf.jkt confirmation claim.
	JKT string
	// JTI is the proof's unique identifier (single-use, replay-guarded).
	JTI string
	// HTM is the HTTP method the proof is bound to.
	HTM string
	// HTU is the HTTP target URI the proof is bound to (query/fragment removed).
	HTU string
	// IssuedAt is the proof's iat.
	IssuedAt time.Time
	// Nonce is the server-provided DPoP-Nonce echoed by the client, if any.
	Nonce string
	// ATH is the base64url SHA-256 hash of the bound access token, if present.
	ATH string
	// PublicJWK is the proof's embedded public key (public parameters only).
	PublicJWK keys.JWK
}

// proofHeader is the protected JOSE header of a DPoP proof.
type proofHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ"`
	JWK json.RawMessage `json:"jwk"`
}

// ParseProof decodes a compact DPoP proof JWS, enforces the dpop+jwt profile,
// verifies the signature against the embedded public JWK, and returns the
// parsed Proof (including its JKT confirmation thumbprint). It performs no
// stateful checks (iat window, replay, nonce) — those belong to Validator so
// that parsing stays pure and easily testable.
func ParseProof(compact string) (*Proof, error) {
	if strings.TrimSpace(compact) == "" {
		return nil, ErrMissingProof
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments", ErrMalformedProof)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: bad header encoding", ErrMalformedProof)
	}
	var header proofHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header JSON", ErrMalformedProof)
	}

	if header.Typ != TypDPoP {
		return nil, fmt.Errorf("%w: %q", ErrWrongType, header.Typ)
	}
	// Algorithm allow-list: only asymmetric RS256/ES256. This rejects "none"
	// and every HS* MAC before any key parsing or crypto is attempted.
	if header.Alg != keys.AlgRS256 && header.Alg != keys.AlgES256 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlg, header.Alg)
	}
	if len(header.JWK) == 0 {
		return nil, ErrMissingJWK
	}

	// Reject any private key material in the embedded JWK (RFC 9449 §4.3).
	// keys.JWK cannot hold private members, but an attacker could still send
	// them, so scan the raw object explicitly.
	if err := rejectPrivateJWK(header.JWK); err != nil {
		return nil, err
	}

	var jwk keys.JWK
	if err := json.Unmarshal(header.JWK, &jwk); err != nil {
		return nil, fmt.Errorf("%w: bad jwk JSON", ErrMalformedProof)
	}
	pub, err := keys.ParsePublicJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedProof, err)
	}
	// The parsed key pins its own algorithm; the header must agree so an
	// attacker cannot present an EC key while claiming RS256, or vice versa.
	if pub.Alg != header.Alg {
		return nil, fmt.Errorf("%w: header %q, key %q", ErrJWKAlgMismatch, header.Alg, pub.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrMalformedProof)
	}
	signingInput := parts[0] + "." + parts[1]
	if err := keys.VerifyJWSSignature(header.Alg, pub.Key, signingInput, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrMalformedProof)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: bad payload JSON", ErrMalformedProof)
	}

	// Normalize the JWK so its thumbprint is stable regardless of extra header
	// members the client may have included in the embedded key.
	jkt, err := keys.Thumbprint(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedProof, err)
	}

	proof := &Proof{
		JKT:       jkt,
		JTI:       stringClaim(claims, "jti"),
		HTM:       stringClaim(claims, "htm"),
		HTU:       stringClaim(claims, "htu"),
		Nonce:     stringClaim(claims, "nonce"),
		ATH:       stringClaim(claims, "ath"),
		PublicJWK: jwk,
	}
	if iat, ok := timeClaim(claims, "iat"); ok {
		proof.IssuedAt = iat
	}
	return proof, nil
}

// rejectPrivateJWK returns ErrPrivateJWK when the embedded JWK object carries
// any private key member (RSA or EC), per RFC 9449 §4.3.
func rejectPrivateJWK(raw json.RawMessage) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%w: bad jwk JSON", ErrMalformedProof)
	}
	// "d" is the private exponent (RSA) / private scalar (EC); the remaining
	// members are RSA CRT private parameters.
	for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, ok := obj[priv]; ok {
			return ErrPrivateJWK
		}
	}
	return nil
}

// VerifyParams describes what a proof must be bound to for a given request.
type VerifyParams struct {
	// Method is the expected HTTP method (htm), e.g. "POST".
	Method string
	// URL is the expected HTTP target URI (htu), with any query and fragment
	// already removed. For the token endpoint this is the canonical endpoint
	// URL derived from the issuer (audience-confusion defence), not the raw
	// request URL.
	URL string
	// AccessToken, when non-empty, requires the proof to carry a matching ath
	// (used on resource requests and token-refresh binding checks).
	AccessToken string
	// RequireNonce enforces the server-issued DPoP-Nonce lifecycle: the proof
	// must echo a nonce that validates against the NonceStore.
	RequireNonce bool
}

// Validator performs the stateful validation of a parsed proof: the iat
// acceptance window, single-use jti replay protection, optional ath binding,
// and the DPoP-Nonce lifecycle.
type Validator struct {
	replay ReplayGuard
	nonces NonceStore
	maxAge time.Duration
	now    func() time.Time
}

// Option customizes a Validator.
type Option func(*Validator)

// WithClock overrides the time source (tests inject a deterministic clock).
func WithClock(now func() time.Time) Option {
	return func(v *Validator) {
		if now != nil {
			v.now = now
		}
	}
}

// WithMaxAge overrides the proof iat acceptance window.
func WithMaxAge(d time.Duration) Option {
	return func(v *Validator) {
		if d > 0 {
			v.maxAge = d
		}
	}
}

// NewValidator constructs a Validator. replay enforces single-use jti values;
// nonces backs the DPoP-Nonce lifecycle. nonces may be nil when the deployment
// does not require server nonces, in which case VerifyParams.RequireNonce must
// not be set.
func NewValidator(replay ReplayGuard, nonces NonceStore, opts ...Option) (*Validator, error) {
	if replay == nil {
		return nil, errors.New("dpop: replay guard is required")
	}
	v := &Validator{
		replay: replay,
		nonces: nonces,
		maxAge: DefaultProofMaxAge,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Validate parses, signature-verifies, and fully validates a compact DPoP
// proof against params. On success it returns the Proof whose JKT should be
// bound into issued tokens (cnf.jkt) or checked against a presented token.
//
// A returned ErrNonceRequired signals the transport to answer with a fresh
// server nonce (HTTP 400 use_dpop_nonce at the token endpoint, or 401 with
// WWW-Authenticate: DPoP at a resource server) — see IssueNonce.
func (v *Validator) Validate(ctx context.Context, compact string, params VerifyParams) (*Proof, error) {
	proof, err := ParseProof(compact)
	if err != nil {
		return nil, err
	}

	if proof.HTM != params.Method {
		return nil, fmt.Errorf("%w: proof %q, request %q", ErrMethodMismatch, proof.HTM, params.Method)
	}
	if !sameURI(proof.HTU, params.URL) {
		return nil, fmt.Errorf("%w: proof %q, request %q", ErrURIMismatch, proof.HTU, params.URL)
	}

	now := v.now()
	if proof.IssuedAt.IsZero() {
		return nil, ErrMissingIAT
	}
	if proof.IssuedAt.After(now.Add(clockSkewLeeway)) ||
		proof.IssuedAt.Before(now.Add(-v.maxAge-clockSkewLeeway)) {
		return nil, ErrStaleProof
	}

	if params.AccessToken != "" {
		if proof.ATH == "" {
			return nil, ErrMissingATH
		}
		if !constantTimeEqual(proof.ATH, AccessTokenHash(params.AccessToken)) {
			return nil, ErrATHMismatch
		}
	}

	// Nonce lifecycle: enforced before the jti is consumed so a nonce-less
	// probe does not burn a jti and can simply be retried with the issued
	// nonce.
	if params.RequireNonce {
		if v.nonces == nil {
			return nil, errors.New("dpop: nonce required but no NonceStore configured")
		}
		if proof.Nonce == "" {
			return nil, ErrNonceRequired
		}
		ok, nErr := v.nonces.Validate(ctx, proof.Nonce)
		if nErr != nil {
			return nil, fmt.Errorf("dpop: nonce store: %w", nErr)
		}
		if !ok {
			return nil, ErrNonceRequired
		}
	}

	if proof.JTI == "" {
		return nil, ErrMissingJTI
	}
	// Remember the jti until it could no longer be accepted anyway.
	fresh, err := v.replay.Remember(ctx, proof.JTI, proof.IssuedAt.Add(v.maxAge+clockSkewLeeway))
	if err != nil {
		return nil, fmt.Errorf("dpop: replay guard: %w", err)
	}
	if !fresh {
		return nil, ErrReplay
	}

	return proof, nil
}

// IssueNonce mints a fresh server nonce for the DPoP-Nonce response header. It
// returns an empty string (and no error) when no NonceStore is configured.
func (v *Validator) IssueNonce(ctx context.Context) (string, error) {
	if v.nonces == nil {
		return "", nil
	}
	return v.nonces.Issue(ctx)
}

// AccessTokenHash computes the RFC 9449 ath value: the base64url (no padding)
// encoding of the SHA-256 hash of the access token's ASCII value.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameURI compares two HTTP target URIs for htu matching. Scheme and host are
// compared case-insensitively; the path is compared exactly. Any query or
// fragment on either side is ignored (RFC 9449 §4.3 removes them before
// comparison).
func sameURI(a, b string) bool {
	return canonicalURI(a) == canonicalURI(b)
}

// canonicalURI lowercases the scheme+authority and strips query/fragment.
func canonicalURI(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	scheme := ""
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme = strings.ToLower(raw[:i])
		rest = raw[i+3:]
	}
	// Split authority from path at the first '/'.
	authority := rest
	path := ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority = rest[:i]
		path = rest[i:]
	}
	authority = strings.ToLower(authority)
	// A trailing slash on the path is insignificant for endpoint identity.
	path = strings.TrimSuffix(path, "/")
	if scheme == "" {
		return authority + path
	}
	return scheme + "://" + authority + path
}

// constantTimeEqual compares two strings without leaking length-independent
// timing (used for the ath comparison, matching the codebase's crypto/subtle
// usage elsewhere).
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// stringClaim returns claims[name] when it is a string, else "".
func stringClaim(claims map[string]any, name string) string {
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// timeClaim interprets a NumericDate claim (seconds since the epoch, encoded as
// a JSON number) as a time.Time.
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
