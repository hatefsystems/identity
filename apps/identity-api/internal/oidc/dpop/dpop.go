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
//   - ReplayGuard: single-use enforcement scoped to the realm, verified key,
//     and proof "jti" for the complete proof acceptance window;
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
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// TypDPoP is the required JOSE "typ" header of a DPoP proof (RFC 9449 §4.2).
const TypDPoP = "dpop+jwt"

// MaxProofSize bounds the compact proof before decoding or signature work.
const MaxProofSize = 16 * 1024

// DefaultProofMaxAge bounds how old a proof's iat may be. Proofs are meant to
// be created per-request and are short-lived. Replay retention also includes
// clockSkewLeeway and the inclusive final acceptance instant.
const DefaultProofMaxAge = 60 * time.Second

// clockSkewLeeway tolerates small clock differences between the client and the
// IdP when validating iat so legitimate proofs are not rejected.
const clockSkewLeeway = 5 * time.Second

// Proof errors are opaque sentinels mapped to invalid_dpop_proof or
// use_dpop_nonce. Parameter and state-store failures must remain distinct from
// invalid proofs, and backend details must not be exposed by transports.
var (
	ErrMissingProof     = errors.New("dpop: missing proof")
	ErrMalformedProof   = errors.New("dpop: malformed proof")
	ErrUnsupportedAlg   = errors.New("dpop: unsupported proof algorithm")
	ErrWrongType        = errors.New("dpop: proof typ header must be dpop+jwt")
	ErrMissingJWK       = errors.New("dpop: proof header is missing the public jwk")
	ErrPrivateJWK       = errors.New("dpop: proof jwk must not contain private key material")
	ErrJWKAlgMismatch   = errors.New("dpop: proof jwk algorithm does not match the header alg")
	ErrSignature        = errors.New("dpop: proof signature is invalid")
	ErrMethodMismatch   = errors.New("dpop: proof htm does not match the request method")
	ErrURIMismatch      = errors.New("dpop: proof htu does not match the request URI")
	ErrMissingIAT       = errors.New("dpop: proof is missing iat")
	ErrStaleProof       = errors.New("dpop: proof iat is outside the acceptance window")
	ErrMissingJTI       = errors.New("dpop: proof is missing jti")
	ErrReplay           = errors.New("dpop: proof jti has already been used")
	ErrMissingATH       = errors.New("dpop: proof is missing the access token hash (ath)")
	ErrATHMismatch      = errors.New("dpop: proof ath does not match the presented access token")
	ErrNonceRequired    = errors.New("dpop: a fresh DPoP-Nonce is required")
	ErrKeyMismatch      = errors.New("dpop: proof key does not match the token binding")
	ErrInvalidParams    = errors.New("dpop: invalid verification or store parameters")
	ErrStoreUnavailable = errors.New("dpop: state store unavailable")
)

// NonceChallenge carries only the scope verified before a nonce is required.
// Transports must use these fields to issue a nonce, not reparse the proof.
type NonceChallenge struct {
	Realm string
	JKT   string
}

func (*NonceChallenge) Error() string { return ErrNonceRequired.Error() }
func (*NonceChallenge) Unwrap() error { return ErrNonceRequired }

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
	// HTU is the proof's HTTP target URI; validation excludes its query.
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
	if len(compact) > MaxProofSize {
		return nil, ErrMalformedProof
	}
	if strings.TrimSpace(compact) == "" {
		return nil, ErrMissingProof
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedProof
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedProof
	}
	var header proofHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedProof
	}

	if header.Typ != TypDPoP {
		return nil, ErrWrongType
	}
	// Algorithm allow-list: only asymmetric RS256/ES256. This rejects "none"
	// and every HS* MAC before any key parsing or crypto is attempted.
	if header.Alg != keys.AlgRS256 && header.Alg != keys.AlgES256 {
		return nil, ErrUnsupportedAlg
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
		return nil, ErrMalformedProof
	}
	pub, err := keys.ParsePublicJWK(jwk)
	if err != nil {
		return nil, ErrMalformedProof
	}
	// The parsed key pins its own algorithm; the header must agree so an
	// attacker cannot present an EC key while claiming RS256, or vice versa.
	if pub.Alg != header.Alg {
		return nil, ErrJWKAlgMismatch
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedProof
	}
	signingInput := parts[0] + "." + parts[1]
	if err := keys.VerifyJWSSignature(header.Alg, pub.Key, signingInput, sig); err != nil {
		return nil, ErrSignature
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedProof
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(claimsBytes, &claims); err != nil || claims == nil {
		return nil, ErrMalformedProof
	}

	// Normalize the JWK so its thumbprint is stable regardless of extra header
	// members the client may have included in the embedded key.
	jkt, err := keys.Thumbprint(jwk)
	if err != nil {
		return nil, ErrMalformedProof
	}

	proof := &Proof{
		JKT:       jkt,
		PublicJWK: jwk,
	}
	// JWT claim names are case-sensitive; decoding straight into a Go struct
	// would also accept differently cased names such as JTI and HTM.
	for name, dst := range map[string]*string{
		"jti": &proof.JTI, "htm": &proof.HTM, "htu": &proof.HTU,
		"nonce": &proof.Nonce, "ath": &proof.ATH,
	} {
		if raw, ok := claims[name]; ok {
			if err := json.Unmarshal(raw, dst); err != nil {
				return nil, ErrMalformedProof
			}
		}
	}
	if raw, ok := claims["iat"]; ok {
		var iat *int64
		if err := json.Unmarshal(raw, &iat); err != nil {
			return nil, ErrMalformedProof
		}
		if iat != nil {
			proof.IssuedAt = time.Unix(*iat, 0)
		}
	}
	return proof, nil
}

// rejectPrivateJWK returns ErrPrivateJWK when the embedded JWK object carries
// any private key member (RSA or EC), per RFC 9449 §4.3.
func rejectPrivateJWK(raw json.RawMessage) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ErrMalformedProof
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
	// Realm is the nonempty, trusted validation scope shared by replicas.
	// Authorization-server and resource-server realms must be distinct.
	Realm string
	// ExpectedJKT is the verified token's cnf.jkt. Bound-token callers must
	// supply it; it may be empty only when no prior token binding is required.
	ExpectedJKT string
	// Method is the expected HTTP method (htm), e.g. "POST".
	Method string
	// URL is the expected absolute HTTP target URI (htu). Queries are ignored;
	// userinfo and fragments are rejected. For the token endpoint this is the
	// canonical URL derived from the issuer (audience-confusion defence), not
	// the raw request URL.
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
		return nil, ErrInvalidParams
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
// bound into issued tokens (cnf.jkt). Existing bindings must be supplied in
// ExpectedJKT so they are checked before any state is consumed.
//
// A returned *NonceChallenge signals the transport to answer with a fresh
// server nonce (HTTP 400 use_dpop_nonce at the token endpoint, or 401 with
// WWW-Authenticate: DPoP at a resource server). No Proof is returned on error.
func (v *Validator) Validate(ctx context.Context, compact string, params VerifyParams) (*Proof, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v == nil || strings.TrimSpace(params.Realm) == "" || strings.TrimSpace(params.Method) == "" ||
		canonicalURI(params.URL) == "" || (params.RequireNonce && v.nonces == nil) {
		return nil, ErrInvalidParams
	}
	proof, err := ParseProof(compact)
	if err != nil {
		return nil, err
	}

	if proof.HTM != params.Method {
		return nil, ErrMethodMismatch
	}
	if !sameURI(proof.HTU, params.URL) {
		return nil, ErrURIMismatch
	}

	now := v.now()
	if proof.IssuedAt.IsZero() {
		return nil, ErrMissingIAT
	}
	if proof.IssuedAt.After(now.Add(clockSkewLeeway)) ||
		proof.IssuedAt.Before(now.Add(-v.maxAge-clockSkewLeeway)) {
		return nil, ErrStaleProof
	}
	if proof.JTI == "" {
		return nil, ErrMissingJTI
	}
	if params.ExpectedJKT != "" && !constantTimeEqual(proof.JKT, params.ExpectedJKT) {
		return nil, ErrKeyMismatch
	}

	if params.AccessToken != "" {
		if proof.ATH == "" {
			return nil, ErrMissingATH
		}
		if !constantTimeEqual(proof.ATH, AccessTokenHash(params.AccessToken)) {
			return nil, ErrATHMismatch
		}
	}

	// All stateless checks precede both consuming operations. Only a verified
	// scope can receive a nonce challenge, and challenges do not burn the jti.
	if params.RequireNonce {
		if proof.Nonce == "" {
			return nil, &NonceChallenge{Realm: params.Realm, JKT: proof.JKT}
		}
		ok, nErr := v.nonces.Validate(ctx, params.Realm, proof.JKT, proof.Nonce)
		if nErr != nil {
			return nil, stateStoreError(ctx, nErr)
		}
		if !ok {
			return nil, &NonceChallenge{Realm: params.Realm, JKT: proof.JKT}
		}
	}

	key := stateKey("", params.Realm, proof.JKT, proof.JTI)
	fresh, err := v.replay.Remember(ctx, key, proof.IssuedAt.Add(v.maxAge+clockSkewLeeway))
	if err != nil {
		return nil, stateStoreError(ctx, err)
	}
	if !fresh {
		return nil, ErrReplay
	}

	return proof, nil
}

// IssueNonce mints a fresh server nonce scoped by a verified NonceChallenge.
// A missing store or an empty nonce is an error, never an empty challenge.
func (v *Validator) IssueNonce(ctx context.Context, realm, jkt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if v == nil || v.nonces == nil || strings.TrimSpace(realm) == "" || strings.TrimSpace(jkt) == "" {
		return "", ErrInvalidParams
	}
	nonce, err := v.nonces.Issue(ctx, realm, jkt)
	if err != nil {
		return "", stateStoreError(ctx, err)
	}
	if nonce == "" {
		return "", ErrStoreUnavailable
	}
	return nonce, nil
}

// AccessTokenHash computes the RFC 9449 ath value: the base64url (no padding)
// encoding of the SHA-256 hash of the access token's ASCII value.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameURI compares two HTTP target URIs for htu matching. Scheme and host are
// compared case-insensitively. Queries are excluded; malformed URIs, userinfo,
// and fragments are rejected rather than normalized into valid request context.
func sameURI(a, b string) bool {
	canonical := canonicalURI(a)
	return canonical != "" && canonical == canonicalURI(b)
}

// canonicalURI normalizes the scheme, host, and default port and excludes the
// query. Empty HTTP paths are '/', but non-root trailing slashes are significant.
func canonicalURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Opaque != "" || strings.Contains(raw, "#") {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return ""
		}
		host = address.String()
		if address.Is6() {
			host = "[" + host + "]"
		}
	} else if strings.HasPrefix(u.Host, "[") || strings.Contains(host, ":") {
		return ""
	}
	if strings.HasSuffix(u.Host, ":") {
		return ""
	}
	if rawPort := u.Port(); rawPort != "" {
		port, err := strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
		if (scheme != "https" || port != 443) && (scheme != "http" || port != 80) {
			host += ":" + strconv.Itoa(port)
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// constantTimeEqual compares two strings without leaking length-independent
// timing (used for the ath/JKT comparisons, matching the codebase's crypto/subtle
// usage elsewhere).
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
