package stepup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Grant is a validated step-up authentication grant. It is attached to the
// request context by RequireStepUp so handlers and the audit pipeline can record
// which factor authorised a sensitive operation.
type Grant struct {
	// UserID is the subject the grant was minted for (the sub claim).
	UserID string
	// SessionID is the session the grant is pinned to (the sid claim).
	SessionID string
	// AMR lists the authentication methods that earned the grant (RFC 8176).
	AMR []string
	// AuthTime is when the step-up challenge was successfully completed.
	AuthTime time.Time
	// JTI is the grant's unique identifier, already consumed by the time a
	// caller holds a *Grant.
	JTI string
	// ExpiresAt is the grant's expiry instant.
	ExpiresAt time.Time
}

// MintParams describes the authentication event a grant attests to.
type MintParams struct {
	// UserID is the authenticated subject (required).
	UserID string
	// SessionID is the session that completed the challenge (required); it
	// binds the grant so it cannot be paired with a different session.
	SessionID string
	// AMR lists the RFC 8176 method references for the factor presented.
	AMR []string
	// DPoPJKT binds the grant to a DPoP key thumbprint when the earning session
	// is itself sender-constrained. Empty for bearer sessions, which is every
	// session today: dpop.Middleware is not mounted on /api/v1 and
	// session.Manager.Issue is never called with a thumbprint, so this is a
	// forward hook rather than an active defence.
	DPoPJKT string
}

// grantHeader is the protected JOSE header of a step-up grant, decoded before
// verification purely to select the key and reject a token minted for another
// purpose.
type grantHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Mint signs a step-up grant for a completed challenge and returns the compact
// JWS together with its expiry.
func (s *Service) Mint(p MintParams) (string, time.Time, error) {
	if p.UserID == "" {
		return "", time.Time{}, errors.New("stepup: user id is required")
	}
	if p.SessionID == "" {
		return "", time.Time{}, errors.New("stepup: session id is required")
	}

	signer := s.keys.ActiveSigner()
	if signer == nil {
		return "", time.Time{}, errors.New("stepup: no active signing key")
	}

	now := s.now()
	expiresAt := now.Add(s.tokenTTL)

	claims := token.Claims{
		"iss":       s.issuer,
		"sub":       p.UserID,
		"aud":       s.issuer,
		"acr":       ACRStepUp,
		"amr":       p.AMR,
		"auth_time": now.Unix(),
		"sid":       p.SessionID,
		"jti":       uuid.NewString(),
		"iat":       now.Unix(),
		"exp":       expiresAt.Unix(),
	}
	// RFC 9449 §6 confirmation claim, populated only when the earning session is
	// sender-constrained.
	if p.DPoPJKT != "" {
		claims["cnf"] = map[string]string{"jkt": p.DPoPJKT}
	}

	compact, err := token.Sign(signer, token.TypStepUpToken, claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("stepup: sign grant: %w", err)
	}
	return compact, expiresAt, nil
}

// Validate verifies a presented grant against the caller's live session and
// consumes it, returning the parsed grant on success.
//
// The order of checks below is deliberate and must not be rearranged:
//
//  1. Structure, then the typ header. Access tokens, ID tokens, and grants are
//     signed by the same keys and access tokens already use aud == iss, so
//     without the typ gate an access token would pass every remaining check
//     except acr. Rejecting on typ first means a token minted for another
//     purpose never reaches key resolution.
//  2. Signature, via token.Verify, which also pins alg to the resolved key's
//     algorithm — that is what makes "alg": "none" and every HS* MAC
//     structurally impossible rather than merely denied.
//  3. Claims. token.Verify explicitly does not validate iss, aud, or exp (see
//     internal/oidc/token/jwt.go), so every claim check is this function's
//     responsibility.
//  4. Session binding, before consumption, so a grant presented against the
//     wrong session is not burned for its legitimate owner.
//  5. Single-use consumption, last, so a grant is only spent once it is known
//     to be otherwise acceptable.
func (s *Service) Validate(ctx context.Context, compact string, sess session.Session) (*Grant, error) {
	if strings.TrimSpace(compact) == "" {
		return nil, ErrNoGrant
	}

	header, err := parseGrantHeader(compact)
	if err != nil {
		return nil, err
	}
	// Purpose binding: see the note above. This is the single most important
	// check in this function.
	if header.Typ != token.TypStepUpToken {
		return nil, fmt.Errorf("%w: unexpected typ %q", ErrInvalidGrant, header.Typ)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrInvalidGrant)
	}

	key := s.keys.VerificationKey(header.Kid)
	if key == nil {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrInvalidGrant, header.Kid)
	}

	claims, err := token.Verify(compact, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}

	if got := stringClaim(claims, "iss"); got != s.issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidGrant)
	}
	if got := stringClaim(claims, "aud"); got != s.issuer {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidGrant)
	}
	if got := stringClaim(claims, "acr"); got != ACRStepUp {
		return nil, fmt.Errorf("%w: acr %q is not %q", ErrInvalidGrant, got, ACRStepUp)
	}

	now := s.now()
	exp, ok := timeClaim(claims, "exp")
	if !ok {
		return nil, fmt.Errorf("%w: missing exp", ErrInvalidGrant)
	}
	if !exp.After(now) {
		return nil, fmt.Errorf("%w: expired", ErrInvalidGrant)
	}
	iat, ok := timeClaim(claims, "iat")
	if !ok {
		return nil, fmt.Errorf("%w: missing iat", ErrInvalidGrant)
	}
	if iat.After(now.Add(clockSkewLeeway)) {
		return nil, fmt.Errorf("%w: issued in the future", ErrInvalidGrant)
	}

	jti := stringClaim(claims, "jti")
	if jti == "" {
		return nil, fmt.Errorf("%w: missing jti", ErrInvalidGrant)
	}

	sub := stringClaim(claims, "sub")
	sid := stringClaim(claims, "sid")
	if sub == "" || sid == "" {
		return nil, fmt.Errorf("%w: missing sub or sid", ErrInvalidGrant)
	}
	// Session binding: both halves matter. Matching only sub would let a grant
	// earned in one session authorise an operation in another (e.g. a stale tab
	// or a second device), which defeats the per-operation nature of the grant.
	if sub != sess.UserID || sid != sess.ID {
		return nil, ErrGrantNotForSession
	}

	fresh, err := s.guard.Remember(ctx, jtiGuardKey(jti), exp)
	if err != nil {
		return nil, fmt.Errorf("stepup: consume grant: %w", err)
	}
	if !fresh {
		return nil, ErrGrantConsumed
	}

	authTime, _ := timeClaim(claims, "auth_time")

	return &Grant{
		UserID:    sub,
		SessionID: sid,
		AMR:       stringSliceClaim(claims, "amr"),
		AuthTime:  authTime,
		JTI:       jti,
		ExpiresAt: exp,
	}, nil
}

// jtiGuardKey namespaces a grant's jti inside the replay guard so it cannot
// collide with the TOTP passcode entries.
func jtiGuardKey(jti string) string { return "stepup:jti:" + jti }

// parseGrantHeader decodes the protected header of a compact JWS without
// verifying anything. Its output is used only to reject a wrong-purpose token
// and to select the verification key; every security decision that depends on
// the header's contents is re-made by token.Verify against the resolved key.
func parseGrantHeader(compact string) (grantHeader, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return grantHeader{}, fmt.Errorf("%w: expected 3 segments", ErrInvalidGrant)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return grantHeader{}, fmt.Errorf("%w: bad header encoding", ErrInvalidGrant)
	}
	var header grantHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return grantHeader{}, fmt.Errorf("%w: bad header JSON", ErrInvalidGrant)
	}
	return header, nil
}

// stringClaim returns claims[name] when it is a string, else "".
func stringClaim(claims token.Claims, name string) string {
	v, _ := claims[name].(string)
	return v
}

// timeClaim returns claims[name] interpreted as NumericDate seconds. JSON
// numbers decode as float64, so the value is narrowed here rather than at each
// call site.
func timeClaim(claims token.Claims, name string) (time.Time, bool) {
	switch v := claims[name].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	default:
		return time.Time{}, false
	}
}

// stringSliceClaim returns claims[name] as a string slice, tolerating both a
// JSON array and the single-string form some JWT producers use. It returns an
// empty (non-nil) slice when the claim is absent or malformed.
func stringSliceClaim(claims token.Claims, name string) []string {
	switch v := claims[name].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	default:
		return []string{}
	}
}
