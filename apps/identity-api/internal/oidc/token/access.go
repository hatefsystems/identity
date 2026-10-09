package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// ErrInactiveToken is a negative authentication result, not a dependency failure.
var ErrInactiveToken = errors.New("token: access token inactive")

// ValidatedAccessToken contains claims admitted by the current credential authority.
type ValidatedAccessToken struct {
	PrincipalType string
	Subject       string
	ClientID      string
	Scope         string
	ExpiresAt     int64
	DPoPJKT       string
}

// VerificationKeys resolves trusted local keys without fetching a caller-supplied URL.
type VerificationKeys interface {
	VerificationKey(string) *keys.SigningKey
}

// AccessValidatorConfig supplies local verification and live authority dependencies.
type AccessValidatorConfig struct {
	Issuer   string
	Keys     VerificationKeys
	Clients  clients.Registry
	Grants   GrantReader
	Sessions SessionLookup
	Accounts session.AccountState
}

// AccessValidator verifies access-token purpose, signature and current authority.
type AccessValidator struct {
	cfg AccessValidatorConfig
	now func() time.Time
}

// NewAccessValidator refuses incomplete authority dependencies.
func NewAccessValidator(cfg AccessValidatorConfig) (*AccessValidator, error) {
	if cfg.Issuer == "" || cfg.Keys == nil || cfg.Clients == nil || cfg.Grants == nil || cfg.Sessions == nil || cfg.Accounts == nil {
		return nil, errors.New("token: access validation dependencies required")
	}
	return &AccessValidator{cfg: cfg, now: time.Now}, nil
}

type accessClaims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      string `json:"aud"`
	ClientID      string `json:"client_id"`
	Scope         string `json:"scope"`
	PrincipalType string `json:"principal_type"`
	GrantID       string `json:"grant_id"`
	SessionID     string `json:"sid"`
	AuthVersion   *int64 `json:"auth_version"`
	JTI           string `json:"jti"`
	IssuedAt      *int64 `json:"iat"`
	ExpiresAt     *int64 `json:"exp"`
	NotBefore     *int64 `json:"nbf"`
	Confirmation  *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// Validate makes a fresh authority decision. Signatures are checked locally;
// Redis state and the primary account version are never positively cached.
func (v *AccessValidator) Validate(ctx context.Context, compact, audience string) (ValidatedAccessToken, error) {
	var empty ValidatedAccessToken
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if compact == "" || len(compact) > 16*1024 || audience == "" || len(audience) > 2048 {
		return empty, ErrInactiveToken
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return empty, ErrInactiveToken
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return empty, ErrInactiveToken
	}
	var header jwsHeader
	// Only the compact JWS profile emitted by this issuer is supported. In
	// particular, unencoded payloads and unhandled critical headers are refused.
	if decodeState(string(rawHeader), &header) != nil || header.Typ != TypAccessToken || header.Kid == "" ||
		(header.Alg != keys.AlgRS256 && header.Alg != keys.AlgES256) {
		return empty, ErrInactiveToken
	}
	key := v.cfg.Keys.VerificationKey(header.Kid)
	if key == nil || key.Signer == nil || key.Alg != header.Alg {
		return empty, ErrInactiveToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return empty, ErrInactiveToken
	}
	if err := keys.VerifyJWSSignature(header.Alg, key.Signer.Public(), parts[0]+"."+parts[1], sig); err != nil {
		return empty, ErrInactiveToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return empty, ErrInactiveToken
	}
	var claims accessClaims
	if json.Unmarshal(payload, &claims) != nil {
		return empty, ErrInactiveToken
	}
	now := v.now()
	if claims.Issuer != v.cfg.Issuer || claims.Audience != audience || audience != v.cfg.Issuer ||
		claims.Subject == "" || claims.ClientID == "" || claims.GrantID == "" || claims.JTI == "" ||
		claims.IssuedAt == nil || claims.ExpiresAt == nil || *claims.ExpiresAt <= now.Unix() ||
		*claims.IssuedAt > now.Add(5*time.Second).Unix() || *claims.IssuedAt < 0 ||
		*claims.ExpiresAt <= *claims.IssuedAt || *claims.ExpiresAt-*claims.IssuedAt > int64(DefaultAccessTokenTTL.Seconds()) ||
		(claims.NotBefore != nil && *claims.NotBefore > now.Unix()) {
		return empty, ErrInactiveToken
	}
	jkt := ""
	if claims.Confirmation != nil {
		jkt = claims.Confirmation.JKT
		decoded, err := base64.RawURLEncoding.DecodeString(jkt)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != jkt {
			return empty, ErrInactiveToken
		}
	}
	client, err := v.cfg.Clients.Lookup(claims.ClientID)
	if errors.Is(err, clients.ErrUnknownClient) {
		return empty, ErrInactiveToken
	}
	if err != nil {
		return empty, err
	}
	for _, scope := range splitScopes(claims.Scope) {
		if !client.AllowsScope(scope) {
			return empty, ErrInactiveToken
		}
	}
	grant, err := v.cfg.Grants.GetGrant(ctx, claims.GrantID)
	if errors.Is(err, ErrGrantNotFound) {
		return empty, ErrInactiveToken
	}
	if err != nil {
		return empty, err
	}
	if !validGrant(grant) {
		return empty, ErrStoreUnavailable
	}
	if grant.ID != claims.GrantID || grant.Status != StatusActive || grant.PrincipalType != claims.PrincipalType ||
		grant.Subject != claims.Subject || grant.ClientID != claims.ClientID || grant.Scope != claims.Scope ||
		grant.DPoPJKT != jkt || !grant.ExpiresAt.After(now) || *claims.ExpiresAt > grant.ExpiresAt.Unix() {
		return empty, ErrInactiveToken
	}
	authorityExpiry := minTime(time.Unix(*claims.ExpiresAt, 0), grant.ExpiresAt)
	switch claims.PrincipalType {
	case PrincipalUser:
		id, err := uuid.Parse(claims.Subject)
		if err != nil || id == uuid.Nil || claims.SessionID == "" || claims.AuthVersion == nil || *claims.AuthVersion < 0 ||
			claims.SessionID != grant.SessionID || !grant.AuthVersionSet || *claims.AuthVersion != grant.AuthVersion {
			return empty, ErrInactiveToken
		}
		parent, err := v.cfg.Sessions.LookupByID(ctx, claims.Subject, claims.SessionID)
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return empty, ErrInactiveToken
		}
		if err != nil {
			return empty, err
		}
		if parent.ID != claims.SessionID || parent.UserID != claims.Subject || parent.Kind != session.KindAuthenticated ||
			!parent.AuthVersionSet || parent.AuthVersion != *claims.AuthVersion || !parent.AbsoluteExpiry.After(now) || !parent.IdleExpiry.After(now) {
			return empty, ErrInactiveToken
		}
		authorityExpiry = minTime(authorityExpiry, minTime(parent.AbsoluteExpiry, parent.IdleExpiry))
		if err := v.cfg.Accounts.Validate(ctx, claims.Subject, *claims.AuthVersion); err != nil {
			if errors.Is(err, session.ErrAccountIneligible) {
				return empty, ErrInactiveToken
			}
			return empty, err
		}
	case PrincipalClient:
		if client.IsPublic() || claims.Subject != claims.ClientID || claims.SessionID != "" || claims.AuthVersion != nil || grant.AuthVersionSet {
			return empty, ErrInactiveToken
		}
	default:
		return empty, ErrInactiveToken
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if !authorityExpiry.After(v.now()) {
		return empty, ErrInactiveToken
	}
	return ValidatedAccessToken{PrincipalType: claims.PrincipalType, Subject: claims.Subject, ClientID: claims.ClientID,
		Scope: claims.Scope, ExpiresAt: *claims.ExpiresAt, DPoPJKT: jkt}, nil
}
