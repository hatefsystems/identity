// Grant orchestration for POST /oauth2/token (docs/api-design.md §1.1):
//
//   - authorization_code + PKCE S256: single-use code consumption, strict
//     client/redirect_uri binding, constant-time verifier check.
//   - refresh_token with Refresh Token Rotation (RTR): every exchange rotates
//     the token; presenting an already-rotated or revoked token is treated as
//     breach evidence and instantly revokes ALL of the user's active refresh
//     tokens across every family/session.
//   - client_credentials: confidential clients only, authenticated through
//     the pluggable ClientAuthenticator (RFC 7523 private_key_jwt lands in
//     Task 3.4); no refresh token is issued (OAuth 2.1).
//
// DPoP sender-constraining (Task 3.5) hooks in above this layer.

package token

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Token type values (RFC 6749 §7.1 / RFC 9449 §5). A token confirmed to a DPoP
// key is issued as token_type "DPoP" so the client presents it with the DPoP
// auth scheme; otherwise it is a plain "Bearer" token.
const (
	TokenTypeBearer = "Bearer"
	TokenTypeDPoP   = "DPoP"
)

// OAuth 2.0 token endpoint error codes (RFC 6749 §5.2).
const (
	ErrCodeInvalidRequest       = "invalid_request"
	ErrCodeInvalidClient        = "invalid_client"
	ErrCodeInvalidGrant         = "invalid_grant"
	ErrCodeUnauthorizedClient   = "unauthorized_client"
	ErrCodeUnsupportedGrantType = "unsupported_grant_type"
	ErrCodeInvalidScope         = "invalid_scope"
	ErrCodeServerError          = "server_error"
)

// Supported grant_type values.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

// Default lifetimes (docs: short-lived access tokens; codes are one-shot and
// near-immediate; refresh tokens bound by RTR).
const (
	DefaultAccessTokenTTL  = 10 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	DefaultCodeTTL         = 60 * time.Second
	DefaultIDTokenTTL      = 10 * time.Minute
)

// Error is an RFC 6749 §5.2 token endpoint error. Status carries the HTTP
// status the transport layer must use (400 for most, 401 for invalid_client).
type Error struct {
	Code        string
	Description string
	Status      int
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Code + ": " + e.Description }

func newError(code, description string, status int) *Error {
	return &Error{Code: code, Description: description, Status: status}
}

// ClientAuthenticator verifies client authentication material presented at
// the token endpoint. Task 3.4 provides the RFC 7523 private_key_jwt
// implementation; until then the wiring accepts any implementation (tests use
// fakes).
type ClientAuthenticator interface {
	// Authenticate resolves and verifies the requesting client from the form
	// parameters (client_assertion etc.). It returns the authenticated client
	// or an error translated by the caller into invalid_client.
	Authenticate(ctx context.Context, form url.Values) (clients.Client, error)
}

// BreachRecorder receives RTR breach notifications so they can be surfaced as
// security events (security_event_ledger rows in Task 5.2, and the
// idp_rtr_breach_detections_total metric). Implementations must be
// non-blocking or fast.
type BreachRecorder interface {
	RecordRTRBreach(ctx context.Context, userID, clientID string)
}

// Signer abstracts the keystore so the service always signs with the current
// active key even across rotations.
type Signer interface {
	ActiveSigner() *keys.SigningKey
}

// Config carries the tunable lifetimes for issued artifacts.
type Config struct {
	AccountState session.AccountState
	Sessions     SessionLookup
	// RevokeUser invalidates the primary account version and browser sessions
	// before refresh-family cleanup. It runs outside WithActive's transaction.
	RevokeUser      func(context.Context, string) error
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	CodeTTL         time.Duration
	IDTokenTTL      time.Duration
}

// SessionLookup reads browser authority without touching its idle lifetime.
type SessionLookup interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// withDefaults fills zero durations with the platform defaults.
func (c Config) withDefaults() Config {
	if c.AccessTokenTTL <= 0 {
		c.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if c.RefreshTokenTTL <= 0 {
		c.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = DefaultCodeTTL
	}
	if c.IDTokenTTL <= 0 {
		c.IDTokenTTL = DefaultIDTokenTTL
	}
	return c
}

// Response is the successful token endpoint JSON payload (RFC 6749 §5.1).
//
// Subject and ClientID are transport-only: they are how the HTTP layer learns who
// the grant was for so it can emit the audit/ledger event, and they carry `json:"-"`
// so they never reach the wire. Returning them beats re-parsing the issued JWT,
// which would mean verifying our own signature to recover a value we just had.
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// Subject is the users.id the tokens were issued for. It is empty for the
	// client_credentials grant, where the token's sub is the client acting on its
	// own behalf and no user account exists — so that grant produces an audit row
	// with no subject and no security_event_ledger row, because there is nothing
	// attributable to an account.
	Subject string `json:"-"`
	// ClientID is the OAuth client that received the grant.
	ClientID string `json:"-"`
}

// Service implements the three grants against the pluggable stores.
type Service struct {
	cfg      Config
	keys     Signer
	registry clients.Registry
	codes    AuthorizationCodeStore
	refresh  RefreshTokenStore
	// clientAuth authenticates confidential clients; nil disables the
	// client_credentials grant until Task 3.4 wires the real authenticator.
	clientAuth ClientAuthenticator
	breach     BreachRecorder
	logger     *slog.Logger
	now        func() time.Time
}

// NewService constructs a token Service. registry, keys, codes and refresh
// are mandatory; clientAuth and breach are optional extension points.
func NewService(
	cfg Config,
	signer Signer,
	registry clients.Registry,
	codes AuthorizationCodeStore,
	refresh RefreshTokenStore,
	clientAuth ClientAuthenticator,
	breach BreachRecorder,
	logger *slog.Logger,
) (*Service, error) {
	if signer == nil || registry == nil || codes == nil || refresh == nil || cfg.Sessions == nil || cfg.RevokeUser == nil {
		return nil, errors.New("token: signer, registry, credential stores, sessions and revoker are required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("token: issuer is required")
	}
	if cfg.AccessTokenTTL > DefaultAccessTokenTTL || cfg.IDTokenTTL > DefaultIDTokenTTL {
		return nil, errors.New("token: downstream JWT lifetime must not exceed ten minutes")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:        cfg.withDefaults(),
		keys:       signer,
		registry:   registry,
		codes:      codes,
		refresh:    refresh,
		clientAuth: clientAuth,
		breach:     breach,
		logger:     logger,
		now:        time.Now,
	}, nil
}

// IssueCode mints a single-use authorization code bound to the given consent
// outcome. It is called by the login/consent stage (Task 4.1) after the user
// authenticates and approves; integration tests call it directly. The raw
// code is returned for delivery via redirect; only its hash is stored.
func (s *Service) IssueCode(data AuthorizationCodeData) (string, error) {
	return s.IssueCodeContext(context.Background(), data)
}

// IssueCodeContext requires the version captured by the authenticated session.
func (s *Service) IssueCodeContext(ctx context.Context, data AuthorizationCodeData) (string, error) {
	code, hash, err := NewSecret()
	if err != nil {
		return "", err
	}
	persist := func() error {
		parent, err := s.parentSession(ctx, data.UserID, data.SessionID, data.AuthVersion, data.AuthVersionSet)
		if err != nil {
			return err
		}
		expires := minTime(s.now().Add(s.cfg.CodeTTL), parent.AbsoluteExpiry)
		if data.ExpiresAt.IsZero() || data.ExpiresAt.After(expires) {
			data.ExpiresAt = expires
		}
		return s.codes.Save(ctx, hash, data)
	}
	if s.cfg.AccountState != nil {
		if !data.AuthVersionSet {
			return "", session.ErrAccountIneligible
		}
		err = s.cfg.AccountState.WithActive(ctx, data.UserID, data.AuthVersion, persist)
	} else {
		err = persist()
	}
	if err != nil {
		return "", fmt.Errorf("token: save authorization code: %w", err)
	}
	return code, nil
}

// Exchange dispatches a parsed token request form to the matching grant
// handler. It returns a Response or a *Error suitable for direct
// serialization by the HTTP layer.
func (s *Service) Exchange(ctx context.Context, form url.Values) (*Response, error) {
	switch form.Get("grant_type") {
	case GrantAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, form)
	case GrantRefreshToken:
		return s.exchangeRefreshToken(ctx, form)
	case GrantClientCredentials:
		return s.exchangeClientCredentials(ctx, form)
	case "":
		return nil, newError(ErrCodeInvalidRequest, "missing grant_type", 400)
	default:
		return nil, newError(ErrCodeUnsupportedGrantType, "unsupported grant_type", 400)
	}
}

// exchangeAuthorizationCode implements the authorization_code grant with
// mandatory PKCE S256 (RFC 6749 §4.1.3, RFC 7636 §4.6).
func (s *Service) exchangeAuthorizationCode(ctx context.Context, form url.Values) (*Response, error) {
	clientID := form.Get("client_id")
	if clientID == "" {
		return nil, newError(ErrCodeInvalidRequest, "missing client_id", 400)
	}
	client, err := s.registry.Lookup(clientID)
	if err != nil {
		return nil, newError(ErrCodeInvalidClient, "unknown client", 401)
	}

	code := form.Get("code")
	if code == "" {
		return nil, newError(ErrCodeInvalidRequest, "missing code", 400)
	}
	verifier := form.Get("code_verifier")
	if verifier == "" {
		return nil, newError(ErrCodeInvalidRequest, "code_verifier is required (PKCE)", 400)
	}
	redirectURI := form.Get("redirect_uri")
	if redirectURI == "" {
		return nil, newError(ErrCodeInvalidRequest, "missing redirect_uri", 400)
	}

	// Single-use consumption: the code is atomically removed on first read,
	// so a concurrent or later replay always lands in ErrCodeNotFound.
	data, err := s.codes.Consume(ctx, HashSecret(code))
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return nil, newError(ErrCodeInvalidGrant, "invalid or expired authorization code", 400)
		}
		return nil, s.serverError("consume authorization code", err)
	}

	// Binding checks: the code must belong to this client and the exact
	// redirect_uri it was issued for.
	if data.ClientID != clientID {
		return nil, newError(ErrCodeInvalidGrant, "authorization code was not issued to this client", 400)
	}
	if data.RedirectURI != redirectURI {
		return nil, newError(ErrCodeInvalidGrant, "redirect_uri does not match the authorization request", 400)
	}

	// PKCE S256 proof — constant-time comparison inside.
	if !VerifyPKCE(verifier, data.CodeChallenge) {
		return nil, newError(ErrCodeInvalidGrant, "PKCE verification failed", 400)
	}
	for _, scope := range splitScopes(data.Scope) {
		if !client.AllowsScope(scope) {
			return nil, newError(ErrCodeInvalidGrant, "grant is no longer valid", 400)
		}
	}

	return s.withAccount(ctx, data.UserID, data.AuthVersion, data.AuthVersionSet, func() (*Response, error) {
		parent, err := s.parentSession(ctx, data.UserID, data.SessionID, data.AuthVersion, data.AuthVersionSet)
		if err != nil {
			return nil, s.sessionError(err)
		}
		now := s.now()
		// Sender-constrain the access token to the client's DPoP key when the
		// request carried a validated proof (RFC 9449 §5); otherwise Bearer.
		jkt, tokenType := s.tokenBinding(ctx)
		grant := GrantData{ID: uuid.NewString(), PrincipalType: PrincipalUser, Subject: data.UserID,
			ClientID: clientID, Scope: data.Scope, SessionID: data.SessionID, AuthVersion: data.AuthVersion,
			AuthVersionSet: true, DPoPJKT: jkt, Status: StatusActive, ExpiresAt: parent.AbsoluteExpiry}
		accessToken, expires, err := s.signAccessToken(grant, now)
		if err != nil {
			return nil, s.serverError("sign access token", err)
		}
		idToken, err := s.signIDToken(data.UserID, clientID, data.Nonce, now)
		if err != nil {
			return nil, s.serverError("sign id token", err)
		}

		refreshToken, refreshHash, err := NewSecret()
		if err != nil {
			return nil, s.serverError("issue refresh token", err)
		}
		if err := s.refresh.CreateGrant(ctx, grant, refreshHash, s.refreshForGrant(grant, now)); err != nil {
			return nil, s.serverError("persist grant", err)
		}

		return &Response{
			AccessToken:  accessToken,
			TokenType:    tokenType,
			ExpiresIn:    expires.Unix() - now.Unix(),
			RefreshToken: refreshToken,
			IDToken:      idToken,
			Scope:        data.Scope,
			Subject:      data.UserID,
			ClientID:     clientID,
		}, nil
	})
}

// exchangeRefreshToken implements Refresh Token Rotation with breach
// detection (docs/architecture.md "Refresh Token Rotation (RTR)"):
//
//	active  -> rotated: normal exchange, new token in the same family.
//	rotated -> BREACH:  a rotated token can only reappear if it was stolen
//	                    (or the legitimate client replayed it after losing
//	                    the response). All of the user's refresh tokens are
//	                    revoked instantly, killing every active session.
//	revoked -> BREACH:  same response; continued use after revocation.
func (s *Service) exchangeRefreshToken(ctx context.Context, form url.Values) (*Response, error) {
	presented := form.Get("refresh_token")
	if presented == "" {
		return nil, newError(ErrCodeInvalidRequest, "missing refresh_token", 400)
	}
	clientID := form.Get("client_id")
	if clientID == "" {
		return nil, newError(ErrCodeInvalidRequest, "missing client_id", 400)
	}
	if _, err := s.registry.Lookup(clientID); err != nil {
		return nil, newError(ErrCodeInvalidClient, "unknown client", 401)
	}

	hash := HashSecret(presented)
	data, err := s.refresh.Get(ctx, hash)
	if err != nil {
		// Unknown or expired: plain invalid_grant. No breach signal — there
		// is no record to attribute the attempt to.
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, newError(ErrCodeInvalidGrant, "invalid or expired refresh token", 400)
		}
		return nil, s.serverError("load refresh token", err)
	}
	// The original proof key must be demonstrated before any destructive breach
	// response. A stolen sender-constrained secret alone cannot log out its owner.
	jkt, tokenType := s.tokenBinding(ctx)
	if jkt != data.DPoPJKT {
		return nil, newError(ErrCodeInvalidGrant, "refresh token binding is invalid", 400)
	}

	if data.ClientID != clientID {
		// A token presented by the wrong client is treated with the same
		// severity as a replay: it cannot happen without leakage.
		return nil, s.breachError(ctx, data)
	}

	switch data.Status {
	case StatusActive:
		// Normal rotation path below.
	case StatusRotated, StatusRevoked:
		// Duplicate/replayed presentation — breach detected. Revoke ALL
		// active refresh tokens for the user (every family, every session).
		return nil, s.breachError(ctx, data)
	default:
		return nil, s.serverError("refresh token state", fmt.Errorf("unknown status %q", data.Status))
	}

	breach := false
	response, err := s.withAccount(ctx, data.UserID, data.AuthVersion, data.AuthVersionSet, func() (*Response, error) {
		if _, err := s.parentSession(ctx, data.UserID, data.SessionID, data.AuthVersion, data.AuthVersionSet); err != nil {
			return nil, s.sessionError(err)
		}
		grant, err := s.refresh.GetGrant(ctx, data.FamilyID)
		if errors.Is(err, ErrGrantNotFound) {
			return nil, newError(ErrCodeInvalidGrant, "grant is no longer valid", 400)
		}
		if err != nil {
			return nil, s.serverError("load grant", err)
		}
		if grant.Status != StatusActive {
			breach = true
			return nil, newError(ErrCodeInvalidGrant, "grant is no longer valid", 400)
		}
		now := s.now()
		newRefreshToken, nextHash, err := NewSecret()
		if err != nil {
			return nil, s.serverError("issue rotated refresh token", err)
		}
		accessToken, expires, err := s.signAccessToken(grant, now)
		if err != nil {
			return nil, s.serverError("sign access token", err)
		}
		if err := s.refresh.Rotate(ctx, hash, data, nextHash, s.refreshForGrant(grant, now)); err != nil {
			if errors.Is(err, ErrRefreshReuse) {
				breach = true
				return nil, newError(ErrCodeInvalidGrant, "refresh token already used", 400)
			}
			if errors.Is(err, ErrRefreshTokenNotFound) {
				return nil, newError(ErrCodeInvalidGrant, "grant is no longer valid", 400)
			}
			return nil, s.serverError("rotate refresh token", err)
		}

		return &Response{
			AccessToken:  accessToken,
			TokenType:    tokenType,
			ExpiresIn:    expires.Unix() - now.Unix(),
			RefreshToken: newRefreshToken,
			Scope:        data.Scope,
			Subject:      data.UserID,
			ClientID:     data.ClientID,
		}, nil
	})
	// Do not reenter the account row lock from inside WithActive's callback.
	if breach {
		return nil, s.breachError(ctx, data)
	}
	return response, err
}

func (s *Service) withAccount(ctx context.Context, userID string, version int64, captured bool, issue func() (*Response, error)) (*Response, error) {
	if s.cfg.AccountState == nil {
		return issue()
	}
	if !captured {
		return nil, newError(ErrCodeInvalidGrant, "account authentication is no longer valid", 400)
	}
	var response *Response
	err := s.cfg.AccountState.WithActive(ctx, userID, version, func() error {
		var err error
		response, err = issue()
		return err
	})
	if errors.Is(err, session.ErrAccountIneligible) {
		return nil, newError(ErrCodeInvalidGrant, "account authentication is no longer valid", 400)
	}
	if err != nil {
		var oauthErr *Error
		if errors.As(err, &oauthErr) {
			return nil, err
		}
		return nil, s.serverError("account state", err)
	}
	return response, nil
}

// exchangeClientCredentials implements the client_credentials grant for
// confidential machine clients (docs/client-integration.md §2). The client
// must authenticate via the ClientAuthenticator (private_key_jwt, Task 3.4);
// public clients are categorically rejected. Per OAuth 2.1 no refresh token
// is issued — the client can always re-authenticate.
func (s *Service) exchangeClientCredentials(ctx context.Context, form url.Values) (*Response, error) {
	if s.clientAuth == nil {
		return nil, newError(ErrCodeInvalidClient, "client authentication is not available", 401)
	}
	client, err := s.clientAuth.Authenticate(ctx, form)
	if err != nil {
		return nil, newError(ErrCodeInvalidClient, "client authentication failed", 401)
	}
	if client.IsPublic() {
		return nil, newError(ErrCodeUnauthorizedClient, "public clients cannot use the client_credentials grant", 400)
	}

	scope := form.Get("scope")
	for _, sc := range splitScopes(scope) {
		if !client.AllowsScope(sc) {
			return nil, newError(ErrCodeInvalidScope, "requested scope is not allowed for this client", 400)
		}
	}

	now := s.now()
	// sub == client_id for machine tokens: the client acts on its own behalf.
	jkt, tokenType := s.tokenBinding(ctx)
	grant := GrantData{ID: uuid.NewString(), PrincipalType: PrincipalClient, Subject: client.ID,
		ClientID: client.ID, Scope: scope, DPoPJKT: jkt, Status: StatusActive, ExpiresAt: now.Add(s.cfg.AccessTokenTTL)}
	accessToken, expires, err := s.signAccessToken(grant, now)
	if err != nil {
		return nil, s.serverError("sign access token", err)
	}
	if err := s.refresh.CreateGrant(ctx, grant, "", RefreshTokenData{}); err != nil {
		return nil, s.serverError("persist client grant", err)
	}

	return &Response{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expires.Unix() - now.Unix(),
		Scope:       scope,
		// Subject stays empty on purpose: see Response.Subject.
		ClientID: client.ID,
	}, nil
}

// triggerBreach executes the RTR breach response: revoke every refresh token
// belonging to the user and emit a structured security signal.
func (s *Service) breachError(ctx context.Context, data RefreshTokenData) error {
	// Invalidate primary authority first. Even failed Redis cleanup cannot leave
	// old access tokens valid or let an in-flight issuer restore their authority.
	accountErr := s.cfg.RevokeUser(ctx, data.UserID)
	storeErr := s.refresh.RevokeAllForUser(ctx, data.UserID)
	if accountErr != nil || storeErr != nil {
		s.logger.Error("RTR breach revocation failed", slog.String("user_id", data.UserID))
		return newError(ErrCodeServerError, "credential revocation unavailable", 503)
	}
	s.logger.Warn("RTR breach detected: refresh token reuse; all user sessions revoked",
		slog.String("event", "security.rtr_breach"),
		slog.String("user_id", data.UserID),
		slog.String("client_id", data.ClientID))
	if s.breach != nil {
		s.breach.RecordRTRBreach(ctx, data.UserID, data.ClientID)
	}
	return newError(ErrCodeInvalidGrant, "refresh token reuse detected; all sessions revoked", 400)
}

func (s *Service) refreshForGrant(g GrantData, now time.Time) RefreshTokenData {
	return RefreshTokenData{AuthVersion: g.AuthVersion, AuthVersionSet: g.AuthVersionSet,
		FamilyID: g.ID, UserID: g.Subject, SessionID: g.SessionID, ClientID: g.ClientID,
		Scope: g.Scope, DPoPJKT: g.DPoPJKT, Status: StatusActive,
		ExpiresAt: minTime(now.Add(s.cfg.RefreshTokenTTL), g.ExpiresAt)}
}

// signAccessToken builds and signs an RFC 9068 JWT access token. When jkt is
// non-empty the token is sender-constrained to the client's DPoP key via the
// RFC 9449 §6 cnf.jkt confirmation claim.
func (s *Service) signAccessToken(g GrantData, now time.Time) (string, time.Time, error) {
	expires := minTime(now.Add(s.cfg.AccessTokenTTL), g.ExpiresAt)
	if expires.Unix() <= now.Unix() {
		return "", time.Time{}, session.ErrAccountIneligible
	}
	claims := Claims{
		"iss":            s.cfg.Issuer,
		"sub":            g.Subject,
		"aud":            s.cfg.Issuer,
		"client_id":      g.ClientID,
		"scope":          g.Scope,
		"principal_type": g.PrincipalType,
		"grant_id":       g.ID,
		"jti":            uuid.NewString(),
		"iat":            now.Unix(),
		"exp":            expires.Unix(),
	}
	if g.PrincipalType == PrincipalUser {
		claims["sid"] = g.SessionID
		claims["auth_version"] = g.AuthVersion
	}
	if g.DPoPJKT != "" {
		claims["cnf"] = map[string]string{"jkt": g.DPoPJKT}
	}
	signed, err := Sign(s.keys.ActiveSigner(), TypAccessToken, claims)
	return signed, expires, err
}

func (s *Service) parentSession(ctx context.Context, userID, id string, version int64, captured bool) (session.Session, error) {
	if id == "" || !captured || version < 0 {
		return session.Session{}, session.ErrAccountIneligible
	}
	parent, err := s.cfg.Sessions.LookupByID(ctx, userID, id)
	if errors.Is(err, session.ErrSessionNotFound) {
		return session.Session{}, session.ErrAccountIneligible
	}
	if err != nil {
		return session.Session{}, err
	}
	if parent.ID != id || parent.UserID != userID || parent.Kind != session.KindAuthenticated ||
		!parent.AuthVersionSet || parent.AuthVersion != version || !parent.AbsoluteExpiry.After(s.now()) || !parent.IdleExpiry.After(s.now()) {
		return session.Session{}, session.ErrAccountIneligible
	}
	return parent, nil
}

func (s *Service) sessionError(err error) error {
	if errors.Is(err, session.ErrAccountIneligible) {
		return newError(ErrCodeInvalidGrant, "browser session is no longer valid", 400)
	}
	return s.serverError("browser session", err)
}

// RefreshBinding lets the HTTP adapter enforce the original proof key before
// consuming a nonce. The service independently checks it on direct exchanges.
func (s *Service) RefreshBinding(ctx context.Context, secret string) (string, error) {
	if secret == "" {
		return "", newError(ErrCodeInvalidRequest, "missing refresh_token", 400)
	}
	r, err := s.refresh.Get(ctx, HashSecret(secret))
	if errors.Is(err, ErrRefreshTokenNotFound) {
		return "", newError(ErrCodeInvalidGrant, "invalid or expired refresh token", 400)
	}
	if err != nil {
		return "", s.serverError("refresh token binding", err)
	}
	return r.DPoPJKT, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// tokenBinding resolves the DPoP confirmation thumbprint (cnf.jkt) and the
// token_type the response must advertise for this request. When the request
// carried a validated DPoP proof (injected by the token handler via
// dpop.WithProof), the issued token is confirmed to that key and typed "DPoP";
// otherwise a plain "Bearer" token is issued.
func (s *Service) tokenBinding(ctx context.Context) (jkt, tokenType string) {
	if proof := dpop.ProofFromContext(ctx); proof != nil {
		return proof.JKT, TokenTypeDPoP
	}
	return "", TokenTypeBearer
}

// signIDToken builds and signs the OIDC ID token for the auth-code grant.
func (s *Service) signIDToken(sub, clientID, nonce string, now time.Time) (string, error) {
	claims := Claims{
		"iss": s.cfg.Issuer,
		"sub": sub,
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(s.cfg.IDTokenTTL).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return Sign(s.keys.ActiveSigner(), TypJWT, claims)
}

// serverError logs the internal cause and returns an opaque server_error so
// internals never leak to clients.
func (s *Service) serverError(op string, err error) *Error {
	s.logger.Error("token endpoint internal error", slog.String("op", op))
	if errors.Is(err, ErrStoreUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return newError(ErrCodeServerError, "credential service unavailable", 503)
	}
	return newError(ErrCodeServerError, "internal error", 500)
}

// splitScopes tokenizes a space-delimited scope string, ignoring empties.
func splitScopes(scope string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if start >= 0 {
				out = append(out, scope[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return out
}
