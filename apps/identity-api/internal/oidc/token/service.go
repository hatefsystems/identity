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
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
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
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	CodeTTL         time.Duration
	IDTokenTTL      time.Duration
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
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
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
	if signer == nil || registry == nil || codes == nil || refresh == nil {
		return nil, errors.New("token: signer, registry, code store and refresh store are required")
	}
	if cfg.Issuer == "" {
		return nil, errors.New("token: issuer is required")
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
	code, hash, err := NewSecret()
	if err != nil {
		return "", err
	}
	if data.ExpiresAt.IsZero() {
		data.ExpiresAt = s.now().Add(s.cfg.CodeTTL)
	}
	if err := s.codes.Save(hash, data); err != nil {
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
	if _, err := s.registry.Lookup(clientID); err != nil {
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
	data, err := s.codes.Consume(HashSecret(code))
	if err != nil {
		return nil, newError(ErrCodeInvalidGrant, "invalid or expired authorization code", 400)
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

	now := s.now()
	accessToken, err := s.signAccessToken(data.UserID, clientID, data.Scope, now)
	if err != nil {
		return nil, s.serverError("sign access token", err)
	}
	idToken, err := s.signIDToken(data.UserID, clientID, data.Nonce, now)
	if err != nil {
		return nil, s.serverError("sign id token", err)
	}

	// Start a fresh refresh-token family for this grant/session.
	refreshToken, err := s.issueRefreshToken(uuid.NewString(), data.UserID, clientID, data.Scope, now)
	if err != nil {
		return nil, s.serverError("issue refresh token", err)
	}

	_ = ctx // reserved for DPoP binding and audit hooks in later tasks
	return &Response{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        data.Scope,
	}, nil
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
	data, err := s.refresh.Get(hash)
	if err != nil {
		// Unknown or expired: plain invalid_grant. No breach signal — there
		// is no record to attribute the attempt to.
		return nil, newError(ErrCodeInvalidGrant, "invalid or expired refresh token", 400)
	}

	if data.ClientID != clientID {
		// A token presented by the wrong client is treated with the same
		// severity as a replay: it cannot happen without leakage.
		s.triggerBreach(ctx, data)
		return nil, newError(ErrCodeInvalidGrant, "refresh token was not issued to this client", 400)
	}

	switch data.Status {
	case StatusActive:
		// Normal rotation path below.
	case StatusRotated, StatusRevoked:
		// Duplicate/replayed presentation — breach detected. Revoke ALL
		// active refresh tokens for the user (every family, every session).
		s.triggerBreach(ctx, data)
		return nil, newError(ErrCodeInvalidGrant, "refresh token reuse detected; all sessions revoked", 400)
	default:
		return nil, s.serverError("refresh token state", fmt.Errorf("unknown status %q", data.Status))
	}

	// Rotate: retire the presented token first so a crash between the two
	// writes can never leave two active tokens in the family.
	if err := s.refresh.MarkRotated(hash); err != nil {
		return nil, s.serverError("rotate refresh token", err)
	}

	now := s.now()
	newRefreshToken, err := s.issueRefreshToken(data.FamilyID, data.UserID, data.ClientID, data.Scope, now)
	if err != nil {
		return nil, s.serverError("issue rotated refresh token", err)
	}
	accessToken, err := s.signAccessToken(data.UserID, data.ClientID, data.Scope, now)
	if err != nil {
		return nil, s.serverError("sign access token", err)
	}

	return &Response{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: newRefreshToken,
		Scope:        data.Scope,
	}, nil
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
	accessToken, err := s.signAccessToken(client.ID, client.ID, scope, now)
	if err != nil {
		return nil, s.serverError("sign access token", err)
	}

	return &Response{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.cfg.AccessTokenTTL.Seconds()),
		Scope:       scope,
	}, nil
}

// triggerBreach executes the RTR breach response: revoke every refresh token
// belonging to the user and emit a structured security signal.
func (s *Service) triggerBreach(ctx context.Context, data RefreshTokenData) {
	if err := s.refresh.RevokeAllForUser(data.UserID); err != nil {
		// Revocation failure is itself a security-critical condition; log at
		// error level so it pages via log-based alerting.
		s.logger.Error("RTR breach: failed to revoke user refresh tokens",
			slog.String("user_id", data.UserID), slog.String("error", err.Error()))
	}
	s.logger.Warn("RTR breach detected: refresh token reuse; all user sessions revoked",
		slog.String("event", "security.rtr_breach"),
		slog.String("user_id", data.UserID),
		slog.String("client_id", data.ClientID))
	if s.breach != nil {
		s.breach.RecordRTRBreach(ctx, data.UserID, data.ClientID)
	}
}

// issueRefreshToken mints and stores a new active refresh token in familyID.
func (s *Service) issueRefreshToken(familyID, userID, clientID, scope string, now time.Time) (string, error) {
	tokenValue, hash, err := NewSecret()
	if err != nil {
		return "", err
	}
	err = s.refresh.Save(hash, RefreshTokenData{
		FamilyID:  familyID,
		UserID:    userID,
		ClientID:  clientID,
		Scope:     scope,
		Status:    StatusActive,
		ExpiresAt: now.Add(s.cfg.RefreshTokenTTL),
	})
	if err != nil {
		return "", fmt.Errorf("token: save refresh token: %w", err)
	}
	return tokenValue, nil
}

// signAccessToken builds and signs an RFC 9068 JWT access token.
func (s *Service) signAccessToken(sub, clientID, scope string, now time.Time) (string, error) {
	return Sign(s.keys.ActiveSigner(), TypAccessToken, Claims{
		"iss":       s.cfg.Issuer,
		"sub":       sub,
		"aud":       s.cfg.Issuer,
		"client_id": clientID,
		"scope":     scope,
		"jti":       uuid.NewString(),
		"iat":       now.Unix(),
		"exp":       now.Add(s.cfg.AccessTokenTTL).Unix(),
	})
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
	s.logger.Error("token endpoint internal error", slog.String("op", op), slog.String("error", err.Error()))
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
