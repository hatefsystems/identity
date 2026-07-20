// Authorization endpoint request parsing and validation (OAuth 2.1 / OIDC Core
// 1.0, RFC 6749 §4.1.1, RFC 7636). This file is transport-agnostic: it takes
// the decoded query parameters and the resolved client, applies the hardened
// protocol rules, and returns either a validated request or a typed error that
// tells the HTTP layer whether the failure may be redirected back to the client
// or not.
//
// Hardened posture (docs/architecture.md, docs/api-design.md §1.1):
//   - response_type: only "code" (OAuth 2.1 removes implicit/hybrid).
//   - PKCE: code_challenge is REQUIRED and code_challenge_method MUST be S256;
//     the "plain" method is rejected at the protocol layer (RFC 7636 §4.3).
//   - scope: must contain "openid" and stay within the client's allowed set.
//   - redirect_uri: exact match against the registered set (validated by the
//     caller before reaching redirectable-error handling).

package oidc

import (
	"errors"
	"net/url"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
)

// PKCE constants (RFC 7636).
const (
	// CodeChallengeMethodS256 is the only accepted PKCE method. "plain" is
	// deliberately unsupported.
	CodeChallengeMethodS256 = "S256"
	// codeChallengeLen is the length of a base64url-encoded SHA-256 digest
	// without padding (32 bytes -> 43 chars). The verifier is hashed with
	// SHA-256 by the client, so a well-formed S256 challenge is always 43
	// characters.
	codeChallengeLen = 43
)

// responseTypeCode is the only supported OAuth 2.1 response type.
const responseTypeCode = "code"

// scopeOpenID is the mandatory OIDC scope; without it the request is a bare
// OAuth request, not an OIDC authentication request.
const scopeOpenID = "openid"

// OAuth 2.0 authorization error codes (RFC 6749 §4.1.2.1).
const (
	ErrCodeInvalidRequest          = "invalid_request"
	ErrCodeUnauthorizedClient      = "unauthorized_client"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope            = "invalid_scope"
	ErrCodeInvalidClient           = "invalid_client"
)

// AuthorizationRequest is a validated /oauth2/auth request ready to be handed
// to the login/consent stage. All fields have passed protocol validation.
type AuthorizationRequest struct {
	Client              clients.Client
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizationError is a typed validation failure. Redirectable errors are
// returned to the client's (already-validated) redirect_uri as query
// parameters per RFC 6749 §4.1.2.1; non-redirectable errors (unknown client or
// bad/missing redirect_uri) must NOT be redirected to an unverified URI and are
// instead shown on the IdP's own error page.
type AuthorizationError struct {
	// Code is the OAuth error code (e.g. "invalid_request").
	Code string
	// Description is a human-readable, non-sensitive explanation.
	Description string
	// Redirectable indicates the error may be delivered to the client's
	// redirect_uri. When false, the redirect_uri could not be trusted.
	Redirectable bool
	// RedirectURI is the target for a redirectable error. It is always sourced
	// from the client's configured allow-list (never from raw request input),
	// so it is safe to use as a redirect target. Empty for fatal errors.
	RedirectURI string
	// State is the client-supplied state to echo back on a redirectable error
	// (RFC 6749 §4.1.2.1). Empty when the client sent none.
	State string
}

// Error implements the error interface.
func (e *AuthorizationError) Error() string {
	return e.Code + ": " + e.Description
}

// newRedirectableError builds an error that is safe to return to the client's
// verified redirect_uri. The redirectURI must be the canonical, config-sourced
// value (not raw request input).
func newRedirectableError(code, description, redirectURI, state string) *AuthorizationError {
	return &AuthorizationError{
		Code:         code,
		Description:  description,
		Redirectable: true,
		RedirectURI:  redirectURI,
		State:        state,
	}
}

// newFatalError builds an error that must be shown on the IdP's own error page
// because the redirect_uri cannot be trusted.
func newFatalError(code, description string) *AuthorizationError {
	return &AuthorizationError{Code: code, Description: description, Redirectable: false}
}

// ParseAuthorizationRequest validates the decoded authorization request query
// parameters against the registry. Validation order matters: the client and
// redirect_uri are checked first because they determine whether any subsequent
// error may be redirected back to the client (RFC 6749 §4.1.2.1). On success it
// returns a fully validated AuthorizationRequest.
func ParseAuthorizationRequest(q url.Values, registry clients.Registry) (*AuthorizationRequest, error) {
	// 1. client_id — required, must be known. A failure here is fatal
	//    (non-redirectable): we cannot trust any redirect_uri for an unknown
	//    client.
	clientID := strings.TrimSpace(q.Get("client_id"))
	if clientID == "" {
		return nil, newFatalError(ErrCodeInvalidRequest, "missing client_id")
	}
	client, err := registry.Lookup(clientID)
	if err != nil {
		if errors.Is(err, clients.ErrUnknownClient) {
			return nil, newFatalError(ErrCodeInvalidClient, "unknown client_id")
		}
		return nil, newFatalError(ErrCodeInvalidClient, "client lookup failed")
	}

	// 2. redirect_uri — required, must exactly match a registered URI. A
	//    mismatch is fatal: redirecting an error to an unverified URI would be
	//    an open redirect / token-leak vector. From here on we use canonicalURI
	//    (the config-sourced value) as the redirect target so that raw request
	//    input never flows into a redirect.
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		return nil, newFatalError(ErrCodeInvalidRequest, "missing redirect_uri")
	}
	canonicalURI, ok := client.CanonicalRedirectURI(redirectURI)
	if !ok {
		return nil, newFatalError(ErrCodeInvalidRequest, "redirect_uri does not match a registered URI")
	}

	// From here on, errors may be redirected back to the client's canonical
	// (config-sourced) redirect_uri, echoing state per RFC 6749 §4.1.2.1.
	state := q.Get("state")

	// 3. response_type — only "code" (OAuth 2.1).
	responseType := q.Get("response_type")
	if responseType == "" {
		return nil, newRedirectableError(ErrCodeInvalidRequest, "missing response_type", canonicalURI, state)
	}
	if responseType != responseTypeCode {
		return nil, newRedirectableError(ErrCodeUnsupportedResponseType, "only the authorization code flow (response_type=code) is supported", canonicalURI, state)
	}

	// 4. PKCE — code_challenge required, method MUST be S256 (plain rejected).
	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		return nil, newRedirectableError(ErrCodeInvalidRequest, "code_challenge is required (PKCE)", canonicalURI, state)
	}
	// The method defaults to "plain" when omitted (RFC 7636 §4.3); we require
	// it to be present and explicitly S256 so an omitted method can never be
	// silently treated as plain.
	method := q.Get("code_challenge_method")
	if method == "" {
		return nil, newRedirectableError(ErrCodeInvalidRequest, "code_challenge_method is required and must be S256", canonicalURI, state)
	}
	if method != CodeChallengeMethodS256 {
		return nil, newRedirectableError(ErrCodeInvalidRequest, "unsupported code_challenge_method; only S256 is allowed", canonicalURI, state)
	}
	if !isValidS256Challenge(codeChallenge) {
		return nil, newRedirectableError(ErrCodeInvalidRequest, "malformed code_challenge; expected base64url-encoded SHA-256 digest", canonicalURI, state)
	}

	// 5. scope — required, must contain openid and stay within the client's
	//    allowed set.
	scope := strings.TrimSpace(q.Get("scope"))
	if scope == "" {
		return nil, newRedirectableError(ErrCodeInvalidScope, "scope is required and must include openid", canonicalURI, state)
	}
	scopes := strings.Fields(scope)
	if !containsScope(scopes, scopeOpenID) {
		return nil, newRedirectableError(ErrCodeInvalidScope, "the openid scope is required", canonicalURI, state)
	}
	for _, s := range scopes {
		if !client.AllowsScope(s) {
			return nil, newRedirectableError(ErrCodeInvalidScope, "requested scope is not allowed for this client", canonicalURI, state)
		}
	}

	return &AuthorizationRequest{
		Client:              client,
		ClientID:            clientID,
		RedirectURI:         canonicalURI,
		ResponseType:        responseType,
		Scope:               scope,
		Scopes:              scopes,
		State:               state,
		Nonce:               q.Get("nonce"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: method,
	}, nil
}

// isValidS256Challenge reports whether s is a well-formed base64url (no
// padding) encoding of a 32-byte SHA-256 digest: exactly 43 characters drawn
// from the base64url alphabet. This rejects padded, wrong-length, or
// out-of-alphabet challenges before they reach the token endpoint.
func isValidS256Challenge(s string) bool {
	if len(s) != codeChallengeLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// containsScope reports whether target is present in scopes.
func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// RedirectErrorURL builds the redirect URL used to return a redirectable error
// to the client. It uses the error's own RedirectURI and State — both sourced
// from the client's configured allow-list / captured during validation, never
// from raw request input reread at call time — preserving any existing query on
// the base redirect_uri and appending error, error_description, and (when
// present) state per RFC 6749 §4.1.2.1. It returns an error only if the stored
// redirect_uri cannot be parsed, which should never happen because it was
// validated on registration.
func RedirectErrorURL(authErr *AuthorizationError) (string, error) {
	u, err := url.Parse(authErr.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("error", authErr.Code)
	if authErr.Description != "" {
		q.Set("error_description", authErr.Description)
	}
	if authErr.State != "" {
		q.Set("state", authErr.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
