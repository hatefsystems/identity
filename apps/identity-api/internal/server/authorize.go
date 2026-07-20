package server

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc"
)

// Frontend UI routes the authorization endpoint hands off to. These are served
// by the Next.js app (docs/frontend-pages.md §2, docs/devops-operations.md
// Nginx routing): the consent screen collects login/consent, and the error page
// renders a non-redirectable authorization failure. They are relative paths on
// the same host so the reverse proxy routes them to the frontend.
const (
	consentUIPath = "/oauth2/authorize"
	errorUIPath   = "/oauth2/error"
)

// handleAuthorize implements the OIDC/OAuth 2.1 authorization endpoint
// (GET /oauth2/auth, docs/api-design.md §1.1). It strictly validates the
// request — including mandatory PKCE S256 (RFC 7636) — and then routes the
// user-agent:
//
//   - success: 302 to the consent UI carrying the validated parameters. The
//     login/consent stage and authorization-code issuance land in later tasks
//     (session management Task 4.1, token endpoint Task 3.3); this endpoint's
//     responsibility is to admit only well-formed, policy-compliant requests.
//   - redirectable error: 302 back to the client's verified redirect_uri with
//     error/error_description/state (RFC 6749 §4.1.2.1).
//   - non-redirectable error (unknown client or bad redirect_uri): 302 to the
//     IdP's own error page — never to an unverified URI.
func (s *Server) handleAuthorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		req, err := oidc.ParseAuthorizationRequest(q, s.deps.Clients)
		if err != nil {
			s.handleAuthorizeError(w, r, err)
			return
		}

		// Hand off to the login/consent UI with the sanitized, validated
		// parameters. Only known-good values are forwarded.
		params := url.Values{}
		params.Set("client_id", req.ClientID)
		params.Set("redirect_uri", req.RedirectURI)
		params.Set("response_type", req.ResponseType)
		params.Set("scope", req.Scope)
		params.Set("code_challenge", req.CodeChallenge)
		params.Set("code_challenge_method", req.CodeChallengeMethod)
		if req.State != "" {
			params.Set("state", req.State)
		}
		if req.Nonce != "" {
			params.Set("nonce", req.Nonce)
		}

		// Task 3.3/4.1: after the user authenticates and consents at the
		// consent UI, the authorization code is minted (bound to this
		// code_challenge) and returned to redirect_uri; the token endpoint
		// then verifies the code_verifier against the challenge.
		http.Redirect(w, r, consentUIPath+"?"+params.Encode(), http.StatusFound)
	}
}

// handleAuthorizeError routes an authorization validation failure. Redirectable
// errors go back to the client's verified redirect_uri; everything else is
// shown on the IdP's own error page so an unverified redirect_uri is never
// used as a redirect target.
func (s *Server) handleAuthorizeError(w http.ResponseWriter, r *http.Request, err error) {
	authErr, ok := err.(*oidc.AuthorizationError)
	if !ok {
		// Defensive: an unexpected error type is treated as a generic,
		// non-redirectable failure.
		s.redirectToErrorPage(w, r, oidc.ErrCodeInvalidRequest, "invalid authorization request")
		return
	}

	if authErr.Redirectable {
		// authErr.RedirectURI is the config-sourced canonical redirect URI
		// (never raw request input), so it is a safe redirect target.
		target, buildErr := oidc.RedirectErrorURL(authErr)
		if buildErr != nil {
			// The redirect_uri was validated as a registered exact match, so a
			// parse failure here is unexpected; fall back to the error page.
			s.logger.Warn("failed to build authorization error redirect",
				slog.String("error", buildErr.Error()))
			s.redirectToErrorPage(w, r, authErr.Code, authErr.Description)
			return
		}
		// #nosec G710 -- target is derived solely from the client's configured
		// redirect-URI allow-list (clients.CanonicalRedirectURI), never from
		// raw request input, so this cannot be an open redirect. gosec's taint
		// tracker cannot follow the value through the AuthorizationError struct.
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	s.redirectToErrorPage(w, r, authErr.Code, authErr.Description)
}

// redirectToErrorPage sends the user-agent to the IdP's own error UI with the
// error code and description as query parameters.
func (s *Server) redirectToErrorPage(w http.ResponseWriter, r *http.Request, code, description string) {
	params := url.Values{}
	params.Set("error", code)
	if description != "" {
		params.Set("error_description", description)
	}
	http.Redirect(w, r, errorUIPath+"?"+params.Encode(), http.StatusFound)
}
