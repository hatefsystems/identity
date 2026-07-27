package dpop

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// HeaderProof is the request header carrying the compact DPoP proof JWS
// (RFC 9449 §4).
const HeaderProof = "DPoP"

// HeaderNonce is the response header by which the server supplies a fresh nonce
// the client must echo in the next proof (RFC 9449 §8).
const HeaderNonce = "DPoP-Nonce"

// authSchemeDPoP is the HTTP authentication scheme for DPoP-bound access tokens
// (RFC 9449 §7.1): "Authorization: DPoP <token>".
const authSchemeDPoP = "DPoP"

// RFC 9449 §5 / §7 error codes surfaced to clients. They are intentionally the
// only detail leaked; the specific internal cause stays in server logs.
const (
	errCodeInvalidProof = "invalid_dpop_proof"
	errCodeUseNonce     = "use_dpop_nonce"
)

// Middleware is chi/net-http compatible middleware that enforces DPoP on a
// route. It extracts the DPoP proof, validates it against the actual request
// method and URL, requires the bound access token's ath when a DPoP-scheme
// Authorization header is present, and manages the DPoP-Nonce lifecycle. On
// success the validated Proof is stored in the request context
// (ProofFromContext) for downstream handlers.
//
// This is the resource-server profile (protecting /api/v1/* per
// docs/frontend-pages.md §5.2). The token endpoint uses the Validator directly
// so it can bind cnf.jkt into freshly issued tokens; see server.handleToken.
type Middleware struct {
	validator *Validator
	// externalBaseURL is the public origin (scheme://host) clients address,
	// e.g. "https://identity.hatef.ir". Because TLS is terminated at the
	// reverse proxy (docs/devops-operations.md §1.0), r.URL carries no scheme
	// or host; htu is reconstructed from this trusted base plus r.URL.Path.
	externalBaseURL string
	// requireNonce toggles the server-issued nonce lifecycle for the route.
	requireNonce bool
}

// MiddlewareOption customizes a Middleware.
type MiddlewareOption func(*Middleware)

// WithRequireNonce enables the DPoP-Nonce lifecycle on the protected route.
func WithRequireNonce(require bool) MiddlewareOption {
	return func(m *Middleware) { m.requireNonce = require }
}

// NewMiddleware constructs DPoP enforcement middleware. externalBaseURL is the
// public origin (scheme://host, no trailing slash) used to reconstruct the htu
// the proof must match.
func NewMiddleware(v *Validator, externalBaseURL string, opts ...MiddlewareOption) (*Middleware, error) {
	if v == nil {
		return nil, errors.New("dpop: validator is required")
	}
	if strings.TrimSpace(externalBaseURL) == "" {
		return nil, errors.New("dpop: external base URL is required")
	}
	m := &Middleware{
		validator:       v,
		externalBaseURL: strings.TrimSuffix(externalBaseURL, "/"),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// Handler wraps next with DPoP enforcement.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proofHeader := r.Header.Get(HeaderProof)
		if proofHeader == "" {
			m.writeError(w, r, http.StatusUnauthorized, errCodeInvalidProof,
				"DPoP proof required", nil)
			return
		}

		params := VerifyParams{
			Method:       r.Method,
			URL:          m.externalBaseURL + r.URL.Path,
			RequireNonce: m.requireNonce,
		}
		// When the caller presents a DPoP-bound access token, the proof must
		// carry a matching ath (RFC 9449 §7.1).
		if tok, ok := bearerDPoPToken(r.Header.Get("Authorization")); ok {
			params.AccessToken = tok
		}

		proof, err := m.validator.Validate(r.Context(), proofHeader, params)
		if err != nil {
			if errors.Is(err, ErrNonceRequired) {
				m.writeError(w, r, http.StatusUnauthorized, errCodeUseNonce,
					"resource server requires nonce in DPoP proof", err)
				return
			}
			m.writeError(w, r, http.StatusUnauthorized, errCodeInvalidProof,
				"DPoP proof validation failed", err)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithProof(r.Context(), proof)))
	})
}

// writeError emits an RFC 9449 §7.2 WWW-Authenticate challenge. When the code
// is use_dpop_nonce it also supplies a fresh DPoP-Nonce so the client can
// retry immediately.
func (m *Middleware) writeError(w http.ResponseWriter, r *http.Request, status int, code, desc string, _ error) {
	if code == errCodeUseNonce {
		if nonce, nErr := m.validator.IssueNonce(r.Context()); nErr == nil && nonce != "" {
			w.Header().Set(HeaderNonce, nonce)
		}
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`%s error=%q, error_description=%q`, authSchemeDPoP, code, desc))
	w.WriteHeader(status)
}

// bearerDPoPToken extracts the token from an "Authorization: DPoP <token>"
// header. It returns ("", false) for any other scheme or a missing header —
// DPoP-bound tokens must use the DPoP auth scheme, never Bearer.
func bearerDPoPToken(authorization string) (string, bool) {
	const prefix = authSchemeDPoP + " "
	if len(authorization) <= len(prefix) ||
		!strings.EqualFold(authorization[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(authorization[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
