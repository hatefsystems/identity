package server

import (
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc"
)

// jwksCacheControl allows short-lived edge/client caching of the JWK set.
// The window must stay well below the rotation overlap period so that a
// rotated-in key is observed long before the previous key stops verifying
// outstanding tokens (graceful 3-key cycle, docs/architecture.md).
const jwksCacheControl = "public, max-age=300, must-revalidate"

// registerOIDCRoutes mounts the discovery and JWKS endpoints. It is only
// called when a key manager is configured (Deps.Keys != nil). The
// authorization endpoint is additionally gated on a configured client registry
// (Deps.Clients != nil), since it cannot validate a client_id without one.
func (s *Server) registerOIDCRoutes() {
	s.router.Get("/.well-known/openid-configuration", s.handleDiscovery())
	s.router.Get("/oauth2/jwks", s.handleJWKS())

	if s.deps.Clients != nil {
		s.router.Get("/oauth2/auth", s.handleAuthorize())
	}
}

// handleDiscovery serves the OpenID Provider Metadata document. The document
// is immutable for the process lifetime (issuer and policy are fixed at
// startup), so it is built once at registration time.
func (s *Server) handleDiscovery() http.HandlerFunc {
	doc := oidc.NewDiscoveryDocument(s.deps.OIDC.Issuer)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", jwksCacheControl)
		writeJSON(w, http.StatusOK, doc)
	}
}

// handleJWKS serves the public JSON Web Key Set. The set is read from the
// manager on every request so that a rotation is visible immediately; the
// manager guarantees only public JWK parameters can be serialized.
func (s *Server) handleJWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", jwksCacheControl)
		writeJSON(w, http.StatusOK, s.deps.Keys.JWKSet())
	}
}
