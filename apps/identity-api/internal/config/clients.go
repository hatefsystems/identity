// OAuth/OIDC client registry configuration. Clients are registered via static
// configuration (Infrastructure as Code) or the KMS/secrets manager — never a
// public developer portal (docs/architecture.md "Secure Client Authentication").
// The registry is loaded from the OIDC_CLIENTS_JSON environment variable, which
// carries a JSON array of client definitions injected at runtime (Infisical in
// production). In development, when the variable is unset, a single public
// client mirroring docs/client-integration.md is seeded so the authorization
// endpoint can be exercised locally.

package config

import (
	"encoding/json"
	"fmt"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
)

// EnvOIDCClients is the environment variable holding the JSON-encoded client
// registry.
const EnvOIDCClients = "OIDC_CLIENTS_JSON"

// devDefaultClient is the public client seeded only in development so local
// authorization-code + PKCE flows work without external configuration. It
// matches the example client in docs/client-integration.md §1.1.
func devDefaultClients() []clients.Client {
	return []clients.Client{
		{
			ID:                      "hatef-nextjs-app",
			RedirectURIs:            []string{"http://localhost:3000/callback"},
			TokenEndpointAuthMethod: clients.AuthMethodNone,
			AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		},
	}
}

// clientJSON is the wire representation of a client in OIDC_CLIENTS_JSON. Field
// names use OAuth/OIDC registration metadata conventions so the same document
// can be authored by ops/IaC without translation.
type clientJSON struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	AllowedScopes           []string `json:"allowed_scopes"`
}

// LoadClients builds the client registry from OIDC_CLIENTS_JSON. Outside
// development the variable is required and must be a non-empty array; in
// development an unset/empty value falls back to a seeded public client. The
// returned registry validates each client (see clients.NewStaticRegistry), so
// malformed configuration fails fast at startup.
func LoadClients(environment string) (*clients.StaticRegistry, error) {
	isDev := environment == "development"
	raw := getEnv(EnvOIDCClients, "")

	if raw == "" {
		if !isDev {
			return nil, fmt.Errorf("config: %s is required outside development", EnvOIDCClients)
		}
		return clients.NewStaticRegistry(devDefaultClients())
	}

	var decoded []clientJSON
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, fmt.Errorf("config: invalid %s: %w", EnvOIDCClients, err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("config: %s must define at least one client", EnvOIDCClients)
	}

	list := make([]clients.Client, 0, len(decoded))
	for _, c := range decoded {
		list = append(list, clients.Client{
			ID:                      c.ClientID,
			RedirectURIs:            c.RedirectURIs,
			TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
			AllowedScopes:           c.AllowedScopes,
		})
	}
	return clients.NewStaticRegistry(list)
}
