// Package clients holds the OAuth/OIDC client registry for the identity-api.
//
// Clients are registered exclusively via static configuration (Infrastructure
// as Code) or a Super Admin internal API — there is deliberately no public
// developer portal (docs/architecture.md "Secure Client Authentication"). This
// package models a registered client and an in-memory registry used by the
// authorization and (later) token endpoints to resolve a client_id, verify the
// redirect_uri with an exact match, and enforce the client's allowed scopes.
package clients

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// Token endpoint authentication methods permitted by the platform. Secret-based
// methods (client_secret_post/basic) are forbidden (docs/architecture.md
// "Forbid Secret-in-Body/URL"); confidential clients use private_key_jwt and
// public clients use none.
const (
	AuthMethodNone          = "none"
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// ErrUnknownClient is returned when a client_id is not present in the registry.
var ErrUnknownClient = errors.New("clients: unknown client_id")

// Client is a registered OAuth/OIDC client.
type Client struct {
	// ID is the client_id used in authorization and token requests.
	ID string
	// RedirectURIs is the exhaustive allow-list of redirect URIs. Matching is
	// exact (OAuth 2.1): no wildcards, prefixes, or substring matches.
	RedirectURIs []string
	// TokenEndpointAuthMethod is how the client authenticates at the token
	// endpoint: "none" (public) or "private_key_jwt" (confidential).
	TokenEndpointAuthMethod string
	// AllowedScopes is the set of scopes the client may request. A request for
	// any scope outside this set is rejected.
	AllowedScopes []string
	// PublicKeys holds the confidential client's registered verification keys,
	// keyed by their kid. It is populated only for private_key_jwt clients and
	// is used by the token endpoint to verify RFC 7523 client assertions
	// against the client's pre-registered public keys. Public clients
	// (AuthMethodNone) must leave this empty.
	PublicKeys map[string]*keys.PublicKey
}

// PublicKey returns the registered verification key with the given kid, along
// with true when it exists. A confidential client selects its signing key by
// kid in the assertion header; an unknown kid yields a failed authentication.
func (c Client) PublicKey(kid string) (*keys.PublicKey, bool) {
	k, ok := c.PublicKeys[kid]
	return k, ok
}

// IsPublic reports whether the client is a public client (no credentials at the
// token endpoint) and therefore incapable of holding a secret.
func (c Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == AuthMethodNone
}

// HasRedirectURI reports whether uri is an exact match of a registered redirect
// URI. Exact string comparison is intentional: OAuth 2.1 forbids fuzzy matching
// of redirect URIs to prevent open-redirect and token-leak attacks.
func (c Client) HasRedirectURI(uri string) bool {
	_, ok := c.CanonicalRedirectURI(uri)
	return ok
}

// CanonicalRedirectURI returns the registered redirect URI that exactly matches
// uri, along with true when a match exists. The returned value is sourced from
// the client's configured allow-list — not the caller's input — so callers can
// use it as a redirect target without reintroducing an open-redirect taint.
func (c Client) CanonicalRedirectURI(uri string) (string, bool) {
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return registered, true
		}
	}
	return "", false
}

// AllowsScope reports whether scope is within the client's allowed set.
func (c Client) AllowsScope(scope string) bool {
	for _, allowed := range c.AllowedScopes {
		if allowed == scope {
			return true
		}
	}
	return false
}

// Registry resolves a client by its client_id.
type Registry interface {
	// Lookup returns the client registered under id, or ErrUnknownClient.
	Lookup(id string) (Client, error)
}

// StaticRegistry is an immutable, in-memory Registry built from static
// configuration. It is safe for concurrent use because it is never mutated
// after construction.
type StaticRegistry struct {
	byID map[string]Client
}

// NewStaticRegistry validates and indexes the provided clients. It rejects
// duplicate IDs, empty IDs, clients without any redirect URI, and unsupported
// token endpoint authentication methods so that misconfiguration fails fast at
// startup rather than surfacing as confusing runtime authorization errors.
func NewStaticRegistry(list []Client) (*StaticRegistry, error) {
	byID := make(map[string]Client, len(list))
	for _, c := range list {
		if strings.TrimSpace(c.ID) == "" {
			return nil, errors.New("clients: client ID must not be empty")
		}
		if _, dup := byID[c.ID]; dup {
			return nil, fmt.Errorf("clients: duplicate client ID %q", c.ID)
		}
		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("clients: client %q has no redirect URIs", c.ID)
		}
		switch c.TokenEndpointAuthMethod {
		case AuthMethodNone:
			// Public clients hold no credentials and therefore must not carry
			// verification keys; a key here signals a misconfiguration.
			if len(c.PublicKeys) > 0 {
				return nil, fmt.Errorf("clients: public client %q must not register public keys", c.ID)
			}
		case AuthMethodPrivateKeyJWT:
			// Confidential clients authenticate with signed assertions and are
			// unusable without at least one registered verification key.
			if len(c.PublicKeys) == 0 {
				return nil, fmt.Errorf("clients: private_key_jwt client %q has no registered public keys", c.ID)
			}
			for kid, key := range c.PublicKeys {
				if key == nil {
					return nil, fmt.Errorf("clients: client %q has a nil public key for kid %q", c.ID, kid)
				}
			}
		default:
			return nil, fmt.Errorf(
				"clients: client %q has unsupported token_endpoint_auth_method %q (only %q and %q are allowed)",
				c.ID, c.TokenEndpointAuthMethod, AuthMethodNone, AuthMethodPrivateKeyJWT,
			)
		}
		byID[c.ID] = c
	}
	return &StaticRegistry{byID: byID}, nil
}

// Lookup implements Registry.
func (r *StaticRegistry) Lookup(id string) (Client, error) {
	c, ok := r.byID[id]
	if !ok {
		return Client{}, ErrUnknownClient
	}
	return c, nil
}

// IDs returns the registered client IDs in sorted order (primarily for logging
// and diagnostics).
func (r *StaticRegistry) IDs() []string {
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
