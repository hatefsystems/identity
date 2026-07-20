// Package oidc implements the public OIDC protocol surface of the identity-api.
// This file builds the OpenID Provider Metadata document served at
// /.well-known/openid-configuration (OpenID Connect Discovery 1.0), advertising
// the hardened protocol posture required by docs/api-design.md §1.1: S256-only
// PKCE, private_key_jwt/none client authentication, asymmetric-only signing
// (RS256/ES256), and DPoP support (RFC 9449).
package oidc

import "strings"

// DiscoveryDocument is the OpenID Provider Metadata payload. Field names
// follow the registered metadata names from OIDC Discovery 1.0 §3 and RFC 8414.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValues []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// NewDiscoveryDocument builds the provider metadata for the given issuer URL.
// All endpoint URLs are derived from the issuer so the document can never
// disagree with the canonical identity of the IdP. Security-critical values
// are fixed at compile time — they are policy, not configuration:
//
//   - code_challenge_methods_supported: only S256 (plain is rejected, RFC 7636)
//   - token_endpoint_auth_methods_supported: private_key_jwt (confidential)
//     and none (public clients); secret-based methods are forbidden
//   - signing algorithms: RS256/ES256 only — symmetric HS* is prohibited
//   - response_types: only "code" (OAuth 2.1: implicit/hybrid removed)
func NewDiscoveryDocument(issuer string) DiscoveryDocument {
	base := strings.TrimSuffix(issuer, "/")
	return DiscoveryDocument{
		Issuer:                base,
		AuthorizationEndpoint: base + "/oauth2/auth",
		TokenEndpoint:         base + "/oauth2/token",
		JWKSURI:               base + "/oauth2/jwks",

		ScopesSupported:        []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:  []string{"public"},

		IDTokenSigningAlgValuesSupported:  []string{"RS256", "ES256"},
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt", "none"},
		TokenEndpointAuthSigningAlgValues: []string{"RS256", "ES256"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		DPoPSigningAlgValuesSupported:     []string{"RS256", "ES256"},

		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "email", "email_verified", "name"},
	}
}
