package oidc

import (
	"encoding/json"
	"testing"
)

func TestNewDiscoveryDocumentDerivesEndpointsFromIssuer(t *testing.T) {
	doc := NewDiscoveryDocument("https://identity.hatef.ir")

	if doc.Issuer != "https://identity.hatef.ir" {
		t.Errorf("issuer = %q", doc.Issuer)
	}
	if doc.AuthorizationEndpoint != "https://identity.hatef.ir/oauth2/auth" {
		t.Errorf("authorization_endpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "https://identity.hatef.ir/oauth2/token" {
		t.Errorf("token_endpoint = %q", doc.TokenEndpoint)
	}
	if doc.JWKSURI != "https://identity.hatef.ir/oauth2/jwks" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
}

func TestNewDiscoveryDocumentTrimsTrailingSlash(t *testing.T) {
	doc := NewDiscoveryDocument("https://identity.hatef.ir/")
	if doc.Issuer != "https://identity.hatef.ir" {
		t.Errorf("issuer should have no trailing slash, got %q", doc.Issuer)
	}
	if doc.JWKSURI != "https://identity.hatef.ir/oauth2/jwks" {
		t.Errorf("jwks_uri = %q", doc.JWKSURI)
	}
}

// TestDiscoverySecurityPosture pins the security-critical metadata values from
// docs/api-design.md §1.1: S256-only PKCE, private_key_jwt/none client auth,
// asymmetric-only signing, and DPoP algorithm support.
func TestDiscoverySecurityPosture(t *testing.T) {
	doc := NewDiscoveryDocument("https://identity.hatef.ir")

	if len(doc.CodeChallengeMethodsSupported) != 1 || doc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("code_challenge_methods_supported must be exactly [S256], got %v", doc.CodeChallengeMethodsSupported)
	}
	if len(doc.TokenEndpointAuthMethodsSupported) != 2 ||
		doc.TokenEndpointAuthMethodsSupported[0] != "private_key_jwt" ||
		doc.TokenEndpointAuthMethodsSupported[1] != "none" {
		t.Errorf("token_endpoint_auth_methods_supported must be [private_key_jwt none], got %v", doc.TokenEndpointAuthMethodsSupported)
	}
	for _, alg := range doc.IDTokenSigningAlgValuesSupported {
		if alg == "HS256" || alg == "HS384" || alg == "HS512" || alg == "none" {
			t.Errorf("symmetric/none signing alg %q must never be advertised", alg)
		}
	}
	if len(doc.DPoPSigningAlgValuesSupported) == 0 {
		t.Error("dpop_signing_alg_values_supported must be advertised (RFC 9449)")
	}
	for _, rt := range doc.ResponseTypesSupported {
		if rt != "code" {
			t.Errorf("OAuth 2.1 forbids response type %q", rt)
		}
	}
}

// TestDiscoveryJSONFieldNames guards the wire-level JSON member names against
// accidental struct-tag typos.
func TestDiscoveryJSONFieldNames(t *testing.T) {
	raw, err := json.Marshal(NewDiscoveryDocument("https://identity.hatef.ir"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, member := range []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported",
		"dpop_signing_alg_values_supported",
	} {
		if _, ok := decoded[member]; !ok {
			t.Errorf("discovery document missing required member %q", member)
		}
	}
}
