package config

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// testJWKJSON generates an ES256 key and returns its public JWK as a JSON
// object string suitable for embedding in an OIDC_CLIENTS_JSON "jwks" set.
func testJWKJSON(t *testing.T) string {
	t.Helper()
	sk, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	raw, err := json.Marshal(sk.PublicJWK)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	return string(raw)
}

func TestLoadClientsDevDefault(t *testing.T) {
	t.Setenv(EnvOIDCClients, "")
	reg, err := LoadClients("development")
	if err != nil {
		t.Fatalf("LoadClients(development): %v", err)
	}
	if _, err := reg.Lookup("hatef-nextjs-app"); err != nil {
		t.Fatalf("dev default client not seeded: %v", err)
	}
}

func TestLoadClientsRequiredOutsideDev(t *testing.T) {
	t.Setenv(EnvOIDCClients, "")
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error when OIDC_CLIENTS_JSON is unset outside development")
	}
}

func TestLoadClientsFromJSON(t *testing.T) {
	jwk := testJWKJSON(t)
	t.Setenv(EnvOIDCClients, fmt.Sprintf(`[
		{
			"client_id": "search-core",
			"redirect_uris": ["https://search.hatef.ir/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"allowed_scopes": ["openid", "search.full"],
			"jwks": {"keys": [%s]}
		}
	]`, jwk))
	reg, err := LoadClients("production")
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	c, err := reg.Lookup("search-core")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if c.IsPublic() {
		t.Error("private_key_jwt client must not be public")
	}
	if !c.HasRedirectURI("https://search.hatef.ir/callback") {
		t.Error("redirect URI not loaded")
	}
	if len(c.PublicKeys) != 1 {
		t.Errorf("expected 1 public key parsed, got %d", len(c.PublicKeys))
	}
}

func TestLoadClientsPrivateKeyJWTRequiresJWKS(t *testing.T) {
	// A confidential client with no jwks must fail fast at load time.
	t.Setenv(EnvOIDCClients, `[
		{
			"client_id": "search-core",
			"redirect_uris": ["https://search.hatef.ir/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"allowed_scopes": ["openid", "search.full"]
		}
	]`)
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error when private_key_jwt client omits jwks")
	}
}

func TestLoadClientsRejectsInvalidJWK(t *testing.T) {
	// An RSA key below the 2048-bit minimum must be rejected by ParsePublicJWK.
	t.Setenv(EnvOIDCClients, `[
		{
			"client_id": "search-core",
			"redirect_uris": ["https://search.hatef.ir/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"allowed_scopes": ["openid"],
			"jwks": {"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB"}]}
		}
	]`)
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error for undersized RSA key")
	}
}

func TestLoadClientsPublicClientRejectsJWKS(t *testing.T) {
	jwk := testJWKJSON(t)
	t.Setenv(EnvOIDCClients, fmt.Sprintf(`[
		{
			"client_id": "web-app",
			"redirect_uris": ["https://app.hatef.ir/callback"],
			"token_endpoint_auth_method": "none",
			"allowed_scopes": ["openid"],
			"jwks": {"keys": [%s]}
		}
	]`, jwk))
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error when a public client registers keys")
	}
}

func TestLoadClientsInvalidJSON(t *testing.T) {
	t.Setenv(EnvOIDCClients, `{not json`)
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoadClientsEmptyArray(t *testing.T) {
	t.Setenv(EnvOIDCClients, `[]`)
	if _, err := LoadClients("production"); err == nil {
		t.Fatal("expected error for empty client array")
	}
}
