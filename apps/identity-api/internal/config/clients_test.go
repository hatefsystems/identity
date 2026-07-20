package config

import (
	"testing"
)

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
	t.Setenv(EnvOIDCClients, `[
		{
			"client_id": "search-core",
			"redirect_uris": ["https://search.hatef.ir/callback"],
			"token_endpoint_auth_method": "private_key_jwt",
			"allowed_scopes": ["openid", "search.full"]
		}
	]`)
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
