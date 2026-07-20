package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// newOIDCTestServer builds a Server with an ephemeral 2-key manager and a
// fixed issuer, returning both for assertions.
func newOIDCTestServer(t *testing.T) (*Server, *keys.Manager) {
	t.Helper()
	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("generate active key: %v", err)
	}
	next, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("generate next key: %v", err)
	}
	manager, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := New(testConfig(t), nil, Deps{
		OIDC: config.OIDCConfig{Issuer: "https://identity.hatef.ir"},
		Keys: manager,
	})
	return srv, manager
}

func TestDiscoveryEndpoint(t *testing.T) {
	srv, _ := newOIDCTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if doc["issuer"] != "https://identity.hatef.ir" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["jwks_uri"] != "https://identity.hatef.ir/oauth2/jwks" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv, manager := newOIDCTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("JWKS response should set Cache-Control")
	}

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("expected 2 published keys (active+next), got %d", len(set.Keys))
	}
	for i, jwk := range set.Keys {
		for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if _, ok := jwk[forbidden]; ok {
				t.Errorf("keys[%d] leaks private member %q", i, forbidden)
			}
		}
		if jwk["kid"] == "" || jwk["kty"] == "" {
			t.Errorf("keys[%d] missing kid/kty: %v", i, jwk)
		}
	}

	// A rotation must be visible on the next request (no stale server-side
	// caching of the key set).
	newNext, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("generate rotation key: %v", err)
	}
	if err := manager.Rotate(newNext); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(set.Keys) != 3 {
		t.Errorf("after rotation expected 3 published keys, got %d", len(set.Keys))
	}
}

func TestOIDCRoutesAbsentWithoutKeyManager(t *testing.T) {
	srv := New(testConfig(t), nil, Deps{})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("without a key manager /oauth2/jwks should 404, got %d", rec.Code)
	}
}
