package clients

import (
	"errors"
	"testing"
)

func validClient() Client {
	return Client{
		ID:                      "hatef-nextjs-app",
		RedirectURIs:            []string{"https://hatef.ir/callback"},
		TokenEndpointAuthMethod: AuthMethodNone,
		AllowedScopes:           []string{"openid", "profile", "email"},
	}
}

func TestNewStaticRegistryValid(t *testing.T) {
	reg, err := NewStaticRegistry([]Client{validClient()})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	got, err := reg.Lookup("hatef-nextjs-app")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.IsPublic() {
		t.Error("client with auth method none should be public")
	}
}

func TestNewStaticRegistryRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		list []Client
	}{
		{
			name: "empty id",
			list: []Client{{ID: "  ", RedirectURIs: []string{"https://a"}, TokenEndpointAuthMethod: AuthMethodNone}},
		},
		{
			name: "duplicate id",
			list: []Client{validClient(), validClient()},
		},
		{
			name: "no redirect uris",
			list: []Client{{ID: "x", TokenEndpointAuthMethod: AuthMethodNone}},
		},
		{
			name: "unsupported auth method",
			list: []Client{{ID: "x", RedirectURIs: []string{"https://a"}, TokenEndpointAuthMethod: "client_secret_post"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewStaticRegistry(tt.list); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestLookupUnknownClient(t *testing.T) {
	reg, err := NewStaticRegistry([]Client{validClient()})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	if _, err := reg.Lookup("nope"); !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("err = %v, want ErrUnknownClient", err)
	}
}

func TestHasRedirectURIExactMatch(t *testing.T) {
	c := Client{RedirectURIs: []string{"https://hatef.ir/callback"}}
	if !c.HasRedirectURI("https://hatef.ir/callback") {
		t.Error("exact registered URI should match")
	}
	// No fuzzy matching: prefixes, trailing slashes, and extra paths must fail.
	for _, uri := range []string{
		"https://hatef.ir/callback/",
		"https://hatef.ir/callback?x=1",
		"https://hatef.ir",
		"https://evil.ir/callback",
		"HTTPS://hatef.ir/callback",
	} {
		if c.HasRedirectURI(uri) {
			t.Errorf("non-exact URI %q must not match", uri)
		}
	}
}

func TestAllowsScope(t *testing.T) {
	c := validClient()
	if !c.AllowsScope("openid") {
		t.Error("openid should be allowed")
	}
	if c.AllowsScope("admin") {
		t.Error("unregistered scope must not be allowed")
	}
}

func TestIDsSorted(t *testing.T) {
	reg, err := NewStaticRegistry([]Client{
		{ID: "zeta", RedirectURIs: []string{"https://z"}, TokenEndpointAuthMethod: AuthMethodNone},
		{ID: "alpha", RedirectURIs: []string{"https://a"}, TokenEndpointAuthMethod: AuthMethodPrivateKeyJWT},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	ids := reg.IDs()
	if len(ids) != 2 || ids[0] != "alpha" || ids[1] != "zeta" {
		t.Fatalf("IDs = %v, want [alpha zeta]", ids)
	}
}
