package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

const testChallenge = "E9Melhoa2OwvFrGMTJguCH5KLUAzSAt9GPmy_8_NfXE"

// newAuthorizeTestServer builds a Server with a key manager and a client
// registry containing a single public client.
func newAuthorizeTestServer(t *testing.T) *Server {
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
	registry, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      "hatef-nextjs-app",
			RedirectURIs:            []string{"https://hatef.ir/callback"},
			TokenEndpointAuthMethod: clients.AuthMethodNone,
			AllowedScopes:           []string{"openid", "profile", "email"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	return New(testConfig(t), nil, Deps{
		OIDC:    config.OIDCConfig{Issuer: "https://identity.hatef.ir"},
		Keys:    manager,
		Clients: registry,
	})
}

func authorizeQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "hatef-nextjs-app")
	q.Set("redirect_uri", "https://hatef.ir/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile")
	q.Set("state", "af0ifjsldkj")
	q.Set("code_challenge", testChallenge)
	q.Set("code_challenge_method", "S256")
	return q
}

// doAuthorize issues a GET /oauth2/auth with the given query and returns the
// recorder. Redirects are NOT followed (httptest records the 302 directly).
func doAuthorize(t *testing.T, srv *Server, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// locationURL parses the Location header of a redirect response.
func locationURL(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("missing Location header")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u
}

func TestAuthorizeSuccessRedirectsToConsentUI(t *testing.T) {
	srv := newAuthorizeTestServer(t)
	u := locationURL(t, doAuthorize(t, srv, authorizeQuery()))

	if u.Path != consentUIPath {
		t.Errorf("redirect path = %q, want %q", u.Path, consentUIPath)
	}
	q := u.Query()
	if q.Get("client_id") != "hatef-nextjs-app" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") != testChallenge {
		t.Errorf("code_challenge not preserved: %q", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") != "af0ifjsldkj" {
		t.Errorf("state not preserved: %q", q.Get("state"))
	}
}

func TestAuthorizeRedirectableErrorGoesToClient(t *testing.T) {
	srv := newAuthorizeTestServer(t)
	q := authorizeQuery()
	q.Set("code_challenge_method", "plain") // rejected → redirectable error
	u := locationURL(t, doAuthorize(t, srv, q))

	// Redirect must go back to the client's registered redirect_uri.
	if u.Scheme != "https" || u.Host != "hatef.ir" || u.Path != "/callback" {
		t.Fatalf("redirect target = %q, want the client redirect_uri", u.String())
	}
	if u.Query().Get("error") != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", u.Query().Get("error"))
	}
	if u.Query().Get("state") != "af0ifjsldkj" {
		t.Errorf("state must be echoed on error, got %q", u.Query().Get("state"))
	}
}

func TestAuthorizeNonRedirectableErrorGoesToErrorPage(t *testing.T) {
	srv := newAuthorizeTestServer(t)

	tests := []struct {
		name   string
		mutate func(url.Values)
	}{
		{"unknown client", func(q url.Values) { q.Set("client_id", "ghost") }},
		{"bad redirect_uri", func(q url.Values) { q.Set("redirect_uri", "https://evil.ir/callback") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := authorizeQuery()
			tt.mutate(q)
			u := locationURL(t, doAuthorize(t, srv, q))
			if u.Path != errorUIPath {
				t.Errorf("redirect path = %q, want %q (must not redirect to client)", u.Path, errorUIPath)
			}
			// The unverified redirect_uri must never be used as the target.
			if u.Host == "evil.ir" {
				t.Error("must not redirect to an unverified redirect_uri")
			}
			if u.Query().Get("error") == "" {
				t.Error("error code missing on error page redirect")
			}
		})
	}
}

func TestAuthorizeRouteAbsentWithoutRegistry(t *testing.T) {
	// Key manager present but no client registry: the route must not be mounted.
	active, _ := keys.NewEphemeralES256()
	next, _ := keys.NewEphemeralES256()
	manager, _ := keys.NewManager(active, next, nil)
	srv := New(testConfig(t), nil, Deps{
		OIDC: config.OIDCConfig{Issuer: "https://identity.hatef.ir"},
		Keys: manager,
	})
	rec := doAuthorize(t, srv, authorizeQuery())
	if rec.Code != http.StatusNotFound {
		t.Errorf("without a client registry /oauth2/auth should 404, got %d", rec.Code)
	}
}
