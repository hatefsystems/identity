package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
)

const (
	testIssuer      = "https://identity.hatef.ir"
	testClientID    = "web-app"
	testRedirectURI = "https://app.test/callback"
	testUserID      = "user-1"
)

// fakeClientAuth is a ClientAuthenticator stand-in for client_credentials
// tests until Task 3.4 lands private_key_jwt.
type fakeClientAuth struct {
	client clients.Client
	err    error
}

func (f *fakeClientAuth) Authenticate(_ context.Context, _ url.Values) (clients.Client, error) {
	return f.client, f.err
}

// challengeFor computes the S256 PKCE challenge for a verifier.
func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newTokenTestServer builds a Server wired with a token service backed by
// in-memory stores. The returned service is used by tests to mint codes
// directly (the consent stage that would normally call IssueCode is Task 4.1).
func newTokenTestServer(t *testing.T, auth token.ClientAuthenticator) (*Server, *token.Service) {
	t.Helper()
	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("active key: %v", err)
	}
	next, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("next key: %v", err)
	}
	manager, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	registry, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      testClientID,
			RedirectURIs:            []string{testRedirectURI},
			TokenEndpointAuthMethod: clients.AuthMethodNone,
			AllowedScopes:           []string{"openid", "profile"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}

	svc, err := token.NewService(
		token.Config{Issuer: testIssuer},
		manager,
		registry,
		token.NewMemoryCodeStore(),
		token.NewMemoryRefreshTokenStore(),
		auth,
		nil,
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	srv := New(testConfig(t), nil, Deps{
		OIDC:         config.OIDCConfig{Issuer: testIssuer},
		Keys:         manager,
		Clients:      registry,
		TokenService: svc,
	})
	return srv, svc
}

// postForm issues a form-encoded POST to /oauth2/token.
func postForm(t *testing.T, srv *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// mintCode issues a fresh authorization code and returns it with the matching
// PKCE verifier.
func mintCode(t *testing.T, svc *token.Service) (code, verifier string) {
	t.Helper()
	verifier = strings.Repeat("v", 50)
	code, err := svc.IssueCode(token.AuthorizationCodeData{
		ClientID:      testClientID,
		RedirectURI:   testRedirectURI,
		UserID:        testUserID,
		Scope:         "openid profile",
		Nonce:         "n-xyz",
		CodeChallenge: challengeFor(verifier),
	})
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	return code, verifier
}

func decodeTokenResponse(t *testing.T, rec *httptest.ResponseRecorder) token.Response {
	t.Helper()
	var resp token.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) tokenErrorResponse {
	t.Helper()
	var e tokenErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, rec.Body.String())
	}
	return e
}

func authCodeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {token.GrantAuthorizationCode},
		"client_id":     {testClientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	}
}

func TestTokenEndpointAuthorizationCodeFlow(t *testing.T) {
	srv, svc := newTokenTestServer(t, nil)
	code, verifier := mintCode(t, svc)

	rec := postForm(t, srv, authCodeForm(code, verifier))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	resp := decodeTokenResponse(t, rec)
	if resp.AccessToken == "" || resp.IDToken == "" || resp.RefreshToken == "" {
		t.Fatalf("missing tokens in response: %+v", resp)
	}

	// The access token must verify against the server's active signing key.
	claims, err := token.Verify(resp.AccessToken, srv.deps.Keys.ActiveSigner())
	if err != nil {
		t.Fatalf("verify access token against active key: %v", err)
	}
	if claims["iss"] != testIssuer || claims["sub"] != testUserID {
		t.Errorf("unexpected access token claims: %+v", claims)
	}
}

func TestTokenEndpointCodeReplayRejected(t *testing.T) {
	srv, svc := newTokenTestServer(t, nil)
	code, verifier := mintCode(t, svc)

	if rec := postForm(t, srv, authCodeForm(code, verifier)); rec.Code != http.StatusOK {
		t.Fatalf("first exchange status = %d, want 200", rec.Code)
	}
	rec := postForm(t, srv, authCodeForm(code, verifier))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidGrant {
		t.Errorf("replay error = %q, want invalid_grant", e.Error)
	}
}

func TestTokenEndpointWrongVerifierRejected(t *testing.T) {
	srv, svc := newTokenTestServer(t, nil)
	code, _ := mintCode(t, svc)

	rec := postForm(t, srv, authCodeForm(code, strings.Repeat("w", 50)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidGrant {
		t.Errorf("error = %q, want invalid_grant", e.Error)
	}
}

func TestTokenEndpointRefreshRotationAndBreach(t *testing.T) {
	srv, svc := newTokenTestServer(t, nil)
	code, verifier := mintCode(t, svc)

	first := decodeTokenResponse(t, postForm(t, srv, authCodeForm(code, verifier)))

	refreshForm := url.Values{
		"grant_type":    {token.GrantRefreshToken},
		"client_id":     {testClientID},
		"refresh_token": {first.RefreshToken},
	}

	// First rotation succeeds and yields a new refresh token.
	rec := postForm(t, srv, refreshForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotation status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rotated := decodeTokenResponse(t, rec)
	if rotated.RefreshToken == first.RefreshToken || rotated.RefreshToken == "" {
		t.Fatal("rotation must return a new refresh token")
	}

	// Replaying the original (now rotated) token is a breach: rejected, and
	// it revokes the entire family.
	rec = postForm(t, srv, refreshForm)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidGrant {
		t.Errorf("replay error = %q, want invalid_grant", e.Error)
	}

	// The rotated (previously valid) token is now revoked as part of the
	// breach response — every session for the user is dead.
	rec = postForm(t, srv, url.Values{
		"grant_type":    {token.GrantRefreshToken},
		"client_id":     {testClientID},
		"refresh_token": {rotated.RefreshToken},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("post-breach rotated-token status = %d, want 400", rec.Code)
	}
}

func TestTokenEndpointClientCredentials(t *testing.T) {
	confidential := clients.Client{
		ID:                      "svc-billing",
		RedirectURIs:            []string{"https://unused.test"},
		TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT,
		AllowedScopes:           []string{"billing.read"},
	}

	t.Run("confidential success without refresh token", func(t *testing.T) {
		srv, _ := newTokenTestServer(t, &fakeClientAuth{client: confidential})
		rec := postForm(t, srv, url.Values{
			"grant_type": {token.GrantClientCredentials},
			"scope":      {"billing.read"},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
		resp := decodeTokenResponse(t, rec)
		if resp.AccessToken == "" {
			t.Error("missing access token")
		}
		if resp.RefreshToken != "" {
			t.Error("client_credentials must not issue a refresh token")
		}
	})

	t.Run("public client rejected", func(t *testing.T) {
		public := confidential
		public.TokenEndpointAuthMethod = clients.AuthMethodNone
		srv, _ := newTokenTestServer(t, &fakeClientAuth{client: public})
		rec := postForm(t, srv, url.Values{"grant_type": {token.GrantClientCredentials}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if e := decodeError(t, rec); e.Error != token.ErrCodeUnauthorizedClient {
			t.Errorf("error = %q, want unauthorized_client", e.Error)
		}
	})
}

func TestTokenEndpointRejectsGET(t *testing.T) {
	srv, _ := newTokenTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /oauth2/token status = %d, want 405", rec.Code)
	}
}

func TestTokenEndpointUnsupportedGrant(t *testing.T) {
	srv, _ := newTokenTestServer(t, nil)
	rec := postForm(t, srv, url.Values{"grant_type": {"password"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeUnsupportedGrantType {
		t.Errorf("error = %q, want unsupported_grant_type", e.Error)
	}
}

func TestTokenEndpointRejectsWrongContentType(t *testing.T) {
	srv, _ := newTokenTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(`{"grant_type":"client_credentials"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidRequest {
		t.Errorf("error = %q, want invalid_request", e.Error)
	}
}
