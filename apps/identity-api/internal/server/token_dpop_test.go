package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
)

// newDPoPTokenTestServer builds a token-endpoint server wired with a DPoP
// validator (in-memory replay guard + nonce store) so the /oauth2/token DPoP
// lifecycle can be exercised end-to-end.
func newDPoPTokenTestServer(t *testing.T) (*Server, *token.Service, *dpop.Validator) {
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
	registry, err := clients.NewStaticRegistry([]clients.Client{{
		ID:                      testClientID,
		RedirectURIs:            []string{testRedirectURI},
		TokenEndpointAuthMethod: clients.AuthMethodNone,
		AllowedScopes:           []string{"openid", "profile"},
	}})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	svc, err := token.NewService(
		token.Config{Issuer: testIssuer},
		manager, registry,
		token.NewMemoryCodeStore(), token.NewMemoryRefreshTokenStore(),
		nil, nil, slog.Default(),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	validator, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), dpop.NewMemoryNonceStore())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	srv := New(testConfig(t), nil, Deps{
		OIDC:          config.OIDCConfig{Issuer: testIssuer},
		Keys:          manager,
		Clients:       registry,
		TokenService:  svc,
		DPoPValidator: validator,
	})
	return srv, svc, validator
}

// dpopTokenProof mints a compact ES256 DPoP proof bound to the token endpoint.
func dpopTokenProof(t *testing.T, key *ecdsa.PrivateKey, jwk keys.JWK, nonce string) string {
	t.Helper()
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": keys.AlgES256, "jwk": json.RawMessage(jwkBytes)}
	headerJSON, _ := json.Marshal(header)

	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(buf),
		"htm": http.MethodPost,
		"htu": testIssuer + "/oauth2/token",
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	claimsJSON, _ := json.Marshal(claims)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// postFormDPoP issues a form POST with a DPoP proof header.
func postFormDPoP(t *testing.T, srv *Server, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestTokenEndpointDPoPNonceChallenge(t *testing.T) {
	srv, svc, _ := newDPoPTokenTestServer(t)
	code, verifier := mintCode(t, svc)

	key, err := ecdsaKeyFrom(t)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// Proof without a nonce must be challenged with 400 use_dpop_nonce and a
	// fresh DPoP-Nonce response header.
	proof := dpopTokenProof(t, key.Signer.(*ecdsa.PrivateKey), key.PublicJWK, "")
	rec := postFormDPoP(t, srv, authCodeForm(code, verifier), proof)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != "use_dpop_nonce" {
		t.Errorf("error = %q, want use_dpop_nonce", e.Error)
	}
	if rec.Header().Get("DPoP-Nonce") == "" {
		t.Error("missing DPoP-Nonce response header on challenge")
	}
}

func TestTokenEndpointDPoPBindsCnfJKT(t *testing.T) {
	srv, svc, validator := newDPoPTokenTestServer(t)
	code, verifier := mintCode(t, svc)

	key, err := ecdsaKeyFrom(t)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	// Obtain a nonce, then present a proof echoing it.
	nonce, err := validator.IssueNonce(context.Background())
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	proof := dpopTokenProof(t, key.Signer.(*ecdsa.PrivateKey), key.PublicJWK, nonce)
	rec := postFormDPoP(t, srv, authCodeForm(code, verifier), proof)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	resp := decodeTokenResponse(t, rec)
	if resp.TokenType != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", resp.TokenType)
	}

	claims, err := token.Verify(resp.AccessToken, srv.deps.Keys.ActiveSigner())
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("missing cnf claim: %+v", claims)
	}
	wantJKT, _ := keys.Thumbprint(key.PublicJWK)
	if cnf["jkt"] != wantJKT {
		t.Errorf("cnf.jkt = %v, want %q", cnf["jkt"], wantJKT)
	}
}

func TestTokenEndpointWithoutDPoPIssuesBearer(t *testing.T) {
	srv, svc, _ := newDPoPTokenTestServer(t)
	code, verifier := mintCode(t, svc)

	rec := postFormDPoP(t, srv, authCodeForm(code, verifier), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	resp := decodeTokenResponse(t, rec)
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
	claims, err := token.Verify(resp.AccessToken, srv.deps.Keys.ActiveSigner())
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if _, ok := claims["cnf"]; ok {
		t.Error("Bearer token must not carry a cnf confirmation claim")
	}
}

func TestTokenEndpointDPoPInvalidProofRejected(t *testing.T) {
	srv, svc, _ := newDPoPTokenTestServer(t)
	code, verifier := mintCode(t, svc)

	rec := postFormDPoP(t, srv, authCodeForm(code, verifier), "this-is-not-a-proof")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.Error != "invalid_dpop_proof" {
		t.Errorf("error = %q, want invalid_dpop_proof", e.Error)
	}
}

// ecdsaKeyFrom returns a fresh ES256 signing key for proof construction.
func ecdsaKeyFrom(t *testing.T) (*keys.SigningKey, error) {
	t.Helper()
	return keys.NewEphemeralES256()
}
