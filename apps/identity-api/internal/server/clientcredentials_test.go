package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clientauth"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
)

const ccClientID = "search-core"

// ccSigner is the confidential client's ES256 key pair.
type ccSigner struct {
	priv *ecdsa.PrivateKey
	pub  *keys.PublicKey
}

func newCCSigner(t *testing.T) *ccSigner {
	t.Helper()
	sk, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	pub, err := keys.ParsePublicJWK(sk.PublicJWK)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	return &ccSigner{priv: sk.Signer.(*ecdsa.PrivateKey), pub: pub}
}

// assertion mints a compact ES256 JWS client assertion for the given claims.
func (s *ccSigner) assertion(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": keys.AlgES256, "typ": "JWT", "kid": s.pub.KID}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// newClientCredentialsServer wires a Server whose token service uses the REAL
// RFC 7523 authenticator, with the given signer's key registered for
// ccClientID. It returns the server, the signer, and the token endpoint URL
// (the assertion audience).
func newClientCredentialsServer(t *testing.T, sk *ccSigner) (*Server, string) {
	t.Helper()
	active, _ := keys.NewEphemeralES256()
	next, _ := keys.NewEphemeralES256()
	manager, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	registry, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      ccClientID,
			RedirectURIs:            []string{"https://search.hatef.ir/callback"},
			TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT,
			AllowedScopes:           []string{"search.full"},
			PublicKeys:              map[string]*keys.PublicKey{sk.pub.KID: sk.pub},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}

	audience := testIssuer + "/oauth2/token"
	authenticator, err := clientauth.New(registry, audience, clientauth.NewMemoryJTIGuard())
	if err != nil {
		t.Fatalf("clientauth.New: %v", err)
	}

	svc, err := token.NewService(
		token.Config{Issuer: testIssuer},
		manager,
		registry,
		token.NewMemoryCodeStore(),
		token.NewMemoryRefreshTokenStore(),
		authenticator,
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
	return srv, audience
}

func ccClaims(audience string, now time.Time) map[string]any {
	return map[string]any{
		"iss": ccClientID,
		"sub": ccClientID,
		"aud": audience,
		"jti": "jti-" + now.Format("150405.000000000"),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
}

func ccForm(assertion, scope string) url.Values {
	f := url.Values{
		"grant_type":            {token.GrantClientCredentials},
		"client_assertion_type": {clientauth.AssertionType},
		"client_assertion":      {assertion},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	return f
}

// TestClientCredentialsPrivateKeyJWTEndToEnd drives a real signed assertion
// through POST /oauth2/token and asserts an access token comes back, verifies
// against the server's active key, and carries sub == client_id with no
// refresh token (OAuth 2.1 client_credentials).
func TestClientCredentialsPrivateKeyJWTEndToEnd(t *testing.T) {
	sk := newCCSigner(t)
	srv, audience := newClientCredentialsServer(t, sk)

	assertion := sk.assertion(t, ccClaims(audience, time.Now()))
	rec := postForm(t, srv, ccForm(assertion, "search.full"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	resp := decodeTokenResponse(t, rec)
	if resp.AccessToken == "" {
		t.Fatal("missing access token")
	}
	if resp.RefreshToken != "" {
		t.Error("client_credentials must not issue a refresh token")
	}

	claims, err := token.Verify(resp.AccessToken, srv.deps.Keys.ActiveSigner())
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims["sub"] != ccClientID || claims["client_id"] != ccClientID {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

// TestClientCredentialsTamperedAssertionRejected flips a byte in the signature
// so verification fails; the endpoint must answer 401 invalid_client.
func TestClientCredentialsTamperedAssertionRejected(t *testing.T) {
	sk := newCCSigner(t)
	srv, audience := newClientCredentialsServer(t, sk)

	assertion := sk.assertion(t, ccClaims(audience, time.Now()))
	// Flip the last character of the signature segment to a different valid
	// base64url character so decoding still succeeds but verification fails.
	last := assertion[len(assertion)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	tampered := assertion[:len(assertion)-1] + string(repl)

	rec := postForm(t, srv, ccForm(tampered, "search.full"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidClient {
		t.Errorf("error = %q, want invalid_client", e.Error)
	}
}

// TestClientCredentialsReplayedAssertionRejected reuses the same assertion
// twice; the second attempt must be rejected by the JTI replay guard.
func TestClientCredentialsReplayedAssertionRejected(t *testing.T) {
	sk := newCCSigner(t)
	srv, audience := newClientCredentialsServer(t, sk)

	assertion := sk.assertion(t, ccClaims(audience, time.Now()))
	if rec := postForm(t, srv, ccForm(assertion, "search.full")); rec.Code != http.StatusOK {
		t.Fatalf("first use status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rec := postForm(t, srv, ccForm(assertion, "search.full"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidClient {
		t.Errorf("error = %q, want invalid_client", e.Error)
	}
}

// TestClientCredentialsDisallowedScopeRejected requests a scope outside the
// client's allow-list; the endpoint must answer 400 invalid_scope.
func TestClientCredentialsDisallowedScopeRejected(t *testing.T) {
	sk := newCCSigner(t)
	srv, audience := newClientCredentialsServer(t, sk)

	assertion := sk.assertion(t, ccClaims(audience, time.Now()))
	rec := postForm(t, srv, ccForm(assertion, "billing.write"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidScope {
		t.Errorf("error = %q, want invalid_scope", e.Error)
	}
}

// TestClientCredentialsWrongAudienceRejected mints an assertion whose aud does
// not equal this endpoint's URL (e.g. minted for another IdP); it must be
// rejected 401 invalid_client.
func TestClientCredentialsWrongAudienceRejected(t *testing.T) {
	sk := newCCSigner(t)
	srv, _ := newClientCredentialsServer(t, sk)

	claims := ccClaims("https://evil.example/oauth2/token", time.Now())
	assertion := sk.assertion(t, claims)
	rec := postForm(t, srv, ccForm(assertion, "search.full"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidClient {
		t.Errorf("error = %q, want invalid_client", e.Error)
	}
}

// stripSig removes the signature segment, used only to keep the strings import
// meaningful in negative parsing paths.
func stripSig(assertion string) string {
	if i := strings.LastIndex(assertion, "."); i >= 0 {
		return assertion[:i]
	}
	return assertion
}

// TestClientCredentialsMalformedAssertionRejected sends an assertion missing
// its signature segment; the endpoint must answer 401 invalid_client.
func TestClientCredentialsMalformedAssertionRejected(t *testing.T) {
	sk := newCCSigner(t)
	srv, audience := newClientCredentialsServer(t, sk)

	assertion := stripSig(sk.assertion(t, ccClaims(audience, time.Now())))
	rec := postForm(t, srv, ccForm(assertion, "search.full"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
	if e := decodeError(t, rec); e.Error != token.ErrCodeInvalidClient {
		t.Errorf("error = %q, want invalid_client", e.Error)
	}
}
