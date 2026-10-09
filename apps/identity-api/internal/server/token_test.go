package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const (
	testIssuer      = "https://identity.hatef.ir"
	testClientID    = "web-app"
	testRedirectURI = "https://app.test/callback"
	testUserID      = "user-1"
	testSessionID   = "browser-session-1"
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
	return newTokenTestServerWithStores(t, auth, token.NewMemoryCodeStore(), token.NewMemoryRefreshTokenStore())
}

type tokenSessionLookupFunc func(context.Context, string, string) (session.Session, error)

func (f tokenSessionLookupFunc) LookupByID(ctx context.Context, userID, id string) (session.Session, error) {
	return f(ctx, userID, id)
}

func newTokenTestServerWithStores(t *testing.T, auth token.ClientAuthenticator, codes token.AuthorizationCodeStore, refresh token.RefreshTokenStore) (*Server, *token.Service) {
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

	// Issuance must use an actual captured normal session, including version 0.
	sessions := session.NewMemoryStore()
	now := time.Now()
	if err := sessions.Create(context.Background(), session.HashToken("test-browser-secret"), session.Session{
		ID: testSessionID, UserID: testUserID, Kind: session.KindAuthenticated,
		AuthVersion: 0, AuthVersionSet: true, CreatedAt: now, LastSeenAt: now,
		IdleExpiry: now.Add(2 * time.Hour), AbsoluteExpiry: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create captured browser session: %v", err)
	}
	svc, err := token.NewService(
		token.Config{Issuer: testIssuer, Sessions: tokenSessionLookupFunc(sessions.GetByID), RevokeUser: sessions.DeleteAllForUser},
		manager,
		registry,
		codes,
		refresh,
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
	code, err := svc.IssueCodeContext(context.Background(), token.AuthorizationCodeData{
		ClientID:       testClientID,
		RedirectURI:    testRedirectURI,
		UserID:         testUserID,
		SessionID:      testSessionID,
		AuthVersion:    0,
		AuthVersionSet: true,
		Scope:          "openid profile",
		Nonce:          "n-xyz",
		CodeChallenge:  challengeFor(verifier),
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
	if claims["sid"] != testSessionID || claims["auth_version"] != float64(0) || claims["principal_type"] != token.PrincipalUser {
		t.Errorf("missing captured session/version claims: %+v", claims)
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

type tokenReplaySpy struct {
	dpop.ReplayGuard
	calls int
	err   error
}

func (s *tokenReplaySpy) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	s.calls++
	if s.err != nil {
		return false, s.err
	}
	return s.ReplayGuard.Remember(ctx, key, expiresAt)
}

type tokenNonceSpy struct {
	dpop.NonceStore
	issueCalls    int
	validateCalls int
	issueErr      error
	validateErr   error
	emptyNonce    bool
	realm         string
	jkt           string
}

func (s *tokenNonceSpy) Issue(ctx context.Context, realm, jkt string) (string, error) {
	s.issueCalls++
	s.realm, s.jkt = realm, jkt
	if s.issueErr != nil || s.emptyNonce {
		return "", s.issueErr
	}
	return s.NonceStore.Issue(ctx, realm, jkt)
}

func (s *tokenNonceSpy) Validate(ctx context.Context, realm, jkt, nonce string) (bool, error) {
	s.validateCalls++
	if s.validateErr != nil {
		return false, s.validateErr
	}
	return s.NonceStore.Validate(ctx, realm, jkt, nonce)
}

func attachTokenEndpointDPoP(t *testing.T, srv *Server) (*tokenReplaySpy, *tokenNonceSpy) {
	t.Helper()
	replay := &tokenReplaySpy{ReplayGuard: dpop.NewMemoryReplayGuard()}
	nonces := &tokenNonceSpy{NonceStore: dpop.NewMemoryNonceStore()}
	validator, err := dpop.NewValidator(replay, nonces)
	if err != nil {
		t.Fatal(err)
	}
	srv.deps.DPoPValidator = validator
	return replay, nonces
}

func newTokenProofKey(t *testing.T) (*keys.SigningKey, string) {
	t.Helper()
	key, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := keys.Thumbprint(key.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	return key, jkt
}

func tokenEndpointProof(t *testing.T, key *keys.SigningKey, nonce string) string {
	t.Helper()
	return dpopTokenProof(t, key.Signer.(*ecdsa.PrivateKey), key.PublicJWK, nonce)
}

func issueTokenEndpointGrant(t *testing.T, srv *Server, svc *token.Service, key *keys.SigningKey) token.Response {
	t.Helper()
	code, verifier := mintCode(t, svc)
	form := authCodeForm(code, verifier)
	var rec *httptest.ResponseRecorder
	if key == nil {
		rec = postForm(t, srv, form)
	} else {
		challenge := postFormDPoP(t, srv, form, tokenEndpointProof(t, key, ""))
		if challenge.Code != http.StatusBadRequest || decodeError(t, challenge).Error != "use_dpop_nonce" || challenge.Header().Get(dpop.HeaderNonce) == "" {
			t.Fatalf("initial nonce challenge = %d, %s", challenge.Code, challenge.Body.String())
		}
		rec = postFormDPoP(t, srv, form, tokenEndpointProof(t, key, challenge.Header().Get(dpop.HeaderNonce)))
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("initial grant = %d, %s", rec.Code, rec.Body.String())
	}
	return decodeTokenResponse(t, rec)
}

func refreshTokenForm(raw string) url.Values {
	return url.Values{"grant_type": {token.GrantRefreshToken}, "client_id": {testClientID}, "refresh_token": {raw}}
}

func assertTokenServiceUnavailable(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	e := decodeError(t, rec)
	if rec.Code != http.StatusServiceUnavailable || e.Error != token.ErrCodeServerError || e.ErrorDescription != "" {
		t.Fatalf("service failure = %d, %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(dpop.HeaderNonce) != "" || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("service failure emitted an authentication challenge: %v", rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("service failure lost cache protections: %v", rec.Header())
	}
}

func TestTokenEndpointRefreshBindingRejectedBeforeStateConsumption(t *testing.T) {
	for _, missingProof := range []bool{true, false} {
		name := "wrong key"
		if missingProof {
			name = "missing proof"
		}
		t.Run(name, func(t *testing.T) {
			srv, svc := newTokenTestServer(t, nil)
			replay, nonces := attachTokenEndpointDPoP(t, srv)
			key, jkt := newTokenProofKey(t)
			initial := issueTokenEndpointGrant(t, srv, svc, key)
			if nonces.realm != "as:"+testIssuer || nonces.jkt != jkt {
				t.Fatalf("challenge used unverified scope: %q, %q", nonces.realm, nonces.jkt)
			}
			nonce, err := nonces.NonceStore.Issue(context.Background(), "as:"+testIssuer, jkt)
			if err != nil {
				t.Fatal(err)
			}
			replay.calls, nonces.issueCalls, nonces.validateCalls = 0, 0, 0
			proof := ""
			if !missingProof {
				otherKey, _ := newTokenProofKey(t)
				proof = tokenEndpointProof(t, otherKey, nonce)
			}
			rec := postFormDPoP(t, srv, refreshTokenForm(initial.RefreshToken), proof)
			if rec.Code != http.StatusBadRequest || decodeError(t, rec).Error != "invalid_dpop_proof" || rec.Header().Get(dpop.HeaderNonce) != "" {
				t.Fatalf("binding rejection = %d, %s", rec.Code, rec.Body.String())
			}
			if replay.calls != 0 || nonces.validateCalls != 0 || nonces.issueCalls != 0 {
				t.Fatalf("binding rejection consumed state: replay=%d validate=%d issue=%d", replay.calls, nonces.validateCalls, nonces.issueCalls)
			}

			// The original proof key can still rotate using the unconsumed nonce.
			rec = postFormDPoP(t, srv, refreshTokenForm(initial.RefreshToken), tokenEndpointProof(t, key, nonce))
			if rec.Code != http.StatusOK {
				t.Fatalf("valid refresh after rejection = %d, %s", rec.Code, rec.Body.String())
			}
			rotated := decodeTokenResponse(t, rec)
			if rotated.TokenType != token.TokenTypeDPoP || rotated.RefreshToken == "" || rotated.RefreshToken == initial.RefreshToken {
				t.Fatal("refresh did not preserve sender binding and rotate its secret")
			}
			binding, err := svc.RefreshBinding(context.Background(), rotated.RefreshToken)
			if err != nil || binding != jkt {
				t.Fatalf("rotated refresh binding = %q, %v", binding, err)
			}
			claims, err := token.Verify(rotated.AccessToken, srv.deps.Keys.ActiveSigner())
			if err != nil {
				t.Fatal(err)
			}
			cnf, ok := claims["cnf"].(map[string]any)
			if !ok || cnf["jkt"] != jkt || claims["sid"] != testSessionID || claims["auth_version"] != float64(0) {
				t.Fatalf("rotated access claims lost binding or captured session: %v", claims)
			}
		})
	}
}

func TestTokenEndpointRefreshRejectsProofUpgradeBeforeStateConsumption(t *testing.T) {
	srv, svc := newTokenTestServer(t, nil)
	replay, nonces := attachTokenEndpointDPoP(t, srv)
	initial := issueTokenEndpointGrant(t, srv, svc, nil)
	key, jkt := newTokenProofKey(t)
	nonce, err := nonces.NonceStore.Issue(context.Background(), "as:"+testIssuer, jkt)
	if err != nil {
		t.Fatal(err)
	}
	rec := postFormDPoP(t, srv, refreshTokenForm(initial.RefreshToken), tokenEndpointProof(t, key, nonce))
	if rec.Code != http.StatusBadRequest || decodeError(t, rec).Error != token.ErrCodeInvalidGrant {
		t.Fatalf("unbound refresh upgrade = %d, %s", rec.Code, rec.Body.String())
	}
	if replay.calls != 0 || nonces.validateCalls != 0 || nonces.issueCalls != 0 || rec.Header().Get(dpop.HeaderNonce) != "" {
		t.Fatal("unbound refresh upgrade touched DPoP state")
	}
	if ok, err := nonces.NonceStore.Validate(context.Background(), "as:"+testIssuer, jkt, nonce); !ok || err != nil {
		t.Fatalf("upgrade rejection consumed nonce: %v, %v", ok, err)
	}
	rec = postForm(t, srv, refreshTokenForm(initial.RefreshToken))
	if rec.Code != http.StatusOK || decodeTokenResponse(t, rec).TokenType != token.TokenTypeBearer {
		t.Fatalf("Bearer refresh after rejected upgrade = %d, %s", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointMissingRefreshMetadataConsumesNoDPoPState(t *testing.T) {
	for _, raw := range []string{"", "unknown-refresh-secret"} {
		t.Run("refresh="+raw, func(t *testing.T) {
			srv, _ := newTokenTestServer(t, nil)
			replay, nonces := attachTokenEndpointDPoP(t, srv)
			key, jkt := newTokenProofKey(t)
			nonce, err := nonces.NonceStore.Issue(context.Background(), "as:"+testIssuer, jkt)
			if err != nil {
				t.Fatal(err)
			}
			rec := postFormDPoP(t, srv, refreshTokenForm(raw), tokenEndpointProof(t, key, nonce))
			want := token.ErrCodeInvalidGrant
			if raw == "" {
				want = token.ErrCodeInvalidRequest
			}
			if rec.Code != http.StatusBadRequest || decodeError(t, rec).Error != want {
				t.Fatalf("missing metadata = %d, %s", rec.Code, rec.Body.String())
			}
			if replay.calls != 0 || nonces.issueCalls != 0 || nonces.validateCalls != 0 {
				t.Fatal("missing refresh metadata touched DPoP state")
			}
			if ok, err := nonces.NonceStore.Validate(context.Background(), "as:"+testIssuer, jkt, nonce); !ok || err != nil {
				t.Fatalf("missing refresh metadata consumed nonce: %v, %v", ok, err)
			}
		})
	}
}

type tokenEndpointRefreshStore struct {
	token.RefreshTokenStore
	getErr    error
	createErr error
}

func (s *tokenEndpointRefreshStore) Get(ctx context.Context, hash string) (token.RefreshTokenData, error) {
	if s.getErr != nil {
		return token.RefreshTokenData{}, s.getErr
	}
	return s.RefreshTokenStore.Get(ctx, hash)
}

func (s *tokenEndpointRefreshStore) CreateGrant(ctx context.Context, grant token.GrantData, hash string, refresh token.RefreshTokenData) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.RefreshTokenStore.CreateGrant(ctx, grant, hash, refresh)
}

type tokenEndpointCodeStore struct {
	token.AuthorizationCodeStore
	err error
}

func (s *tokenEndpointCodeStore) Consume(ctx context.Context, hash string) (token.AuthorizationCodeData, error) {
	if s.err != nil {
		return token.AuthorizationCodeData{}, s.err
	}
	return s.AuthorizationCodeStore.Consume(ctx, hash)
}

func TestTokenEndpointRefreshStoreFailurePrecedesDPoPState(t *testing.T) {
	refresh := &tokenEndpointRefreshStore{RefreshTokenStore: token.NewMemoryRefreshTokenStore()}
	srv, svc := newTokenTestServerWithStores(t, nil, token.NewMemoryCodeStore(), refresh)
	replay, nonces := attachTokenEndpointDPoP(t, srv)
	key, jkt := newTokenProofKey(t)
	initial := issueTokenEndpointGrant(t, srv, svc, key)
	nonce, err := nonces.NonceStore.Issue(context.Background(), "as:"+testIssuer, jkt)
	if err != nil {
		t.Fatal(err)
	}
	replay.calls, nonces.issueCalls, nonces.validateCalls = 0, 0, 0
	refresh.getErr = errors.Join(token.ErrStoreUnavailable, errors.New("private shared-store failure"))
	rec := postFormDPoP(t, srv, refreshTokenForm(initial.RefreshToken), tokenEndpointProof(t, key, nonce))
	assertTokenServiceUnavailable(t, rec)
	if replay.calls != 0 || nonces.issueCalls != 0 || nonces.validateCalls != 0 {
		t.Fatal("refresh lookup failure consumed DPoP state")
	}
	refresh.getErr = nil
	rec = postFormDPoP(t, srv, refreshTokenForm(initial.RefreshToken), tokenEndpointProof(t, key, nonce))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh after store recovery = %d, %s", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointCredentialStoreFailuresAreServiceErrors(t *testing.T) {
	for _, stage := range []string{"consume code", "persist grant"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.Join(token.ErrStoreUnavailable, errors.New("private credential store failure"))
			codes := &tokenEndpointCodeStore{AuthorizationCodeStore: token.NewMemoryCodeStore()}
			refresh := &tokenEndpointRefreshStore{RefreshTokenStore: token.NewMemoryRefreshTokenStore()}
			srv, svc := newTokenTestServerWithStores(t, nil, codes, refresh)
			code, verifier := mintCode(t, svc)
			if stage == "consume code" {
				codes.err = failure
			} else {
				refresh.createErr = failure
			}
			assertTokenServiceUnavailable(t, postForm(t, srv, authCodeForm(code, verifier)))
		})
	}
}

func TestTokenEndpointDPoPUnavailableIsNotAProofError(t *testing.T) {
	for _, stage := range []string{"replay", "validate nonce", "issue nonce", "empty nonce", "missing store", "missing validator", "canceled", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			srv, svc := newTokenTestServer(t, nil)
			replay, nonces := attachTokenEndpointDPoP(t, srv)
			key, jkt := newTokenProofKey(t)
			code, verifier := mintCode(t, svc)
			failure := errors.New("private DPoP backend failure")
			nonce := ""
			switch stage {
			case "replay":
				var err error
				nonce, err = nonces.NonceStore.Issue(context.Background(), "as:"+testIssuer, jkt)
				if err != nil {
					t.Fatal(err)
				}
				replay.err = failure
			case "validate nonce":
				nonce, nonces.validateErr = "nonce", failure
			case "issue nonce":
				nonces.issueErr = failure
			case "empty nonce":
				nonces.emptyNonce = true
			case "missing store":
				validator, err := dpop.NewValidator(replay, nil)
				if err != nil {
					t.Fatal(err)
				}
				srv.deps.DPoPValidator = validator
			case "missing validator":
				srv.deps.DPoPValidator = nil
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(authCodeForm(code, verifier).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set(dpop.HeaderProof, tokenEndpointProof(t, key, nonce))
			if stage == "canceled" {
				ctx, cancel := context.WithCancel(req.Context())
				cancel()
				req = req.WithContext(ctx)
			}
			if stage == "deadline" {
				ctx, cancel := context.WithDeadline(req.Context(), time.Now().Add(-time.Second))
				defer cancel()
				req = req.WithContext(ctx)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			assertTokenServiceUnavailable(t, rec)
			// Failed proof validation must not consume the authorization code.
			if rec := postForm(t, srv, authCodeForm(code, verifier)); rec.Code != http.StatusOK {
				t.Fatalf("DPoP outage consumed grant code: %d, %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestTokenEndpointRejectsAmbiguousOrOversizedProofHeaders(t *testing.T) {
	for _, headers := range [][]string{
		{"first", "second"}, {"first,second"}, {""}, {" \t"}, {strings.Repeat("x", dpop.MaxProofSize+1)},
	} {
		srv, svc := newTokenTestServer(t, nil)
		replay, nonces := attachTokenEndpointDPoP(t, srv)
		code, verifier := mintCode(t, svc)
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(authCodeForm(code, verifier).Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, value := range headers {
			req.Header.Add(dpop.HeaderProof, value)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || decodeError(t, rec).Error != "invalid_dpop_proof" || rec.Header().Get(dpop.HeaderNonce) != "" {
			t.Fatalf("invalid proof headers = %d, %s", rec.Code, rec.Body.String())
		}
		if replay.calls != 0 || nonces.issueCalls != 0 || nonces.validateCalls != 0 {
			t.Fatal("invalid proof headers reached DPoP stores")
		}
		if rec := postForm(t, srv, authCodeForm(code, verifier)); rec.Code != http.StatusOK {
			t.Fatalf("invalid proof headers consumed grant code: %d", rec.Code)
		}
	}
}

func TestTokenEndpointDoesNotIssueUnverifiedNonceChallenge(t *testing.T) {
	srv, _ := newTokenTestServer(t, nil)
	_, nonces := attachTokenEndpointDPoP(t, srv)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	rec := httptest.NewRecorder()
	srv.writeTokenDPoPError(rec, req, dpop.ErrNonceRequired)
	if rec.Code != http.StatusBadRequest || decodeError(t, rec).Error != "invalid_dpop_proof" || rec.Header().Get(dpop.HeaderNonce) != "" || nonces.issueCalls != 0 {
		t.Fatalf("unverified nonce error triggered issuance: %d, %s", rec.Code, rec.Body.String())
	}
}

func TestTokenEndpointRejectsUnlinkedCodeIssuance(t *testing.T) {
	_, svc := newTokenTestServer(t, nil)
	for _, captured := range []bool{false, true} {
		data := token.AuthorizationCodeData{ClientID: testClientID, RedirectURI: testRedirectURI, UserID: testUserID,
			CodeChallenge: challengeFor(strings.Repeat("v", 50)), AuthVersionSet: captured}
		if !captured {
			data.SessionID = testSessionID
		}
		if _, err := svc.IssueCodeContext(context.Background(), data); !errors.Is(err, session.ErrAccountIneligible) {
			t.Fatalf("unlinked code issuance accepted: %v", err)
		}
	}
}
