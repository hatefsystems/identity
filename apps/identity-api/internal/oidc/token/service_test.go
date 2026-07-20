package token

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// fakeAuthenticator is a ClientAuthenticator stand-in until Task 3.4 lands
// the RFC 7523 implementation.
type fakeAuthenticator struct {
	client clients.Client
	err    error
}

func (f *fakeAuthenticator) Authenticate(_ context.Context, _ url.Values) (clients.Client, error) {
	return f.client, f.err
}

// recordingBreach captures RecordRTRBreach invocations.
type recordingBreach struct {
	userIDs   []string
	clientIDs []string
}

func (r *recordingBreach) RecordRTRBreach(_ context.Context, userID, clientID string) {
	r.userIDs = append(r.userIDs, userID)
	r.clientIDs = append(r.clientIDs, clientID)
}

const (
	testIssuer      = "https://id.test"
	testPublicID    = "web-app"
	testRedirectURI = "https://app.test/callback"
)

// newTestService builds a Service with in-memory stores, an ephemeral key,
// and the standard test client registry.
func newTestService(t *testing.T, auth ClientAuthenticator, breach BreachRecorder) (*Service, *MemoryRefreshTokenStore) {
	t.Helper()
	key := testES256Key(t)
	next := testES256Key(t)
	manager, err := keys.NewManager(key, next, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	registry, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      testPublicID,
			RedirectURIs:            []string{testRedirectURI},
			TokenEndpointAuthMethod: clients.AuthMethodNone,
			AllowedScopes:           []string{"openid", "profile"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	refresh := NewMemoryRefreshTokenStore()
	svc, err := NewService(
		Config{Issuer: testIssuer},
		manager,
		registry,
		NewMemoryCodeStore(),
		refresh,
		auth,
		breach,
		slog.Default(),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, refresh
}

// issueTestCode mints a code for the standard test client and returns the raw
// code plus the verifier that satisfies its PKCE challenge.
func issueTestCode(t *testing.T, svc *Service) (code, verifier string) {
	t.Helper()
	verifier = strings.Repeat("v", 50)
	code, err := svc.IssueCode(AuthorizationCodeData{
		ClientID:      testPublicID,
		RedirectURI:   testRedirectURI,
		UserID:        "user-1",
		Scope:         "openid profile",
		Nonce:         "n-123",
		CodeChallenge: challengeFor(verifier),
	})
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	return code, verifier
}

func authCodeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {GrantAuthorizationCode},
		"client_id":     {testPublicID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {testRedirectURI},
	}
}

// wantTokenError asserts err is a *Error with the given code and returns the
// asserted HTTP status so callers can additionally check it.
func wantTokenError(t *testing.T, err error, code string) int {
	t.Helper()
	var tokenErr *Error
	if !errors.As(err, &tokenErr) {
		t.Fatalf("want *token.Error %q, got %v", code, err)
	}
	if tokenErr.Code != code {
		t.Fatalf("want error code %q, got %q (%s)", code, tokenErr.Code, tokenErr.Description)
	}
	return tokenErr.Status
}

func TestExchangeGrantTypeDispatch(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	ctx := context.Background()

	_, err := svc.Exchange(ctx, url.Values{})
	wantTokenError(t, err, ErrCodeInvalidRequest)

	_, err = svc.Exchange(ctx, url.Values{"grant_type": {"password"}})
	wantTokenError(t, err, ErrCodeUnsupportedGrantType)
}

func TestAuthorizationCodeExchangeSuccess(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, verifier := issueTestCode(t, svc)

	resp, err := svc.Exchange(context.Background(), authCodeForm(code, verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if resp.AccessToken == "" || resp.IDToken == "" || resp.RefreshToken == "" {
		t.Errorf("response missing tokens: %+v", resp)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}

	// Access token verifies against the active key and carries the profile
	// claims.
	claims, err := Verify(resp.AccessToken, svc.keys.ActiveSigner())
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if claims["iss"] != testIssuer || claims["sub"] != "user-1" || claims["client_id"] != testPublicID {
		t.Errorf("access token claims: %+v", claims)
	}

	// ID token carries the nonce from the authorization request.
	idClaims, err := Verify(resp.IDToken, svc.keys.ActiveSigner())
	if err != nil {
		t.Fatalf("Verify id token: %v", err)
	}
	if idClaims["nonce"] != "n-123" || idClaims["aud"] != testPublicID {
		t.Errorf("id token claims: %+v", idClaims)
	}
}

func TestAuthorizationCodeReplayRejected(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, verifier := issueTestCode(t, svc)
	ctx := context.Background()

	if _, err := svc.Exchange(ctx, authCodeForm(code, verifier)); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	_, err := svc.Exchange(ctx, authCodeForm(code, verifier))
	wantTokenError(t, err, ErrCodeInvalidGrant)
}

func TestAuthorizationCodeWrongVerifier(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, _ := issueTestCode(t, svc)

	_, err := svc.Exchange(context.Background(), authCodeForm(code, strings.Repeat("w", 50)))
	wantTokenError(t, err, ErrCodeInvalidGrant)
}

func TestAuthorizationCodeBindingChecks(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	ctx := context.Background()

	t.Run("wrong redirect_uri", func(t *testing.T) {
		code, verifier := issueTestCode(t, svc)
		form := authCodeForm(code, verifier)
		form.Set("redirect_uri", "https://evil.test/callback")
		_, err := svc.Exchange(ctx, form)
		wantTokenError(t, err, ErrCodeInvalidGrant)
	})

	t.Run("unknown client", func(t *testing.T) {
		code, verifier := issueTestCode(t, svc)
		form := authCodeForm(code, verifier)
		form.Set("client_id", "nope")
		_, err := svc.Exchange(ctx, form)
		if status := wantTokenError(t, err, ErrCodeInvalidClient); status != 401 {
			t.Errorf("invalid_client status = %d, want 401", status)
		}
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	svc, _ := newTestService(t, nil, nil)
	code, verifier := issueTestCode(t, svc)
	ctx := context.Background()

	first, err := svc.Exchange(ctx, authCodeForm(code, verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}

	refreshForm := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {testPublicID},
		"refresh_token": {first.RefreshToken},
	}
	second, err := svc.Exchange(ctx, refreshForm)
	if err != nil {
		t.Fatalf("refresh exchange: %v", err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Error("rotation must issue a new, different refresh token")
	}
	if second.AccessToken == "" {
		t.Error("rotation must issue a new access token")
	}
}

func TestRefreshTokenReuseTriggersBreach(t *testing.T) {
	breach := &recordingBreach{}
	svc, _ := newTestService(t, nil, breach)
	code, verifier := issueTestCode(t, svc)
	ctx := context.Background()

	first, err := svc.Exchange(ctx, authCodeForm(code, verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	refreshForm := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {testPublicID},
		"refresh_token": {first.RefreshToken},
	}
	second, err := svc.Exchange(ctx, refreshForm)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	// Replay the ROTATED token: breach must fire and revoke everything.
	_, err = svc.Exchange(ctx, refreshForm)
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if len(breach.userIDs) != 1 || breach.userIDs[0] != "user-1" {
		t.Errorf("breach recorder calls = %v, want [user-1]", breach.userIDs)
	}

	// The freshly-rotated (previously valid) token is now revoked too — using
	// it is itself another breach presentation, not a success.
	newestForm := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {testPublicID},
		"refresh_token": {second.RefreshToken},
	}
	_, err = svc.Exchange(ctx, newestForm)
	wantTokenError(t, err, ErrCodeInvalidGrant)
}

func TestRefreshTokenWrongClientTriggersBreach(t *testing.T) {
	breach := &recordingBreach{}
	svc, refresh := newTestService(t, nil, breach)
	code, verifier := issueTestCode(t, svc)
	ctx := context.Background()

	first, err := svc.Exchange(ctx, authCodeForm(code, verifier))
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}

	// Register a second client by swapping the registry is not possible with
	// StaticRegistry; instead present the token under a client_id that exists
	// in the registry check first. Simulate by tampering the stored record's
	// client binding.
	hash := HashSecret(first.RefreshToken)
	data, err := refresh.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	data.ClientID = "another-client"
	if err := refresh.Save(hash, data); err != nil {
		t.Fatalf("Save: %v", err)
	}

	form := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {testPublicID},
		"refresh_token": {first.RefreshToken},
	}
	_, err = svc.Exchange(ctx, form)
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if len(breach.userIDs) != 1 {
		t.Errorf("wrong-client presentation must record a breach, got %v", breach.userIDs)
	}
}

func TestRefreshTokenUnknownIsPlainInvalidGrant(t *testing.T) {
	breach := &recordingBreach{}
	svc, _ := newTestService(t, nil, breach)

	form := url.Values{
		"grant_type":    {GrantRefreshToken},
		"client_id":     {testPublicID},
		"refresh_token": {"completely-unknown"},
	}
	_, err := svc.Exchange(context.Background(), form)
	wantTokenError(t, err, ErrCodeInvalidGrant)
	if len(breach.userIDs) != 0 {
		t.Errorf("unknown token must not record a breach, got %v", breach.userIDs)
	}
}

func TestClientCredentials(t *testing.T) {
	confidential := clients.Client{
		ID:                      "svc-billing",
		RedirectURIs:            []string{"https://unused.test"},
		TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT,
		AllowedScopes:           []string{"billing.read"},
	}
	ctx := context.Background()

	t.Run("success without refresh token", func(t *testing.T) {
		svc, _ := newTestService(t, &fakeAuthenticator{client: confidential}, nil)
		resp, err := svc.Exchange(ctx, url.Values{
			"grant_type": {GrantClientCredentials},
			"scope":      {"billing.read"},
		})
		if err != nil {
			t.Fatalf("Exchange: %v", err)
		}
		if resp.RefreshToken != "" {
			t.Error("client_credentials must not issue a refresh token (OAuth 2.1)")
		}
		claims, err := Verify(resp.AccessToken, svc.keys.ActiveSigner())
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims["sub"] != "svc-billing" || claims["client_id"] != "svc-billing" {
			t.Errorf("machine token claims: %+v", claims)
		}
	})

	t.Run("authentication failure", func(t *testing.T) {
		svc, _ := newTestService(t, &fakeAuthenticator{err: errors.New("bad assertion")}, nil)
		_, err := svc.Exchange(ctx, url.Values{"grant_type": {GrantClientCredentials}})
		if status := wantTokenError(t, err, ErrCodeInvalidClient); status != 401 {
			t.Errorf("status = %d, want 401", status)
		}
	})

	t.Run("public client rejected", func(t *testing.T) {
		public := confidential
		public.TokenEndpointAuthMethod = clients.AuthMethodNone
		svc, _ := newTestService(t, &fakeAuthenticator{client: public}, nil)
		_, err := svc.Exchange(ctx, url.Values{"grant_type": {GrantClientCredentials}})
		wantTokenError(t, err, ErrCodeUnauthorizedClient)
	})

	t.Run("disallowed scope rejected", func(t *testing.T) {
		svc, _ := newTestService(t, &fakeAuthenticator{client: confidential}, nil)
		_, err := svc.Exchange(ctx, url.Values{
			"grant_type": {GrantClientCredentials},
			"scope":      {"admin.write"},
		})
		wantTokenError(t, err, ErrCodeInvalidScope)
	})

	t.Run("no authenticator configured", func(t *testing.T) {
		svc, _ := newTestService(t, nil, nil)
		_, err := svc.Exchange(ctx, url.Values{"grant_type": {GrantClientCredentials}})
		wantTokenError(t, err, ErrCodeInvalidClient)
	})
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"openid", []string{"openid"}},
		{"openid profile", []string{"openid", "profile"}},
		{"  openid   profile  ", []string{"openid", "profile"}},
	}
	for _, tc := range tests {
		got := splitScopes(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitScopes(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitScopes(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}
