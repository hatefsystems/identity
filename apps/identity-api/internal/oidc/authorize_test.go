package oidc

import (
	"net/url"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
)

// validChallenge is a well-formed 43-char base64url S256 code_challenge.
const validChallenge = "E9Melhoa2OwvFrGMTJguCH5KLUAzSAt9GPmy_8_NfXE"

func testRegistry(t *testing.T) clients.Registry {
	t.Helper()
	reg, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      "hatef-nextjs-app",
			RedirectURIs:            []string{"https://hatef.ir/callback"},
			TokenEndpointAuthMethod: clients.AuthMethodNone,
			AllowedScopes:           []string{"openid", "profile", "email", "offline_access"},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	return reg
}

func baseQuery() url.Values {
	q := url.Values{}
	q.Set("client_id", "hatef-nextjs-app")
	q.Set("redirect_uri", "https://hatef.ir/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile")
	q.Set("state", "af0ifjsldkj")
	q.Set("code_challenge", validChallenge)
	q.Set("code_challenge_method", "S256")
	return q
}

func TestParseAuthorizationRequestValid(t *testing.T) {
	req, err := ParseAuthorizationRequest(baseQuery(), testRegistry(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ClientID != "hatef-nextjs-app" {
		t.Errorf("ClientID = %q", req.ClientID)
	}
	if req.State != "af0ifjsldkj" {
		t.Errorf("State = %q", req.State)
	}
	if req.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod = %q", req.CodeChallengeMethod)
	}
	if len(req.Scopes) != 2 {
		t.Errorf("Scopes = %v", req.Scopes)
	}
}

// asAuthErr extracts a *AuthorizationError or fails the test.
func asAuthErr(t *testing.T, err error) *AuthorizationError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	ae, ok := err.(*AuthorizationError)
	if !ok {
		t.Fatalf("error is %T, want *AuthorizationError", err)
	}
	return ae
}

func TestParseAuthorizationRequestFatalErrors(t *testing.T) {
	reg := testRegistry(t)
	tests := []struct {
		name   string
		mutate func(url.Values)
		code   string
	}{
		{"missing client_id", func(q url.Values) { q.Del("client_id") }, ErrCodeInvalidRequest},
		{"unknown client", func(q url.Values) { q.Set("client_id", "ghost") }, ErrCodeInvalidClient},
		{"missing redirect_uri", func(q url.Values) { q.Del("redirect_uri") }, ErrCodeInvalidRequest},
		{"mismatched redirect_uri", func(q url.Values) { q.Set("redirect_uri", "https://evil.ir/callback") }, ErrCodeInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := baseQuery()
			tt.mutate(q)
			ae := asAuthErr(t, mustErr(t, reg, q))
			if ae.Redirectable {
				t.Error("client/redirect_uri failures must NOT be redirectable")
			}
			if ae.Code != tt.code {
				t.Errorf("Code = %q, want %q", ae.Code, tt.code)
			}
		})
	}
}

func TestParseAuthorizationRequestRedirectableErrors(t *testing.T) {
	reg := testRegistry(t)
	tests := []struct {
		name   string
		mutate func(url.Values)
		code   string
	}{
		{"missing response_type", func(q url.Values) { q.Del("response_type") }, ErrCodeInvalidRequest},
		{"implicit flow rejected", func(q url.Values) { q.Set("response_type", "token") }, ErrCodeUnsupportedResponseType},
		{"missing code_challenge", func(q url.Values) { q.Del("code_challenge") }, ErrCodeInvalidRequest},
		{"missing method", func(q url.Values) { q.Del("code_challenge_method") }, ErrCodeInvalidRequest},
		{"plain method rejected", func(q url.Values) { q.Set("code_challenge_method", "plain") }, ErrCodeInvalidRequest},
		{"malformed challenge (short)", func(q url.Values) { q.Set("code_challenge", "tooshort") }, ErrCodeInvalidRequest},
		{"malformed challenge (padding)", func(q url.Values) { q.Set("code_challenge", validChallenge[:42]+"=") }, ErrCodeInvalidRequest},
		{"missing scope", func(q url.Values) { q.Del("scope") }, ErrCodeInvalidScope},
		{"scope without openid", func(q url.Values) { q.Set("scope", "profile email") }, ErrCodeInvalidScope},
		{"disallowed scope", func(q url.Values) { q.Set("scope", "openid admin") }, ErrCodeInvalidScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := baseQuery()
			tt.mutate(q)
			ae := asAuthErr(t, mustErr(t, reg, q))
			if !ae.Redirectable {
				t.Errorf("error %q should be redirectable", tt.name)
			}
			if ae.Code != tt.code {
				t.Errorf("Code = %q, want %q", ae.Code, tt.code)
			}
		})
	}
}

// mustErr runs ParseAuthorizationRequest and asserts it failed.
func mustErr(t *testing.T, reg clients.Registry, q url.Values) error {
	t.Helper()
	_, err := ParseAuthorizationRequest(q, reg)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	return err
}

func TestIsValidS256Challenge(t *testing.T) {
	if !isValidS256Challenge(validChallenge) {
		t.Error("valid challenge rejected")
	}
	for _, bad := range []string{
		"",
		"short",
		validChallenge + "x",      // 44 chars
		validChallenge[:42] + "+", // out-of-alphabet
		validChallenge[:42] + "/", // out-of-alphabet
	} {
		if isValidS256Challenge(bad) {
			t.Errorf("challenge %q should be invalid", bad)
		}
	}
}

func TestRedirectErrorURL(t *testing.T) {
	ae := newRedirectableError(ErrCodeInvalidScope, "bad scope", "https://hatef.ir/callback", "xyz")
	got, err := RedirectErrorURL(ae)
	if err != nil {
		t.Fatalf("RedirectErrorURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse result: %v", err)
	}
	q := u.Query()
	if q.Get("error") != ErrCodeInvalidScope {
		t.Errorf("error = %q", q.Get("error"))
	}
	if q.Get("error_description") != "bad scope" {
		t.Errorf("error_description = %q", q.Get("error_description"))
	}
	if q.Get("state") != "xyz" {
		t.Errorf("state = %q", q.Get("state"))
	}
}

func TestRedirectErrorURLOmitsEmptyState(t *testing.T) {
	ae := newRedirectableError(ErrCodeInvalidRequest, "x", "https://hatef.ir/callback", "")
	got, err := RedirectErrorURL(ae)
	if err != nil {
		t.Fatalf("RedirectErrorURL: %v", err)
	}
	u, _ := url.Parse(got)
	if _, ok := u.Query()["state"]; ok {
		t.Error("state must be omitted when empty")
	}
}
