package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func accessFixture(t testing.TB, version int64) (*AccessValidator, *Service, *Response, *tokenAccountState) {
	t.Helper()
	svc, store := newTestService(t, nil, nil)
	state := &tokenAccountState{active: true, version: version}
	svc.cfg.AccountState = state
	userID := uuid.NewString()
	seedTestSession(svc, userID, "access-session", version)
	verifier := strings.Repeat("v", 50)
	code, err := svc.IssueCode(AuthorizationCodeData{UserID: userID, SessionID: "access-session", AuthVersion: version,
		AuthVersionSet: true, ClientID: testPublicID, RedirectURI: testRedirectURI, Scope: "openid profile", CodeChallenge: challengeFor(verifier)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := svc.Exchange(t.Context(), authCodeForm(code, verifier))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewAccessValidator(AccessValidatorConfig{Issuer: testIssuer, Keys: svc.keys.(VerificationKeys), Clients: svc.registry,
		Grants: store, Sessions: svc.cfg.Sessions, Accounts: state})
	if err != nil {
		t.Fatal(err)
	}
	return v, svc, response, state
}

func decodeTestClaims(t *testing.T, compact string) Claims {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var claims Claims
	if err := decoder.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestAccessValidationPreservesCapturedVersion(t *testing.T) {
	for _, version := range []int64{0, 9007199254740993} {
		v, svc, response, state := accessFixture(t, version)
		before, err := svc.cfg.Sessions.LookupByID(t.Context(), response.Subject, "access-session")
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			got, err := v.Validate(t.Context(), response.AccessToken, testIssuer)
			if err != nil || got.Subject != response.Subject || got.PrincipalType != PrincipalUser {
				t.Fatalf("validation: %+v %v", got, err)
			}
		}
		after, err := svc.cfg.Sessions.LookupByID(t.Context(), response.Subject, "access-session")
		if err != nil || !before.IdleExpiry.Equal(after.IdleExpiry) || !before.LastSeenAt.Equal(after.LastSeenAt) {
			t.Fatalf("validation touched browser: %v", err)
		}
		state.active = false
		if _, err := v.Validate(t.Context(), response.AccessToken, testIssuer); !errors.Is(err, ErrInactiveToken) {
			t.Fatal(err)
		}
		state.active = true
		state.version++
		if _, err := v.Validate(t.Context(), response.AccessToken, testIssuer); !errors.Is(err, ErrInactiveToken) {
			t.Fatalf("reactivation revived token: %v", err)
		}
	}
}

func TestAccessValidationRejectsInvalidClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(Claims)
		typ    string
	}{
		{"issuer", func(c Claims) { c["iss"] = "https://other.test" }, TypAccessToken},
		{"audience", func(c Claims) { c["aud"] = "other" }, TypAccessToken},
		{"expired", func(c Claims) {
			c["iat"] = time.Now().Add(-time.Hour).Unix()
			c["exp"] = time.Now().Add(-time.Second).Unix()
		}, TypAccessToken},
		{"future", func(c Claims) { c["iat"] = time.Now().Add(time.Minute).Unix() }, TypAccessToken},
		{"not yet valid", func(c Claims) { c["nbf"] = time.Now().Add(time.Minute).Unix() }, TypAccessToken},
		{"long lifetime", func(c Claims) { c["exp"] = time.Now().Add(time.Hour).Unix() }, TypAccessToken},
		{"missing version", func(c Claims) { delete(c, "auth_version") }, TypAccessToken},
		{"version string", func(c Claims) { c["auth_version"] = "0" }, TypAccessToken},
		{"missing session", func(c Claims) { delete(c, "sid") }, TypAccessToken},
		{"missing grant", func(c Claims) { delete(c, "grant_id") }, TypAccessToken},
		{"missing principal", func(c Claims) { delete(c, "principal_type") }, TypAccessToken},
		{"missing jti", func(c Claims) { delete(c, "jti") }, TypAccessToken},
		{"scope expansion", func(c Claims) { c["scope"] = "openid admin.write" }, TypAccessToken},
		{"wrong subject", func(c Claims) { c["sub"] = uuid.NewString() }, TypAccessToken},
		{"wrong confirmation", func(c Claims) { c["cnf"] = map[string]string{"jkt": "invalid"} }, TypAccessToken},
		{"ID token", func(Claims) {}, TypJWT},
		{"stepup token", func(Claims) {}, TypStepUpToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, svc, response, _ := accessFixture(t, 0)
			claims := decodeTestClaims(t, response.AccessToken)
			tc.change(claims)
			compact, err := Sign(svc.keys.ActiveSigner(), tc.typ, claims)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.Validate(t.Context(), compact, testIssuer)
			if !errors.Is(err, ErrInactiveToken) || got != (ValidatedAccessToken{}) {
				t.Fatalf("invalid token accepted: %+v %v", got, err)
			}
		})
	}
}

func TestAccessValidationLiveSessionAndGrant(t *testing.T) {
	for _, mode := range []string{"logout", "idle", "absolute", "restricted", "family", "missing", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			v, svc, response, _ := accessFixture(t, 0)
			claims := decodeTestClaims(t, response.AccessToken)
			grantID := claims["grant_id"].(string)
			sessions := svc.cfg.Sessions.(*testSessions)
			parent := sessions.values["access-session"]
			store := svc.refresh.(*MemoryRefreshTokenStore)
			want := ErrInactiveToken
			switch mode {
			case "logout":
				delete(sessions.values, parent.ID)
			case "idle":
				parent.IdleExpiry = time.Now()
				sessions.values[parent.ID] = parent
			case "absolute":
				parent.AbsoluteExpiry = time.Now()
				sessions.values[parent.ID] = parent
			case "restricted":
				parent.Kind = session.KindRecoveryEnrollment
				sessions.values[parent.ID] = parent
			case "family":
				if err := store.RevokeFamily(t.Context(), grantID); err != nil {
					t.Fatal(err)
				}
			case "missing":
				delete(store.grants, grantID)
			case "corrupt":
				g := store.grants[grantID]
				g.PrincipalType = "unknown"
				store.grants[grantID] = g
				want = ErrStoreUnavailable
			}
			got, err := v.Validate(t.Context(), response.AccessToken, testIssuer)
			if !errors.Is(err, want) || got != (ValidatedAccessToken{}) {
				t.Fatalf("authority bypass: %+v %v", got, err)
			}
		})
	}
}

func TestAccessValidationDependencyFailureAndCancellation(t *testing.T) {
	v, _, response, state := accessFixture(t, 0)
	state.err = errors.New("primary database unavailable")
	got, err := v.Validate(t.Context(), response.AccessToken, testIssuer)
	if err == nil || errors.Is(err, ErrInactiveToken) || got != (ValidatedAccessToken{}) {
		t.Fatalf("outage misclassified: %+v %v", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := v.Validate(ctx, response.AccessToken, testIssuer); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type oneClientRegistry struct{ client clients.Client }

func (r oneClientRegistry) Lookup(id string) (clients.Client, error) {
	if id != r.client.ID {
		return clients.Client{}, clients.ErrUnknownClient
	}
	return r.client, nil
}

type noUserLookups struct{ t *testing.T }

func (n noUserLookups) LookupByID(context.Context, string, string) (session.Session, error) {
	n.t.Error("client token performed browser lookup")
	return session.Session{}, session.ErrSessionNotFound
}
func (n noUserLookups) Validate(context.Context, string, int64) error {
	n.t.Error("client token performed account lookup")
	return session.ErrAccountIneligible
}
func (n noUserLookups) WithActive(context.Context, string, int64, func() error) error {
	n.t.Error("client token locked user")
	return session.ErrAccountIneligible
}
func (n noUserLookups) Epoch(context.Context) (int64, error) {
	n.t.Error("client token read account epoch")
	return 0, session.ErrAccountIneligible
}

func TestClientAccessTokenIsNeverAUser(t *testing.T) {
	client := clients.Client{ID: uuid.NewString(), TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT, AllowedScopes: []string{"read"}}
	svc, store := newTestService(t, &fakeAuthenticator{client: client}, nil)
	svc.registry = oneClientRegistry{client}
	response, err := svc.Exchange(t.Context(), map[string][]string{"grant_type": {GrantClientCredentials}, "scope": {"read"}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewAccessValidator(AccessValidatorConfig{Issuer: testIssuer, Keys: svc.keys.(VerificationKeys), Clients: svc.registry,
		Grants: store, Sessions: noUserLookups{t}, Accounts: noUserLookups{t}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Validate(t.Context(), response.AccessToken, testIssuer)
	if err != nil || got.PrincipalType != PrincipalClient || got.Subject != client.ID {
		t.Fatalf("client validation: %+v %v", got, err)
	}
	client.TokenEndpointAuthMethod = clients.AuthMethodNone
	v.cfg.Clients = oneClientRegistry{client}
	if _, err := v.Validate(t.Context(), response.AccessToken, testIssuer); !errors.Is(err, ErrInactiveToken) {
		t.Fatalf("public client accepted: %v", err)
	}
}

// This isolates local ES256/claims/state overhead. Storage is in-memory and the
// primary account gate is a test double, so results are not an end-to-end SLO.
func BenchmarkAccessValidation(b *testing.B) {
	for _, principal := range []string{PrincipalUser, PrincipalClient} {
		b.Run(principal, func(b *testing.B) {
			validator, service, issued, _ := accessFixture(b, 0)
			if principal == PrincipalClient {
				client := clients.Client{ID: uuid.NewString(), TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT, AllowedScopes: []string{"read"}}
				service.registry = oneClientRegistry{client}
				service.clientAuth = &fakeAuthenticator{client: client}
				validator.cfg.Clients = service.registry
				var err error
				issued, err = service.Exchange(b.Context(), map[string][]string{"grant_type": {GrantClientCredentials}, "scope": {"read"}})
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := validator.Validate(b.Context(), issued.AccessToken, testIssuer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
