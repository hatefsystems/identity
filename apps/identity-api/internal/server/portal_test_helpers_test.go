package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const testPortalOrigin = "https://identity.example"

func requirePortalSessionRequired(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	err := json.Unmarshal(response.Body.Bytes(), &body)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Cookie" ||
		err != nil || body.Error != "session_required" {
		t.Fatalf("expected Cookie/session_required, got status=%d challenge=%q body=%s (decode error: %v)",
			response.Code, response.Header().Get("WWW-Authenticate"), response.Body.String(), err)
	}
}

// portalTestClient supplies real browser credentials only when a test explicitly
// requests them. Boundary-negative tests can keep using the unwrapped handler.
type portalTestClient struct {
	origin    string
	jkt       string
	key       *keys.SigningKey
	validator *dpop.Validator
}

func newPortalTestClient(t *testing.T, origin string) *portalTestClient {
	t.Helper()
	if origin == "" {
		t.Fatal("portal test client requires an explicit origin")
	}
	key, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("portal signing key: %v", err)
	}
	jkt, err := keys.Thumbprint(key.PublicJWK)
	if err != nil {
		t.Fatalf("portal key thumbprint: %v", err)
	}
	validator, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), dpop.NewMemoryNonceStore())
	if err != nil {
		t.Fatalf("portal DPoP validator: %v", err)
	}
	return &portalTestClient{origin: origin, jkt: jkt, key: key, validator: validator}
}

func (c *portalTestClient) issueSession(t *testing.T, manager *session.Manager, params session.IssueParams) (session.Session, []*http.Cookie) {
	t.Helper()
	if params.DPoPJKT != "" && params.DPoPJKT != c.jkt {
		t.Fatal("use the raw session manager to issue an intentionally foreign binding")
	}
	params.DPoPJKT = c.jkt
	recorder := httptest.NewRecorder()
	current, err := manager.IssueContext(t.Context(), recorder, params)
	if err != nil {
		t.Fatalf("issue bound portal session: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("bound portal session did not set a cookie")
	}
	return current, cookies
}

// prepare supplies transport headers, not authentication. Supplied values,
// including intentionally invalid or duplicate headers, are never repaired.
func (c *portalTestClient) prepare(req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodOptions {
		return
	}
	if len(req.Header.Values("Origin")) == 0 {
		req.Header.Set("Origin", c.origin)
	}
	if req.Body != nil && req.Body != http.NoBody && len(req.Header.Values("Content-Type")) == 0 {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (c *portalTestClient) authorize(t *testing.T, req *http.Request, current session.Session, cookies ...*http.Cookie) {
	t.Helper()
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodOptions &&
		len(req.Header.Values("X-Portal-Session")) == 0 {
		req.Header.Set("X-Portal-Session", current.ID)
	}
	c.sign(t, req)
}

// sign obtains a nonce from a cryptographically verified challenge without
// invoking the HTTP handler or retrying a potentially state-changing request.
func (c *portalTestClient) sign(t *testing.T, req *http.Request) {
	t.Helper()
	c.prepare(req)
	if len(req.Header.Values(dpop.HeaderProof)) != 0 {
		return
	}
	_, err := c.validator.Validate(t.Context(), c.proof(t, req, ""), dpop.VerifyParams{
		Realm: "browser:" + c.origin, ExpectedJKT: c.jkt,
		Method: req.Method, URL: c.origin + req.URL.EscapedPath(), RequireNonce: true,
	})
	var challenge *dpop.NonceChallenge
	if !errors.As(err, &challenge) || challenge.Realm != "browser:"+c.origin || challenge.JKT != c.jkt {
		t.Fatalf("portal nonce challenge: %v", err)
	}
	nonce, err := c.validator.IssueNonce(t.Context(), challenge.Realm, challenge.JKT)
	if err != nil {
		t.Fatalf("issue portal nonce: %v", err)
	}
	req.Header.Set(dpop.HeaderProof, c.proof(t, req, nonce))
}

func (c *portalTestClient) proof(t *testing.T, req *http.Request, nonce string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"typ": dpop.TypDPoP, "alg": keys.AlgES256, "jwk": c.key.PublicJWK})
	if err != nil {
		t.Fatalf("marshal portal proof header: %v", err)
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		t.Fatalf("portal proof JTI: %v", err)
	}
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti[:]),
		"htm": req.Method,
		"htu": c.origin + req.URL.EscapedPath(),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal portal proof claims: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, c.key.Signer.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		t.Fatalf("sign portal proof: %v", err)
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature[:])
}

func TestPortalTestClientIssuesBoundProofs(t *testing.T) {
	browser := newPortalTestClient(t, testPortalOrigin)
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: time.Hour, IdleTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	current, cookies := browser.issueSession(t, manager, session.IssueParams{UserID: "fixture-user"})
	if current.Kind != session.KindAuthenticated || current.DPoPJKT != browser.jkt {
		t.Fatal("fixture issued an unbound or restricted normal session")
	}
	var previous *dpop.Proof
	for range 2 {
		req := httptest.NewRequest(http.MethodPatch, "https://untrusted.invalid/api/v1/escaped%2Fpath?ignored=true", strings.NewReader(`{}`))
		browser.authorize(t, req, current, cookies...)
		if req.Header.Get("Origin") != browser.origin || req.Header.Get("Content-Type") != "application/json" ||
			req.Header.Get("X-Portal-Session") != current.ID {
			t.Fatal("fixture omitted required mutation headers")
		}
		resolved, err := manager.Resolve(req)
		if err != nil || resolved.ID != current.ID {
			t.Fatalf("resolve fixture cookie: %v", err)
		}
		proof, err := browser.validator.Validate(t.Context(), req.Header.Get(dpop.HeaderProof), dpop.VerifyParams{
			Realm: "browser:" + browser.origin, ExpectedJKT: resolved.DPoPJKT,
			Method: http.MethodPatch, URL: browser.origin + "/api/v1/escaped%2Fpath", RequireNonce: true,
		})
		if err != nil {
			t.Fatalf("fixture proof failed real validation: %v", err)
		}
		if proof.ATH != "" || proof.Nonce == "" || proof.JTI == "" {
			t.Fatal("fixture proof has invalid browser claims")
		}
		if previous != nil && (previous.JTI == proof.JTI || previous.Nonce == proof.Nonce) {
			t.Fatal("fixture reused a proof JTI or server nonce")
		}
		previous = proof
	}
}

func TestPortalTestClientPreservesExplicitInvalidHeaders(t *testing.T) {
	browser := newPortalTestClient(t, testPortalOrigin)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", strings.NewReader(`{}`))
	headers := []string{"Origin", "Content-Type", "X-Portal-Session", dpop.HeaderProof}
	for _, header := range headers {
		req.Header.Set(header, "")
		req.Header.Add(header, "intentionally-invalid")
	}
	browser.authorize(t, req, session.Session{ID: "not-an-authentication-credential"})
	for _, header := range headers {
		values := req.Header.Values(header)
		if len(values) != 2 || values[0] != "" || values[1] != "intentionally-invalid" {
			t.Fatalf("fixture repaired explicit %s headers: %q", header, values)
		}
	}
	if len(req.Cookies()) != 0 {
		t.Fatal("fixture invented an absent session cookie")
	}
}
