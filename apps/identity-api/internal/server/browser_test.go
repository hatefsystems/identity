package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const boundaryTestPath = "/api/v1/portal-test/protected"

type boundaryStore struct {
	session.Store
	touches   atomic.Int32
	getErr    error
	touchErr  error
	deleteErr error
}

func (s *boundaryStore) Get(ctx context.Context, hash string) (session.Session, error) {
	if s.getErr != nil {
		return session.Session{}, s.getErr
	}
	return s.Store.Get(ctx, hash)
}

func (s *boundaryStore) Touch(ctx context.Context, hash string, expiry time.Time) error {
	s.touches.Add(1)
	if s.touchErr != nil {
		return s.touchErr
	}
	return s.Store.Touch(ctx, hash, expiry)
}

func (s *boundaryStore) Delete(ctx context.Context, hash string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Store.Delete(ctx, hash)
}

type boundaryAccounts struct{ err error }

func (a *boundaryAccounts) Validate(context.Context, string, int64) error { return a.err }
func (a *boundaryAccounts) Epoch(context.Context) (int64, error)          { return 1, a.err }
func (a *boundaryAccounts) WithActive(_ context.Context, _ string, _ int64, fn func() error) error {
	if a.err != nil {
		return a.err
	}
	return fn()
}

type boundaryHarness struct {
	server   *Server
	manager  *session.Manager
	store    *boundaryStore
	accounts *boundaryAccounts
	client   *portalTestClient
	current  session.Session
	cookies  []*http.Cookie
	calls    atomic.Int32
	grants   atomic.Int32
}

func newBoundaryHarness(t *testing.T, store session.Store, validator *dpop.Validator) *boundaryHarness {
	t.Helper()
	h := &boundaryHarness{client: newPortalTestClient(t, testPortalOrigin), accounts: &boundaryAccounts{}}
	if store == nil {
		store = session.NewMemoryStore()
	}
	if validator != nil {
		h.client.validator = validator
	}
	h.store = &boundaryStore{Store: store}
	cookie, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h.manager, err = session.NewManager(h.store, cookie, session.ManagerConfig{
		AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, AccountState: h.accounts,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.current, h.cookies = h.client.issueSession(t, h.manager, session.IssueParams{
		UserID: uuid.NewString(), AuthVersion: (1 << 54) + 7, AuthVersionSet: true,
	})
	h.server = New(config.Config{Environment: "production", PortalOrigin: h.client.origin}, slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{
		SessionManager: h.manager, DPoPValidator: h.client.validator,
	})
	guard, ok := h.server.sessionGuard("test")
	if !ok {
		t.Fatal("missing guard")
	}
	grant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.grants.Add(1)
			next.ServeHTTP(w, r)
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch} {
		h.server.router.With(guard.Handler, grant).Method(method, boundaryTestPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.calls.Add(1)
			s, ok := session.FromContext(r.Context())
			if !ok || dpop.ProofFromContext(r.Context()) == nil || s.AuthVersion != (1<<54)+7 {
				t.Error("missing or rounded authenticated context")
			}
			writeJSON(w, http.StatusOK, map[string]string{"value": "authorized"})
		}))
	}
	h.server.router.With(guard.Handler).Post("/api/v1/portal-test/denied", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusForbidden, sessionErrorResponse{Error: "insufficient_user_authentication"})
	})
	h.server.router.With(h.server.browserLogin).Post("/api/v1/portal-test/login", func(w http.ResponseWriter, r *http.Request) {
		if dpop.ProofFromContext(r.Context()) == nil {
			t.Error("anonymous login has no verified proof")
		}
		h.calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	return h
}

func (h *boundaryHarness) request(t *testing.T, method, path string) *http.Request {
	t.Helper()
	var body io.Reader
	if unsafeBrowserMethod(method) {
		body = strings.NewReader("{}")
	}
	r := httptest.NewRequest(method, path, body)
	h.client.authorize(t, r, h.current, h.cookies...)
	return r
}

func boundaryServe(t *testing.T, s *Server, r *http.Request, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("HTTP status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("API response did not retain private/no-store/no-referrer policy")
	}
	return w
}

func TestBrowserBoundaryProofAndAuthorityMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *boundaryHarness, *http.Request)
		want   int
		error  string
	}{
		{name: "missing proof", want: 401, error: "invalid_dpop_proof", change: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del("DPoP") }},
		{name: "duplicate proof", want: 401, error: "invalid_dpop_proof", change: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Add("DPoP", r.Header.Get("DPoP")) }},
		{name: "comma proof", want: 401, error: "invalid_dpop_proof", change: func(_ *testing.T, _ *boundaryHarness, r *http.Request) {
			r.Header.Set("DPoP", r.Header.Get("DPoP")+",other")
		}},
		{name: "wrong method", want: 401, error: "invalid_dpop_proof", change: func(t *testing.T, h *boundaryHarness, r *http.Request) {
			r.Header.Set("DPoP", h.client.proof(t, httptest.NewRequest(http.MethodDelete, r.URL.Path, nil), ""))
		}},
		{name: "wrong URI", want: 401, error: "invalid_dpop_proof", change: func(t *testing.T, h *boundaryHarness, r *http.Request) {
			r.Header.Set("DPoP", h.client.proof(t, httptest.NewRequest(r.Method, "/another-resource", nil), ""))
		}},
		{name: "wrong key", want: 401, error: "invalid_dpop_proof", change: func(t *testing.T, h *boundaryHarness, r *http.Request) {
			other := newPortalTestClient(t, h.client.origin)
			r.Header.Set("DPoP", other.proof(t, r, ""))
		}},
		{name: "missing cookie", want: 401, error: "session_required", change: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del("Cookie") }},
		{name: "unbound cookie", want: 401, error: "session_required", change: func(t *testing.T, h *boundaryHarness, r *http.Request) {
			issue := httptest.NewRecorder()
			if _, err := h.manager.Issue(issue, session.IssueParams{UserID: h.current.UserID, AuthVersionSet: true}); err != nil {
				t.Fatal(err)
			}
			r.Header.Del("Cookie")
			r.AddCookie(issue.Result().Cookies()[0])
		}},
		{name: "restricted cookie", want: 401, error: "session_required", change: func(t *testing.T, h *boundaryHarness, r *http.Request) {
			_, cookies := h.client.issueSession(t, h.manager, session.IssueParams{UserID: h.current.UserID, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
			r.Header.Del("Cookie")
			r.AddCookie(cookies[0])
		}},
		{name: "inactive account", want: 401, error: "session_required", change: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.accounts.err = session.ErrAccountIneligible }},
		{name: "database outage", want: 503, error: "temporarily_unavailable", change: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.accounts.err = errors.New("database down") }},
		{name: "session outage", want: 503, error: "temporarily_unavailable", change: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.store.getErr = session.ErrStoreUnavailable }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBoundaryHarness(t, nil, nil)
			r := h.request(t, http.MethodGet, boundaryTestPath)
			tc.change(t, h, r)
			w := boundaryServe(t, h.server, r, tc.want)
			if !strings.Contains(w.Body.String(), tc.error) || h.calls.Load() != 0 || h.grants.Load() != 0 || h.store.touches.Load() != 0 {
				t.Fatalf("denial changed authority or was misclassified: %s calls=%d grants=%d touches=%d", w.Body.String(), h.calls.Load(), h.grants.Load(), h.store.touches.Load())
			}
		})
	}
}

func TestBrowserBoundaryOriginAndJSONMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		want   int
	}{
		{name: "missing origin", want: 403, change: func(r *http.Request) { r.Header.Del("Origin") }},
		{name: "null origin", want: 403, change: func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{name: "sibling origin", want: 403, change: func(r *http.Request) { r.Header.Set("Origin", "https://sibling.identity.example") }},
		{name: "duplicate origin", want: 403, change: func(r *http.Request) { r.Header.Add("Origin", testPortalOrigin) }},
		{name: "joined origins", want: 403, change: func(r *http.Request) { r.Header.Set("Origin", testPortalOrigin+" "+testPortalOrigin) }},
		{name: "cross-site", want: 403, change: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "missing content type", want: 415, change: func(r *http.Request) { r.Header.Del("Content-Type") }},
		{name: "form content type", want: 415, change: func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
		{name: "duplicate content type", want: 415, change: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
		{name: "unsupported charset", want: 415, change: func(r *http.Request) { r.Header.Set("Content-Type", "application/json;charset=utf-16") }},
		{name: "invalid JSON", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{")) }},
		{name: "whitespace is not absent", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(" \t ")) }},
		{name: "multiple objects", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{}{}")) }},
		{name: "null body", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("null")) }},
		{name: "array body", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("[]")) }},
		{name: "duplicate fields", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"name":"first","name":"last"}`)) }},
		{name: "nested duplicate fields", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"response":{"value":1,"value":2}}`)) }},
		{name: "invalid UTF8", want: 400, change: func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("{\"name\":\"\xff\"}")) }},
		{name: "oversized", want: 413, change: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"value":"` + strings.Repeat("a", 65536) + `"}`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newBoundaryHarness(t, nil, nil)
			r := h.request(t, http.MethodPost, boundaryTestPath)
			tc.change(r)
			w := boundaryServe(t, h.server, r, tc.want)
			if h.grants.Load() != 0 || h.calls.Load() != 0 || h.store.touches.Load() != 0 || w.Header().Get("DPoP-Nonce") != "" {
				t.Fatal("invalid transport reached nonce/grant/handler/activity state")
			}
		})
	}
}

func TestBrowserSessionIntentRejectsWithoutBurningProof(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			h := newBoundaryHarness(t, nil, nil)
			r := h.request(t, method, boundaryTestPath)
			r.Header.Set(portalSessionHeader, uuid.NewString())
			w := boundaryServe(t, h.server, r, 409)
			if !strings.Contains(w.Body.String(), "session_changed") || h.store.touches.Load() != 0 || h.grants.Load() != 0 {
				t.Fatal("stale-tab request was not rejected before authorization")
			}
			r.Header.Set(portalSessionHeader, h.current.ID)
			if unsafeBrowserMethod(method) {
				r.Body = io.NopCloser(strings.NewReader("{}"))
			}
			boundaryServe(t, h.server, r, 200)
			if h.calls.Load() != 1 || h.grants.Load() != 1 || h.store.touches.Load() != 1 {
				t.Fatal("intent mismatch consumed an otherwise valid proof")
			}
		})
	}
	for _, duplicate := range []bool{false, true} {
		h := newBoundaryHarness(t, nil, nil)
		r := h.request(t, http.MethodPost, boundaryTestPath)
		if duplicate {
			r.Header.Add(portalSessionHeader, h.current.ID)
		} else {
			r.Header.Del(portalSessionHeader)
		}
		boundaryServe(t, h.server, r, 409)
		if h.grants.Load() != 0 || h.store.touches.Load() != 0 {
			t.Fatal("missing/duplicate intent reached an authorized operation")
		}
	}
}

func TestBrowserExpectedKeyPrecedesNonceConsumption(t *testing.T) {
	h := newBoundaryHarness(t, nil, nil)
	other := newPortalTestClient(t, h.client.origin)
	other.validator = h.client.validator
	current, cookies := other.issueSession(t, h.manager, session.IssueParams{UserID: h.current.UserID, AuthVersion: h.current.AuthVersion, AuthVersionSet: true})
	r := httptest.NewRequest(http.MethodGet, boundaryTestPath, nil)
	other.authorize(t, r, current, h.cookies...)
	boundaryServe(t, h.server, r, 401)
	if h.store.touches.Load() != 0 || h.grants.Load() != 0 {
		t.Fatal("wrong key reached authorization")
	}
	r.Header.Del("Cookie")
	r.AddCookie(cookies[0])
	boundaryServe(t, h.server, r, 200)
}

func TestBrowserCanonicalTargetIgnoresHostAndForwarding(t *testing.T) {
	h := newBoundaryHarness(t, nil, nil)
	r := h.request(t, http.MethodGet, boundaryTestPath+"?untrusted=ignored")
	r.Host = "attacker.example"
	r.Header.Set("Forwarded", "host=attacker.example;proto=http")
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	r.Header.Set("X-Forwarded-Proto", "http")
	boundaryServe(t, h.server, r, 200)
	r = h.request(t, http.MethodGet, boundaryTestPath)
	h.client.origin = "https://attacker.example"
	r.Header.Set("DPoP", h.client.proof(t, r, ""))
	r.Host = "attacker.example"
	boundaryServe(t, h.server, r, 401)
}

func replaceBrowserProofNonce(t *testing.T, client *portalTestClient, compact, nonce string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["nonce"] = nonce
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, client.key.Signer.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature[:])
}

func TestBrowserNonceAndReplayAcrossReplicas(t *testing.T) {
	shared := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: shared.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	replica := func() *boundaryHarness {
		store, err := session.NewRedisStore(client)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := dpop.NewRedisReplayGuard(client)
		if err != nil {
			t.Fatal(err)
		}
		nonces, err := dpop.NewRedisNonceStore(client)
		if err != nil {
			t.Fatal(err)
		}
		validator, err := dpop.NewValidator(replay, nonces)
		if err != nil {
			t.Fatal(err)
		}
		return newBoundaryHarness(t, store, validator)
	}
	a, b := replica(), replica()
	r := httptest.NewRequest(http.MethodPost, boundaryTestPath, strings.NewReader("{}"))
	a.client.prepare(r)
	r.AddCookie(a.cookies[0])
	r.Header.Set(portalSessionHeader, a.current.ID)
	compact := a.client.proof(t, r, "")
	r.Header.Set("DPoP", compact)
	challenge := boundaryServe(t, a.server, r, 401)
	if !strings.Contains(challenge.Body.String(), "use_dpop_nonce") || challenge.Header().Get("DPoP-Nonce") == "" || a.grants.Load() != 0 || a.store.touches.Load() != 0 {
		t.Fatal("nonce response was not a pre-handler challenge")
	}
	compact = replaceBrowserProofNonce(t, a.client, compact, challenge.Header().Get("DPoP-Nonce"))
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for _, node := range []*boundaryHarness{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := r.Clone(t.Context())
			request.Body = io.NopCloser(strings.NewReader("{}"))
			request.Header.Set("DPoP", compact)
			response := httptest.NewRecorder()
			node.server.Handler().ServeHTTP(response, request)
			if response.Code == 200 {
				admitted.Add(1)
			} else if response.Code != 401 {
				t.Errorf("concurrent proof status=%d", response.Code)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 || a.calls.Load()+b.calls.Load() != 1 || a.grants.Load()+b.grants.Load() != 1 {
		t.Fatal("replicas did not enforce one successful nonce/proof consumption")
	}
	nonce, err := b.client.validator.IssueNonce(t.Context(), "browser:"+a.client.origin, a.client.jkt)
	if err != nil {
		t.Fatal(err)
	}
	r.Body = io.NopCloser(strings.NewReader("{}"))
	r.Header.Set("DPoP", replaceBrowserProofNonce(t, a.client, compact, nonce))
	replayed := boundaryServe(t, b.server, r, 401)
	if !strings.Contains(replayed.Body.String(), "invalid_dpop_proof") {
		t.Fatal("new nonce bypassed shared JTI replay protection")
	}
	shared.Close()
	r.Body = io.NopCloser(strings.NewReader("{}"))
	boundaryServe(t, a.server, r, 503)
}

func TestBrowserLogoutAndCurrentSessionDeletion(t *testing.T) {
	t.Run("missing cookie requires Origin then clears", func(t *testing.T) {
		h := newBoundaryHarness(t, nil, nil)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		boundaryServe(t, h.server, r, 403)
		r.Header.Set("Origin", h.client.origin)
		w := boundaryServe(t, h.server, r, 204)
		if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != "" || cookies[0].MaxAge >= 0 {
			t.Fatal("idempotent logout did not clear the hardened cookie")
		}
	})
	t.Run("live cookie requires proof and intent", func(t *testing.T) {
		h := newBoundaryHarness(t, nil, nil)
		r := h.request(t, http.MethodPost, "/api/v1/auth/logout")
		proof := r.Header.Get("DPoP")
		r.Header.Del("DPoP")
		boundaryServe(t, h.server, r, 401)
		if _, err := h.manager.Resolve(r); err != nil {
			t.Fatal("invalid proof revoked a live session")
		}
		r.Header.Set("DPoP", proof)
		r.Body = io.NopCloser(strings.NewReader("{}"))
		boundaryServe(t, h.server, r, 204)
		if _, err := h.manager.Resolve(r); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("logout authority remains: %v", err)
		}
		if h.store.touches.Load() != 0 {
			t.Fatal("logout renewed activity")
		}
	})
	t.Run("revocation fault is not success", func(t *testing.T) {
		h := newBoundaryHarness(t, nil, nil)
		h.store.deleteErr = session.ErrStoreUnavailable
		w := boundaryServe(t, h.server, h.request(t, http.MethodPost, "/api/v1/auth/logout"), 503)
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("revocation failure falsely cleared the live cookie")
		}
	})
	t.Run("current DELETE clears cookie and never resurrects", func(t *testing.T) {
		h := newBoundaryHarness(t, nil, nil)
		r := h.request(t, http.MethodDelete, "/api/v1/users/me/sessions/"+h.current.ID)
		w := boundaryServe(t, h.server, r, 204)
		if cookies := w.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != "" {
			t.Fatal("current-session DELETE did not clear cookie")
		}
		boundaryServe(t, h.server, h.request(t, http.MethodGet, "/api/v1/users/me/sessions"), 401)
	})
}

func TestBrowserSeparatelyMountedSessionsAndDownstreamDenial(t *testing.T) {
	h := newBoundaryHarness(t, nil, nil)
	for _, path := range []string{"/api/v1/users/me/sessions", "/api/v1/users/me/sessions/"} {
		r := h.request(t, http.MethodGet, path)
		r.Header.Del("DPoP")
		boundaryServe(t, h.server, r, 401)
		boundaryServe(t, h.server, h.request(t, http.MethodGet, path), 200)
	}
	before := h.store.touches.Load()
	r := h.request(t, http.MethodPost, "/api/v1/portal-test/denied")
	w := boundaryServe(t, h.server, r, 403)
	if h.store.touches.Load() != before || !strings.Contains(w.Body.String(), "insufficient_user_authentication") || w.Header().Get("WWW-Authenticate") == "Cookie" {
		t.Fatal("step-up denial renewed activity or was misclassified as session loss")
	}
	r = httptest.NewRequest(http.MethodPost, "/api/v1/portal-test/login", strings.NewReader("{}"))
	h.client.sign(t, r)
	boundaryServe(t, h.server, r, 204)
	if h.store.touches.Load() != before || h.calls.Load() != 1 {
		t.Fatal("anonymous login proof did not remain separate from session authority")
	}
}

func TestBrowserAdminActivityWaitsForFinalResponse(t *testing.T) {
	for _, finalStatus := range []int{200, 500, 503} {
		h := newBoundaryHarness(t, nil, nil)
		r := h.request(t, http.MethodGet, "/api/v1/admin/test")
		buffer := &adminResponseBuffer{header: make(http.Header)}
		guard, _ := h.server.sessionGuard("admin")
		guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"tentative"}`))
		})).ServeHTTP(buffer, r)
		if buffer.status != 200 || buffer.authenticatedSession == nil || h.store.touches.Load() != 0 {
			t.Fatal("tentative admin response renewed activity before the audit transaction completed")
		}
		response := httptest.NewRecorder()
		// The transaction emits its final outcome only after commit/overflow checks.
		h.manager.TrackActivity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(finalStatus)
		})).ServeHTTP(response, r.WithContext(session.WithSession(r.Context(), *buffer.authenticatedSession)))
		wantTouches := int32(0)
		if finalStatus == 200 {
			wantTouches = 1
		}
		if h.store.touches.Load() != wantTouches || response.Code != finalStatus {
			t.Fatalf("final status=%d touches=%d, want %d", response.Code, h.store.touches.Load(), wantTouches)
		}
	}
}

func TestBrowserSessionMetadataIsBoundedAndEscaped(t *testing.T) {
	h := newBoundaryHarness(t, nil, nil)
	h.client.issueSession(t, h.manager, session.IssueParams{
		UserID: h.current.UserID, AuthVersion: h.current.AuthVersion, AuthVersionSet: true,
		IP: strings.Repeat("0", 300), UserAgent: "<script>\n" + strings.Repeat("x", 2000),
	})
	w := boundaryServe(t, h.server, h.request(t, http.MethodGet, "/api/v1/users/me/sessions"), 200)
	var sessions []sessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("session metadata was not safely projected")
	}
	for _, s := range sessions {
		if len([]rune(s.IP)) > 64 || len([]rune(s.UserAgent)) > 256 || strings.Contains(s.UserAgent, "\n") {
			t.Fatal("untrusted session metadata exceeds the public bound")
		}
	}
}

func TestBrowserOptionalEmptyBody(t *testing.T) {
	for _, contentLength := range []int64{0, -1} {
		h := newBoundaryHarness(t, nil, nil)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/portal-test/login", strings.NewReader(""))
		r.ContentLength = contentLength
		h.client.sign(t, r)
		r.Header.Del("Content-Type")
		boundaryServe(t, h.server, r, 204)
		if h.calls.Load() != 1 || h.store.touches.Load() != 0 {
			t.Fatal("empty anonymous options body did not preserve its authority boundary")
		}
	}
}
