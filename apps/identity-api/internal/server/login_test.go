package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/login"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type loginHTTPNames struct {
	id    uuid.UUID
	calls int
}

func (n *loginHTTPNames) NormalizeLookup(string) (username.Value, error) {
	// This protocol fixture intentionally accepts an ASCII name outside the
	// production namespace; real normalization is covered by real-store tests.
	return username.Value{}, username.ErrInvalidUsername
}

func (n *loginHTTPNames) Lookup(_ context.Context, name string) (uuid.UUID, error) {
	n.calls++
	if name != "fixture_user" {
		return uuid.Nil, username.ErrNotFound
	}
	return n.id, nil
}

type loginHTTPLimiter struct{}

func (loginHTTPLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}

type loginHTTPFixture struct {
	server  *Server
	browser *portalTestClient
	manager *session.Manager
	service *login.Service
	users   *stepUpFakeUserStore
	names   *loginHTTPNames
	factor  *stepUpFakeTOTP
	redis   *miniredis.Miniredis
	user    db.User
}

func newLoginHTTPFixture(t *testing.T, enabled bool) *loginHTTPFixture {
	t.Helper()
	browser := newPortalTestClient(t, testPortalOrigin)
	r := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: r.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	pending, err := login.NewRedisPending(client)
	if err != nil {
		t.Fatal(err)
	}
	user := db.User{ID: uuid.New(), Status: "active", AuthVersion: 7, IsMfaEnabled: true}
	users := newStepUpFakeUserStore(user)
	names := &loginHTTPNames{id: user.ID}
	factor := &stepUpFakeTOTP{valid: "123456"}
	accounts := &boundaryAccounts{}
	service, err := login.New(login.Deps{Usernames: names, Users: users, Pending: pending, TOTP: factor, Replay: stepup.NewMemoryReplayGuard(), Accounts: accounts, Limiter: loginHTTPLimiter{}})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: accounts})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.Config{Environment: "production", PortalOrigin: browser.origin}, slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Login: service, PasswordLoginEnabled: enabled, SessionManager: manager, DPoPValidator: browser.validator, WebAuthnLimiter: loginHTTPLimiter{}})
	return &loginHTTPFixture{srv, browser, manager, service, users, names, factor, r, user}
}

func loginHTTPBody(t *testing.T, values map[string]string) string {
	t.Helper()
	body, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func loginHTTPRequest(t *testing.T, browser *portalTestClient, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.8:4242"
	browser.sign(t, req)
	return req
}

func requireLoginNoCookie(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("preauthentication/failure set a normal session cookie")
	}
}

func (f *loginHTTPFixture) pending(t *testing.T) login.Result {
	t.Helper()
	result, err := f.service.Prepare(t.Context(), session.IssueParams{UserID: f.user.ID.String(), AuthVersion: 7, AuthVersionSet: true, DPoPJKT: f.browser.jkt, Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
	if err != nil || result.Issue != nil || result.Preauthentication == "" {
		t.Fatalf("create MFA preauth: %v", err)
	}
	return result
}

func TestLoginHTTPStrictUsernameContractAndBrowserProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		path   string
		mutate func(*http.Request)
		status int
	}{
		{name: "email_identifier", body: `{"email":"owned@example.invalid","password":"secret"}`, status: 400},
		{name: "unknown_field", body: `{"username":"fixture_user","password":"secret","email":"ignored@example.invalid"}`, status: 400},
		{name: "duplicate_field", body: `{"username":"first","username":"last","password":"secret"}`, status: 400},
		{name: "null_password", body: `{"username":"fixture_user","password":null}`, status: 400},
		{name: "lone_surrogate", body: `{"username":"fixture_user","password":"\ud800"}`, status: 400},
		{name: "query_credentials", body: `{"username":"fixture_user","password":"secret"}`, path: "/api/v1/auth/login?password=secret", status: 400},
		{name: "empty_query", body: `{"username":"fixture_user","password":"secret"}`, path: "/api/v1/auth/login?", status: 400},
		{name: "oversized", body: `{"username":"fixture_user","password":"` + strings.Repeat("x", 8192) + `"}`, status: 400},
		{name: "missing_proof", status: 401, mutate: func(r *http.Request) { r.Header.Del("DPoP") }},
		{name: "wrong_origin", status: 403, mutate: func(r *http.Request) { r.Header.Set("Origin", "https://sibling.identity.example") }},
		{name: "form_content_type", status: 415, mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLoginHTTPFixture(t, true)
			if tc.body == "" {
				tc.body = `{"username":"fixture_user","password":"secret"}`
			}
			if tc.path == "" {
				tc.path = "/api/v1/auth/login"
			}
			req := loginHTTPRequest(t, f.browser, tc.path, tc.body)
			if tc.mutate != nil {
				tc.mutate(req)
			}
			response := boundaryServe(t, f.server, req, tc.status)
			requireLoginNoCookie(t, response)
			if f.names.calls != 0 || len(f.redis.Keys()) != 0 {
				t.Fatal("rejected transport reached login mutation")
			}
		})
	}
}

func TestLoginHTTPGenericPasswordFailures(t *testing.T) {
	hash, err := password.HashContext(t.Context(), "private fixture password")
	if err != nil {
		t.Fatal(err)
	}
	var publicBody string
	for _, scenario := range []string{"missing", "passkey_only", "wrong_password"} {
		t.Run(scenario, func(t *testing.T) {
			f := newLoginHTTPFixture(t, true)
			name := "fixture_user"
			if scenario == "missing" {
				name = "absent_user"
			}
			if scenario == "wrong_password" {
				f.user.PasswordHash = &hash
				f.users.byID[f.user.ID] = f.user
			}
			req := loginHTTPRequest(t, f.browser, "/api/v1/auth/login", loginHTTPBody(t, map[string]string{"username": name, "password": "not the password"}))
			response := boundaryServe(t, f.server, req, 401)
			requireLoginNoCookie(t, response)
			if publicBody == "" {
				publicBody = response.Body.String()
			}
			if response.Body.String() != publicBody || !strings.Contains(publicBody, `"invalid_credentials"`) {
				t.Fatal("password failure disclosed account credential configuration")
			}
		})
	}
}

func TestLoginHTTPMFAHasNoSessionUntilCompletionAndPersistsEarnedEvidence(t *testing.T) {
	f := newLoginHTTPFixture(t, true)
	hash, err := password.HashContext(t.Context(), "private fixture password")
	if err != nil {
		t.Fatal(err)
	}
	f.user.PasswordHash = &hash
	f.users.byID[f.user.ID] = f.user
	first := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, "/api/v1/auth/login", `{"username":"fixture_user","password":"private fixture password"}`), 200)
	requireLoginNoCookie(t, first)
	var challenge struct {
		Status            string    `json:"status"`
		Preauthentication string    `json:"preauthentication"`
		ExpiresAt         time.Time `json:"expires_at"`
	}
	if json.Unmarshal(first.Body.Bytes(), &challenge) != nil || challenge.Status != "mfa_required" || challenge.Preauthentication == "" || challenge.ExpiresAt.IsZero() {
		t.Fatal("password did not return opaque MFA-only response")
	}
	unauthorized := httptest.NewRequest(http.MethodGet, "/api/v1/users/me/sessions", nil)
	unauthorized.AddCookie(&http.Cookie{Name: "__Host-session", Value: challenge.Preauthentication, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	f.browser.sign(t, unauthorized)
	denied := boundaryServe(t, f.server, unauthorized, 401)
	requireLoginNoCookie(t, denied)
	other := newPortalTestClient(t, testPortalOrigin)
	other.validator = f.browser.validator
	complete := func(browser *portalTestClient, code string, status int) *httptest.ResponseRecorder {
		return boundaryServe(t, f.server, loginHTTPRequest(t, browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": challenge.Preauthentication, "code": code})), status)
	}
	requireLoginNoCookie(t, complete(other, "123456", 401))
	if f.factor.calls != 0 {
		t.Fatal("wrong browser reached MFA")
	}
	requireLoginNoCookie(t, complete(f.browser, "111111", 401))
	finished := complete(f.browser, "123456", 204)
	cookies := finished.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-session" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("successful MFA omitted hardened normal session cookie")
	}
	resolve := httptest.NewRequest(http.MethodGet, "/", nil)
	resolve.AddCookie(cookies[0])
	current, err := f.manager.Resolve(resolve)
	if err != nil || current.Kind != session.KindAuthenticated || current.DPoPJKT != f.browser.jkt || current.AuthVersion != 7 || current.Evidence.PrimaryMethod != session.MethodPassword || !current.Evidence.TOTP || current.Evidence.UV != session.UVNotApplicable {
		t.Fatalf("completed MFA session lost earned evidence: %v", err)
	}
	requireLoginNoCookie(t, complete(f.browser, "123456", 401))
}

func TestLoginHTTPMFAAttemptExhaustionAndDefaultOffCompletion(t *testing.T) {
	f := newLoginHTTPFixture(t, false)
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/login/code/request", "/api/v1/auth/login/code/verify"} {
		response := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, path, `{}`), 404)
		requireLoginNoCookie(t, response)
	}
	first := f.pending(t)
	for _, code := range []string{"111111", "222222", "333333", "123456"} {
		response := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": first.Preauthentication, "code": code})), 401)
		requireLoginNoCookie(t, response)
		if code == "123456" && !strings.Contains(response.Body.String(), "challenge_expired") {
			t.Fatal("exhausted challenge not terminal")
		}
	}
	if f.factor.calls != 3 {
		t.Fatal("MFA limit reset")
	}
	second := f.pending(t)
	finished := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": second.Preauthentication, "code": "123456"})), 204)
	if len(finished.Result().Cookies()) != 1 {
		t.Fatal("default-off new methods disabled existing MFA completion")
	}
}

func TestLoginHTTPFinishAndErrorClassificationNeverSetsFailureCookie(t *testing.T) {
	f := newLoginHTTPFixture(t, true)
	for _, tc := range []struct {
		err    error
		status int
		key    string
	}{
		{login.ErrInvalidCredentials, 401, "invalid_credentials"},
		{login.ErrChallengeExpired, 401, "challenge_expired"},
		{login.ErrRateLimited, 429, "rate_limited"},
		{login.ErrOutcomeUnknown, 503, "outcome_unknown"},
		{errors.New("private dependency error"), 503, "temporarily_unavailable"},
	} {
		response := httptest.NewRecorder()
		f.server.writeLoginError(response, tc.err)
		if response.Code != tc.status || !strings.Contains(response.Body.String(), tc.key) || strings.Contains(response.Body.String(), "private dependency") {
			t.Fatal("login leaked dependency details or conflated uncertainty")
		}
		requireLoginNoCookie(t, response)
	}
	for _, result := range []login.Result{{}, {Preauthentication: "opaque"}, {Issue: &session.IssueParams{}, Preauthentication: "opaque", ExpiresAt: time.Now()}} {
		response := httptest.NewRecorder()
		f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), result)
		if response.Code != 503 {
			t.Fatal("invalid or dual-authority result issued session")
		}
		requireLoginNoCookie(t, response)
	}
}

type loginHTTPContacts struct {
	proof  *contactproof.Evidence
	onRead func()
}

func (c *loginHTTPContacts) Contact(_ context.Context, _ uuid.UUID, _ string) (*contactproof.Evidence, error) {
	if c.onRead != nil {
		c.onRead()
	}
	if c.proof == nil {
		return nil, nil
	}
	proof := *c.proof
	return &proof, nil
}

type loginHTTPCodeSender struct{ code string }

func (s *loginHTTPCodeSender) SendCode(_ context.Context, _, code string, _ time.Time) error {
	s.code = code
	return nil
}

func (f *loginHTTPFixture) contactResult(t *testing.T, mfaEnabled bool) (login.Result, *loginHTTPContacts) {
	t.Helper()
	f.user.IsMfaEnabled = mfaEnabled
	f.users.byID[f.user.ID] = f.user
	client := redis.NewClient(&redis.Options{Addr: f.redis.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	pending, err := login.NewRedisPending(client)
	if err != nil {
		t.Fatal(err)
	}
	store, err := contactcode.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	sender := &loginHTTPCodeSender{}
	codes, err := contactcode.New(contactcode.Config{HashKey: []byte(strings.Repeat("k", 32))}, store, nil, sender)
	if err != nil {
		t.Fatal(err)
	}
	contacts := &loginHTTPContacts{proof: &contactproof.Evidence{AccountID: f.user.ID, Channel: contactproof.Email, Destination: "original@example.invalid"}}
	f.service, err = login.New(login.Deps{Usernames: f.names, Users: f.users, Contacts: contacts, Codes: codes, Pending: pending, TOTP: f.factor, Replay: stepup.NewMemoryReplayGuard(), Accounts: &boundaryAccounts{}, Limiter: loginHTTPLimiter{}})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.Login = f.service
	handle, _, err := f.service.RequestCode(t.Context(), "fixture_user", contactcode.ChannelEmail, f.browser.jkt, "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.service.VerifyCode(t.Context(), handle, f.browser.jkt, sender.code)
	if err != nil {
		t.Fatal(err)
	}
	return result, contacts
}

type loginHTTPIssuanceAccounts struct {
	boundaryAccounts
	locked           atomic.Bool
	entered, release chan struct{}
}

func (a *loginHTTPIssuanceAccounts) WithActive(ctx context.Context, _ string, _ int64, fn func() error) error {
	if a.entered != nil {
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a.locked.Store(true)
	defer a.locked.Store(false)
	return fn()
}

type loginHTTPCreateCounter struct {
	session.Store
	creates atomic.Int32
}

func (s *loginHTTPCreateCounter) Create(ctx context.Context, hash string, current session.Session) error {
	s.creates.Add(1)
	return s.Store.Create(ctx, hash, current)
}

func TestLoginHTTPContactInvalidationNeverIssuesSession(t *testing.T) {
	for _, mfaEnabled := range []bool{false, true} {
		phases := []string{"before_issuance", "concurrent_issuance"}
		if mfaEnabled {
			phases = append(phases, "before_mfa")
		}
		for _, phase := range phases {
			for _, change := range []string{"destination_changed", "evidence_revoked"} {
				method := "normal"
				if mfaEnabled {
					method = "mfa"
				}
				t.Run(method+"_"+phase+"_"+change, func(t *testing.T) {
					f := newLoginHTTPFixture(t, true)
					result, contacts := f.contactResult(t, mfaEnabled)
					invalidate := func() {
						if change == "destination_changed" {
							contacts.proof.Destination = "replacement@example.invalid"
						} else {
							contacts.proof = nil
						}
					}
					if mfaEnabled {
						preauth := httptest.NewRecorder()
						f.server.finishLogin(preauth, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), result)
						if preauth.Code != 200 {
							t.Fatal("contact first factor did not return MFA-only response")
						}
						requireLoginNoCookie(t, preauth)
						if phase == "before_mfa" {
							invalidate()
							response := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": result.Preauthentication, "code": "123456"})), 401)
							requireLoginNoCookie(t, response)
							return
						}
						var err error
						result, err = f.service.CompleteMFA(t.Context(), result.Preauthentication, f.browser.jkt, "123456")
						if err != nil {
							t.Fatal(err)
						}
					}
					if result.Issue == nil || result.Issue.CheckPrimaryFactor == nil {
						t.Fatal("completed contact factor omitted final issuance check")
					}
					accounts := &loginHTTPIssuanceAccounts{}
					store := &loginHTTPCreateCounter{Store: session.NewMemoryStore()}
					codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
					if err != nil {
						t.Fatal(err)
					}
					manager, err := session.NewManager(store, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: accounts})
					if err != nil {
						t.Fatal(err)
					}
					f.server.deps.SessionManager = manager
					var reads, outsideLock atomic.Int32
					contacts.onRead = func() {
						reads.Add(1)
						if !accounts.locked.Load() {
							outsideLock.Add(1)
						}
					}
					response := httptest.NewRecorder()
					if phase == "concurrent_issuance" {
						accounts.entered, accounts.release = make(chan struct{}), make(chan struct{})
						defer func() {
							select {
							case <-accounts.release:
							default:
								close(accounts.release)
							}
						}()
						ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
						defer cancel()
						done := make(chan struct{})
						go func() {
							defer close(done)
							f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil).WithContext(ctx), result)
						}()
						select {
						case <-accounts.entered:
						case <-done:
							t.Fatal("issuance bypassed final account-lock barrier")
						case <-ctx.Done():
							t.Fatal("issuance barrier timed out")
						}
						invalidate()
						close(accounts.release)
						select {
						case <-done:
						case <-ctx.Done():
							t.Fatal("final issuance did not finish")
						}
					} else {
						invalidate()
						f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), result)
					}
					if response.Code != 401 || store.creates.Load() != 0 || reads.Load() == 0 || outsideLock.Load() != 0 {
						t.Fatalf("revoked contact passed final locked issuance: status=%d creates=%d checks=%d outside_lock=%d", response.Code, store.creates.Load(), reads.Load(), outsideLock.Load())
					}
					requireLoginNoCookie(t, response)
				})
			}
		}
	}
}

func TestLoginHTTPContactIssuanceRequiresOriginalProcessLocalCheck(t *testing.T) {
	f := newLoginHTTPFixture(t, true)
	result, _ := f.contactResult(t, false)
	encoded, err := json.Marshal(result.Issue)
	if err != nil {
		t.Fatal(err)
	}
	var detached session.IssueParams
	if err := json.Unmarshal(encoded, &detached); err != nil {
		t.Fatal(err)
	}
	if detached.CheckPrimaryFactor != nil {
		t.Fatal("process-local contact check entered serialized state")
	}
	response := httptest.NewRecorder()
	f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), login.Result{Issue: &detached})
	if response.Code != 401 {
		t.Fatal("detached contact evidence issued a session without its final proof check")
	}
	requireLoginNoCookie(t, response)
}

func TestLoginHTTPUnchangedContactIssuesSessionWithoutPrivateBinding(t *testing.T) {
	for _, mfaEnabled := range []bool{false, true} {
		name := "normal"
		if mfaEnabled {
			name = "mfa"
		}
		t.Run(name, func(t *testing.T) {
			f := newLoginHTTPFixture(t, true)
			result, contacts := f.contactResult(t, mfaEnabled)
			if mfaEnabled {
				var err error
				result, err = f.service.CompleteMFA(t.Context(), result.Preauthentication, f.browser.jkt, "123456")
				if err != nil {
					t.Fatal(err)
				}
			}
			response := httptest.NewRecorder()
			f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), result)
			if response.Code != 204 || len(response.Result().Cookies()) != 1 {
				t.Fatal("unchanged contact failed normal session issuance")
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.AddCookie(response.Result().Cookies()[0])
			current, err := f.manager.Resolve(request)
			if err != nil || current.Evidence.PrimaryMethod != session.MethodContactCode || current.Evidence.TOTP != mfaEnabled {
				t.Fatalf("contact session changed earned evidence: %v", err)
			}
			encoded, err := json.Marshal(current)
			if err != nil || strings.Contains(string(encoded), contacts.proof.Destination) || strings.Contains(string(encoded), "CheckPrimaryFactor") {
				t.Fatalf("private contact binding entered normal session state: %v", err)
			}
		})
	}
}

func TestLoginAdmissionBoundsNonceAllocationAcrossAllRoutes(t *testing.T) {
	f := newLoginHTTPFixture(t, true)
	client := redis.NewClient(&redis.Options{Addr: f.redis.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := dpop.NewRedisNonceStore(client)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := dpop.NewValidator(dpop.NewMemoryReplayGuard(), nonces)
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.WebAuthnLimiter, f.server.deps.DPoPValidator = limiter, validator
	routes := []struct{ path, body string }{
		{"/api/v1/auth/login", `{"username":"fixture_user","password":"incorrect"}`},
		{"/api/v1/auth/login/code/request", `{"username":"fixture_user","channel":"email"}`},
		{"/api/v1/auth/login/code/verify", `{"challenge":"opaque","code":"123456"}`},
		{"/api/v1/auth/login/mfa", `{"preauthentication":"opaque","code":"123456"}`},
	}
	for attempt := range 120 {
		route := routes[attempt%len(routes)]
		response := boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, route.path, route.body), 401)
		if response.Header().Get(dpop.HeaderNonce) == "" {
			t.Fatal("admitted proof did not receive a nonce challenge")
		}
		requireLoginNoCookie(t, response)
	}
	before := len(f.redis.Keys())
	request := loginHTTPRequest(t, f.browser, routes[0].path, routes[0].body)
	request.RemoteAddr = "203.0.113.250:4242"
	response := boundaryServe(t, f.server, request, 429)
	if response.Header().Get(dpop.HeaderNonce) != "" || len(f.redis.Keys()) != before || f.names.calls != 0 {
		t.Fatal("quota rejection allocated nonce or resolved an account")
	}
	f.server.deps.WebAuthnLimiter = nil
	response = boundaryServe(t, f.server, loginHTTPRequest(t, f.browser, routes[0].path, routes[0].body), 503)
	if response.Header().Get(dpop.HeaderNonce) != "" {
		t.Fatal("missing production admission reached nonce allocation")
	}
}

func TestLoginHTTPProtectedFailuresCannotClearAConcurrentNewSession(t *testing.T) {
	for _, scenario := range []string{"revoked_version", "missing_cookie", "missing_session", "unknown_account_state", "unknown_store_state"} {
		t.Run(scenario, func(t *testing.T) {
			h := newBoundaryHarness(t, nil, nil)
			request := h.request(t, http.MethodGet, "/api/v1/users/me/sessions")
			want := 401
			switch scenario {
			case "revoked_version":
				h.accounts.err = session.ErrAccountIneligible
			case "missing_cookie":
				request.Header.Del("Cookie")
			case "missing_session":
				h.store.getErr = session.ErrSessionNotFound
			case "unknown_account_state":
				h.accounts.err = errors.New("account-state response unavailable")
				want = 503
			case "unknown_store_state":
				h.store.getErr = session.ErrStoreUnavailable
				want = 503
			}
			response := boundaryServe(t, h.server, request, want)
			// An old response must not delete the cookie of a newer concurrent login.
			requireLoginNoCookie(t, response)
		})
	}
}
