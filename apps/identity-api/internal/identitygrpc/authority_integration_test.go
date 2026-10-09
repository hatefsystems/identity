//go:build integration

package identitygrpc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

const (
	authorityRedirect = "https://resource.test/callback"
	authorityScope    = "openid profile objects.read offline_access"
	authorityVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	largeAuthVersion  = int64(1<<53 + 1)
)

// Observe only keys touched by this fixture's clients. Cleanup never enumerates
// the Redis database, flushes it, or guesses which keys belong to another test.
type authorityRedisKeys struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

func (*authorityRedisKeys) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *authorityRedisKeys) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.capture(cmd)
		return next(ctx, cmd)
	}
}

func (h *authorityRedisKeys) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		for _, cmd := range commands {
			h.capture(cmd)
		}
		return next(ctx, commands)
	}
}

func (h *authorityRedisKeys) capture(cmd redis.Cmder) {
	args := cmd.Args()
	var values []any
	switch cmd.Name() {
	case "eval", "evalsha":
		if len(args) >= 3 {
			n, err := strconv.Atoi(fmt.Sprint(args[2]))
			if err == nil && n >= 0 && len(args) >= 3+n {
				values = args[3 : 3+n]
			}
		}
	case "get", "getdel", "set", "hget", "hmget", "hgetall", "pttl", "type":
		if len(args) >= 2 {
			values = args[1:2]
		}
	case "del", "exists":
		values = args[1:]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, value := range values {
		key, ok := value.(string)
		// Client grants pass an unused empty-refresh script key. It is not an
		// artifact created by this fixture and must never be removed by cleanup.
		if key == "identity:v1:oauth:refresh:" {
			continue
		}
		if ok && (strings.HasPrefix(key, "identity:session:v1:") || strings.HasPrefix(key, "identity:v1:oauth:") || strings.HasPrefix(key, "dpop:v1:")) {
			h.keys[key] = struct{}{}
		}
	}
}

// Client assertion authentication is the only fixture stand-in. Issuance,
// signing, RPC verification, browser/account authority and stores are all real.
type authorityClientAuthenticator struct{ client clients.Client }

func (a authorityClientAuthenticator) Authenticate(_ context.Context, form url.Values) (clients.Client, error) {
	if form.Get("client_id") != a.client.ID {
		return clients.Client{}, clients.ErrUnknownClient
	}
	return a.client, nil
}

type authorityFixture struct {
	ctx         context.Context
	userID      uuid.UUID
	publicID    string
	machineID   string
	pools       [2]*pgxpool.Pool
	redis       [2]*redis.Client
	sessions    [2]*session.Manager
	tokens      [2]*token.Service
	refresh     [2]*token.RedisRefreshTokenStore
	clients     [2]identityv1.IdentityServiceClient
	revocations atomic.Int64
}

func newAuthorityFixture(t *testing.T, version int64) *authorityFixture {
	t.Helper()
	rawRedisURL := integrationDependency(t, "REDIS_URL")
	ctx, pool := integrationDatabase(t)
	f := &authorityFixture{ctx: ctx, userID: uuid.New(), publicID: "grpc-public-" + uuid.NewString(), machineID: uuid.NewString()}
	f.pools[0] = pool
	var err error
	f.pools[1], err = pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.pools[1].Close)
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,email,status,password_hash,auth_version)
		VALUES ($1,$2,'active','fixture-password-hash',$3)`, f.userID, f.userID.String()+"@authority.invalid", version); err != nil {
		t.Fatal(err)
	}
	options, err := redis.ParseURL(rawRedisURL)
	if err != nil {
		t.Fatal("invalid Redis integration configuration")
	}
	options.DialTimeout, options.ReadTimeout, options.WriteTimeout, options.MaxRetries = time.Second, time.Second, time.Second, -1
	options.ContextTimeoutEnabled = true
	owned := &authorityRedisKeys{keys: make(map[string]struct{})}
	for i := range f.redis {
		f.redis[i] = redis.NewClient(options)
		t.Cleanup(func() { _ = f.redis[i].Close() })
		if err := f.redis[i].Ping(ctx).Err(); err != nil {
			t.Fatal("configured Redis integration dependency is unavailable")
		}
		f.redis[i].AddHook(owned)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client := redis.NewClient(options)
		defer func() { _ = client.Close() }()
		owned.mu.Lock()
		known := make([]string, 0, len(owned.keys))
		for key := range owned.keys {
			known = append(known, key)
		}
		owned.mu.Unlock()
		if len(known) != 0 {
			if err := client.Del(cleanup, known...).Err(); err != nil {
				t.Error("could not remove this fixture's known Redis keys")
			}
		}
	})

	active, next, clientKey := proofKey(t), proofKey(t), proofKey(t)
	registeredKey, err := keys.ParsePublicJWK(clientKey.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	machine := clients.Client{ID: f.machineID, RedirectURIs: []string{authorityRedirect}, TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT,
		AllowedScopes: []string{"objects.read"}, PublicKeys: map[string]*keys.PublicKey{clientKey.KID: registeredKey}}
	registry, err := clients.NewStaticRegistry([]clients.Client{
		{ID: f.publicID, RedirectURIs: []string{authorityRedirect}, TokenEndpointAuthMethod: clients.AuthMethodNone, AllowedScopes: strings.Fields(authorityScope)},
		machine,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.clients {
		signing, err := keys.NewManager(active, next, nil)
		if err != nil {
			t.Fatal(err)
		}
		accounts := session.NewDBAccountState(f.pools[i])
		store, err := session.NewRedisStore(f.redis[i])
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := session.NewCookieCodec(session.CookieConfig{Name: session.DefaultCookieName, Secure: true, TTL: 5 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		manager, err := session.NewManager(store, cookie, session.ManagerConfig{AccountState: accounts, AbsoluteTTL: 5 * time.Minute, IdleTTL: 2 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		f.sessions[i] = manager
		codes, err := token.NewRedisCodeStore(f.redis[i])
		if err != nil {
			t.Fatal(err)
		}
		f.refresh[i], err = token.NewRedisRefreshTokenStore(f.redis[i])
		if err != nil {
			t.Fatal(err)
		}
		cfg := testConfig(t)
		queries := db.New(f.pools[i])
		f.tokens[i], err = token.NewService(token.Config{
			Issuer: testAudience, AccountState: accounts, Sessions: manager,
			RevokeUser: func(ctx context.Context, userID string) error {
				id, err := uuid.Parse(userID)
				if err != nil {
					return err
				}
				if err := queries.RevokeUserCredentials(ctx, id); err != nil {
					return err
				}
				f.revocations.Add(1)
				return manager.RevokeAllForUser(ctx, userID)
			},
		}, signing, registry, codes, f.refresh[i], authorityClientAuthenticator{machine}, nil, cfg.Logger)
		if err != nil {
			t.Fatal(err)
		}
		validator, err := token.NewAccessValidator(token.AccessValidatorConfig{
			Issuer: testAudience, Keys: signing, Clients: registry, Grants: f.refresh[i], Sessions: manager, Accounts: accounts,
		})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Validator, cfg.Queries, cfg.DPoP = validator, queries, redisDPoP(t, f.redis[i])
		f.clients[i] = newMTLSHarness(t, cfg, allGrants(testCaller)).client(t, testCaller)
	}
	return f
}

func (f *authorityFixture) browser(t *testing.T, replica int, version int64) session.Session {
	t.Helper()
	value, err := f.sessions[replica].IssueContext(f.ctx, httptest.NewRecorder(), session.IssueParams{
		UserID: f.userID.String(), AuthVersion: version, AuthVersionSet: true, Kind: session.KindAuthenticated,
	})
	if err != nil {
		t.Fatalf("issue authenticated browser session: %v", err)
	}
	return value
}

func (f *authorityFixture) codeData(browser session.Session) token.AuthorizationCodeData {
	digest := sha256.Sum256([]byte(authorityVerifier))
	return token.AuthorizationCodeData{UserID: browser.UserID, SessionID: browser.ID,
		AuthVersion: browser.AuthVersion, AuthVersionSet: browser.AuthVersionSet, ClientID: f.publicID,
		RedirectURI: authorityRedirect, Scope: authorityScope, Nonce: uuid.NewString(),
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:])}
}

func (f *authorityFixture) code(t *testing.T, replica int, browser session.Session) url.Values {
	t.Helper()
	// This is the internal post-authentication/consent issuance boundary. There
	// is intentionally no invented HTTP login or consent route in this fixture.
	code, err := f.tokens[replica].IssueCodeContext(f.ctx, f.codeData(browser))
	if err != nil {
		t.Fatalf("issue code from captured browser authority: %v", err)
	}
	return url.Values{"grant_type": {token.GrantAuthorizationCode}, "client_id": {f.publicID}, "redirect_uri": {authorityRedirect}, "code": {code}, "code_verifier": {authorityVerifier}}
}

func (f *authorityFixture) exchange(t *testing.T, replica int, ctx context.Context, form url.Values) *token.Response {
	t.Helper()
	response, err := f.tokens[replica].Exchange(ctx, form)
	if err != nil || response == nil || response.AccessToken == "" {
		t.Fatalf("real token exchange failed: %v", err)
	}
	return response
}

func refreshForm(response *token.Response) url.Values {
	return url.Values{"grant_type": {token.GrantRefreshToken}, "client_id": {response.ClientID}, "refresh_token": {response.RefreshToken}}
}

type issuedAuthorityClaims struct {
	GrantID     string `json:"grant_id"`
	SessionID   string `json:"sid"`
	AuthVersion *int64 `json:"auth_version"`
	ExpiresAt   int64  `json:"exp"`
}

// Decode only to locate fixture-owned authority and assert exact integers. The
// actual RPC always uses AccessValidator for independent signature verification.
func issuedClaims(t *testing.T, compact string) issuedAuthorityClaims {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatal("issuer returned a malformed compact token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal("issuer returned malformed claims encoding")
	}
	var claims issuedAuthorityClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal("issuer returned malformed or inexact integer claims")
	}
	return claims
}

func assertIssuedPrincipal(t *testing.T, got *identityv1.ValidateTokenResponse, issued *token.Response, principal identityv1.PrincipalType, subject string) {
	t.Helper()
	want := &identityv1.ValidateTokenResponse{Active: true, PrincipalType: principal, Subject: subject, ClientId: issued.ClientID,
		Scopes: strings.Fields(issued.Scope), ExpiresAt: issuedClaims(t, issued.AccessToken).ExpiresAt}
	if principal == identityv1.PrincipalType_PRINCIPAL_TYPE_USER {
		want.UserId = subject
	}
	if !proto.Equal(got, want) {
		t.Fatalf("unexpected real validated principal: got=%v want=%v", got, want)
	}
}

func (f *authorityFixture) active(t *testing.T, replica int, issued *token.Response, principal identityv1.PrincipalType, subject string) {
	t.Helper()
	req := validRequest()
	req.AccessToken, req.AuthorizationScheme = issued.AccessToken, issued.TokenType
	response, err := f.clients[replica].ValidateToken(f.ctx, req)
	if err != nil {
		t.Fatalf("real access validation failed: %v", err)
	}
	assertIssuedPrincipal(t, response, issued, principal, subject)
}

func (f *authorityFixture) inactive(t *testing.T, replica int, compact string) {
	t.Helper()
	req := validRequest()
	req.AccessToken = compact
	response, err := f.clients[replica].ValidateToken(f.ctx, req)
	if err != nil {
		t.Fatalf("inactive authority became a dependency failure: %v", err)
	}
	assertNoClaims(t, response)
	if !proto.Equal(response, &identityv1.ValidateTokenResponse{}) {
		t.Fatal("inactive authority leaked a proof outcome or challenge")
	}
}

func assertInvalidGrant(t *testing.T, response *token.Response, err error) {
	t.Helper()
	var oauth *token.Error
	if response != nil || !errors.As(err, &oauth) || oauth.Code != token.ErrCodeInvalidGrant || oauth.Status != 400 {
		t.Fatalf("expected a legitimate invalid_grant, got %v", err)
	}
}

func TestTokenAuthorityCrossReplicaExchangeIntegration(t *testing.T) {
	for _, version := range []int64{0, largeAuthVersion} {
		t.Run(strconv.FormatInt(version, 10), func(t *testing.T) {
			f := newAuthorityFixture(t, version)
			browser := f.browser(t, 0, version)
			before, err := f.sessions[1].LookupByID(f.ctx, browser.UserID, browser.ID)
			if err != nil || !before.AuthVersionSet || before.AuthVersion != version {
				t.Fatalf("captured version did not survive Redis session storage: %v", err)
			}
			form := f.code(t, 0, browser)
			issued := f.exchange(t, 1, f.ctx, form)
			claims := issuedClaims(t, issued.AccessToken)
			if claims.AuthVersion == nil || *claims.AuthVersion != version || claims.SessionID != browser.ID || claims.ExpiresAt > browser.AbsoluteExpiry.Unix() {
				t.Fatal("issuer changed the captured version/session or exceeded browser lifetime")
			}
			f.active(t, 0, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
			replayed, err := f.tokens[0].Exchange(f.ctx, form)
			assertInvalidGrant(t, replayed, err)
			rotated := f.exchange(t, 0, f.ctx, refreshForm(issued))
			f.active(t, 1, rotated, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
			f.active(t, 1, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
			old, err := f.refresh[1].Get(f.ctx, token.HashSecret(issued.RefreshToken))
			if err != nil || old.Status != token.StatusRotated || !old.AuthVersionSet || old.AuthVersion != version {
				t.Fatalf("rotation lost exact captured version or consumed marker: %v", err)
			}
			grant, err := f.refresh[1].GetGrant(f.ctx, claims.GrantID)
			if err != nil || grant.AuthVersion != version || !grant.AuthVersionSet || !grant.ExpiresAt.Equal(before.AbsoluteExpiry) {
				t.Fatalf("grant lifetime/version drift: %v", err)
			}
			after, err := f.sessions[0].LookupByID(f.ctx, browser.UserID, browser.ID)
			if err != nil || !after.IdleExpiry.Equal(before.IdleExpiry) || !after.LastSeenAt.Equal(before.LastSeenAt) {
				t.Fatalf("validation or refresh silently touched browser lifetime: %v", err)
			}
			machine := f.exchange(t, 0, f.ctx, url.Values{"grant_type": {token.GrantClientCredentials}, "client_id": {f.machineID}, "scope": {"objects.read"}})
			if machine.RefreshToken != "" || issuedClaims(t, machine.AccessToken).AuthVersion != nil {
				t.Fatal("machine credentials acquired user authority or a refresh token")
			}
			f.active(t, 1, machine, identityv1.PrincipalType_PRINCIPAL_TYPE_CLIENT, f.machineID)
		})
	}
}

func TestTokenAuthorityBrowserRevocationIntegration(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	first, second := f.browser(t, 0, 0), f.browser(t, 1, 0)
	one := f.exchange(t, 1, f.ctx, f.code(t, 0, first))
	two := f.exchange(t, 0, f.ctx, f.code(t, 1, second))
	f.active(t, 0, one, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	removed, err := f.sessions[1].RevokeByID(f.ctx, f.userID.String(), first.ID)
	if err != nil || !removed {
		t.Fatalf("cross-replica browser revocation failed: %v", err)
	}
	f.inactive(t, 0, one.AccessToken)
	f.inactive(t, 1, one.AccessToken)
	refreshed, err := f.tokens[0].Exchange(f.ctx, refreshForm(one))
	assertInvalidGrant(t, refreshed, err)
	f.active(t, 1, two, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	f.exchange(t, 1, f.ctx, refreshForm(two))
	if f.revocations.Load() != 0 {
		t.Fatal("single-browser revocation incorrectly invalidated the whole account")
	}
}

func TestTokenAuthorityRefreshReuseInvalidatesAccountIntegration(t *testing.T) {
	f := newAuthorityFixture(t, largeAuthVersion)
	first, second := f.browser(t, 0, largeAuthVersion), f.browser(t, 1, largeAuthVersion)
	one := f.exchange(t, 1, f.ctx, f.code(t, 0, first))
	two := f.exchange(t, 0, f.ctx, f.code(t, 1, second))
	rotated := f.exchange(t, 0, f.ctx, refreshForm(one))
	f.active(t, 1, rotated, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	replayed, err := f.tokens[1].Exchange(ctx, refreshForm(one))
	assertInvalidGrant(t, replayed, err)
	state, err := db.New(f.pools[0]).GetAccountAuthState(f.ctx, f.userID)
	if err != nil || state.AuthVersion != largeAuthVersion+1 || f.revocations.Load() != 1 {
		t.Fatalf("reuse did not establish one exact primary revocation barrier: %v", err)
	}
	for _, browser := range []session.Session{first, second} {
		if _, err := f.sessions[0].LookupByID(f.ctx, browser.UserID, browser.ID); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("reuse left browser authority alive: %v", err)
		}
	}
	for _, issued := range []*token.Response{one, rotated, two} {
		for replica := range f.clients {
			f.inactive(t, replica, issued.AccessToken)
		}
		grant, err := f.refresh[0].GetGrant(f.ctx, issuedClaims(t, issued.AccessToken).GrantID)
		if err != nil || grant.Status != token.StatusRevoked || grant.AuthVersion != largeAuthVersion {
			t.Fatalf("reuse did not revoke every family while preserving its captured version: %v", err)
		}
	}
	fresh := f.browser(t, 0, state.AuthVersion)
	reauthenticated := f.exchange(t, 1, f.ctx, f.code(t, 0, fresh))
	f.active(t, 0, reauthenticated, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	f.inactive(t, 0, one.AccessToken)
	stale, err := f.tokens[1].IssueCodeContext(f.ctx, f.codeData(first))
	if stale != "" || !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatalf("old browser version was silently restamped after reuse: %v", err)
	}
}

// Synchronize only the first real Redis refresh reads so both services observe
// the active secret before contending on the primary account lock. No backing
// result, token, or validation decision is fabricated by this scheduling hook.
type refreshReadBarrier struct {
	key      string
	ready    chan struct{}
	arrivals atomic.Int64
}

func (*refreshReadBarrier) DialHook(next redis.DialHook) redis.DialHook { return next }

func (*refreshReadBarrier) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func (b *refreshReadBarrier) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		args := cmd.Args()
		if err != nil || cmd.Name() != "get" || len(args) < 2 || args[1] != b.key {
			return err
		}
		if b.arrivals.Add(1) == 2 {
			close(b.ready)
		}
		select {
		case <-b.ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestTokenAuthorityConcurrentRefreshReuseIntegration(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	first, second := f.browser(t, 0, 0), f.browser(t, 1, 0)
	one := f.exchange(t, 1, f.ctx, f.code(t, 0, first))
	two := f.exchange(t, 0, f.ctx, f.code(t, 1, second))
	barrier := &refreshReadBarrier{key: "identity:v1:oauth:refresh:" + token.HashSecret(one.RefreshToken), ready: make(chan struct{})}
	for _, client := range f.redis {
		client.AddHook(barrier)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	type result struct {
		response *token.Response
		err      error
	}
	results := make(chan result, len(f.tokens))
	for _, service := range f.tokens {
		go func() {
			response, err := service.Exchange(ctx, refreshForm(one))
			results <- result{response, err}
		}()
	}
	var winner *token.Response
	for range f.tokens {
		select {
		case r := <-results:
			if r.err == nil {
				if winner != nil || r.response == nil {
					t.Fatal("concurrent refresh produced multiple successes or no token")
				}
				winner = r.response
			} else {
				assertInvalidGrant(t, r.response, r.err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent refresh cleanup deadlocked under account authority")
		}
	}
	if winner == nil || f.revocations.Load() != 1 {
		t.Fatal("concurrent refresh did not produce one rotation and one account-wide invalidation")
	}
	state, err := db.New(f.pools[0]).GetAccountAuthState(f.ctx, f.userID)
	if err != nil || state.AuthVersion != 1 {
		t.Fatalf("concurrent reuse did not commit its primary revocation barrier: %v", err)
	}
	for _, issued := range []*token.Response{one, winner, two} {
		for replica := range f.clients {
			f.inactive(t, replica, issued.AccessToken)
		}
	}
}

func TestTokenAuthoritySuspendReactivateIntegration(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	browser := f.browser(t, 0, 0)
	issued := f.exchange(t, 1, f.ctx, f.code(t, 0, browser))
	pendingCode := f.code(t, 0, browser)
	f.active(t, 0, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	for _, storedStatus := range []string{"suspended", "active"} {
		if _, err := f.pools[1].Exec(f.ctx, "UPDATE users SET status=$2 WHERE id=$1", f.userID, storedStatus); err != nil {
			t.Fatal(err)
		}
		for replica := range f.clients {
			f.inactive(t, replica, issued.AccessToken)
		}
	}
	// Redis authority deliberately remains present. The primary account version,
	// not cleanup timing or a local revocation cache, must reject the old JWT.
	grant, err := f.refresh[0].GetGrant(f.ctx, issuedClaims(t, issued.AccessToken).GrantID)
	if err != nil || grant.Status != token.StatusActive {
		t.Fatalf("fixture no longer isolates the primary account barrier: %v", err)
	}
	if _, err := f.sessions[1].LookupByID(f.ctx, browser.UserID, browser.ID); err != nil {
		t.Fatal("fixture browser disappeared instead of testing account authority")
	}
	refreshed, err := f.tokens[0].Exchange(f.ctx, refreshForm(issued))
	assertInvalidGrant(t, refreshed, err)
	exchanged, err := f.tokens[1].Exchange(f.ctx, pendingCode)
	assertInvalidGrant(t, exchanged, err)
	state, err := db.New(f.pools[0]).GetAccountAuthState(f.ctx, f.userID)
	if err != nil || state.AuthVersion != 2 {
		t.Fatalf("suspend/reactivate version transitions: %v", err)
	}
	if _, err := f.sessions[0].IssueContext(f.ctx, httptest.NewRecorder(), session.IssueParams{UserID: f.userID.String(), AuthVersion: 0, AuthVersionSet: true}); !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatalf("stale authentication version was restamped: %v", err)
	}
	fresh := f.browser(t, 1, state.AuthVersion)
	reauthenticated := f.exchange(t, 0, f.ctx, f.code(t, 1, fresh))
	f.active(t, 1, reauthenticated, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	f.inactive(t, 1, issued.AccessToken)
}

func TestTokenAuthorityRequiresCapturedNormalSessionIntegration(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	browser := f.browser(t, 0, 0)
	for _, missing := range []string{"captured version", "session ID"} {
		data := f.codeData(browser)
		if missing == "captured version" {
			data.AuthVersionSet = false
		} else {
			data.SessionID = ""
		}
		code, err := f.tokens[1].IssueCodeContext(f.ctx, data)
		if code != "" || !errors.Is(err, session.ErrAccountIneligible) {
			t.Fatalf("code issuance accepted missing %s: %v", missing, err)
		}
	}
	restricted, err := f.sessions[0].IssueContext(f.ctx, httptest.NewRecorder(), session.IssueParams{
		UserID: f.userID.String(), AuthVersion: 0, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, err := f.tokens[1].IssueCodeContext(f.ctx, f.codeData(restricted))
	if code != "" || !errors.Is(err, session.ErrAccountIneligible) {
		t.Fatalf("restricted recovery session became OAuth authority: %v", err)
	}
}

func TestTokenAuthorityBoundDPoPRoundtripIntegration(t *testing.T) {
	f := newAuthorityFixture(t, 0)
	key := proofKey(t)
	browser := f.browser(t, 0, 0)
	// The HTTP adapter verifies this proof before entering token.Service. Its
	// HTTP proof-validation tests are separate; this explicit verified context
	// exercises the real internal issuance boundary, not a synthetic JWT.
	verified := dpop.WithProof(f.ctx, &dpop.Proof{JKT: key.KID})
	issued := f.exchange(t, 1, verified, f.code(t, 0, browser))
	if issued.TokenType != token.TokenTypeDPoP {
		t.Fatal("verified issuance context did not produce a bound token")
	}
	resourceRequest := func(nonce string) *identityv1.ValidateTokenRequest {
		claims := proofClaims(nonce)
		claims["ath"] = dpop.AccessTokenHash(issued.AccessToken)
		req := proofRequest(signProof(t, key, claims))
		req.AccessToken = issued.AccessToken
		return req
	}
	challenge, err := f.clients[0].ValidateToken(f.ctx, resourceRequest(""))
	assertProofOutcome(t, challenge, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	req := resourceRequest(challenge.DpopNonce)
	response, err := f.clients[1].ValidateToken(f.ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	assertIssuedPrincipal(t, response, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
	replayed, err := f.clients[0].ValidateToken(f.ctx, req)
	assertProofOutcome(t, replayed, err, identityv1.DpopOutcome_DPOP_OUTCOME_USE_NONCE)
	wrongKey := dpop.WithProof(f.ctx, &dpop.Proof{JKT: proofKey(t).KID})
	for _, ctx := range []context.Context{f.ctx, wrongKey} {
		response, err := f.tokens[0].Exchange(ctx, refreshForm(issued))
		assertInvalidGrant(t, response, err)
	}
	rotated := f.exchange(t, 0, verified, refreshForm(issued))
	record, err := f.refresh[1].Get(f.ctx, token.HashSecret(rotated.RefreshToken))
	if err != nil || record.DPoPJKT != key.KID || f.revocations.Load() != 0 {
		t.Fatalf("invalid proof burned refresh authority or changed its key: %v", err)
	}
	if _, err := f.sessions[1].RevokeByID(f.ctx, browser.UserID, browser.ID); err != nil {
		t.Fatal(err)
	}
	response, err = f.clients[0].ValidateToken(f.ctx, resourceRequest(replayed.DpopNonce))
	if err != nil || !proto.Equal(response, &identityv1.ValidateTokenResponse{}) {
		t.Fatalf("revoked bound authority issued claims/challenge: %v", err)
	}
}

func TestTokenAuthorityStateFailuresIntegration(t *testing.T) {
	for _, failure := range []string{"missing grant", "corrupt grant", "missing account", "Redis connection", "primary DB connection"} {
		t.Run(failure, func(t *testing.T) {
			f := newAuthorityFixture(t, 0)
			browser := f.browser(t, 0, 0)
			issued := f.exchange(t, 1, f.ctx, f.code(t, 0, browser))
			f.active(t, 0, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
			key := "identity:v1:oauth:grant:" + issuedClaims(t, issued.AccessToken).GrantID
			failingReplica := 0
			switch failure {
			case "missing grant":
				if err := f.redis[0].Del(f.ctx, key).Err(); err != nil {
					t.Fatal(err)
				}
				f.inactive(t, 1, issued.AccessToken)
				return
			case "corrupt grant":
				if err := f.redis[0].Set(f.ctx, key, `{"corrupt":true}`, time.Minute).Err(); err != nil {
					t.Fatal(err)
				}
			case "missing account":
				if _, err := f.pools[0].Exec(f.ctx, "DELETE FROM users WHERE id=$1", f.userID); err != nil {
					t.Fatal(err)
				}
				f.inactive(t, 1, issued.AccessToken)
				return
			case "Redis connection":
				if err := f.redis[0].Close(); err != nil {
					t.Fatal(err)
				}
				f.active(t, 1, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
			case "primary DB connection":
				machine := f.exchange(t, 0, f.ctx, url.Values{"grant_type": {token.GrantClientCredentials}, "client_id": {f.machineID}, "scope": {"objects.read"}})
				f.pools[1].Close()
				failingReplica = 1
				f.active(t, 0, issued, identityv1.PrincipalType_PRINCIPAL_TYPE_USER, f.userID.String())
				f.active(t, 1, machine, identityv1.PrincipalType_PRINCIPAL_TYPE_CLIENT, f.machineID)
			}
			req := validRequest()
			req.AccessToken = issued.AccessToken
			response, err := f.clients[failingReplica].ValidateToken(f.ctx, req)
			if response != nil || status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), issued.AccessToken) || strings.Contains(err.Error(), f.userID.String()) {
				t.Fatalf("real authority dependency was not a sanitized Unavailable: %v", err)
			}
		})
	}
}
