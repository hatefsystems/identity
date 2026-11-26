//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/login"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Only fixture key names change. Production Lua, clocks, payloads, quotas and
// atomicity run against real Redis; cleanup cannot touch another fixture's keys.
type loginRedisNamespace struct {
	prefix, fault string
	calls         atomic.Int32
}

func (*loginRedisNamespace) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *loginRedisNamespace) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		args := cmd.Args()
		indexes := []int{}
		switch cmd.Name() {
		case "eval", "evalsha":
			n, err := strconv.Atoi(fmt.Sprint(args[2]))
			if err != nil {
				return err
			}
			for i := 3; i < 3+n; i++ {
				indexes = append(indexes, i)
			}
		case "set", "get", "hget", "hset", "hgetall", "pttl", "pexpire", "zcard":
			indexes = append(indexes, 1)
		case "del", "exists":
			for i := 1; i < len(args); i++ {
				indexes = append(indexes, i)
			}
		}
		for _, i := range indexes {
			if key, ok := args[i].(string); ok && !strings.HasPrefix(key, h.prefix) {
				args[i] = h.prefix + key
			}
		}
		lose := h.fault == "replay" && cmd.Name() == "set" && strings.Contains(fmt.Sprint(args[1]), "stepup:") ||
			h.fault == "consume" && cmd.Name() == "eval" && len(args) > 3 && strings.Contains(fmt.Sprint(args[3]), "login:preauth:v1:") && args[len(args)-1] == "consume"
		if err := next(ctx, cmd); err != nil {
			return err
		}
		if lose {
			h.calls.Add(1)
			return errors.New("confirmed mutation response lost")
		}
		return nil
	}
}
func (*loginRedisNamespace) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

type loginDeliveryCapture struct {
	mu    sync.Mutex
	code  string
	calls int
	err   error
}

func (c *loginDeliveryCapture) send(code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.code = code
	c.calls++
	return c.err
}
func (c *loginDeliveryCapture) last() string { c.mu.Lock(); defer c.mu.Unlock(); return c.code }

type loginEmailCapture struct{ *loginDeliveryCapture }

func (c loginEmailCapture) SendCode(_ context.Context, _, code string, _ time.Time) error {
	return c.send(code)
}

type loginSMSCapture struct{ *loginDeliveryCapture }

func (c loginSMSCapture) SendCode(_ context.Context, _, code string) error { return c.send(code) }

type loginCodeCaptureStore struct {
	contactcode.Store
	record contactcode.Record
}

func (s *loginCodeCaptureStore) Reserve(ctx context.Context, rec contactcode.Record, budgets []contactcode.Budget, lock string, capacity int) error {
	s.record = rec
	return s.Store.Reserve(ctx, rec, budgets, lock, capacity)
}

type realLoginFixture struct {
	ctx           context.Context
	pool          *pgxpool.Pool
	client        *redis.Client
	sessionClient *redis.Client
	hook          *loginRedisNamespace
	cipher        contactproof.Cipher
	names         *username.Store
	pending       *login.RedisPending
	replay        *stepup.RedisReplayGuard
	accounts      *session.DBAccountState
	factor        *mfa.Service
	manager       *session.Manager
	service       *login.Service
	codeStore     *loginCodeCaptureStore
	delivery      *loginDeliveryCapture
	browser       *portalTestClient
	server        *Server
	index         int
}

func newRealLoginFixture(t *testing.T, emailEnabled, smsEnabled bool) *realLoginFixture {
	t.Helper()
	ctx, pool, _ := phoneIntegrationServices(t)
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x79}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit test-only policy installation, never a production policy default.
	normalizer, err := username.New(username.Policy{ID: uuid.New(), Normalization: username.NormalizationV1, MinLetters: 1, MaxCodePoints: 40, Folds: []username.Fold{{From: "\u064a", To: "\u06cc"}, {From: "\u0643", To: "\u06a9"}, {From: "\u0624", To: "\u0648"}, {From: "\u0626", To: "\u06cc"}}, ReservedNames: []string{}}, `[\x{0621}-\x{06CC}]+`, bytes.Repeat([]byte{0x51}, 32), "login-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	a := normalizer.Authority()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO username_policy_artifacts(policy_id,fingerprint,artifact) VALUES($1,$2,$3)`, []any{a.PolicyID, a.Fingerprint[:], normalizer.CanonicalArtifact()}},
		{`INSERT INTO username_lookup_keys(key_id,key_verifier) VALUES($1,$2)`, []any{a.KeyID, a.KeyVerifier[:]}},
		{`UPDATE username_active_policy SET policy_id=$1,fingerprint=$2,epoch=1,key_id=$3,key_verifier=$4,admission_state='open' WHERE singleton`, []any{a.PolicyID, a.Fingerprint[:], a.KeyID, a.KeyVerifier[:]}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	names, err := username.NewStore(pool, cipher, normalizer)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := redis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		t.Fatal("invalid owned Redis configuration")
	}
	opts.MaxRetries, opts.ContextTimeoutEnabled = -1, true
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("owned Redis unavailable")
	}
	hook := &loginRedisNamespace{prefix: "login_fixture:" + uuid.NewString() + ":"}
	client.AddHook(hook)
	// Session Lua reconstructs fixed keys, so sessions and cleanup bypass the hook.
	cleanupClient := redis.NewClient(opts)
	t.Cleanup(func() {
		defer func() { _ = cleanupClient.Close() }()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var cursor uint64
		for {
			keys, next, err := cleanupClient.Scan(cleanup, cursor, hook.prefix+"*", 100).Result()
			if err != nil {
				t.Error("owned login Redis cleanup scan failed")
				return
			}
			if len(keys) > 0 {
				if err := cleanupClient.Del(cleanup, keys...).Err(); err != nil {
					t.Error("owned login Redis cleanup failed")
					return
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		keys, _, err := cleanupClient.Scan(cleanup, 0, hook.prefix+"*", 100).Result()
		if err != nil || len(keys) != 0 {
			t.Error("owned login Redis teardown incomplete")
		}
	})
	pending, err := login.NewRedisPending(client)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := stepup.NewRedisReplayGuard(client, bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.NewRedisLimiter(client)
	if err != nil {
		t.Fatal(err)
	}
	accounts := session.NewDBAccountState(pool)
	factor, err := mfa.New(mfa.Config{}, db.New(pool), cipher, mfa.WithTransacter(pool))
	if err != nil {
		t.Fatal(err)
	}
	store, err := session.NewRedisStore(cleanupClient)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, AccountState: accounts})
	if err != nil {
		t.Fatal(err)
	}
	delivery := &loginDeliveryCapture{}
	var sms *smsotp.Service
	if smsEnabled {
		users, err := smsotp.NewUserStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		otps, err := smsotp.NewRedisOTPStore(client)
		if err != nil {
			t.Fatal(err)
		}
		sms, err = smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{0x23}, 32), PerPhonePerMinute: 5, PerPhonePerHour: 20, PerSubnetPerHour: 100}, users, cipher, phoneFakeIndexer{}, limiter, otps, loginSMSCapture{delivery})
		if err != nil {
			t.Fatal(err)
		}
	}
	var email contactcode.Sender
	if emailEnabled {
		email = loginEmailCapture{delivery}
	}
	redisCodes, err := contactcode.NewRedisStore(client)
	if err != nil {
		t.Fatal(err)
	}
	codeStore := &loginCodeCaptureStore{Store: redisCodes}
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{0x33}, 32), PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}, codeStore, sms, email)
	if err != nil {
		t.Fatal(err)
	}
	service, err := login.New(login.Deps{Usernames: names, Users: db.New(pool), Contacts: login.DBContacts{Queries: db.New(pool), Cipher: cipher}, Codes: codes, Pending: pending, TOTP: factor, Replay: replay, Accounts: accounts, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	browser := newPortalTestClient(t, testPortalOrigin)
	srv := New(config.Config{Environment: "production", PortalOrigin: browser.origin}, slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{Login: service, PasswordLoginEnabled: true, SessionManager: manager, DPoPValidator: browser.validator, WebAuthnLimiter: limiter})
	return &realLoginFixture{ctx: ctx, pool: pool, client: client, sessionClient: cleanupClient, hook: hook, cipher: cipher, names: names, pending: pending, replay: replay, accounts: accounts, factor: factor, manager: manager, service: service, codeStore: codeStore, delivery: delivery, browser: browser, server: srv}
}

type realLoginAccount struct {
	user                            db.User
	name, secret, totpSecret, phone string
}

func (f *realLoginFixture) account(t *testing.T, credential string, mfaEnabled bool) realLoginAccount {
	t.Helper()
	f.index++
	name := strings.Repeat("\u0633", f.index) + "\u0639\u0644\u06cc"
	email := uuid.NewString() + "@login.invalid"
	secret := "private fixture password"
	var hash *string
	if credential != "passkey_only" {
		value, err := password.HashContext(f.ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		hash = &value
	}
	user, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: &email, PasswordHash: hash, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id := user.ID.String()
		if err := f.manager.RevokeAllForUser(cleanup, id); err != nil {
			t.Error("owned login session revocation failed")
			return
		}
		// Revocation retains negative ID markers; remove only this UUID subject's.
		prefix := "identity:session:v1:id:" + strconv.Itoa(len(id)) + ":" + id + ":"
		var cursor uint64
		for {
			keys, next, err := f.sessionClient.Scan(cleanup, cursor, prefix+"*", 100).Result()
			if err != nil {
				t.Error("owned login session cleanup scan failed")
				return
			}
			if len(keys) > 0 {
				if err := f.sessionClient.Del(cleanup, keys...).Err(); err != nil {
					t.Error("owned login session marker cleanup failed")
					return
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		keys, _, err := f.sessionClient.Scan(cleanup, 0, prefix+"*", 100).Result()
		owner := "identity:session:v1:user:" + strconv.Itoa(len(id)) + ":" + id
		remaining, ownerErr := f.sessionClient.Exists(cleanup, owner).Result()
		if err != nil || len(keys) != 0 || ownerErr != nil || remaining != 0 {
			t.Error("owned login session teardown incomplete")
		}
	})
	if credential != "password_unclaimed" {
		value, err := f.names.Normalizer().Normalize(name)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		if err := f.names.Assign(f.ctx, tx, user.ID, user.AuthVersion, value); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if credential != "password_only" && credential != "password_unclaimed" {
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)`, []byte(uuid.NewString()), user.ID, []byte("credential-presence-fixture"), uuid.Nil); err != nil {
			t.Fatal(err)
		}
	}
	phone := fmt.Sprintf("+98912000%04d", f.index)
	f.contact(t, user.ID, contactproof.Email, email)
	f.contact(t, user.ID, contactproof.Phone, phone)
	totpSecret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if mfaEnabled {
		blob, err := f.cipher.Encrypt(f.ctx, []byte(totpSecret))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(f.ctx, `UPDATE users SET is_mfa_enabled=true,mfa_totp_secret_encrypted=$2 WHERE id=$1`, user.ID, blob); err != nil {
			t.Fatal(err)
		}
	}
	user, err = db.New(f.pool).GetUserByID(f.ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return realLoginAccount{user, name, secret, totpSecret, phone}
}

func (f *realLoginFixture) contact(t *testing.T, id uuid.UUID, channel, destination string) {
	t.Helper()
	method := contactproof.EmailLink
	if channel == contactproof.Phone {
		method = contactproof.SMSOTP
		blob, err := f.cipher.Encrypt(f.ctx, []byte(destination))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(f.ctx, `UPDATE users SET phone_encrypted=$2,phone_blind_index=$3 WHERE id=$1`, id, blob, phoneFakeIndexer{}.Compute(destination)); err != nil {
			t.Fatal(err)
		}
	}
	blob, err := contactproof.Seal(f.ctx, f.cipher, id, channel, destination, method, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO contact_verification_evidence(user_id,channel,evidence_encrypted) VALUES($1,$2,$3) ON CONFLICT(user_id,channel) DO UPDATE SET evidence_encrypted=EXCLUDED.evidence_encrypted`, id, channel, blob); err != nil {
		t.Fatal(err)
	}
}

func (f *realLoginFixture) request(t *testing.T, browser *portalTestClient, path string, body map[string]string, want int) *httptest.ResponseRecorder {
	t.Helper()
	return boundaryServe(t, f.server, loginHTTPRequest(t, browser, path, loginHTTPBody(t, body)), want)
}

func (f *realLoginFixture) session(t *testing.T, response *httptest.ResponseRecorder) session.Session {
	t.Helper()
	cookies := response.Result().Cookies()
	if response.Code != 204 || len(cookies) != 1 || cookies[0].Name != "__Host-session" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("real login did not issue exactly one hardened session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])
	current, err := f.manager.Resolve(req)
	if err != nil || current.Kind != session.KindAuthenticated || current.DPoPJKT != f.browser.jkt {
		t.Fatalf("real session/browser binding: %v", err)
	}
	return current
}

func (f *realLoginFixture) preauth(t *testing.T, a realLoginAccount, method string) login.Result {
	t.Helper()
	uv := session.UVNotApplicable
	if method == session.MethodPasskey {
		uv = session.UVVerified
	}
	// Prepare consumes previously earned first-factor evidence; it does not verify
	// an assertion. Real WebAuthn ceremony/browser proof has its own suites.
	result, err := f.service.Prepare(f.ctx, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: a.user.AuthVersion, AuthVersionSet: true, DPoPJKT: f.browser.jkt, Evidence: session.Evidence{PrimaryMethod: method, UV: uv, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
	if err != nil || result.Issue != nil || result.Preauthentication == "" {
		t.Fatalf("real preauthentication: %v", err)
	}
	return result
}

func realLoginCode(t *testing.T, a realLoginAccount) string {
	t.Helper()
	code, err := totp.GenerateCode(a.totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func (f *realLoginFixture) complete(t *testing.T, handle, code string, want int) *httptest.ResponseRecorder {
	t.Helper()
	return f.request(t, f.browser, "/api/v1/auth/login/mfa", map[string]string{"preauthentication": handle, "code": code}, want)
}

func TestLoginRealServicesCredentialAndContactMatrixIntegration(t *testing.T) {
	f := newRealLoginFixture(t, true, true)
	var accounts []realLoginAccount
	for _, credential := range []string{"password_only", "passkey_only", "dual"} {
		t.Run(credential, func(t *testing.T) {
			a := f.account(t, credential, false)
			accounts = append(accounts, a)
			want := 204
			if credential == "passkey_only" {
				want = 401
			}
			response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, want)
			if want == 401 {
				requireLoginNoCookie(t, response)
			} else {
				current := f.session(t, response)
				if current.UserID != a.user.ID.String() || current.Evidence.PrimaryMethod != session.MethodPassword || current.Evidence.TOTP || current.Evidence.AdminEligible() {
					t.Fatal("password configuration acquired wrong authority")
				}
			}
			for _, channel := range []string{contactcode.ChannelEmail, contactcode.ChannelSMS} {
				requested := f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": a.name, "channel": channel}, 202)
				requireLoginNoCookie(t, requested)
				var challenge struct {
					Challenge string    `json:"challenge"`
					ExpiresAt time.Time `json:"expires_at"`
				}
				if json.Unmarshal(requested.Body.Bytes(), &challenge) != nil || challenge.Challenge == "" || challenge.ExpiresAt.IsZero() {
					t.Fatal("real code request omitted opaque challenge")
				}
				completed := f.request(t, f.browser, "/api/v1/auth/login/code/verify", map[string]string{"challenge": challenge.Challenge, "code": f.delivery.last()}, 204)
				current := f.session(t, completed)
				if current.UserID != a.user.ID.String() || current.Evidence.PrimaryMethod != session.MethodContactCode || current.Evidence.UV != session.UVNotApplicable || current.Evidence.AdminEligible() {
					t.Fatal("contact sign-in changed account or gained administrative eligibility")
				}
			}
		})
	}
	if len(accounts) != 3 {
		t.Fatal("credential matrix fixtures incomplete")
	}
	var failureBody string
	for _, input := range []struct{ name, secret string }{
		{"\u0641\u0642\u062f", "wrong password"},
		{accounts[1].name, accounts[1].secret},
		{accounts[0].name, "wrong password"},
		{*accounts[0].user.Email, accounts[0].secret},
	} {
		response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": input.name, "password": input.secret}, 401)
		requireLoginNoCookie(t, response)
		if failureBody == "" {
			failureBody = response.Body.String()
		}
		if response.Body.String() != failureBody || !strings.Contains(failureBody, `"invalid_credentials"`) {
			t.Fatal("real password failures disclosed account or credential configuration")
		}
	}
}

func TestLoginRealServicesAccountBindingAndIndependentChannelsIntegration(t *testing.T) {
	for _, channel := range []string{contactcode.ChannelEmail, contactcode.ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			f := newRealLoginFixture(t, channel == contactcode.ChannelEmail, channel == contactcode.ChannelSMS)
			a, b := f.account(t, "passkey_only", false), f.account(t, "password_only", false)
			if a.phone == b.phone {
				t.Fatal("owned accounts must have distinct phones")
			}
			requested := f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": a.name, "channel": channel}, 202)
			requireLoginNoCookie(t, requested)
			rec := f.codeStore.record
			if rec.AccountID != a.user.ID {
				t.Fatal("contact challenge selected another account")
			}
			other := newPortalTestClient(t, testPortalOrigin)
			other.validator = f.browser.validator
			wrong := f.request(t, other, "/api/v1/auth/login/code/verify", map[string]string{"challenge": rec.Operation, "code": f.delivery.last()}, 401)
			requireLoginNoCookie(t, wrong)
			foreign := rec
			foreign.Purpose = "signup"
			payload, err := json.Marshal(foreign)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.client.HSet(f.ctx, "contact:login:challenge:"+rec.Operation, "payload", string(payload)).Err(); err != nil {
				t.Fatal(err)
			}
			requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login/code/verify", map[string]string{"challenge": rec.Operation, "code": f.delivery.last()}, 401))
			if f.client.HGet(f.ctx, "contact:login:challenge:"+rec.Operation, "attempts").Val() != "0" {
				t.Fatal("purpose/browser mismatch consumed login-code attempt")
			}
			payload, err = json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.client.HSet(f.ctx, "contact:login:challenge:"+rec.Operation, "payload", string(payload)).Err(); err != nil {
				t.Fatal(err)
			}
			current := f.session(t, f.request(t, f.browser, "/api/v1/auth/login/code/verify", map[string]string{"challenge": rec.Operation, "code": f.delivery.last()}, 204))
			if current.UserID != a.user.ID.String() {
				t.Fatal("challenge authenticated another account")
			}
			disabled := contactcode.ChannelSMS
			if channel == contactcode.ChannelSMS {
				disabled = contactcode.ChannelEmail
			}
			before := f.delivery.calls
			decoy := f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": b.name, "channel": disabled}, 202)
			requireLoginNoCookie(t, decoy)
			if f.delivery.calls != before {
				t.Fatal("disabled alternate channel delivered")
			}
		})
	}
}

func TestLoginRealServicesMandatoryMFAAndCrossStepupReplayIntegration(t *testing.T) {
	f := newRealLoginFixture(t, true, false)
	for _, method := range []string{session.MethodPassword, session.MethodContactCode, session.MethodPasskey} {
		t.Run(method, func(t *testing.T) {
			a := f.account(t, "dual", true)
			var first login.Result
			switch method {
			case session.MethodPassword:
				response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, 200)
				requireLoginNoCookie(t, response)
				if json.Unmarshal(response.Body.Bytes(), &struct {
					Preauthentication *string    `json:"preauthentication"`
					ExpiresAt         *time.Time `json:"expires_at"`
				}{&first.Preauthentication, &first.ExpiresAt}) != nil {
					t.Fatal("invalid MFA response")
				}
			case session.MethodContactCode:
				requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": a.name, "channel": "email"}, 202))
				response := f.request(t, f.browser, "/api/v1/auth/login/code/verify", map[string]string{"challenge": f.codeStore.record.Operation, "code": f.delivery.last()}, 200)
				requireLoginNoCookie(t, response)
				if json.Unmarshal(response.Body.Bytes(), &struct {
					Preauthentication *string    `json:"preauthentication"`
					ExpiresAt         *time.Time `json:"expires_at"`
				}{&first.Preauthentication, &first.ExpiresAt}) != nil {
					t.Fatal("invalid contact MFA response")
				}
			default:
				first = f.preauth(t, a, method)
			}
			if first.Preauthentication == "" {
				t.Fatal("mandatory MFA returned no preauth")
			}
			code := realLoginCode(t, a)
			current := f.session(t, f.complete(t, first.Preauthentication, code, 204))
			if !current.Evidence.TOTP || current.Evidence.PrimaryMethod != method || method == session.MethodContactCode && current.Evidence.AdminEligible() {
				t.Fatal("MFA changed primary authentication evidence")
			}
			_, keyStore := newTestStepUpService(t, db.New(f.pool), nil, f.factor)
			grants, err := stepup.New(stepup.Config{Issuer: testStepUpIssuer, AccountState: f.accounts}, keyStore, db.New(f.pool), nil, f.factor, f.replay)
			if err != nil {
				t.Fatal(err)
			}
			ctx := session.WithSession(f.ctx, current)
			grant, _, err := grants.Verify(ctx, stepup.VerifyParams{UserID: a.user.ID, SessionID: current.ID, Method: stepup.MethodTOTP, Code: code, DPoPJKT: f.browser.jkt, ClientIP: "203.0.113.8"})
			if !errors.Is(err, stepup.ErrCodeReplayed) || grant != "" {
				t.Fatalf("login TOTP reused for step-up: %v", err)
			}
		})
	}
	// Reverse direction with a distinct account/secret, so this is a real first
	// claim by authenticated step-up, not a second login replay by the same guard.
	a := f.account(t, "dual", true)
	current, _ := f.browser.issueSession(t, f.manager, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: a.user.AuthVersion, AuthVersionSet: true, Evidence: session.Evidence{PrimaryMethod: session.MethodPasskey, UV: session.UVVerified, TOTP: true, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
	_, keyStore := newTestStepUpService(t, db.New(f.pool), nil, f.factor)
	grants, err := stepup.New(stepup.Config{Issuer: testStepUpIssuer, AccountState: f.accounts}, keyStore, db.New(f.pool), nil, f.factor, f.replay)
	if err != nil {
		t.Fatal(err)
	}
	code := realLoginCode(t, a)
	if grant, _, err := grants.Verify(session.WithSession(f.ctx, current), stepup.VerifyParams{UserID: a.user.ID, SessionID: current.ID, Method: stepup.MethodTOTP, Code: code, DPoPJKT: f.browser.jkt, ClientIP: "203.0.113.8"}); err != nil || grant == "" {
		t.Fatalf("initial real step-up: %v", err)
	}
	first := f.preauth(t, a, session.MethodPassword)
	requireLoginNoCookie(t, f.complete(t, first.Preauthentication, code, 401))
}

func loginPendingRedisKey(t *testing.T, handle string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(handle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return "login:preauth:v1:" + hex.EncodeToString(digest[:])
}

func TestLoginRealServicesPendingExpiryAttemptsAndOneWinnerIntegration(t *testing.T) {
	f := newRealLoginFixture(t, true, false)
	a := f.account(t, "dual", true)
	first := f.preauth(t, a, session.MethodPassword)
	key := loginPendingRedisKey(t, first.Preauthentication)
	deadline := f.client.HGet(f.ctx, key, "deadline").Val()
	other := newPortalTestClient(t, testPortalOrigin)
	other.validator = f.browser.validator
	requireLoginNoCookie(t, f.request(t, other, "/api/v1/auth/login/mfa", map[string]string{"preauthentication": first.Preauthentication, "code": realLoginCode(t, a)}, 401))
	if f.client.HGet(f.ctx, key, "attempts").Val() != "0" {
		t.Fatal("wrong browser burned attempt")
	}
	validCodes := make(map[string]bool)
	for offset := -2; offset <= 2; offset++ {
		code, err := totp.GenerateCode(a.totpSecret, time.Now().Add(time.Duration(offset)*30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		validCodes[code] = true
	}
	wrongCodes := []string{}
	for candidate := 0; len(wrongCodes) < 3; candidate++ {
		code := fmt.Sprintf("%06d", candidate)
		if !validCodes[code] {
			wrongCodes = append(wrongCodes, code)
		}
	}
	for _, code := range wrongCodes {
		requireLoginNoCookie(t, f.complete(t, first.Preauthentication, code, 401))
		if f.client.HGet(f.ctx, key, "deadline").Val() != deadline {
			t.Fatal("failed MFA refreshed original expiry")
		}
	}
	requireLoginNoCookie(t, f.complete(t, first.Preauthentication, realLoginCode(t, a), 401))
	short := f.preauth(t, a, session.MethodPassword)
	claimed, err := f.pending.Claim(f.ctx, short.Preauthentication, f.browser.jkt, "fixture_claim")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pending.Consume(f.ctx, short.Preauthentication, "fixture_claim"); err != nil {
		t.Fatal(err)
	}
	claimed.ExpiresAt = time.Now().UTC().Add(100 * time.Millisecond)
	if err := f.pending.Create(f.ctx, short.Preauthentication, claimed); err != nil {
		t.Fatal(err)
	}
	if err := f.client.PExpire(f.ctx, loginPendingRedisKey(t, short.Preauthentication), 5*time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(claimed.ExpiresAt) + 10*time.Millisecond)
	requireLoginNoCookie(t, f.complete(t, short.Preauthentication, realLoginCode(t, a), 401))

	first = f.preauth(t, a, session.MethodPassword)
	code := realLoginCode(t, a)
	requests := make([]*http.Request, 12)
	for i := range requests {
		requests[i] = loginHTTPRequest(t, f.browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": first.Preauthentication, "code": code}))
	}
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, len(requests))
	for _, req := range requests {
		go func() {
			<-start
			response := httptest.NewRecorder()
			f.server.Handler().ServeHTTP(response, req)
			responses <- response
		}()
	}
	close(start)
	winners := 0
	for range requests {
		response := <-responses
		if response.Code == 204 {
			winners++
			_ = f.session(t, response)
		} else {
			if response.Code != 401 {
				t.Fatalf("concurrent completion status=%d", response.Code)
			}
			requireLoginNoCookie(t, response)
		}
	}
	if winners != 1 {
		t.Fatalf("real MFA completion winners=%d", winners)
	}
}

type loginTOTPBarrier struct {
	factor           stepup.TOTPVerifier
	entered, release chan struct{}
}

func (b *loginTOTPBarrier) VerifyEnabledCode(ctx context.Context, id uuid.UUID, code string) error {
	if err := b.factor.VerifyEnabledCode(ctx, id, code); err != nil {
		return err
	}
	close(b.entered)
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestLoginRealServicesRoleAndStatusBetweenFactorsIntegration(t *testing.T) {
	f := newRealLoginFixture(t, true, false)
	actions, err := adminaction.New(f.pool, f.cipher, "identity.audit.login-fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = op.Rollback(f.ctx) }()
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/login-policy-operator"}
	policy := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "login-fixture-approval", Fixture: true, ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600, ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt, HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry, LegacyInventoryReference: "login-fixture-inventory"}
	if err := legalpolicy.Install(f.ctx, op, policy, "test"); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"grant", "revoke", "suspended", "during_totp"} {
		t.Run(change, func(t *testing.T) {
			a := f.account(t, "dual", true)
			operator := uuid.New()
			if change == "revoke" {
				if err := rbac.ProvisionRole(f.ctx, actions, operator, "spiffe://identity.test/login-role-operator", a.user.ID, "dpo", false, "test", accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}); err != nil {
					t.Fatal(err)
				}
				a.user, err = db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			first := f.preauth(t, a, session.MethodPassword)
			switch change {
			case "grant", "revoke":
				if err := rbac.ProvisionRole(f.ctx, actions, operator, "spiffe://identity.test/login-role-operator", a.user.ID, "dpo", change == "revoke", "test", accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}); err != nil {
					t.Fatal(err)
				}
				var version int64
				if err := f.pool.QueryRow(f.ctx, `SELECT auth_version FROM users WHERE id=$1`, a.user.ID).Scan(&version); err != nil || version != a.user.AuthVersion+1 {
					t.Fatal("real role mutation did not advance version")
				}
			case "suspended":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET status='suspended',auth_version=auth_version+1 WHERE id=$1`, a.user.ID); err != nil {
					t.Fatal(err)
				}
			}
			if change != "during_totp" {
				requireLoginNoCookie(t, f.complete(t, first.Preauthentication, realLoginCode(t, a), 401))
				return
			}
			barrier := &loginTOTPBarrier{factor: f.factor, entered: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-barrier.release:
				default:
					close(barrier.release)
				}
			}()
			service, err := login.New(login.Deps{Users: db.New(f.pool), Pending: f.pending, TOTP: barrier, Replay: f.replay, Accounts: f.accounts, Limiter: loginHTTPLimiter{}})
			if err != nil {
				t.Fatal(err)
			}
			f.server.deps.Login = service
			defer func() { f.server.deps.Login = f.service }()
			req := loginHTTPRequest(t, f.browser, "/api/v1/auth/login/mfa", loginHTTPBody(t, map[string]string{"preauthentication": first.Preauthentication, "code": realLoginCode(t, a)}))
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); f.server.Handler().ServeHTTP(response, req) }()
			select {
			case <-barrier.entered:
			case <-done:
				t.Fatal("real TOTP did not reach authority barrier")
			case <-f.ctx.Done():
				t.Fatal("MFA authority barrier timed out")
			}
			if _, err := f.pool.Exec(f.ctx, `UPDATE users SET status='suspended',auth_version=auth_version+1 WHERE id=$1`, a.user.ID); err != nil {
				t.Fatal(err)
			}
			close(barrier.release)
			select {
			case <-done:
			case <-f.ctx.Done():
				t.Fatal("MFA completion timed out")
			}
			if response.Code != 401 {
				t.Fatal("authority changed during valid TOTP still issued session")
			}
			requireLoginNoCookie(t, response)
		})
	}
}

func TestLoginRealServicesUnknownDeliveryAndCommitNeverIssueCookieIntegration(t *testing.T) {
	for _, fault := range []string{"delivery", "replay", "consume"} {
		t.Run(fault, func(t *testing.T) {
			f := newRealLoginFixture(t, true, false)
			a := f.account(t, "dual", true)
			if fault == "delivery" {
				f.delivery.err = errors.New("delivery acceptance unknown")
				requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": a.name, "channel": "email"}, 202))
				if f.delivery.calls != 1 {
					t.Fatal("unknown delivery retried")
				}
				requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login/code/verify", map[string]string{"challenge": f.codeStore.record.Operation, "code": f.delivery.last()}, 401))
				return
			}
			first := f.preauth(t, a, session.MethodPassword)
			f.hook.fault = fault
			response := f.complete(t, first.Preauthentication, realLoginCode(t, a), 503)
			requireLoginNoCookie(t, response)
			if !strings.Contains(response.Body.String(), "outcome_unknown") || f.hook.calls.Load() != 1 {
				t.Fatal("lost commit classified as confirmed success/failure or retried")
			}
			f.hook.fault = ""
			requireLoginNoCookie(t, f.complete(t, first.Preauthentication, realLoginCode(t, a), 401))
		})
	}
}

// Compile-time contracts keep the fixtures on the production service surfaces.
var _ contactcode.Store = (*loginCodeCaptureStore)(nil)
var _ stepup.TOTPVerifier = (*loginTOTPBarrier)(nil)

type loginDBIssuanceBarrier struct {
	session.EvidenceAccountState
	entered, release chan struct{}
}

func (b *loginDBIssuanceBarrier) WithActiveEvidence(ctx context.Context, id string, version int64, kind session.Kind, evidence session.Evidence, fn func() error) error {
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.EvidenceAccountState.WithActiveEvidence(ctx, id, version, kind, evidence, fn)
}

func (f *realLoginFixture) invalidateContact(t *testing.T, a realLoginAccount, channel, change string) {
	t.Helper()
	if change == "evidence_revoked" {
		if _, err := f.pool.Exec(f.ctx, `DELETE FROM contact_verification_evidence WHERE user_id=$1 AND channel=$2`, a.user.ID, channel); err != nil {
			t.Fatal(err)
		}
	} else if channel == contactproof.Email {
		destination := uuid.NewString() + "@replacement.invalid"
		if _, err := f.pool.Exec(f.ctx, `UPDATE users SET email=$2 WHERE id=$1`, a.user.ID, destination); err != nil {
			t.Fatal(err)
		}
		f.contact(t, a.user.ID, channel, destination)
	} else {
		f.contact(t, a.user.ID, channel, strings.Replace(a.phone, "+98912", "+98913", 1))
	}
	current, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || current.AuthVersion != a.user.AuthVersion || current.Status != "active" {
		t.Fatal("contact invalidation changed account authority instead of exercising the original contact binding")
	}
}

func TestLoginRealServicesContactInvalidationBeforeFinalIssuanceIntegration(t *testing.T) {
	for _, channel := range []string{contactcode.ChannelEmail, contactcode.ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			f := newRealLoginFixture(t, true, true)
			proofChannel := contactproof.Email
			if channel == contactcode.ChannelSMS {
				proofChannel = contactproof.Phone
			}
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
							f.server.deps.SessionManager = f.manager
							defer func() { f.server.deps.SessionManager = f.manager }()
							a := f.account(t, "dual", mfaEnabled)
							requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login/code/request", map[string]string{"username": a.name, "channel": channel}, 202))
							result, err := f.service.VerifyCode(f.ctx, f.codeStore.record.Operation, f.browser.jkt, f.delivery.last())
							if err != nil {
								t.Fatal(err)
							}
							if mfaEnabled {
								if result.Issue != nil || result.Preauthentication == "" {
									t.Fatal("contact verification bypassed MFA")
								}
								preauth := httptest.NewRecorder()
								f.server.finishLogin(preauth, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), result)
								if preauth.Code != 200 {
									t.Fatal("real contact verification omitted MFA response")
								}
								requireLoginNoCookie(t, preauth)
								if phase == "before_mfa" {
									f.invalidateContact(t, a, proofChannel, change)
									requireLoginNoCookie(t, f.complete(t, result.Preauthentication, realLoginCode(t, a), 401))
									current, err := f.manager.List(f.ctx, a.user.ID.String())
									if err != nil || len(current) != 0 {
										t.Fatal("revoked contact created a session during MFA")
									}
									return
								}
								result, err = f.service.CompleteMFA(f.ctx, result.Preauthentication, f.browser.jkt, realLoginCode(t, a))
								if err != nil {
									t.Fatal(err)
								}
							}
							if result.Issue == nil || result.Issue.CheckPrimaryFactor == nil {
								t.Fatal("contact evidence lost final proof check")
							}
							response := httptest.NewRecorder()
							if phase == "concurrent_issuance" {
								barrier := &loginDBIssuanceBarrier{EvidenceAccountState: f.accounts, entered: make(chan struct{}), release: make(chan struct{})}
								defer func() {
									select {
									case <-barrier.release:
									default:
										close(barrier.release)
									}
								}()
								store, err := session.NewRedisStore(f.sessionClient)
								if err != nil {
									t.Fatal(err)
								}
								codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
								if err != nil {
									t.Fatal(err)
								}
								manager, err := session.NewManager(store, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, AccountState: barrier})
								if err != nil {
									t.Fatal(err)
								}
								f.server.deps.SessionManager = manager
								ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
								defer cancel()
								done := make(chan struct{})
								go func() {
									defer close(done)
									f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil).WithContext(ctx), result)
								}()
								select {
								case <-barrier.entered:
								case <-done:
									t.Fatal("real issuance bypassed account-lock barrier")
								case <-ctx.Done():
									t.Fatal("real issuance barrier timed out")
								}
								// Commit contact invalidation before the final PostgreSQL row
								// lock/read, without changing auth_version or account status.
								f.invalidateContact(t, a, proofChannel, change)
								close(barrier.release)
								select {
								case <-done:
								case <-ctx.Done():
									t.Fatal("real final issuance did not finish")
								}
							} else {
								f.invalidateContact(t, a, proofChannel, change)
								f.server.finishLogin(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/code/verify", nil), result)
							}
							if response.Code != 401 {
								t.Fatal("invalidated primary contact still issued a normal session")
							}
							requireLoginNoCookie(t, response)
							current, err := f.manager.List(f.ctx, a.user.ID.String())
							if err != nil || len(current) != 0 {
								t.Fatal("invalidated contact persisted real Redis session authority")
							}
						})
					}
				}
			}
		})
	}
}

func TestLoginRealServicesEquivalentUsernameQuotaIntegration(t *testing.T) {
	f := newRealLoginFixture(t, true, false)
	a := f.account(t, "password_only", false)
	spellings := []string{a.name, strings.ReplaceAll(a.name, "\u06cc", "\u064a")}
	for _, spelling := range spellings {
		id, err := f.names.Lookup(f.ctx, spelling)
		if err != nil || id != a.user.ID {
			t.Fatal("real alias does not resolve to the same account")
		}
	}
	for attempt := range 10 {
		requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": spellings[attempt%len(spellings)], "password": "wrong fixture password"}, 401))
	}
	for _, spelling := range spellings {
		request := loginHTTPRequest(t, f.browser, "/api/v1/auth/login", loginHTTPBody(t, map[string]string{"username": spelling, "password": a.secret}))
		request.RemoteAddr = "198.51.100.8:4242"
		response := boundaryServe(t, f.server, request, 429)
		requireLoginNoCookie(t, response)
		if !strings.Contains(response.Body.String(), "rate_limited") {
			t.Fatal("equivalent username bypassed real identifier quota")
		}
	}
}
