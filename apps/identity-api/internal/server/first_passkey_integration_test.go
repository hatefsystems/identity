//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// Delivery is an explicitly owned in-memory fixture, not inbox/provider evidence.
// Password, contact evidence, proof SQL, Redis Lua, TCP HTTP and crypto are real.
type firstHTTPDelivery struct {
	mu                       sync.Mutex
	channel, recipient, code string
	expires                  time.Time
	calls                    int
	err                      error
}

func (d *firstHTTPDelivery) send(channel, recipient, code string, expires time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channel, d.recipient, d.code, d.expires = channel, recipient, code, expires
	d.calls++
	return d.err
}

type firstHTTPEmail struct{ *firstHTTPDelivery }

func (d firstHTTPEmail) SendCode(_ context.Context, recipient, code string, expires time.Time) error {
	return d.send("email", recipient, code, expires)
}

type firstHTTPSMS struct{ *firstHTTPDelivery }

func (d firstHTTPSMS) SendCode(_ context.Context, recipient, code string) error {
	return d.send("sms", recipient, code, time.Time{})
}

type firstHTTPFixture struct {
	login    *realLoginFixture
	runtime  *pgxpool.Pool
	delivery *firstHTTPDelivery
	servers  [2]*httptest.Server
	current  session.Session
	cookies  []*http.Cookie
}

func newFirstHTTPFixture(t *testing.T, channel string) *firstHTTPFixture {
	t.Helper()
	f := newRealLoginFixture(t, false, false)
	role := "first_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{role}.Sanitize()
	secret := uuid.NewString()
	exec := func(sql string) {
		t.Helper()
		if _, err := f.pool.Exec(f.ctx, sql); err != nil {
			t.Fatal("owned first HTTP runtime provisioning failed")
		}
	}
	exec("CREATE ROLE " + quoted + " LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '" + secret + "'")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(cleanup, "DROP OWNED BY "+quoted); err != nil {
			t.Error("owned first HTTP grants teardown failed")
		}
		if _, err := f.pool.Exec(cleanup, "DROP ROLE "+quoted); err != nil {
			t.Error("owned first HTTP login teardown failed")
		}
	})
	exec("GRANT CONNECT ON DATABASE " + pgx.Identifier{f.pool.Config().ConnConfig.Database}.Sanitize() + " TO " + quoted)
	exec("GRANT USAGE ON SCHEMA public TO " + quoted)
	exec("GRANT SELECT ON users,webauthn_credentials,roles,user_roles,contact_verification_evidence,username_policy_artifacts,username_lookup_keys,username_active_policy TO " + quoted)
	exec("GRANT UPDATE(auth_version,updated_at,webauthn_user_handle) ON users TO " + quoted)
	exec("GRANT UPDATE(guard) ON username_active_policy TO " + quoted)
	exec("GRANT USAGE ON SEQUENCE account_auth_epoch_seq TO " + quoted)
	exec("GRANT INSERT ON webauthn_credentials TO " + quoted)
	exec("GRANT SELECT,INSERT,DELETE ON first_passkey_enrollment_action_proofs,account_deletion_action_proofs,password_change_action_proofs TO " + quoted)
	cfg := f.pool.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, secret
	runtime, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("owned restricted first HTTP login failed")
	}
	t.Cleanup(runtime.Close)
	var current, login string
	if err := runtime.QueryRow(f.ctx, "SELECT current_user,session_user").Scan(&current, &login); err != nil || current != role || login != role {
		t.Fatal("first HTTP fixture did not authenticate as restricted login")
	}
	names, err := username.NewStore(runtime, f.cipher, f.names.Normalizer())
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.NewRedisLimiter(f.client)
	if err != nil {
		t.Fatal(err)
	}
	delivery := &firstHTTPDelivery{}
	codeConfig := contactcode.Config{HashKey: bytes.Repeat([]byte{0x63}, 32), PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}
	var sms *smsotp.Service
	if channel == "email" {
		codeConfig.FirstPasskeyEmail = firstHTTPEmail{delivery}
		codeConfig.DeletionEmail = firstHTTPEmail{delivery}
		codeConfig.PasswordChangeEmail = firstHTTPEmail{delivery}
	} else {
		users, err := smsotp.NewUserStore(runtime)
		if err != nil {
			t.Fatal(err)
		}
		otps, err := smsotp.NewRedisOTPStore(f.client)
		if err != nil {
			t.Fatal(err)
		}
		sms, err = smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{0x64}, 32), FirstPasskeySender: firstHTTPSMS{delivery},
			PerPhonePerMinute: 5, PerPhonePerHour: 20, PerSubnetPerHour: 100}, users, f.cipher, phoneFakeIndexer{}, limiter, otps, firstHTTPSMS{delivery})
		if err != nil {
			t.Fatal(err)
		}
	}
	codeStore, err := contactcode.NewRedisStore(f.client)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := contactcode.New(codeConfig, codeStore, sms, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := actionproof.NewFirstPasskey(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x65}, 32)}, actionproof.Deps{
		DB: runtime, Queries: db.New(runtime), Codes: codes, Cipher: f.cipher, Limiter: limiter, Sessions: f.manager})
	if err != nil {
		t.Fatal(err)
	}
	h := &firstHTTPFixture{login: f, runtime: runtime, delivery: delivery}
	for i := range h.servers {
		pending, err := webauthn.NewRedisChallengeStore(f.client)
		if err != nil {
			t.Fatal(err)
		}
		wa, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPDisplayName: "Owned first HTTP", RPOrigins: []string{f.browser.origin},
			ChallengeTTL: time.Minute, UserVerification: "preferred", ResidentKey: "required", MockChallengeKey: bytes.Repeat([]byte{0x66}, 32)},
			db.New(runtime), db.New(runtime), pending, webauthn.WithTransacter(runtime))
		if err != nil {
			t.Fatal(err)
		}
		wa.SetFirstPasskeyDependencies(proofs, f.manager, names)
		srv := New(f.server.cfg, f.server.logger, Deps{Login: f.service, PasswordLoginEnabled: true, SessionManager: f.manager,
			DPoPValidator: f.browser.validator, WebAuthnLimiter: limiter, FirstPasskeyProofs: proofs, AccountDeletionProofs: proofs, PasswordChangeProofs: proofs, WebAuthn: wa})
		h.servers[i] = httptest.NewServer(srv.router)
		t.Cleanup(h.servers[i].Close)
	}
	return h
}

func (f *firstHTTPFixture) request(t *testing.T, replica int, path string, body any, headers http.Header, want int) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal("owned HTTP body encoding failed")
	}
	request, err := http.NewRequestWithContext(f.login.ctx, http.MethodPost, f.servers[replica].URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal("owned HTTP request creation failed")
	}
	for key, values := range headers {
		request.Header[key] = append([]string(nil), values...)
	}
	if f.current.ID == "" {
		f.login.browser.sign(t, request)
	} else {
		f.login.browser.authorize(t, request, f.current, f.cookies...)
	}
	response, err := f.servers[replica].Client().Do(request)
	if err != nil {
		t.Fatal("real owned TCP HTTP request failed")
	}
	defer func() { _ = response.Body.Close() }()
	result, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(result) > 65536 || response.StatusCode != want {
		t.Fatalf("owned HTTP status = %d, expected %d; private body suppressed", response.StatusCode, want)
	}
	if !strings.Contains(response.Header.Get("Cache-Control"), "no-store") || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("first HTTP response privacy headers changed")
	}
	if path == "/api/v1/auth/login" && want == 204 {
		f.cookies = response.Cookies()
		if len(f.cookies) != 1 || !f.cookies[0].Secure || !f.cookies[0].HttpOnly || f.cookies[0].SameSite != http.SameSiteStrictMode {
			t.Fatal("real password login cookie was not strict")
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(f.cookies[0])
		f.current, err = f.login.manager.Resolve(req)
		if err != nil || f.current.Evidence.PrimaryMethod != session.MethodPassword {
			t.Fatal("real password login did not earn bound password session")
		}
	} else if len(response.Header.Values("Set-Cookie")) != 0 && want != 201 {
		t.Fatal("proof or failed enrollment set authentication cookie")
	}
	return result
}

type firstHTTPAuthority struct {
	Challenge string    `json:"challenge"`
	Proof     string    `json:"action_proof"`
	Expires   time.Time `json:"expires_at"`
}

func (f *firstHTTPFixture) earn(t *testing.T, a realLoginAccount, channel string) firstHTTPAuthority {
	t.Helper()
	var challenge, proof firstHTTPAuthority
	if json.Unmarshal(f.request(t, 0, firstPasskeyProofPath+"/challenge", map[string]string{"password": a.secret, "channel": channel}, nil, 202), &challenge) != nil || challenge.Challenge == "" || challenge.Expires.IsZero() {
		t.Fatal("real first HTTP challenge omitted authority")
	}
	f.delivery.mu.Lock()
	code, recipient, selected, expires := f.delivery.code, f.delivery.recipient, f.delivery.channel, f.delivery.expires
	f.delivery.mu.Unlock()
	want := a.phone
	if channel == "email" {
		want = *a.user.Email
		if !expires.Equal(challenge.Expires) {
			t.Fatal("first email deadline changed")
		}
	}
	if recipient != want || selected != channel || code == "" {
		t.Fatal("first proof did not select the currently evidenced destination")
	}
	if json.Unmarshal(f.request(t, 1, firstPasskeyProofPath+"/verify", map[string]string{"challenge": challenge.Challenge, "code": code}, nil, 200), &proof) != nil || proof.Proof == "" || !proof.Expires.Equal(challenge.Expires) {
		t.Fatal("real first HTTP verification renewed or omitted authority")
	}
	return proof
}

func (f *firstHTTPFixture) options(t *testing.T, proof firstHTTPAuthority, want int) *protocol.CredentialCreation {
	t.Helper()
	result := f.request(t, 0, "/api/v1/auth/webauthn/register/generate-options", map[string]string{"name": "Owned first HTTP key"}, http.Header{"X-Action-Proof": {proof.Proof}}, want)
	if want != 200 {
		return nil
	}
	var options protocol.CredentialCreation
	var envelope firstHTTPAuthority
	if json.Unmarshal(result, &options) != nil || json.Unmarshal(result, &envelope) != nil || envelope.Expires.IsZero() || envelope.Expires.After(proof.Expires) || options.Response.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("real first HTTP options changed original expiry or required UV")
	}
	return &options
}

func TestFirstPasskeyRealHTTPEmailSMSIntegration(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			f := newFirstHTTPFixture(t, channel)
			a := f.login.account(t, "password_only", false)
			f.request(t, 0, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, nil, 204)
			f.request(t, 0, firstPasskeyProofPath+"/challenge", map[string]string{"password": " " + a.secret, "channel": channel}, nil, 403)
			proof := f.earn(t, a, channel)
			options := f.options(t, proof, 200)
			if options.Response.User.Name != a.name || options.Response.User.DisplayName != a.name {
				t.Fatal("first HTTP native identity was not the protected username")
			}
			before, err := db.New(f.login.pool).GetUserByID(f.login.ctx, a.user.ID)
			if err != nil || !reflect.DeepEqual(before, a.user) {
				t.Fatal("options changed account handle, version or lifecycle")
			}
			f.options(t, proof, 403)
			authenticator := newSignupAuthenticator(t, options)
			attestation := authenticator.credential(t, options, true)
			for _, headers := range []http.Header{{"X-Action-Proof": {proof.Proof}}, {"X-Step-Up-Auth": {"strong"}}} {
				f.request(t, 1, "/api/v1/auth/webauthn/register/verify", attestation, headers, 400)
			}
			finish := f.request(t, 1, "/api/v1/auth/webauthn/register/verify", attestation, nil, 201)
			var success webauthnCredentialResponse
			if json.Unmarshal(finish, &success) != nil || !success.UserVerified {
				t.Fatal("first HTTP success did not evidence actual verified UV")
			}
			after, err := db.New(f.login.pool).GetUserByID(f.login.ctx, a.user.ID)
			count, countErr := db.New(f.runtime).CountWebauthnCredentialsByUser(f.login.ctx, a.user.ID)
			if err != nil || countErr != nil || count != 1 || after.AuthVersion != before.AuthVersion+1 || after.AuthEpoch <= before.AuthEpoch || !bytes.Equal(after.WebauthnUserHandle, authenticator.handle) {
				t.Fatal("first HTTP finish did not commit one credential/handle/cutoff")
			}
			after.AuthVersion, after.WebauthnUserHandle, after.UpdatedAt = before.AuthVersion, before.WebauthnUserHandle, before.UpdatedAt
			after.AuthEpoch = before.AuthEpoch
			if !reflect.DeepEqual(after, before) {
				t.Fatal("first HTTP finish altered password, contacts, MFA, username or lifecycle")
			}
			f.request(t, 1, firstPasskeyProofPath+"/challenge", map[string]string{"password": a.secret, "channel": channel}, nil, 401)
			f.current, f.cookies = session.Session{}, nil
			f.request(t, 0, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, nil, 204)
			f.request(t, 1, firstPasskeyProofPath+"/challenge", map[string]string{"password": a.secret, "channel": channel}, nil, 403)
			f.options(t, proof, 403)
		})
	}
}

func TestFirstPasskeyRealHTTPHeaderBindingsAndNoRefundIntegration(t *testing.T) {
	f := newFirstHTTPFixture(t, "email")
	a := f.login.account(t, "password_only", false)
	f.request(t, 0, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, nil, 204)
	proof := f.earn(t, a, "email")
	for _, purpose := range []string{accountDeletionProofPath, passwordChangeProofPath} {
		var challenge, foreign firstHTTPAuthority
		if json.Unmarshal(f.request(t, 0, purpose+"/challenge", map[string]string{"password": a.secret, "channel": "email"}, nil, 202), &challenge) != nil {
			t.Fatal("cross-purpose challenge decoding failed")
		}
		if json.Unmarshal(f.request(t, 1, purpose+"/verify", map[string]string{"challenge": challenge.Challenge, "code": f.delivery.code}, nil, 200), &foreign) != nil || foreign.Proof == "" {
			t.Fatal("cross-purpose proof decoding failed")
		}
		f.options(t, foreign, 403)
	}
	for _, headers := range []http.Header{
		nil, {"X-Action-Proof": {""}}, {"X-Action-Proof": {proof.Proof, proof.Proof}},
		{"X-Action-Proof": {proof.Proof}, "X-Step-Up-Auth": {"strong"}},
	} {
		f.request(t, 0, "/api/v1/auth/webauthn/register/generate-options", map[string]string{}, headers, 403)
	}
	f.request(t, 0, "/api/v1/auth/webauthn/register/generate-options", map[string]string{"unknown": "field"}, http.Header{"X-Action-Proof": {proof.Proof}}, 400)
	f.request(t, 0, "/api/v1/auth/webauthn/register/generate-options", map[string]string{}, http.Header{"X-Action-Proof": {proof.Proof}, "X-Portal-Session": {"foreign"}}, 409)
	f.request(t, 0, "/api/v1/auth/webauthn/register/generate-options", map[string]string{}, http.Header{"X-Action-Proof": {proof.Proof}, "Origin": {"https://foreign.example"}}, 403)
	original, cookies := f.current, f.cookies
	f.current, f.cookies = f.login.browser.issueSession(t, f.login.manager, session.IssueParams{UserID: original.UserID, AuthVersion: original.AuthVersion, AuthVersionSet: true})
	f.options(t, proof, 403)
	other := f.login.account(t, "password_only", false)
	f.current, f.cookies = f.login.browser.issueSession(t, f.login.manager, session.IssueParams{UserID: other.user.ID.String(), AuthVersion: other.user.AuthVersion, AuthVersionSet: true})
	f.options(t, proof, 403)
	browser := f.login.browser
	foreignBrowser := newPortalTestClient(t, browser.origin)
	foreignBrowser.validator = browser.validator
	f.login.browser = foreignBrowser
	f.current, f.cookies = foreignBrowser.issueSession(t, f.login.manager, session.IssueParams{UserID: original.UserID, AuthVersion: original.AuthVersion, AuthVersionSet: true})
	f.options(t, proof, 403)
	f.login.browser = browser
	f.current, f.cookies = original, cookies
	options := f.options(t, proof, 200)
	competitor := f.earn(t, a, "email")
	f.options(t, competitor, 409)
	f.options(t, competitor, 403)
	authenticator := newSignupAuthenticator(t, options)
	f.request(t, 1, "/api/v1/auth/webauthn/register/verify", authenticator.credential(t, options, true), http.Header{"X-Action-Proof": {proof.Proof}}, 400)
	// A validly formed non-UV response reaches the pinned provider and takes pending
	// authority. It cannot save a handle or refund the original start proof.
	f.request(t, 1, "/api/v1/auth/webauthn/register/verify", authenticator.credential(t, options, false), nil, 400)
	f.options(t, proof, 403)
	f.request(t, 1, "/api/v1/auth/webauthn/register/verify", authenticator.credential(t, options, true), nil, 400)
	current, err := db.New(f.login.pool).GetUserByID(f.login.ctx, a.user.ID)
	count, countErr := db.New(f.runtime).CountWebauthnCredentialsByUser(f.login.ctx, a.user.ID)
	if err != nil || countErr != nil || count != 0 || !reflect.DeepEqual(current, a.user) {
		t.Fatal("rejected first HTTP boundary changed account or saved partial credential")
	}
}

func TestFirstPasskeyRealHTTPCurrentContactAndPolicyIntegration(t *testing.T) {
	for _, mode := range []string{"contact", "mfa", "role", "version", "recovery", "delivery-unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newFirstHTTPFixture(t, "email")
			a := f.login.account(t, "password_only", false)
			f.request(t, 0, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, nil, 204)
			if mode == "delivery-unknown" {
				f.delivery.err = io.ErrUnexpectedEOF
				body := f.request(t, 0, firstPasskeyProofPath+"/challenge", map[string]string{"password": a.secret, "channel": "email"}, nil, 503)
				var result map[string]string
				if json.Unmarshal(body, &result) != nil || result["error"] != "outcome_unknown" || len(result) != 1 || f.delivery.calls != 1 {
					t.Fatal("uncertain first delivery retried or exposed tentative authority")
				}
				return
			}
			proof := f.earn(t, a, "email")
			options := f.options(t, proof, 200)
			want := 403
			switch mode {
			case "contact":
				f.login.contact(t, a.user.ID, contactproof.Email, *a.user.Email)
			case "mfa":
				if _, err := f.login.pool.Exec(f.login.ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", a.user.ID); err != nil {
					t.Fatal("owned MFA policy mutation failed")
				}
				want = 401
			case "role":
				if _, err := f.login.pool.Exec(f.login.ctx, "INSERT INTO user_roles(user_id,role_id) VALUES($1,'support')", a.user.ID); err != nil {
					t.Fatal("owned role policy mutation failed")
				}
			case "version":
				if _, err := f.login.pool.Exec(f.login.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", a.user.ID); err != nil {
					t.Fatal("owned version mutation failed")
				}
				want = 401
			case "recovery":
				f.current, f.cookies = f.login.browser.issueSession(t, f.login.manager, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: a.user.AuthVersion, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
				want = 401
			}
			authenticator := newSignupAuthenticator(t, options)
			f.request(t, 1, "/api/v1/auth/webauthn/register/verify", authenticator.credential(t, options, true), nil, want)
			current, err := db.New(f.login.pool).GetUserByID(f.login.ctx, a.user.ID)
			count, countErr := db.New(f.runtime).CountWebauthnCredentialsByUser(f.login.ctx, a.user.ID)
			if err != nil || countErr != nil || count != 0 || len(current.WebauthnUserHandle) != 0 || current.LifecycleRevision != a.user.LifecycleRevision {
				t.Fatal("current-policy rejection saved a partial first credential")
			}
		})
	}
}
