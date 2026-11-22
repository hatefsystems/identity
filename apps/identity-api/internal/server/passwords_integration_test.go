//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/passwordmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

type passwordProofHTTPAdapter struct{ service *actionproof.Service }

func (a passwordProofHTTPAdapter) Challenge(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	return a.service.ChallengePasswordChange(ctx, sess, secret, channel, sourceIP)
}

func (a passwordProofHTTPAdapter) Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return a.service.VerifyPasswordChange(ctx, sess, challenge, code)
}

type realPasswordFixture struct {
	*realLoginFixture
	mutations *passwordmanager.Service
	proofs    *actionproof.Service
	deletion  *actionproof.Service
	wa        *webauthn.Service
	grants    *stepup.Service
	limiter   ratelimit.Limiter
	count     uint32
}

func newRealPasswordFixture(t *testing.T, enabled bool) *realPasswordFixture {
	t.Helper()
	f := newRealLoginFixture(t, true, false)
	limiter, err := ratelimit.NewRedisLimiter(f.client)
	if err != nil {
		t.Fatal(err)
	}
	challenges, err := webauthn.NewRedisChallengeStore(f.client)
	if err != nil {
		t.Fatal(err)
	}
	q := db.New(f.pool)
	wa, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPOrigins: []string{testPortalOrigin}, RPDisplayName: "Identity", ChallengeTTL: time.Minute, MockChallengeKey: bytes.Repeat([]byte{0x67}, 32), AccountState: f.accounts}, q, q, challenges, webauthn.WithTransacter(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	policy := accountpolicy.Policy{PasswordLoginEnabled: enabled, Usernames: f.names}
	wa.SetAccountPolicy(policy)
	_, keys := newTestStepUpService(t, q, wa, f.factor)
	grants, err := stepup.New(stepup.Config{Issuer: testStepUpIssuer, AccountState: f.accounts}, keys, q, wa, f.factor, f.replay)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{0x45}, 32), PasswordChangeEmail: loginEmailCapture{f.delivery}, DeletionEmail: loginEmailCapture{f.delivery}, PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}, f.codeStore, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofDeps := actionproof.Deps{DB: f.pool, Queries: q, Codes: codes, Cipher: f.cipher, Limiter: limiter, Sessions: f.manager}
	proofs, err := actionproof.NewPasswordChange(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x68}, 32)}, proofDeps)
	if err != nil {
		t.Fatal(err)
	}
	deletion, err := actionproof.New(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x69}, 32)}, proofDeps)
	if err != nil {
		t.Fatal(err)
	}
	mutations, err := passwordmanager.New(passwordmanager.Deps{DB: f.pool, Queries: q, Sessions: f.manager, Limiter: limiter, Policy: policy, Proofs: proofs})
	if err != nil {
		t.Fatal(err)
	}
	f.server = New(f.server.cfg, f.server.logger, Deps{Login: f.service, PasswordLoginEnabled: enabled, SessionManager: f.manager, DPoPValidator: f.browser.validator, WebAuthnLimiter: limiter, WebAuthn: wa, StepUp: grants, Passwords: mutations, PasswordChangeProofs: passwordProofHTTPAdapter{proofs}, AccountDeletionProofs: deletion})
	return &realPasswordFixture{realLoginFixture: f, mutations: mutations, proofs: proofs, deletion: deletion, wa: wa, grants: grants, limiter: limiter}
}

func (f *realPasswordFixture) authenticator(t *testing.T, a realLoginAccount) *signupAuthenticator {
	t.Helper()
	handle := make([]byte, 8)
	if _, err := rand.Read(handle); err != nil {
		t.Fatal(err)
	}
	options := &protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{User: protocol.UserEntity{ID: protocol.URLEncodedBase64(handle)}}}
	auth := newSignupAuthenticator(t, options)
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET webauthn_user_handle=$2 WHERE id=$1`, a.user.ID, handle); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM webauthn_credentials WHERE user_id=$1`, a.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.New(f.pool).CreateWebauthnCredential(f.ctx, db.CreateWebauthnCredentialParams{ID: auth.id, UserID: a.user.ID, PublicKey: auth.cose, AttestationType: "none", UserPresent: true, UserVerified: true}); err != nil {
		t.Fatal(err)
	}
	return auth
}

func (f *realPasswordFixture) assertion(t *testing.T, auth *signupAuthenticator, options *protocol.CredentialAssertion, uv bool) []byte {
	t.Helper()
	f.count++
	flags := byte(0x01)
	if uv {
		flags |= 0x04
	}
	authData := auth.authData(flags, f.count, false)
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(options.Response.Challenge), "origin": auth.origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(bytes.Clone(authData), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, auth.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{"id": enc(auth.id), "rawId": enc(auth.id), "type": "public-key", "response": map[string]any{"clientDataJSON": enc(clientData), "authenticatorData": enc(authData), "signature": enc(signature), "userHandle": enc(auth.handle)}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (f *realPasswordFixture) bound(t *testing.T, current session.Session, cookies []*http.Cookie, method, path, body string, headers http.Header, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.8:12345"
	for name, values := range headers {
		r.Header[name] = append([]string(nil), values...)
	}
	f.browser.authorize(t, r, current, cookies...)
	return boundaryServe(t, f.server, r, want)
}

func (f *realPasswordFixture) issue(t *testing.T, a realLoginAccount, primary string) (session.Session, []*http.Cookie) {
	t.Helper()
	user, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	uv := session.UVNotApplicable
	if primary == session.MethodPasskey {
		uv = session.UVVerified
	}
	return f.browser.issueSession(t, f.manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true, Evidence: session.Evidence{PrimaryMethod: primary, UV: uv, TOTP: user.IsMfaEnabled, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
}

func (f *realPasswordFixture) stepup(t *testing.T, current session.Session, cookies []*http.Cookie, auth *signupAuthenticator, a realLoginAccount) string {
	t.Helper()
	body := loginHTTPBody(t, map[string]string{"method": stepup.MethodTOTP, "code": realLoginCode(t, a)})
	if auth != nil {
		challenge := f.bound(t, current, cookies, "POST", stepUpChallengePath, "", nil, 200)
		var options stepUpChallengeResponse
		if json.Unmarshal(challenge.Body.Bytes(), &options) != nil || options.WebAuthn == nil || options.WebAuthn.Response.UserVerification != protocol.VerificationRequired {
			t.Fatal("real Step-up did not require WebAuthn UV")
		}
		encoded, err := json.Marshal(map[string]any{"method": stepup.MethodWebAuthn, "assertion": json.RawMessage(f.assertion(t, auth, options.WebAuthn, true))})
		if err != nil {
			t.Fatal(err)
		}
		body = string(encoded)
	}
	response := f.bound(t, current, cookies, "POST", stepUpVerifyPath, body, nil, 200)
	var grant stepUpVerifyResponse
	if json.Unmarshal(response.Body.Bytes(), &grant) != nil || grant.Token == "" {
		t.Fatal("real factor verification did not issue Step-up grant")
	}
	return grant.Token
}

func passwordMutationBody(t *testing.T, operation, secret string) string {
	t.Helper()
	return loginHTTPBody(t, map[string]string{"operation": operation, "new_password": secret})
}

func (f *realPasswordFixture) mutate(t *testing.T, current session.Session, cookies []*http.Cookie, operation, secret, grant, proof string, want int) *httptest.ResponseRecorder {
	t.Helper()
	method, body := "PUT", passwordMutationBody(t, operation, secret)
	if operation == "remove" {
		method, body = "DELETE", ""
	}
	headers := http.Header{}
	if grant != "" {
		headers.Set(stepup.HeaderStepUpAuth, grant)
	}
	if proof != "" {
		headers.Set("X-Action-Proof", proof)
	}
	response := f.bound(t, current, cookies, method, passwordPath, body, headers, want)
	if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("password response permits caching")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("password operation issued new authenticated authority")
		}
	}
	return response
}

func (f *realPasswordFixture) assertState(t *testing.T, a realLoginAccount, version int64, secret *string) db.User {
	t.Helper()
	user, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || user.AuthVersion != version || (user.PasswordHash == nil) != (secret == nil) {
		t.Fatalf("password/version state mismatch: version=%d wanted=%d error=%v", user.AuthVersion, version, err)
	}
	if secret != nil {
		matches, err := password.VerifyContext(f.ctx, *secret, *user.PasswordHash)
		if err != nil || !matches {
			t.Fatal("stored verifier does not match exact chosen bytes", err)
		}
	}
	return user
}

func TestPasswordHTTPRealAddChangeRemoveAndRetainedPasskeyLoginIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "passkey_only", false)
	auth := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	oldSession, oldCookies := f.issue(t, a, session.MethodPasskey)
	firstSecret := "  private cafe\u0301 password " + uuid.NewString() + "  "
	staleGrant := f.stepup(t, current, cookies, auth, a)
	grant := f.stepup(t, current, cookies, auth, a)
	f.mutate(t, current, cookies, "add", firstSecret, grant, "", 204)
	f.assertState(t, a, a.user.AuthVersion+1, &firstSecret)
	f.mutate(t, oldSession, oldCookies, "remove", "", grant, "", 401)
	loggedIn := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": firstSecret}, 204)
	current, cookies = f.session(t, loggedIn), loggedIn.Result().Cookies()
	f.mutate(t, current, cookies, "change", firstSecret, staleGrant, "", 403)
	for _, altered := range []string{strings.TrimSpace(firstSecret), strings.ReplaceAll(firstSecret, "e\u0301", "\u00e9")} {
		requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": altered}, 401))
	}
	secondSecret := "different private fixture secret"
	grant = f.stepup(t, current, cookies, auth, a)
	f.mutate(t, current, cookies, "change", secondSecret, grant, "", 204)
	f.assertState(t, a, a.user.AuthVersion+2, &secondSecret)
	requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": firstSecret}, 401))
	loggedIn = f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": secondSecret}, 204)
	current, cookies = f.session(t, loggedIn), loggedIn.Result().Cookies()
	grant = f.stepup(t, current, cookies, auth, a)
	f.mutate(t, current, cookies, "remove", "", grant, "", 204)
	f.assertState(t, a, a.user.AuthVersion+3, nil)
	requireLoginNoCookie(t, f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": secondSecret}, 401))
	optionsResponse := f.request(t, f.browser, "/api/v1/auth/webauthn/login/generate-options", map[string]string{}, 200)
	var options protocol.CredentialAssertion
	if json.Unmarshal(optionsResponse.Body.Bytes(), &options) != nil {
		t.Fatal("real discoverable login options malformed")
	}
	request := loginHTTPRequest(t, f.browser, "/api/v1/auth/webauthn/login/verify", string(f.assertion(t, auth, &options, true)))
	response := boundaryServe(t, f.server, request, 204)
	current = f.session(t, response)
	if current.UserID != a.user.ID.String() || current.Evidence.PrimaryMethod != session.MethodPasskey || current.Evidence.UV != session.UVVerified || current.AuthVersion != a.user.AuthVersion+3 {
		t.Fatal("removal did not preserve actual passkey login at new authority version")
	}
}

func TestPasswordHTTPNoopsKeepVerifierVersionAndSessionButConsumeGrantIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	for _, operation := range []string{"change", "remove"} {
		t.Run(operation, func(t *testing.T) {
			credential := "dual"
			if operation == "remove" {
				credential = "passkey_only"
			}
			a := f.account(t, credential, false)
			auth := f.authenticator(t, a)
			current, cookies := f.issue(t, a, session.MethodPasskey)
			grant := f.stepup(t, current, cookies, auth, a)
			before, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			beforeSession, err := f.manager.LookupByID(f.ctx, current.UserID, current.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret := a.secret
			if operation == "remove" {
				secret = ""
			}
			response := f.mutate(t, current, cookies, operation, secret, grant, "", 204)
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("authorized no-op cleared or replaced session cookie")
			}
			after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("authorized no-op rewrote verifier, version or account metadata", err)
			}
			afterSession, err := f.manager.LookupByID(f.ctx, current.UserID, current.ID)
			if err != nil || afterSession.ID != current.ID || afterSession.AuthVersion != beforeSession.AuthVersion || !afterSession.AbsoluteExpiry.Equal(beforeSession.AbsoluteExpiry) {
				t.Fatal("authorized no-op replaced or invalidated current session", err)
			}
			f.mutate(t, current, cookies, operation, secret, grant, "", 403)
		})
	}
}

func TestPasswordHTTPRealTOTPAuthorizationAndLastCredentialIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	for _, credential := range []string{"dual", "password_only"} {
		t.Run(credential, func(t *testing.T) {
			a := f.account(t, credential, true)
			current, cookies := f.issue(t, a, session.MethodPassword)
			grant := f.stepup(t, current, cookies, nil, a)
			if credential == "password_only" {
				response := f.mutate(t, current, cookies, "remove", "", grant, "", 409)
				if !strings.Contains(response.Body.String(), "last_credential") {
					t.Fatal("TOTP was treated as a retained primary credential")
				}
				f.assertState(t, a, a.user.AuthVersion, &a.secret)
				return
			}
			replacement := "TOTP authorized private secret"
			f.mutate(t, current, cookies, "change", replacement, grant, "", 204)
			f.assertState(t, a, a.user.AuthVersion+1, &replacement)
		})
	}
}

func (f *realPasswordFixture) proof(t *testing.T, current session.Session, cookies []*http.Cookie, secret string) string {
	t.Helper()
	challengeResponse := f.bound(t, current, cookies, "POST", passwordChangeProofPath+"/challenge", loginHTTPBody(t, map[string]string{"password": secret, "channel": "email"}), nil, 202)
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal(challengeResponse.Body.Bytes(), &challenge) != nil || challenge.Challenge == "" {
		t.Fatal("real password-change challenge missing")
	}
	verifyResponse := f.bound(t, current, cookies, "POST", passwordChangeProofPath+"/verify", loginHTTPBody(t, map[string]string{"challenge": challenge.Challenge, "code": f.delivery.last()}), nil, 200)
	var proof struct {
		Proof string `json:"action_proof"`
	}
	if json.Unmarshal(verifyResponse.Body.Bytes(), &proof) != nil || proof.Proof == "" || len(verifyResponse.Result().Cookies()) != 0 {
		t.Fatal("real purpose-bound proof missing or issued session authority")
	}
	return proof.Proof
}

func TestPasswordHTTPProofOnlyChangeNoopAndPurposeIsolationIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	for _, noop := range []bool{false, true} {
		t.Run(map[bool]string{false: "real change", true: "identical"}[noop], func(t *testing.T) {
			a := f.account(t, "password_only", false)
			loggedIn := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, 204)
			current, cookies := f.session(t, loggedIn), loggedIn.Result().Cookies()
			proof := f.proof(t, current, cookies, a.secret)
			tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			purposeErr := f.deletion.ConsumeTx(f.ctx, tx, current, proof)
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(purposeErr, actionproof.ErrInvalid) {
				t.Fatalf("password-change proof passed deletion consumer: %v", purposeErr)
			}
			f.mutate(t, current, cookies, "add", "private replacement secret", "", proof, 403)
			f.mutate(t, current, cookies, "remove", "", "", proof, 403)
			if err := f.proofs.CheckPasswordChange(f.ctx, current, proof); err != nil {
				t.Fatal("wrong operation consumed change-only proof", err)
			}
			before, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret, version := "private OTP replacement "+uuid.NewString(), a.user.AuthVersion+1
			if noop {
				secret, version = a.secret, a.user.AuthVersion
			}
			f.mutate(t, current, cookies, "change", secret, "", proof, 204)
			after := f.assertState(t, a, version, &secret)
			if noop && !reflect.DeepEqual(before, after) {
				t.Fatal("proof-authorized no-op changed verifier or version")
			}
			var remaining int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM password_change_action_proofs WHERE user_id=$1`, a.user.ID).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatal("proof was not atomically consumed for success/no-op", err)
			}
			want := 401
			if noop {
				want = 403
			}
			f.mutate(t, current, cookies, "change", secret, "", proof, want)
			response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": secret}, 204)
			if f.session(t, response).AuthVersion != version {
				t.Fatal("OTP-authorized password did not support actual username login")
			}
		})
	}
}

type passwordRollbackDatabase struct {
	passwordmanager.Beginner
	calls int
}
type passwordRollbackTx struct {
	pgx.Tx
	database *passwordRollbackDatabase
}

func (d *passwordRollbackDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.Beginner.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &passwordRollbackTx{tx, d}, nil
}

func (tx *passwordRollbackTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil && strings.HasPrefix(sql, "-- name: UpdateUserPassword ") {
		tx.database.calls++
		return tag, errors.New("injected failure after proof consumption and verifier write")
	}
	return tag, err
}

func TestPasswordHTTPRollbackRestoresProofAndVerifierIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "password_only", false)
	current, cookies := f.issue(t, a, session.MethodPassword)
	proof := f.proof(t, current, cookies, a.secret)
	database := &passwordRollbackDatabase{Beginner: f.pool}
	mutations, err := passwordmanager.New(passwordmanager.Deps{DB: database, Queries: db.New(f.pool), Sessions: f.manager, Limiter: f.limiter, Policy: accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}, Proofs: f.proofs})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.Passwords = mutations
	f.mutate(t, current, cookies, "change", "private rollback replacement", "", proof, 503)
	if database.calls != 1 {
		t.Fatal("rollback fault did not reach verifier write")
	}
	f.assertState(t, a, a.user.AuthVersion, &a.secret)
	if err := f.proofs.CheckPasswordChange(f.ctx, current, proof); err != nil {
		t.Fatal("rollback consumed proof", err)
	}
	if _, err := f.manager.LookupByID(f.ctx, current.UserID, current.ID); err != nil {
		t.Fatal("rollback revoked live session", err)
	}
	f.server.deps.Passwords = f.mutations
	replacement := "private rollback replacement"
	f.mutate(t, current, cookies, "change", replacement, "", proof, 204)
	f.assertState(t, a, a.user.AuthVersion+1, &replacement)
}

func TestPasswordHTTPRejectsAmbiguousAuthorizationBeforeConsumptionIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	auth := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	grant := f.stepup(t, current, cookies, auth, a)
	body := passwordMutationBody(t, "change", a.secret)
	for _, tc := range []struct {
		name    string
		headers http.Header
	}{
		{"missing", http.Header{}},
		{"duplicate grant", http.Header{stepup.HeaderStepUpAuth: {grant, grant}}},
		{"comma grant", http.Header{stepup.HeaderStepUpAuth: {grant + "," + grant}}},
		{"empty grant", http.Header{stepup.HeaderStepUpAuth: {""}}},
		{"oversized grant", http.Header{stepup.HeaderStepUpAuth: {strings.Repeat("x", 16*1024+1)}}},
		{"grant and proof", http.Header{stepup.HeaderStepUpAuth: {grant}, "X-Action-Proof": {"opaque"}}},
		{"duplicate proof", http.Header{"X-Action-Proof": {"opaque", "opaque"}}},
		{"comma proof", http.Header{"X-Action-Proof": {"opaque,opaque"}}},
		{"empty proof", http.Header{"X-Action-Proof": {""}}},
		{"oversized proof", http.Header{"X-Action-Proof": {strings.Repeat("x", 129)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.bound(t, current, cookies, "PUT", passwordPath, body, tc.headers, 403)
		})
	}
	for _, malformed := range []string{
		`{"operation":"change","new_password":"fixture\ud800password"}`,
		`{"operation":"change","new_password":"private fixture secret","new_password":"replacement"}`,
		`{"operation":"change","new_password":null}`,
		"{\"operation\":\"change\",\"new_password\":\"fixture\xffpassword\"}",
	} {
		f.bound(t, current, cookies, "PUT", passwordPath, malformed, http.Header{stepup.HeaderStepUpAuth: {grant}}, 400)
	}
	f.assertState(t, a, a.user.AuthVersion, &a.secret)
	// The same genuinely earned grant remains usable because every ambiguous
	// request was refused before single-use Step-up admission.
	f.mutate(t, current, cookies, "change", a.secret, grant, "", 204)
}

func TestPasswordHTTPRealWebAuthnRequiresUVIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	auth := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	challenge := f.bound(t, current, cookies, "POST", stepUpChallengePath, "", nil, 200)
	var options stepUpChallengeResponse
	if json.Unmarshal(challenge.Body.Bytes(), &options) != nil || options.WebAuthn == nil {
		t.Fatal("real UV ceremony options missing")
	}
	body, err := json.Marshal(map[string]any{"method": stepup.MethodWebAuthn, "assertion": json.RawMessage(f.assertion(t, auth, options.WebAuthn, false))})
	if err != nil {
		t.Fatal(err)
	}
	response := f.bound(t, current, cookies, "POST", stepUpVerifyPath, string(body), nil, 403)
	if !strings.Contains(response.Body.String(), "user_verification_required") || strings.Contains(response.Body.String(), `"token"`) {
		t.Fatal("signed UP-only assertion gained Step-up authority")
	}
	f.assertState(t, a, a.user.AuthVersion, &a.secret)
	grant := f.stepup(t, current, cookies, auth, a)
	f.mutate(t, current, cookies, "change", a.secret, grant, "", 204)
}

func TestPasswordHTTPOperationPolicyAndDisabledRemovalIntegration(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			f := newRealPasswordFixture(t, enabled)
			for _, mode := range []string{"add existing", "change absent", "missing username", "remove"} {
				t.Run(mode, func(t *testing.T) {
					credential, operation := "dual", "add"
					if mode == "change absent" {
						credential, operation = "passkey_only", "change"
					}
					if mode == "missing username" {
						credential, operation = "password_unclaimed", "change"
					}
					if mode == "remove" {
						operation = "remove"
					}
					a := f.account(t, credential, false)
					auth := f.authenticator(t, a)
					current, cookies := f.issue(t, a, session.MethodPasskey)
					grant := f.stepup(t, current, cookies, auth, a)
					secret, want := "private policy replacement", 409
					if mode == "remove" {
						secret, want = "", 204
					}
					response := f.mutate(t, current, cookies, operation, secret, grant, "", want)
					if want == 409 && !strings.Contains(response.Body.String(), "password_state_conflict") {
						t.Fatal("operation conflict exposed wrong error")
					}
					version, expectedSecret := a.user.AuthVersion, &a.secret
					if mode == "change absent" {
						expectedSecret = nil
					}
					if mode == "remove" {
						version++
						expectedSecret = nil
					}
					f.assertState(t, a, version, expectedSecret)
				})
			}
		})
	}
}

func TestPasswordHTTPProofEligibilityBindingsAndDeletionIsolationIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	for _, mode := range []string{"wrong password", "disabled channel", "passkey", "TOTP", "privileged", "foreign session", "foreign browser", "changed contact", "expired", "deletion proof"} {
		t.Run(mode, func(t *testing.T) {
			credential, totp := "password_only", false
			if mode == "passkey" {
				credential = "dual"
			}
			if mode == "TOTP" {
				totp = true
			}
			a := f.account(t, credential, totp)
			if mode == "privileged" {
				role := "password-" + uuid.NewString()
				if _, err := db.New(f.pool).CreateRole(f.ctx, db.CreateRoleParams{ID: role, Description: "Fixture role"}); err != nil {
					t.Fatal(err)
				}
				if err := db.New(f.pool).AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: a.user.ID, RoleID: role}); err != nil {
					t.Fatal(err)
				}
			}
			current, cookies := f.issue(t, a, session.MethodPassword)
			if mode == "wrong password" || mode == "disabled channel" || mode == "passkey" || mode == "TOTP" || mode == "privileged" {
				secret, channel := a.secret, "email"
				if mode == "wrong password" {
					secret = "wrong private fixture secret"
				}
				if mode == "disabled channel" {
					channel = "sms"
				}
				before := f.delivery.calls
				want := 403
				if mode == "disabled channel" {
					want = 503
				}
				f.bound(t, current, cookies, "POST", passwordChangeProofPath+"/challenge", loginHTTPBody(t, map[string]string{"password": secret, "channel": channel}), nil, want)
				if f.delivery.calls != before {
					t.Fatal("ineligible proof challenge dispatched contact code")
				}
				return
			}
			proof := f.proof(t, current, cookies, a.secret)
			switch mode {
			case "foreign session":
				current, cookies = f.issue(t, a, session.MethodPassword)
			case "foreign browser":
				other := newPortalTestClient(t, testPortalOrigin)
				other.validator = f.browser.validator
				foreign, foreignCookies := other.issueSession(t, f.manager, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: a.user.AuthVersion, AuthVersionSet: true, Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
				oldBrowser := f.browser
				f.browser = other
				defer func() { f.browser = oldBrowser }()
				current, cookies = foreign, foreignCookies
			case "changed contact":
				f.contact(t, a.user.ID, "email", uuid.NewString()+"@replacement.invalid")
			case "expired":
				if _, err := f.pool.Exec(f.ctx, `UPDATE password_change_action_proofs SET created_at=created_at-interval '10 minutes',expires_at=expires_at-interval '10 minutes' WHERE user_id=$1`, a.user.ID); err != nil {
					t.Fatal(err)
				}
			case "deletion proof":
				challenge, _, err := f.deletion.Challenge(f.ctx, current, a.secret, "email", "203.0.113.8")
				if err != nil {
					t.Fatal(err)
				}
				proof, _, err = f.deletion.Verify(f.ctx, current, challenge, f.delivery.last())
				if err != nil {
					t.Fatal(err)
				}
			}
			f.mutate(t, current, cookies, "change", "private rejected replacement", "", proof, 403)
			f.assertState(t, a, a.user.AuthVersion, &a.secret)
		})
	}
}

type passwordUnknownDatabase struct {
	passwordmanager.Beginner
	commits int
}
type passwordUnknownTx struct {
	pgx.Tx
	database *passwordUnknownDatabase
}

func (d *passwordUnknownDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := d.Beginner.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &passwordUnknownTx{tx, d}, nil
}

func (tx *passwordUnknownTx) Commit(ctx context.Context) error {
	if err := tx.Tx.Commit(ctx); err != nil {
		return err
	}
	tx.database.commits++
	return errors.New("injected lost positive commit acknowledgement")
}

func TestPasswordHTTPRealCommitLostAcknowledgementIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "password_only", false)
	current, cookies := f.issue(t, a, session.MethodPassword)
	proof := f.proof(t, current, cookies, a.secret)
	database := &passwordUnknownDatabase{Beginner: f.pool}
	mutations, err := passwordmanager.New(passwordmanager.Deps{DB: database, Queries: db.New(f.pool), Sessions: f.manager, Limiter: f.limiter, Policy: accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}, Proofs: f.proofs})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.Passwords = mutations
	replacement := "private unknown-outcome replacement " + uuid.NewString()
	response := f.mutate(t, current, cookies, "change", replacement, "", proof, 503)
	if !strings.Contains(response.Body.String(), "outcome_unknown") || database.commits != 1 {
		t.Fatal("uncertain commit retried or represented as confirmed outcome")
	}
	f.assertState(t, a, a.user.AuthVersion+1, &replacement)
	var remaining int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM password_change_action_proofs WHERE user_id=$1`, a.user.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("real unknown commit did not consume proof atomically", err)
	}
	f.mutate(t, current, cookies, "change", replacement, "", proof, 401)
	if database.commits != 1 {
		t.Fatal("unknown result retry committed a second mutation")
	}
	loggedIn := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": replacement}, 204)
	if f.session(t, loggedIn).AuthVersion != a.user.AuthVersion+1 {
		t.Fatal("fresh actual login did not recover unknown committed password")
	}
}

func TestPasswordHTTPPrivilegedRetainedPasskeyAndExactCreationBoundsIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "passkey_only", false)
	auth := f.authenticator(t, a)
	role := "password-" + uuid.NewString()
	q := db.New(f.pool)
	if _, err := q.CreateRole(f.ctx, db.CreateRoleParams{ID: role, Description: "Fixture role"}); err != nil {
		t.Fatal(err)
	}
	if err := q.AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: a.user.ID, RoleID: role}); err != nil {
		t.Fatal(err)
	}
	current, cookies := f.issue(t, a, session.MethodPasskey)
	minimum := strings.Repeat("\u0633", password.MinCodePoints)
	maximum := strings.Repeat("x", password.MaxPasswordBytes-36) + uuid.NewString()
	for index, secret := range []string{minimum, maximum} {
		operation := "add"
		if index != 0 {
			operation = "change"
		}
		grant := f.stepup(t, current, cookies, auth, a)
		f.mutate(t, current, cookies, operation, secret, grant, "", 204)
		f.assertState(t, a, a.user.AuthVersion+int64(index)+1, &secret)
		response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": secret}, 204)
		current, cookies = f.session(t, response), response.Result().Cookies()
	}
	grant := f.stepup(t, current, cookies, auth, a)
	f.mutate(t, current, cookies, "remove", "", grant, "", 204)
	f.assertState(t, a, a.user.AuthVersion+3, nil)
	count, err := q.CountWebauthnCredentialsByUser(f.ctx, a.user.ID)
	privileged, roleErr := q.UserHasPrivilegedRole(f.ctx, a.user.ID)
	if err != nil || roleErr != nil || count != 1 || !privileged {
		t.Fatal("privileged mutation lost required protection or role")
	}
}

func TestPasswordHTTPInadmissibleRetainedUsernameUnderUnchangedAuthorityIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	auth := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	grant := f.stepup(t, current, cookies, auth, a)
	var epoch int64
	if err := f.pool.QueryRow(f.ctx, `SELECT epoch FROM username_active_policy WHERE singleton`).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	// A wrong decryptor makes retained evidence unreadable without bypassing
	// the immutable username assignment or changing its policy authority.
	names, err := username.NewStore(f.pool, phoneIntegrationCipher(t), f.names.Normalizer())
	if err != nil {
		t.Fatal(err)
	}
	mutations, err := passwordmanager.New(passwordmanager.Deps{DB: f.pool, Queries: db.New(f.pool), Sessions: f.manager, Limiter: f.limiter, Policy: accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: names}, Proofs: f.proofs})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.Passwords = mutations
	f.mutate(t, current, cookies, "change", "private inadmissible replacement", grant, "", 503)
	f.assertState(t, a, a.user.AuthVersion, &a.secret)
	var afterEpoch int64
	if err := f.pool.QueryRow(f.ctx, `SELECT epoch FROM username_active_policy WHERE singleton`).Scan(&afterEpoch); err != nil || afterEpoch != epoch {
		t.Fatal("username rejection accidentally tested changed policy authority")
	}
}

type passwordTouchFailureStore struct {
	session.Store
	touches int
}

func (s *passwordTouchFailureStore) Touch(context.Context, string, time.Time) error {
	s.touches++
	return session.ErrStoreUnavailable
}

func TestPasswordHTTPConfirmedNoopSurvivesRedisRenewalFailureIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	auth := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	grant := f.stepup(t, current, cookies, auth, a)
	store, err := session.NewRedisStore(f.sessionClient)
	if err != nil {
		t.Fatal(err)
	}
	failure := &passwordTouchFailureStore{Store: store}
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "__Host-session", Secure: true, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(failure, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, AccountState: f.accounts})
	if err != nil {
		t.Fatal(err)
	}
	f.server.deps.SessionManager = manager
	// Rebuild the real guard because its manager is captured when routes mount.
	f.server = New(f.server.cfg, f.server.logger, f.server.deps)
	before, err := f.manager.LookupByID(f.ctx, current.UserID, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	response := f.mutate(t, current, cookies, "change", a.secret, grant, "", 204)
	if failure.touches != 1 || len(response.Result().Cookies()) != 0 {
		t.Fatal("confirmed no-op was overwritten by renewal failure or rotated session")
	}
	f.assertState(t, a, a.user.AuthVersion, &a.secret)
	after, err := f.manager.LookupByID(f.ctx, current.UserID, current.ID)
	if err != nil || !after.AbsoluteExpiry.Equal(before.AbsoluteExpiry) || !after.IdleExpiry.Equal(before.IdleExpiry) {
		t.Fatal("renewal failure invalidated or extended confirmed no-op session", err)
	}
}
