package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/token"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

const (
	testStepUpIssuer    = "https://identity.test"
	stepUpChallengePath = "/api/v1/auth/stepup/challenge"
	stepUpVerifyPath    = "/api/v1/auth/stepup/verify"
	mfaDisablePath      = "/api/v1/auth/mfa/"
)

// --- Shared step-up test helpers -------------------------------------------
//
// These are exercised here and reused by every suite whose routes became
// step-up gated (mfa_test, recovery_test, webauthn_test, phone_test).

// stepUpFakeUserStore is a minimal stepup.UserStore.
type stepUpFakeUserStore struct {
	byID map[uuid.UUID]db.User
}

func newStepUpFakeUserStore(users ...db.User) *stepUpFakeUserStore {
	byID := make(map[uuid.UUID]db.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	return &stepUpFakeUserStore{byID: byID}
}

func (f *stepUpFakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

// stepUpFakePasskeys is a stepup.PasskeyVerifier whose outcome each test sets
// directly. The WebAuthn ceremony itself — including the user-verification
// enforcement this package depends on — is covered in internal/webauthn; here we
// only exercise routing and error mapping.
type stepUpFakePasskeys struct {
	beginErr        error
	finishErr       error
	finished        int
	beginSessionID  string
	finishSessionID string
}

func (f *stepUpFakePasskeys) BeginStepUp(
	_ context.Context,
	_ uuid.UUID,
	sessionID string,
) (*protocol.CredentialAssertion, error) {
	f.beginSessionID = sessionID
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge:        protocol.URLEncodedBase64("test-challenge"),
			RelyingPartyID:   "localhost",
			UserVerification: protocol.VerificationRequired,
		},
	}, nil
}

func (f *stepUpFakePasskeys) FinishStepUp(
	_ context.Context,
	_ uuid.UUID,
	sessionID string,
	_ []byte,
) error {
	f.finished++
	f.finishSessionID = sessionID
	return f.finishErr
}

// stepUpFakeTOTP is a stepup.TOTPVerifier accepting one fixed passcode.
type stepUpFakeTOTP struct {
	valid string
	calls int
}

func (f *stepUpFakeTOTP) VerifyEnabledCode(_ context.Context, _ uuid.UUID, code string) error {
	f.calls++
	if code != f.valid {
		return mfa.ErrInvalidCode
	}
	return nil
}

// newTestStepUpService builds a step-up service over ephemeral ES256 keys, so a
// grant it mints verifies against the same keystore the middleware consults. The
// keystore is returned as well so a test can sign a deliberately wrong-purpose
// token with the very key the validator trusts.
func newTestStepUpService(
	t *testing.T,
	users stepup.UserStore,
	passkeys stepup.PasskeyVerifier,
	totp stepup.TOTPVerifier,
) (*stepup.Service, *keys.Manager) {
	t.Helper()

	active, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("keys.NewEphemeralES256: %v", err)
	}
	next, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("keys.NewEphemeralES256: %v", err)
	}
	km, err := keys.NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("keys.NewManager: %v", err)
	}

	svc, err := stepup.New(
		stepup.Config{Issuer: testStepUpIssuer},
		km, users, passkeys, totp, stepup.NewMemoryReplayGuard(),
	)
	if err != nil {
		t.Fatalf("stepup.New: %v", err)
	}
	return svc, km
}

// newStepUpServiceForUser is the common case used by the other suites: an active
// account with TOTP enabled and one fixed valid passcode.
func newStepUpServiceForUser(t *testing.T, userID uuid.UUID) *stepup.Service {
	t.Helper()
	svc, _ := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
		nil,
		&stepUpFakeTOTP{valid: "000000"},
	)
	return svc
}

// signImpostorToken signs a token carrying every claim a valid grant carries, but
// with a caller-chosen typ header and acr claim, using the same key the step-up
// validator trusts. It is how the token-substitution defences are exercised.
func signImpostorToken(t *testing.T, km *keys.Manager, typ, sub, sid, acr string) string {
	t.Helper()

	now := time.Now()
	compact, err := token.Sign(km.ActiveSigner(), typ, token.Claims{
		"iss":       testStepUpIssuer,
		"sub":       sub,
		"aud":       testStepUpIssuer,
		"acr":       acr,
		"amr":       []string{"otp"},
		"auth_time": now.Unix(),
		"sid":       sid,
		"jti":       uuid.NewString(),
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("token.Sign: %v", err)
	}
	return compact
}

// mintTestGrant signs a fresh single-use grant bound to the given session.
func mintTestGrant(t *testing.T, svc *stepup.Service, userID, sessionID string) string {
	t.Helper()

	token, _, err := svc.Mint(stepup.MintParams{
		UserID:    userID,
		SessionID: sessionID,
		AMR:       []string{"otp"},
	})
	if err != nil {
		t.Fatalf("stepup.Mint: %v", err)
	}
	return token
}

// --- Tests -----------------------------------------------------------------

// TestStepUpChallengeListsAvailableFactors covers the three shapes of the
// challenge response: both factors, TOTP only, and no factor at all.
func TestStepUpChallengeListsAvailableFactors(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name        string
		mfaEnabled  bool
		passkeys    stepup.PasskeyVerifier
		wantStatus  int
		wantMethods []string
		wantOptions bool
	}{
		{
			name:        "passkey and totp",
			mfaEnabled:  true,
			passkeys:    &stepUpFakePasskeys{},
			wantStatus:  http.StatusOK,
			wantMethods: []string{stepup.MethodWebAuthn, stepup.MethodTOTP},
			wantOptions: true,
		},
		{
			name:        "totp only when no passkey is enrolled",
			mfaEnabled:  true,
			passkeys:    &stepUpFakePasskeys{beginErr: webauthn.ErrNoCredentials},
			wantStatus:  http.StatusOK,
			wantMethods: []string{stepup.MethodTOTP},
		},
		{
			name:       "no factor enrolled",
			mfaEnabled: false,
			passkeys:   &stepUpFakePasskeys{beginErr: webauthn.ErrNoCredentials},
			wantStatus: http.StatusConflict,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestStepUpService(t,
				newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: tc.mfaEnabled}),
				tc.passkeys,
				&stepUpFakeTOTP{valid: "000000"},
			)
			fx := newStepUpFixture(t, userID, svc)

			rec := fx.do(t, http.MethodPost, stepUpChallengePath, nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d (%s)", tc.wantStatus, rec.Code, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK {
				return
			}

			var body stepUpChallengeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal challenge: %v", err)
			}
			if len(body.Methods) != len(tc.wantMethods) {
				t.Fatalf("expected methods %v, got %v", tc.wantMethods, body.Methods)
			}
			for i, want := range tc.wantMethods {
				if body.Methods[i] != want {
					t.Fatalf("method %d: expected %q, got %q", i, want, body.Methods[i])
				}
			}
			if tc.wantOptions != (body.WebAuthn != nil) {
				t.Fatalf("expected webauthn options present=%v", tc.wantOptions)
			}
		})
	}
}

func TestStepUpHandlersBindWebAuthnCeremonyToCurrentSession(t *testing.T) {
	userID := uuid.New()
	passkeys := &stepUpFakePasskeys{}
	svc, _ := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active"}),
		passkeys,
		nil,
	)
	fx := newStepUpFixture(t, userID, svc)

	if rec := fx.do(t, http.MethodPost, stepUpChallengePath, nil); rec.Code != http.StatusOK {
		t.Fatalf("challenge: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if passkeys.beginSessionID != fx.sess.ID {
		t.Fatalf("BeginStepUp session = %q, want current session %q", passkeys.beginSessionID, fx.sess.ID)
	}

	rec := fx.verify(t, `{"method":"webauthn","assertion":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if passkeys.finishSessionID != fx.sess.ID {
		t.Fatalf("FinishStepUp session = %q, want current session %q", passkeys.finishSessionID, fx.sess.ID)
	}
}

// TestStepUpVerifyIssuesUsableGrant confirms a verified factor yields a
// no-store grant that actually satisfies the gate it was minted for.
func TestStepUpVerifyIssuesUsableGrant(t *testing.T) {
	userID := uuid.New()
	svc := newStepUpServiceForUser(t, userID)
	fx := newStepUpFixture(t, userID, svc)

	rec := fx.verify(t, `{"method":"totp","code":"000000"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}

	var body stepUpVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal verify: %v", err)
	}
	if body.Token == "" {
		t.Fatal("expected a grant token")
	}
	if body.ACR != stepup.ACRStepUp {
		t.Fatalf("expected acr %q, got %q", stepup.ACRStepUp, body.ACR)
	}
	if body.TokenType != "StepUp" {
		t.Fatalf("expected token_type StepUp, got %q", body.TokenType)
	}
	if body.ExpiresIn <= 0 {
		t.Fatalf("expected a positive expires_in, got %d", body.ExpiresIn)
	}

	if code := fx.sendWithGrant(t, body.Token); code == http.StatusForbidden {
		t.Fatal("a freshly minted grant was rejected by the gate it was issued for")
	}
}

// TestStepUpVerifyRejectsReplayedPasscode confirms one passcode cannot mint two
// grants, closing the window the TOTP ±1-step tolerance would otherwise leave.
func TestStepUpVerifyRejectsReplayedPasscode(t *testing.T) {
	userID := uuid.New()
	totp := &stepUpFakeTOTP{valid: "000000"}
	svc, _ := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
		nil, totp,
	)
	fx := newStepUpFixture(t, userID, svc)

	if rec := fx.verify(t, `{"method":"totp","code":"000000"}`); rec.Code != http.StatusOK {
		t.Fatalf("first verify: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	rec := fx.verify(t, `{"method":"totp","code":"000000"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed passcode: expected 401, got %d (%s)", rec.Code, rec.Body.String())
	}
	// The replay must be caught before the verifier runs again, or the guard is
	// decorative rather than protective.
	if totp.calls != 1 {
		t.Fatalf("expected the TOTP verifier to be consulted once, got %d", totp.calls)
	}
}

// TestStepUpVerifyErrorMapping pins the status codes the portal branches on.
func TestStepUpVerifyErrorMapping(t *testing.T) {
	userID := uuid.New()

	tests := []struct {
		name       string
		body       string
		passkeys   stepup.PasskeyVerifier
		wantStatus int
		wantError  string
	}{
		{
			name:       "wrong passcode is opaque",
			body:       `{"method":"totp","code":"999999"}`,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_credentials",
		},
		{
			name:       "unknown method",
			body:       `{"method":"carrier-pigeon"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "unsupported_method",
		},
		{
			// Recovery codes are a login bypass, not a step-up factor: accepting
			// one would let a stolen code authorise the very operations the gate
			// protects, including regenerating the code batch itself.
			name:       "recovery codes are not a step-up factor",
			body:       `{"method":"recovery_code","code":"ABCDEFGH"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "unsupported_method",
		},
		{
			name:       "assertion without user verification is actionable",
			body:       `{"method":"webauthn","assertion":{}}`,
			passkeys:   &stepUpFakePasskeys{finishErr: webauthn.ErrUserVerificationRequired},
			wantStatus: http.StatusForbidden,
			wantError:  "user_verification_required",
		},
		{
			name:       "failed assertion is opaque",
			body:       `{"method":"webauthn","assertion":{}}`,
			passkeys:   &stepUpFakePasskeys{finishErr: webauthn.ErrVerification},
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_credentials",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestStepUpService(t,
				newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
				tc.passkeys,
				&stepUpFakeTOTP{valid: "000000"},
			)
			fx := newStepUpFixture(t, userID, svc)

			rec := fx.verify(t, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d (%s)", tc.wantStatus, rec.Code, rec.Body.String())
			}
			var body stepUpErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if body.Error != tc.wantError {
				t.Fatalf("expected error %q, got %q", tc.wantError, body.Error)
			}
		})
	}
}

// TestStepUpGatedRoutesChallengeWithoutGrant walks the gated routes and asserts
// the 403 challenge shape, which is what tells the SPA to open the step-up
// overlay instead of bouncing the user through a full login.
func TestStepUpGatedRoutesChallengeWithoutGrant(t *testing.T) {
	userID := uuid.New()
	svc := newStepUpServiceForUser(t, userID)
	fx := newStepUpFixture(t, userID, svc)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodDelete, mfaDisablePath},
		{http.MethodPost, recoveryGeneratePath},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := fx.do(t, route.method, route.path, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
			}

			var body struct {
				Error     string `json:"error"`
				ACRValues string `json:"acr_values"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal challenge: %v", err)
			}
			if body.Error != "insufficient_user_authentication" {
				t.Fatalf("expected insufficient_user_authentication, got %q", body.Error)
			}
			if body.ACRValues != stepup.ACRStepUp {
				t.Fatalf("expected acr_values %q, got %q", stepup.ACRStepUp, body.ACRValues)
			}
		})
	}
}

// TestStepUpGrantIsSingleUse confirms the middleware consumes the grant, so a
// captured header cannot authorise a second sensitive operation.
func TestStepUpGrantIsSingleUse(t *testing.T) {
	userID := uuid.New()
	svc := newStepUpServiceForUser(t, userID)
	fx := newStepUpFixture(t, userID, svc)

	grant := mintTestGrant(t, svc, fx.sess.UserID, fx.sess.ID)

	if code := fx.sendWithGrant(t, grant); code == http.StatusForbidden {
		t.Fatal("first use of a fresh grant was rejected")
	}
	if code := fx.sendWithGrant(t, grant); code != http.StatusForbidden {
		t.Fatalf("replayed grant: expected 403, got %d", code)
	}
}

// TestStepUpGrantIsBoundToItsSession confirms a grant minted for one session
// cannot be paired with another session's cookie, even for the same subject.
func TestStepUpGrantIsBoundToItsSession(t *testing.T) {
	userID := uuid.New()
	svc := newStepUpServiceForUser(t, userID)
	fx := newStepUpFixture(t, userID, svc)

	foreign := mintTestGrant(t, svc, fx.sess.UserID, uuid.NewString())
	if code := fx.sendWithGrant(t, foreign); code != http.StatusForbidden {
		t.Fatalf("expected 403 for a foreign-session grant, got %d", code)
	}
}

// TestStepUpGrantRejectsAccessToken is the token-substitution guard.
//
// Access tokens, ID tokens, and step-up grants are all signed by the same
// keystore, and access tokens already use aud == iss, so a token minted for a
// different purpose must be rejected on its typ header before any claim is
// trusted. This is the highest-severity failure mode of the whole design.
func TestStepUpGrantRejectsAccessToken(t *testing.T) {
	userID := uuid.New()
	svc, km := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
		nil,
		&stepUpFakeTOTP{valid: "000000"},
	)
	fx := newStepUpFixture(t, userID, svc)

	// A token with every claim a valid grant carries, but the access-token typ.
	impostor := signImpostorToken(t, km, token.TypAccessToken, fx.sess.UserID, fx.sess.ID, stepup.ACRStepUp)
	if code := fx.sendWithGrant(t, impostor); code != http.StatusForbidden {
		t.Fatalf("an at+jwt token was accepted as a step-up grant (status %d)", code)
	}

	// And the mirror case: correct typ, but not the step-up ACR.
	noACR := signImpostorToken(t, km, token.TypStepUpToken, fx.sess.UserID, fx.sess.ID, "urn:example:weak")
	if code := fx.sendWithGrant(t, noACR); code != http.StatusForbidden {
		t.Fatalf("a token without the step-up acr was accepted (status %d)", code)
	}

	// Control: the same helper with the right typ and acr must be accepted, so
	// the two rejections above are attributable to the checks under test rather
	// than to the impostor being malformed.
	valid := signImpostorToken(t, km, token.TypStepUpToken, fx.sess.UserID, fx.sess.ID, stepup.ACRStepUp)
	if code := fx.sendWithGrant(t, valid); code == http.StatusForbidden {
		t.Fatal("a correctly formed grant was rejected; the impostor tests prove nothing")
	}
}

// TestStepUpGatedRoutesAbsentWithoutService is the fail-closed guarantee: with no
// step-up service configured, a route documented as step-up gated must not exist
// at all rather than be served without its gate.
func TestStepUpGatedRoutesAbsentWithoutService(t *testing.T) {
	fx := setupMFATestFixture(t)

	// Sanity: the pending-enrollment finish sibling remains mounted, so a 404 below means
	// "this route was withheld", not "no routes were registered".
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", nil)
	req.AddCookie(fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatal("expected the session-bound MFA finish route to remain mounted")
	}

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodDelete, mfaDisablePath},
		{http.MethodPost, stepUpChallengePath},
		{http.MethodPost, stepUpVerifyPath},
	} {
		req := httptest.NewRequest(route.method, route.path, nil)
		req.AddCookie(fx.cookie)
		rec := httptest.NewRecorder()
		fx.server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: expected the route to be withheld, got %d",
				route.method, route.path, rec.Code)
		}
	}
}

// --- Fixture ---------------------------------------------------------------

// stepUpFixture is a server with a live session, a step-up service, and the two
// gated subsystems the step-up tests probe.
type stepUpFixture struct {
	server *Server
	sess   session.Session
	cookie *http.Cookie
	stepUp *stepup.Service
}

func newStepUpFixture(t *testing.T, userID uuid.UUID, stepUpSvc *stepup.Service) *stepUpFixture {
	t.Helper()

	sessMgr := newRecoverySessionManager(t)

	w := httptest.NewRecorder()
	sess, err := sessMgr.Issue(w, session.IssueParams{
		UserID:    userID.String(),
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("sessMgr.Issue: %v", err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("session cookie was not set")
	}

	// The MFA and recovery services exist only so their gated routes are mounted
	// to be probed; their behaviour is covered by their own suites.
	mfaStore := &mfaFakeStore{users: map[uuid.UUID]*mfaTestUser{
		userID: {id: userID, email: "stepup@example.com"},
	}}
	mfaSvc, err := mfa.New(mfa.Config{}, mfaStore, &mfaTestEncryptor{})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	recoveryStore := newRecoveryFakeStore()
	recoveryStore.users[userID] = db.User{ID: userID, Status: "active"}
	recoverySvc, err := recovery.New(recovery.Config{}, recoveryStore)
	if err != nil {
		t.Fatalf("recovery.New: %v", err)
	}

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		MFA:            mfaSvc,
		Recovery:       recoverySvc,
		StepUp:         stepUpSvc,
	})

	return &stepUpFixture{server: srv, sess: sess, cookie: cookie, stepUp: stepUpSvc}
}

// do issues a request carrying the session cookie but no step-up grant.
func (fx *stepUpFixture) do(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.AddCookie(fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// verify posts a step-up verify request.
func (fx *stepUpFixture) verify(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return fx.do(t, http.MethodPost, stepUpVerifyPath, []byte(body))
}

// sendWithGrant presents the given grant at a gated route and reports the status.
func (fx *stepUpFixture) sendWithGrant(t *testing.T, grant string) int {
	t.Helper()

	req := httptest.NewRequest(http.MethodDelete, mfaDisablePath, nil)
	req.AddCookie(fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, grant)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec.Code
}
