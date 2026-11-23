package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type mfaTestUser struct {
	id      uuid.UUID
	email   string
	secret  []byte
	mfaOn   bool
	version int64
}

type mfaFakeStore struct {
	users       map[uuid.UUID]*mfaTestUser
	enrollments map[uuid.UUID]db.MfaTotpEnrollment
}

func (f *mfaFakeStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return db.User{
		ID:                     u.id,
		Email:                  &u.email,
		MfaTotpSecretEncrypted: u.secret,
		IsMfaEnabled:           u.mfaOn,
		Status:                 "active",
		AuthVersion:            u.version,
	}, nil
}

func TestMFAMutationsRejectStaleOrUncapturedSessions(t *testing.T) {
	for _, operation := range []string{"setup", "enable", "disable"} {
		for _, captured := range []bool{true, false} {
			t.Run(operation+"/"+map[bool]string{true: "stale", false: "uncaptured"}[captured], func(t *testing.T) {
				fx := setupMFATestFixtureWithStepUp(t)
				setup, err := fx.server.deps.MFA.GenerateSetup(t.Context(), fx.sess, mfaAuthorizationForSession(fx.sess, mfa.AuthorizationWebAuthnUV))
				if err != nil {
					t.Fatal(err)
				}
				grant := fx.grantHeader(t)
				fx.user.version = 1
				if operation == "disable" {
					fx.user.mfaOn = true
					fx.user.secret = []byte("active-secret")
				}
				fx.sess.AuthVersionSet = captured
				recorder := &profileAuditRecorder{}
				fx.server.deps.AuditRecorder = recorder
				body, err := json.Marshal(mfaVerifyRequest{EnrollmentID: setup.EnrollmentID, Code: "123456"})
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa", nil)
				if operation == "enable" {
					req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req.Header.Set(stepup.HeaderStepUpAuth, grant)
				}
				req = req.WithContext(session.WithSession(req.Context(), fx.sess))
				response := httptest.NewRecorder()
				switch operation {
				case "setup":
					fx.server.handleMFAGenerate()(response, req)
				case "enable":
					fx.server.handleMFAVerify()(response, req)
				case "disable":
					fx.server.handleMFADisable()(response, req)
				}
				if response.Code != http.StatusUnauthorized || len(fx.store.enrollments) != 1 || fx.user.mfaOn != (operation == "disable") {
					t.Fatalf("refused mutation changed credentials: status %d", response.Code)
				}
				for _, event := range recorder.events {
					if event.ActionStatus == "success" {
						t.Fatal("refused mutation recorded success")
					}
				}
			})
		}
	}
}

func (f *mfaFakeStore) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

// GetUserByIDForAdmin satisfies the soft-delete-blind lookup mfa.UserStore now
// requires for VerifyTOTPForReclaim. These handler tests never exercise the reclaim
// path, so it simply delegates.
func (f *mfaFakeStore) GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

func (f *mfaFakeStore) CountWebauthnCredentialsByUser(context.Context, uuid.UUID) (int64, error) {
	return 1, nil
}

func (f *mfaFakeStore) RevokeUserCredentials(_ context.Context, id uuid.UUID) error {
	f.users[id].version++
	return nil
}

func (f *mfaFakeStore) DeleteMfaTotpEnrollmentsForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for id, row := range f.enrollments {
		if row.UserID == userID {
			delete(f.enrollments, id)
			count++
		}
	}
	return count, nil
}

func (f *mfaFakeStore) CreateMfaTotpEnrollment(_ context.Context, arg db.CreateMfaTotpEnrollmentParams) (db.MfaTotpEnrollment, error) {
	row := db.MfaTotpEnrollment{
		ID:                  uuid.New(),
		UserID:              arg.UserID,
		SessionID:           arg.SessionID,
		Purpose:             arg.Purpose,
		SecretEncrypted:     arg.SecretEncrypted,
		ExpiresAt:           arg.ExpiresAt,
		AuthVersion:         arg.AuthVersion,
		Jkt:                 arg.Jkt,
		AuthorizationMethod: arg.AuthorizationMethod,
		Channel:             arg.Channel,
		ContactBinding:      append([]byte(nil), arg.ContactBinding...),
		CreatedAt:           pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	f.enrollments[row.ID] = row
	return row, nil
}

func (f *mfaFakeStore) GetMfaTotpEnrollmentForUpdate(_ context.Context, arg db.GetMfaTotpEnrollmentForUpdateParams) (db.MfaTotpEnrollment, error) {
	row, ok := f.enrollments[arg.ID]
	if !ok || row.UserID != arg.UserID || row.SessionID != arg.SessionID || row.Purpose != arg.Purpose {
		return db.MfaTotpEnrollment{}, pgx.ErrNoRows
	}
	return row, nil
}

func (f *mfaFakeStore) IncrementMfaTotpEnrollmentAttempts(_ context.Context, id uuid.UUID) (int64, error) {
	row, ok := f.enrollments[id]
	if !ok {
		return 0, nil
	}
	row.FailedAttempts++
	f.enrollments[id] = row
	return 1, nil
}

func (f *mfaFakeStore) DeleteMfaTotpEnrollment(_ context.Context, id uuid.UUID) (int64, error) {
	if _, ok := f.enrollments[id]; !ok {
		return 0, nil
	}
	delete(f.enrollments, id)
	return 1, nil
}

func (f *mfaFakeStore) CompleteMfaTotpEnrollment(_ context.Context, arg db.CompleteMfaTotpEnrollmentParams) (int64, error) {
	u, ok := f.users[arg.ID]
	if !ok || u.mfaOn {
		return 0, nil
	}
	u.secret = arg.MfaTotpSecretEncrypted
	u.mfaOn = true
	return 1, nil
}

func (f *mfaFakeStore) SetMfaTotpSecret(_ context.Context, arg db.SetMfaTotpSecretParams) (int64, error) {
	u, ok := f.users[arg.ID]
	if !ok {
		return 0, nil
	}
	u.secret = arg.MfaTotpSecretEncrypted
	return 1, nil
}

func (f *mfaFakeStore) EnableMfa(_ context.Context, id uuid.UUID) (int64, error) {
	u, ok := f.users[id]
	if !ok || len(u.secret) == 0 {
		return 0, nil
	}
	u.mfaOn = true
	return 1, nil
}

func (f *mfaFakeStore) DisableMfa(_ context.Context, id uuid.UUID) (int64, error) {
	u, ok := f.users[id]
	if !ok {
		return 0, nil
	}
	u.mfaOn = false
	u.secret = nil
	return 1, nil
}

type mfaTestEncryptor struct{}

func (e *mfaTestEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte("enc_"), plaintext...), nil
}

func (e *mfaTestEncryptor) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4 || string(ciphertext[:4]) != "enc_" {
		return nil, mfa.ErrDecryptFailed
	}
	return append([]byte(nil), ciphertext[4:]...), nil
}

type mfaTestFixture struct {
	server       *Server
	browser      *portalTestClient
	store        *mfaFakeStore
	user         *mfaTestUser
	sess         session.Session
	cookie       *http.Cookie
	sessMgr      *session.Manager
	sessionStore *boundaryStore
	// stepUp is nil for the default fixture, which deliberately has no step-up
	// service so the fail-closed behaviour of the gated DELETE route stays
	// covered. setupMFATestFixtureWithStepUp populates it.
	stepUp *stepup.Service
}

// grantHeader mints a fresh single-use step-up grant for this fixture's session.
func (fx *mfaTestFixture) grantHeader(t *testing.T) string {
	t.Helper()
	if fx.stepUp == nil {
		t.Fatal("fixture has no step-up service")
	}
	return mintMFAGrant(t, fx.stepUp, fx.sess, []string{"hwk", "user"})
}

func mfaAuthorizationForSession(sess session.Session, method string) mfa.Authorization {
	return mfa.Authorization{UserID: sess.UserID, SessionID: sess.ID, JKT: sess.DPoPJKT,
		AuthVersion: sess.AuthVersion, Method: method, ExpiresAt: time.Now().Add(5 * time.Minute)}
}

func mintMFAGrant(t *testing.T, svc *stepup.Service, sess session.Session, amr []string) string {
	t.Helper()
	grant, _, err := svc.Mint(stepup.MintParams{UserID: sess.UserID, SessionID: sess.ID,
		DPoPJKT: sess.DPoPJKT, AuthVersion: sess.AuthVersion, AuthVersionSet: sess.AuthVersionSet, AMR: amr})
	if err != nil {
		t.Fatal("mint MFA grant", err)
	}
	return grant
}

func setupMFATestFixture(t *testing.T) *mfaTestFixture {
	t.Helper()
	return newMFATestFixture(t, false)
}

// setupMFATestFixtureWithStepUp additionally wires a step-up service, which is
// what mounts DELETE /api/v1/auth/mfa at all.
func setupMFATestFixtureWithStepUp(t *testing.T) *mfaTestFixture {
	t.Helper()
	return newMFATestFixture(t, true)
}

func newMFATestFixture(t *testing.T, withStepUp bool) *mfaTestFixture {
	t.Helper()

	store := &mfaFakeStore{
		users:       make(map[uuid.UUID]*mfaTestUser),
		enrollments: make(map[uuid.UUID]db.MfaTotpEnrollment),
	}
	u := &mfaTestUser{
		id:    uuid.New(),
		email: "mfauser@example.com",
	}
	store.users[u.id] = u

	enc := &mfaTestEncryptor{}
	mfaSvc, err := mfa.New(mfa.Config{Issuer: "Hatef Test"}, store, enc)
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	codec, err := session.NewCookieCodec(session.CookieConfig{
		Name:   "session",
		Secure: false,
		TTL:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}

	sessionStore := &boundaryStore{Store: session.NewMemoryStore()}
	sessMgr, err := session.NewManager(sessionStore, codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	browser := newPortalTestClient(t, testPortalOrigin)
	// Pre-issue a session bound to the fixture's real browser key.
	w := httptest.NewRecorder()
	sess, err := sessMgr.Issue(w, session.IssueParams{
		UserID:         u.id.String(),
		AuthVersionSet: true,
		IP:             "127.0.0.1",
		UserAgent:      "test-agent",
		DPoPJKT:        browser.jkt,
		Evidence:       session.Evidence{PrimaryMethod: session.MethodPasskey, UV: session.UVVerified, TOTPSet: true, AuthenticatedAt: time.Now().UTC()},
	})
	if err != nil {
		t.Fatalf("sessMgr.Issue: %v", err)
	}
	res := w.Result()
	cookies := res.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session" {
			sessionCookie = c
			break
		}
	}

	var stepUpSvc *stepup.Service
	if withStepUp {
		stepUpSvc, _ = newTestStepUpService(t,
			newStepUpFakeUserStore(db.User{ID: u.id, Status: "active", IsMfaEnabled: true}),
			nil,
			&stepUpFakeTOTP{valid: "000000"},
		)
	}

	srv := New(config.Config{Environment: "development", PortalOrigin: browser.origin}, nil, Deps{
		SessionManager: sessMgr,
		DPoPValidator:  browser.validator,
		MFA:            mfaSvc,
		StepUp:         stepUpSvc,
	})

	return &mfaTestFixture{
		server:       srv,
		browser:      browser,
		store:        store,
		user:         u,
		sess:         sess,
		cookie:       sessionCookie,
		sessMgr:      sessMgr,
		stepUp:       stepUpSvc,
		sessionStore: sessionStore,
	}
}

func TestMFARoutesEndToEnd(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	// 1. Generate Setup
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "private, no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("TOTP secret response is cacheable: Cache-Control=%q Pragma=%q", rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	}

	var genResp mfa.SetupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("unmarshal setup response: %v", err)
	}
	if len(genResp.Secret) != 32 {
		t.Errorf("expected 32-char secret, got %q", genResp.Secret)
	}

	if genResp.ExpiresAt.IsZero() || !genResp.ExpiresAt.Equal(fx.store.enrollments[uuid.MustParse(genResp.EnrollmentID)].ExpiresAt.Time) {
		t.Fatal("setup response lost frozen enrollment deadline")
	}
	// 2. Verify with a code outside all accepted time steps.
	wrong := wrongMFAHTTPCode(t, genResp.Secret, time.Now())
	verifyBody, _ := json.Marshal(map[string]string{"enrollment_id": genResp.EnrollmentID, "code": wrong})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(verifyBody))
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("verify with wrong code: expected 400 Bad Request, got %d", rec.Code)
	}

	// 3. Verify with valid TOTP code
	now := time.Now().UTC()
	validCode, err := totp.GenerateCode(genResp.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	verifyBody, _ = json.Marshal(map[string]string{"enrollment_id": genResp.EnrollmentID, "code": validCode})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(verifyBody))
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Check DB status
	if !fx.user.mfaOn {
		t.Error("expected user mfaOn = true")
	}
	if fx.user.version != 1 || rec.Header().Get(session.HeaderAuthInvalidated) != "true" {
		t.Fatal("successful TOTP enrollment did not revoke initiating authority")
	}

	// 4. The former public enabled-code oracle is absent.
	verifyCodeBody, _ := json.Marshal(map[string]string{"code": validCode})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify-code", bytes.NewReader(verifyCodeBody))
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("verify-code: expected 404 Not Found, got %d", rec.Code)
	}

	// 5. Disable rejects the old earned account version, even with a fresh grant.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !fx.user.mfaOn || fx.user.version != 1 {
		t.Fatal("earlier authentication survived committed TOTP enrollment")
	}
	// The fresh sign-in fixture carries the newly earned version and TOTP evidence.
	var cookies []*http.Cookie
	fx.sess, cookies = fx.browser.issueSession(t, fx.sessMgr, session.IssueParams{
		UserID: fx.user.id.String(), AuthVersion: fx.user.version, AuthVersionSet: true,
		Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, TOTP: true, AuthenticatedAt: time.Now().UTC()},
	})
	fx.cookie = cookies[0]
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("disable: expected 204 No Content, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	if fx.user.mfaOn {
		t.Error("expected user mfaOn = false after disable")
	}
	if fx.user.version != 2 || rec.Header().Get(session.HeaderAuthInvalidated) != "true" {
		t.Fatal("TOTP disable did not revoke exactly once")
	}
}

func TestMFARoutesRequireSession(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	// Call without cookie
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	fx.browser.prepare(req)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	requirePortalSessionRequired(t, rec)
}

func TestMFAGenerateRejectsSessionWithoutStepUp(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("generate without step-up = %d, want 403", rec.Code)
	}
	if got := errorBody(t, rec); got != "insufficient_user_authentication" {
		t.Fatalf("generate without step-up error = %q", got)
	}
	if len(fx.store.enrollments) != 0 {
		t.Fatal("pending enrollment was created without step-up")
	}
}

// TestMFADisableRequiresSessionBeforeStepUp confirms the two guards compose in
// the right order. RequireStepUp reads the session from the request context, so
// a request with a grant but no session must be rejected by the session layer
// (401) rather than reaching the step-up layer, which would have no session to
// bind the grant against.
func TestMFADisableRequiresSessionBeforeStepUp(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	fx.browser.prepare(req)
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	requirePortalSessionRequired(t, rec)
}

// TestMFADisableRejectedWithoutGrant confirms a live session alone is not enough
// to tear down a second factor.
func TestMFADisableRejectedWithoutGrant(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	fx.browser.authorize(t, req, fx.sess, fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "insufficient_user_authentication" {
		t.Fatalf("disable without step-up error = %q", got)
	}
	if fx.user.mfaOn {
		// Belt and braces: a rejected request must not have run the handler.
		t.Error("MFA state changed despite the request being rejected")
	}
}

func wrongMFAHTTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	for _, code := range []string{"000000", "111111", "222222", "333333"} {
		if !totp.ValidateCode(secret, code, now, 1) {
			return code
		}
	}
	t.Fatal("no code outside accepted TOTP window")
	return ""
}

func TestMFAMalformedRequestsDoNotSpendValidGrant(t *testing.T) {
	for _, operation := range []string{"setup", "disable"} {
		for _, malformed := range []string{"body", "query", "duplicate", "comma_joined", "mixed", "oversized", "empty"} {
			t.Run(operation+"/"+malformed, func(t *testing.T) {
				fx := setupMFATestFixtureWithStepUp(t)
				grant := fx.grantHeader(t)
				method, path := http.MethodPost, "/api/v1/auth/mfa/generate"
				if operation == "disable" {
					method, path = http.MethodDelete, "/api/v1/auth/mfa"
				}
				body := ""
				if malformed == "body" {
					body = "{}"
				}
				if malformed == "query" {
					path += "?unexpected=true"
				}
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				fx.browser.authorize(t, req, fx.sess, fx.cookie)
				req.Header.Set(stepup.HeaderStepUpAuth, grant)
				switch malformed {
				case "duplicate":
					req.Header.Add(stepup.HeaderStepUpAuth, grant)
				case "comma_joined":
					req.Header.Set(stepup.HeaderStepUpAuth, grant+","+grant)
				case "mixed":
					req.Header.Set("X-Action-Proof", strings.Repeat("A", 43))
				case "oversized":
					req.Header.Set(stepup.HeaderStepUpAuth, strings.Repeat("a", 16*1024+1))
				case "empty":
					req.Header.Set(stepup.HeaderStepUpAuth, "")
				}
				response := httptest.NewRecorder()
				fx.server.Handler().ServeHTTP(response, req)
				want := http.StatusForbidden
				if malformed == "body" || malformed == "query" {
					want = http.StatusBadRequest
				}
				if response.Code != want || len(fx.store.enrollments) != 0 || fx.user.version != 0 {
					t.Fatalf("malformed request touched state: status %d", response.Code)
				}
				if _, err := fx.stepUp.Validate(t.Context(), grant, fx.sess); err != nil {
					t.Fatal("malformed request spent otherwise valid authority", err)
				}
			})
		}
	}
}

func TestMFAVerifyStrictBodyAndMisplacedAuthorityDoNotBurnEnrollment(t *testing.T) {
	for _, malformed := range []string{"unknown", "duplicate", "trailing", "numeric", "missing", "null", "noncanonical_id", "whitespace_code", "unicode_code", "stepup_header", "proof_header"} {
		t.Run(malformed, func(t *testing.T) {
			fx := setupMFATestFixtureWithStepUp(t)
			setup, err := fx.server.deps.MFA.GenerateSetup(t.Context(), fx.sess, mfaAuthorizationForSession(fx.sess, mfa.AuthorizationWebAuthnUV))
			if err != nil {
				t.Fatal(err)
			}
			grant := fx.grantHeader(t)
			id := setup.EnrollmentID
			body := `{"enrollment_id":"` + id + `","code":"123456"}`
			switch malformed {
			case "unknown":
				body = `{"enrollment_id":"` + id + `","code":"123456","extra":"x"}`
			case "duplicate":
				body = `{"enrollment_id":"` + id + `","code":"123456","code":"123456"}`
			case "trailing":
				body += `{}`
			case "numeric":
				body = `{"enrollment_id":"` + id + `","code":123456}`
			case "missing":
				body = `{"enrollment_id":"` + id + `"}`
			case "null":
				body = `{"enrollment_id":"` + id + `","code":null}`
			case "noncanonical_id":
				body = `{"enrollment_id":"{` + id + `}","code":"123456"}`
			case "whitespace_code":
				body = `{"enrollment_id":"` + id + `","code":" 123456"}`
			case "unicode_code":
				body = `{"enrollment_id":"` + id + `","code":"\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"}`
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", strings.NewReader(body))
			fx.browser.authorize(t, req, fx.sess, fx.cookie)
			if malformed == "stepup_header" {
				req.Header.Set(stepup.HeaderStepUpAuth, grant)
			}
			if malformed == "proof_header" {
				req.Header.Set("X-Action-Proof", strings.Repeat("A", 43))
			}
			response := httptest.NewRecorder()
			fx.server.Handler().ServeHTTP(response, req)
			want := http.StatusBadRequest
			if malformed == "stepup_header" || malformed == "proof_header" {
				want = http.StatusForbidden
			}
			if response.Code != want || len(fx.store.enrollments) != 1 || fx.store.enrollments[uuid.MustParse(id)].FailedAttempts != 0 || fx.user.mfaOn || fx.user.version != 0 {
				t.Fatalf("malformed verify spent pending authority: status %d", response.Code)
			}
			if _, err := fx.stepUp.Validate(t.Context(), grant, fx.sess); err != nil {
				t.Fatal("verify spent misplaced grant", err)
			}
		})
	}
}

func TestMFAManagementRequiresActuallyEarnedStrongAMR(t *testing.T) {
	for _, operation := range []string{"setup", "disable"} {
		for _, amr := range [][]string{{"pwd"}, {"email"}, {"sms"}, {"recovery"}, {"webauthn"}, {"hwk"}, {"user"}, {"otp"}, {"hwk", "user"}} {
			t.Run(operation+"/"+strings.Join(amr, "+"), func(t *testing.T) {
				fx := setupMFATestFixtureWithStepUp(t)
				method, path := http.MethodPost, "/api/v1/auth/mfa/generate"
				if operation == "disable" {
					method, path = http.MethodDelete, "/api/v1/auth/mfa"
					fx.user.mfaOn, fx.user.secret = true, []byte("active-secret")
				}
				req := httptest.NewRequest(method, path, nil)
				fx.browser.authorize(t, req, fx.sess, fx.cookie)
				req.Header.Set(stepup.HeaderStepUpAuth, mintMFAGrant(t, fx.stepUp, fx.sess, amr))
				response := httptest.NewRecorder()
				fx.server.Handler().ServeHTTP(response, req)
				strong := len(amr) == 2 || operation == "disable" && amr[0] == "otp"
				want := http.StatusForbidden
				if strong {
					want = http.StatusOK
					if operation == "disable" {
						want = http.StatusNoContent
					}
				}
				if response.Code != want {
					t.Fatalf("AMR acceptance mismatch: status %d, want %d", response.Code, want)
				}
				if !strong && (len(fx.store.enrollments) != 0 || fx.user.version != 0 || fx.user.mfaOn != (operation == "disable")) {
					t.Fatal("weak AMR wrote credentials")
				}
			})
		}
	}
}

func TestMFASetupAndPendingOnlyNoopSurviveRenewalFailureWithoutInvalidationOrAudit(t *testing.T) {
	for _, operation := range []string{"setup", "absent_disable", "pending_disable"} {
		t.Run(operation, func(t *testing.T) {
			fx := setupMFATestFixtureWithStepUp(t)
			if operation == "pending_disable" {
				if _, err := fx.server.deps.MFA.GenerateSetup(t.Context(), fx.sess, mfaAuthorizationForSession(fx.sess, mfa.AuthorizationWebAuthnUV)); err != nil {
					t.Fatal(err)
				}
			}
			recorder := &profileAuditRecorder{}
			fx.server.deps.AuditRecorder = recorder
			before, err := fx.sessMgr.LookupByID(t.Context(), fx.sess.UserID, fx.sess.ID)
			if err != nil {
				t.Fatal(err)
			}
			fx.sessionStore.touchErr = session.ErrStoreUnavailable
			method, path, want := http.MethodDelete, "/api/v1/auth/mfa", http.StatusNoContent
			if operation == "setup" {
				method, path, want = http.MethodPost, "/api/v1/auth/mfa/generate", http.StatusOK
			}
			grant := fx.grantHeader(t)
			req := httptest.NewRequest(method, path, nil)
			fx.browser.authorize(t, req, fx.sess, fx.cookie)
			req.Header.Set(stepup.HeaderStepUpAuth, grant)
			response := httptest.NewRecorder()
			fx.server.Handler().ServeHTTP(response, req)
			if response.Code != want || response.Header().Get(session.HeaderAuthInvalidated) != "" || len(response.Result().Cookies()) != 0 || fx.user.version != 0 || fx.sessionStore.touches.Load() != 1 {
				t.Fatalf("renewal failure overwrote known outcome or rotated authority: status %d", response.Code)
			}
			after, err := fx.sessMgr.LookupByID(t.Context(), fx.sess.UserID, fx.sess.ID)
			if err != nil || !before.IdleExpiry.Equal(after.IdleExpiry) || !before.AbsoluteExpiry.Equal(after.AbsoluteExpiry) {
				t.Fatal("failed renewal extended or removed known committed session", err)
			}
			if operation != "setup" && len(fx.store.enrollments) != 0 {
				t.Fatal("pending-only cancellation did not clear enrollment")
			}
			for _, event := range recorder.events {
				if event.ActionStatus == "success" {
					t.Fatal("setup/no-op emitted factor-change audit")
				}
			}
			if _, err := fx.stepUp.Validate(t.Context(), grant, fx.sess); err == nil {
				t.Fatal("known no-op restored single-use strong grant")
			}
		})
	}
}
