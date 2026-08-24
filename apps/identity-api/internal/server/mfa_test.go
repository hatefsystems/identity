package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	id     uuid.UUID
	email  string
	secret []byte
	mfaOn  bool
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
		Email:                  u.email,
		MfaTotpSecretEncrypted: u.secret,
		IsMfaEnabled:           u.mfaOn,
		Status:                 "active",
	}, nil
}

func (f *mfaFakeStore) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

func (f *mfaFakeStore) CountWebauthnCredentialsByUser(context.Context, uuid.UUID) (int64, error) {
	return 1, nil
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
		ID:              uuid.New(),
		UserID:          arg.UserID,
		SessionID:       arg.SessionID,
		Purpose:         arg.Purpose,
		SecretEncrypted: arg.SecretEncrypted,
		ExpiresAt:       arg.ExpiresAt,
		CreatedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
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
	return ciphertext[4:], nil
}

type mfaTestFixture struct {
	server  *Server
	store   *mfaFakeStore
	user    *mfaTestUser
	sess    session.Session
	cookie  *http.Cookie
	sessMgr *session.Manager
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
	return mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID)
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

	sessionStore := session.NewMemoryStore()
	sessMgr, err := session.NewManager(sessionStore, codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	// Pre-issue valid session
	w := httptest.NewRecorder()
	sess, err := sessMgr.Issue(w, session.IssueParams{
		UserID:    u.id.String(),
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
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

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		MFA:            mfaSvc,
		StepUp:         stepUpSvc,
	})

	return &mfaTestFixture{
		server:  srv,
		store:   store,
		user:    u,
		sess:    sess,
		cookie:  sessionCookie,
		sessMgr: sessMgr,
		stepUp:  stepUpSvc,
	}
}

func TestMFARoutesEndToEnd(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	// 1. Generate Setup
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("TOTP secret response is cacheable: Cache-Control=%q Pragma=%q", rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	}

	var genResp mfa.SetupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("unmarshal setup response: %v", err)
	}
	if len(genResp.Secret) != 32 {
		t.Errorf("expected 32-char secret, got %q", genResp.Secret)
	}

	// 2. Verify with invalid code
	verifyBody, _ := json.Marshal(map[string]string{"enrollment_id": genResp.EnrollmentID, "code": "000000"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(verifyBody))
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
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
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// Check DB status
	if !fx.user.mfaOn {
		t.Error("expected user mfaOn = true")
	}

	// 4. The former public enabled-code oracle is absent.
	verifyCodeBody, _ := json.Marshal(map[string]string{"code": validCode})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify-code", bytes.NewReader(verifyCodeBody))
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("verify-code: expected 404 Not Found, got %d", rec.Code)
	}

	// 5. Disable MFA. This route is step-up gated, so it needs both the session
	// cookie and a fresh grant; the fixture is built with a step-up service for
	// exactly this step.
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("disable: expected 204 No Content, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	if fx.user.mfaOn {
		t.Error("expected user mfaOn = false after disable")
	}
}

func TestMFARoutesRequireSession(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	// Call without cookie
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated generate: expected 401 Unauthorized, got %d", rec.Code)
	}
}

func TestMFAGenerateRejectsSessionWithoutStepUp(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	req.AddCookie(fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("generate without step-up = %d, want 403", rec.Code)
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
	req.Header.Set(stepup.HeaderStepUpAuth, fx.grantHeader(t))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from the session guard, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestMFADisableRejectedWithoutGrant confirms a live session alone is not enough
// to tear down a second factor.
func TestMFADisableRejectedWithoutGrant(t *testing.T) {
	fx := setupMFATestFixtureWithStepUp(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	req.AddCookie(fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fx.user.mfaOn {
		// Belt and braces: a rejected request must not have run the handler.
		t.Error("MFA state changed despite the request being rejected")
	}
}
