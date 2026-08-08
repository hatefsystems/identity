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

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type mfaTestUser struct {
	id     uuid.UUID
	email  string
	secret []byte
	mfaOn  bool
}

type mfaFakeStore struct {
	users map[uuid.UUID]*mfaTestUser
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
	}, nil
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
}

func setupMFATestFixture(t *testing.T) *mfaTestFixture {
	t.Helper()

	store := &mfaFakeStore{users: make(map[uuid.UUID]*mfaTestUser)}
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

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		MFA:            mfaSvc,
	})

	return &mfaTestFixture{
		server:  srv,
		store:   store,
		user:    u,
		sess:    sess,
		cookie:  sessionCookie,
		sessMgr: sessMgr,
	}
}

func TestMFARoutesEndToEnd(t *testing.T) {
	fx := setupMFATestFixture(t)

	// 1. Generate Setup
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	var genResp mfa.SetupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("unmarshal setup response: %v", err)
	}
	if len(genResp.Secret) != 32 {
		t.Errorf("expected 32-char secret, got %q", genResp.Secret)
	}

	// 2. Verify with invalid code
	verifyBody, _ := json.Marshal(map[string]string{"code": "000000"})
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

	verifyBody, _ = json.Marshal(map[string]string{"code": validCode})
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

	// 4. Verify Code Endpoint
	verifyCodeBody, _ := json.Marshal(map[string]string{"code": validCode})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify-code", bytes.NewReader(verifyCodeBody))
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("verify-code: expected 200 OK, got %d", rec.Code)
	}

	// 5. Disable MFA
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/mfa", nil)
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	rec = httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("disable: expected 204 No Content, got %d", rec.Code)
	}

	if fx.user.mfaOn {
		t.Error("expected user mfaOn = false after disable")
	}
}

func TestMFARoutesRequireSession(t *testing.T) {
	fx := setupMFATestFixture(t)

	// Call without cookie
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated generate: expected 401 Unauthorized, got %d", rec.Code)
	}
}
