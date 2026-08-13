package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

// --- Fakes ------------------------------------------------------------------
//
// The phone routes are exercised against a real smsotp.Service so the HTTP layer,
// the session guard, the domain-error → status mapping, and the send/verify flow
// are all covered end-to-end; only the service's collaborators (DB, crypto,
// Redis, SMS gateway) are faked.

// phoneFakeUserStore is the smsotp.UserStore seam: it confirms the account
// exists and records the persisted, encrypted phone plus its blind index.
type phoneFakeUserStore struct {
	users map[uuid.UUID]bool

	setCalled     bool
	setUserID     uuid.UUID
	setEncrypted  []byte
	setBlindIndex *string
}

func (f *phoneFakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if !f.users[id] {
		return db.User{}, pgx.ErrNoRows
	}
	return db.User{ID: id}, nil
}

func (f *phoneFakeUserStore) SetUserPhone(_ context.Context, arg db.SetUserPhoneParams) (int64, error) {
	f.setCalled = true
	f.setUserID = arg.ID
	f.setEncrypted = arg.PhoneEncrypted
	f.setBlindIndex = arg.PhoneBlindIndex
	return 1, nil
}

// phoneFakeEncryptor prefixes plaintext so the test can confirm encryption ran.
type phoneFakeEncryptor struct{}

func (phoneFakeEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte("enc_"), plaintext...), nil
}

// phoneFakeIndexer returns a deterministic blind index.
type phoneFakeIndexer struct{}

func (phoneFakeIndexer) Compute(pii string) string { return "idx_" + pii }

// phoneFakeLimiter is a ratelimit.Limiter whose verdict the test controls: with
// allow=false it saturates every window so SendCode returns ErrRateLimited.
type phoneFakeLimiter struct{ allow bool }

func (f *phoneFakeLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, error) {
	return f.allow, nil
}

// phoneFakeOTPStore is an in-memory smsotp.OTPStore.
type phoneFakeOTPStore struct {
	mu       sync.Mutex
	records  map[string]*smsotp.OTPRecord
	lockouts map[string]bool
}

func newPhoneFakeOTPStore() *phoneFakeOTPStore {
	return &phoneFakeOTPStore{
		records:  make(map[string]*smsotp.OTPRecord),
		lockouts: make(map[string]bool),
	}
}

func (f *phoneFakeOTPStore) Store(_ context.Context, phone, codeHash string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[phone] = &smsotp.OTPRecord{CodeHash: codeHash, Attempts: 0}
	return nil
}

func (f *phoneFakeOTPStore) Get(_ context.Context, phone string) (smsotp.OTPRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[phone]
	if !ok {
		return smsotp.OTPRecord{}, smsotp.ErrNoActiveCode
	}
	return *rec, nil
}

func (f *phoneFakeOTPStore) IncrementAttempts(_ context.Context, phone string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[phone]
	if !ok {
		return 0, smsotp.ErrNoActiveCode
	}
	rec.Attempts++
	return rec.Attempts, nil
}

func (f *phoneFakeOTPStore) Delete(_ context.Context, phone string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, phone)
	return nil
}

func (f *phoneFakeOTPStore) Lockout(_ context.Context, phone string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lockouts[phone] = true
	return nil
}

func (f *phoneFakeOTPStore) IsLockedOut(_ context.Context, phone string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lockouts[phone], nil
}

// phoneCapturingSender records the delivered message so the test can recover the
// plaintext OTP (the last whitespace-delimited token of the default template)
// and replay it against the verify endpoint.
type phoneCapturingSender struct {
	mu        sync.Mutex
	calls     int
	lastPhone string
	lastCode  string
}

func (f *phoneCapturingSender) Send(_ context.Context, phone, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastPhone = phone
	if fields := strings.Fields(message); len(fields) > 0 {
		f.lastCode = fields[len(fields)-1]
	}
	return nil
}

func (f *phoneCapturingSender) code() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCode
}

// --- Fixture ----------------------------------------------------------------

type phoneTestFixture struct {
	server *Server
	users  *phoneFakeUserStore
	otps   *phoneFakeOTPStore
	sender *phoneCapturingSender
	userID uuid.UUID
	cookie *http.Cookie
}

func setupPhoneTestFixture(t *testing.T, limiterAllows bool) *phoneTestFixture {
	t.Helper()

	userID := uuid.New()
	users := &phoneFakeUserStore{users: map[uuid.UUID]bool{userID: true}}
	otps := newPhoneFakeOTPStore()
	sender := &phoneCapturingSender{}

	svc, err := smsotp.New(
		smsotp.Config{},
		users,
		phoneFakeEncryptor{},
		phoneFakeIndexer{},
		&phoneFakeLimiter{allow: limiterAllows},
		otps,
		sender,
	)
	if err != nil {
		t.Fatalf("smsotp.New: %v", err)
	}

	codec, err := session.NewCookieCodec(session.CookieConfig{
		Name:   "session",
		Secure: false,
		TTL:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}

	sessMgr, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("session.NewManager: %v", err)
	}

	// Pre-issue a valid session and capture its cookie.
	w := httptest.NewRecorder()
	if _, err := sessMgr.Issue(w, session.IssueParams{
		UserID:    userID.String(),
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}); err != nil {
		t.Fatalf("sessMgr.Issue: %v", err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("expected a session cookie to be issued")
	}

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		SMSOTP:         svc,
	})

	return &phoneTestFixture{
		server: srv,
		users:  users,
		otps:   otps,
		sender: sender,
		userID: userID,
		cookie: cookie,
	}
}

// doPhone issues a request against the phone routes, optionally attaching the
// fixture's session cookie.
func (fx *phoneTestFixture) doPhone(t *testing.T, path string, body any, withCookie bool) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(http.MethodPost, path, reader)
	req.RemoteAddr = "203.0.113.9:5555"
	if withCookie {
		req.AddCookie(fx.cookie)
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// --- Tests ------------------------------------------------------------------

func TestPhoneRoutesRequireSession(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, false)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated send-code: expected 401, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be dispatched for an unauthenticated request")
	}
}

func TestPhoneVerifyEndToEnd(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	const phone = "+15550102020"

	// 1. Request a code.
	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code", map[string]string{"phone": phone}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 1 {
		t.Fatalf("expected exactly one SMS dispatched, got %d", fx.sender.calls)
	}
	code := fx.sender.code()
	if len(code) != 6 {
		t.Fatalf("expected a 6-digit code delivered, got %q", code)
	}

	// 2. Verify with the delivered code.
	rec = fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"phone": phone, "code": code}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// The verified phone must have been persisted encrypted + blind-indexed.
	if !fx.users.setCalled {
		t.Fatal("expected the verified phone to be persisted")
	}
	if fx.users.setUserID != fx.userID {
		t.Errorf("persisted for user %v, want %v", fx.users.setUserID, fx.userID)
	}
	if string(fx.users.setEncrypted) != "enc_"+phone {
		t.Errorf("stored ciphertext = %q, want enc_%s", fx.users.setEncrypted, phone)
	}
	if fx.users.setBlindIndex == nil || *fx.users.setBlindIndex != "idx_"+phone {
		t.Errorf("stored blind index = %v, want idx_%s", fx.users.setBlindIndex, phone)
	}
}

func TestPhoneVerifyWrongCode(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	const phone = "+15550102020"

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code", map[string]string{"phone": phone}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	rec = fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"phone": phone, "code": "000000"}, true)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("verify wrong code: expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.users.setCalled {
		t.Error("phone must not be persisted on a wrong code")
	}
}

func TestPhoneSendCodeInvalidPhone(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "not-a-phone"}, true)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("send-code invalid phone: expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be dispatched for an invalid phone")
	}
}

func TestPhoneSendCodeRateLimited(t *testing.T) {
	// A limiter that admits nothing saturates the first (per-minute) window.
	fx := setupPhoneTestFixture(t, false)

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, true)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("send-code rate limited: expected 429, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be dispatched when rate limited")
	}
}
