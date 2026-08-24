package server

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
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

	removeCalled bool
	removeUserID uuid.UUID
}

func (f *phoneFakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if !f.users[id] {
		return db.User{}, pgx.ErrNoRows
	}
	return db.User{ID: id, Status: "active"}, nil
}

func (f *phoneFakeUserStore) SetUserPhone(_ context.Context, arg db.SetUserPhoneParams) (int64, error) {
	f.setCalled = true
	f.setUserID = arg.ID
	f.setEncrypted = arg.PhoneEncrypted
	f.setBlindIndex = arg.PhoneBlindIndex
	return 1, nil
}

func (f *phoneFakeUserStore) RemoveUserPhone(_ context.Context, id uuid.UUID) (int64, error) {
	f.removeCalled = true
	f.removeUserID = id
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

func (f *phoneFakeOTPStore) Store(_ context.Context, verificationID string, record smsotp.OTPRecord, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record.Attempts = 0
	f.records[verificationID] = &record
	return nil
}

func (f *phoneFakeOTPStore) Get(_ context.Context, verificationID string) (smsotp.OTPRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[verificationID]
	if !ok {
		return smsotp.OTPRecord{}, smsotp.ErrNoActiveCode
	}
	return *rec, nil
}

func (f *phoneFakeOTPStore) IncrementAttempts(_ context.Context, verificationID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.records[verificationID]
	if !ok {
		return 0, smsotp.ErrNoActiveCode
	}
	rec.Attempts++
	return rec.Attempts, nil
}

func (f *phoneFakeOTPStore) Delete(_ context.Context, verificationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.records, verificationID)
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
	server         *Server
	users          *phoneFakeUserStore
	otps           *phoneFakeOTPStore
	sender         *phoneCapturingSender
	userID         uuid.UUID
	cookie         *http.Cookie
	sess           session.Session
	sessionManager *session.Manager
	stepUp         *stepup.Service
}

func setupPhoneTestFixture(t *testing.T, limiterAllows bool) *phoneTestFixture {
	t.Helper()
	return newPhoneTestFixture(t, limiterAllows, true)
}

// newPhoneTestFixture builds the phone fixture. withStepUp controls whether the
// sensitive send-code and DELETE routes are mounted at all.
func newPhoneTestFixture(t *testing.T, limiterAllows, withStepUp bool) *phoneTestFixture {
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
			break
		}
	}
	if cookie == nil {
		t.Fatal("expected a session cookie to be issued")
	}

	var stepUpSvc *stepup.Service
	if withStepUp {
		stepUpSvc, _ = newTestStepUpService(t,
			newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
			nil,
			&stepUpFakeTOTP{valid: "000000"},
		)
	}

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		SMSOTP:         svc,
		StepUp:         stepUpSvc,
	})

	return &phoneTestFixture{
		server:         srv,
		users:          users,
		otps:           otps,
		sender:         sender,
		userID:         userID,
		cookie:         cookie,
		sess:           sess,
		sessionManager: sessMgr,
		stepUp:         stepUpSvc,
	}
}

// deletePhone issues DELETE /api/v1/users/me/phone, optionally with a fresh
// single-use step-up grant.
func (fx *phoneTestFixture) deletePhone(t *testing.T, withGrant bool) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/phone", nil)
	req.AddCookie(fx.cookie)
	if withGrant {
		req.Header.Set(stepup.HeaderStepUpAuth,
			mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID))
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// doPhone issues a request against the phone routes with explicitly selected
// session and step-up credentials.
func (fx *phoneTestFixture) doPhone(t *testing.T, path string, body any, cookie *http.Cookie, grant string) *httptest.ResponseRecorder {
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
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if grant != "" {
		req.Header.Set(stepup.HeaderStepUpAuth, grant)
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

func (fx *phoneTestFixture) freshGrant(t *testing.T) string {
	t.Helper()
	return mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID)
}

func (fx *phoneTestFixture) issueSession(t *testing.T) (session.Session, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	sess, err := fx.sessionManager.Issue(w, session.IssueParams{
		UserID:    fx.userID.String(),
		IP:        "127.0.0.2",
		UserAgent: "second-test-agent",
	})
	if err != nil {
		t.Fatalf("issue second session: %v", err)
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "session" {
			return sess, cookie
		}
	}
	t.Fatal("expected second session cookie")
	return session.Session{}, nil
}

func decodePhoneSendResponse(t *testing.T, rec *httptest.ResponseRecorder) phoneSendCodeResponse {
	t.Helper()
	var response phoneSendCodeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode send-code response: %v", err)
	}
	return response
}

// --- Tests ------------------------------------------------------------------

func TestPhoneRoutesRequireSession(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, nil, "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated send-code: expected 401, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be dispatched for an unauthenticated request")
	}
}

func TestPhoneSendCodeRequiresStepUp(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, fx.cookie, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("send-code without grant: expected 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 || len(fx.otps.records) != 0 {
		t.Fatal("request without step-up dispatched or stored an OTP")
	}
}

func TestPhoneSendCodeConsumesGrantBeforeBodyParsing(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	grant := fx.freshGrant(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/phone/send-code", strings.NewReader("{"))
	req.AddCookie(fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, grant)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed request: expected 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	rec = fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, fx.cookie, grant)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replayed grant: expected 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Fatal("consumed grant dispatched an SMS on replay")
	}
}

func TestPhoneVerifyEndToEnd(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	const phone = "+15550102020"

	// 1. Request a code.
	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code", map[string]string{"phone": phone}, fx.cookie, fx.freshGrant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("send-code Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if fx.sender.calls != 1 {
		t.Fatalf("expected exactly one SMS dispatched, got %d", fx.sender.calls)
	}
	code := fx.sender.code()
	if len(code) != 6 {
		t.Fatalf("expected a 6-digit code delivered, got %q", code)
	}
	response := decodePhoneSendResponse(t, rec)
	rawID, err := base64.RawURLEncoding.DecodeString(response.VerificationID)
	if err != nil || len(rawID) != 32 {
		t.Fatalf("verification_id = %q, want 32 bytes of base64url entropy (decode error: %v)", response.VerificationID, err)
	}

	// 2. Verify with the delivered code.
	rec = fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"verification_id": response.VerificationID, "code": code}, fx.cookie, "")
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

	rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code", map[string]string{"phone": phone}, fx.cookie, fx.freshGrant(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	response := decodePhoneSendResponse(t, rec)
	rec = fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"verification_id": response.VerificationID, "code": "000000"}, fx.cookie, "")
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
		map[string]string{"phone": "not-a-phone"}, fx.cookie, fx.freshGrant(t))
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
		map[string]string{"phone": "+15550102020"}, fx.cookie, fx.freshGrant(t))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("send-code rate limited: expected 429, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.sender.calls != 0 {
		t.Error("no SMS should be dispatched when rate limited")
	}
}

func TestPhoneVerifyForeignSessionDoesNotConsumeChallenge(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	const phone = "+15550102020"

	send := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": phone}, fx.cookie, fx.freshGrant(t))
	if send.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d (body: %s)", send.Code, send.Body.String())
	}
	response := decodePhoneSendResponse(t, send)
	code := fx.sender.code()

	_, foreignCookie := fx.issueSession(t)
	foreign := fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"verification_id": response.VerificationID, "code": code}, foreignCookie, "")
	if foreign.Code != http.StatusBadRequest {
		t.Fatalf("foreign-session verify: expected 400, got %d (body: %s)", foreign.Code, foreign.Body.String())
	}
	var failure phoneErrorResponse
	if err := json.Unmarshal(foreign.Body.Bytes(), &failure); err != nil {
		t.Fatalf("decode foreign-session response: %v", err)
	}
	if failure.Error != "no_active_code" {
		t.Fatalf("foreign-session error = %q, want no_active_code", failure.Error)
	}
	fx.otps.mu.Lock()
	record := fx.otps.records[response.VerificationID]
	if record == nil || record.Attempts != 0 {
		fx.otps.mu.Unlock()
		t.Fatalf("foreign session consumed or mutated challenge: %+v", record)
	}
	fx.otps.mu.Unlock()

	owner := fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"verification_id": response.VerificationID, "code": code}, fx.cookie, "")
	if owner.Code != http.StatusOK {
		t.Fatalf("initiating-session verify: expected 200, got %d (body: %s)", owner.Code, owner.Body.String())
	}
}

// --- DELETE /api/v1/users/me/phone (step-up gated) --------------------------

// TestPhoneRemoveRequiresAGrant confirms a live session alone cannot detach the
// verified phone. The phone is a password-reset and account-recovery channel
// (docs/api-design.md §1.6), so silently removing it is a step an attacker takes
// to cut off the owner's way back in.
func TestPhoneRemoveRequiresAGrant(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.deletePhone(t, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if fx.users.removeCalled {
		t.Error("the phone was removed despite the request being rejected")
	}

	var body struct {
		Error     string `json:"error"`
		ACRValues string `json:"acr_values"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if body.Error != "insufficient_user_authentication" {
		t.Fatalf("error = %q, want insufficient_user_authentication", body.Error)
	}
	if body.ACRValues != stepup.ACRStepUp {
		t.Fatalf("acr_values = %q, want %q", body.ACRValues, stepup.ACRStepUp)
	}
}

// TestPhoneRemoveWithGrant is the happy path: the encrypted payload and its blind
// index are cleared together by the single statement the service issues.
func TestPhoneRemoveWithGrant(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	rec := fx.deletePhone(t, true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body: %s)", rec.Code, rec.Body.String())
	}
	if !fx.users.removeCalled {
		t.Fatal("expected the phone to be cleared")
	}
	if fx.users.removeUserID != fx.userID {
		t.Fatalf("cleared %s, want %s", fx.users.removeUserID, fx.userID)
	}
}

// TestPhoneRemoveIsSingleUsePerGrant confirms one grant authorises one removal:
// the second attempt with the same header is refused.
func TestPhoneRemoveIsSingleUsePerGrant(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)
	grant := mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID)

	send := func() int {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/phone", nil)
		req.AddCookie(fx.cookie)
		req.Header.Set(stepup.HeaderStepUpAuth, grant)
		rec := httptest.NewRecorder()
		fx.server.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(); code != http.StatusNoContent {
		t.Fatalf("first removal = %d, want 204", code)
	}
	if code := send(); code != http.StatusForbidden {
		t.Fatalf("replayed grant = %d, want 403", code)
	}
}

// TestPhoneRemoveRequiresSessionBeforeStepUp confirms guard ordering: a grant
// without a session must be rejected by the session layer, since the step-up
// layer has no session to bind the grant against.
func TestPhoneRemoveRequiresSessionBeforeStepUp(t *testing.T) {
	fx := setupPhoneTestFixture(t, true)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/phone", nil)
	req.Header.Set(stepup.HeaderStepUpAuth,
		mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 from the session guard", rec.Code)
	}
	if fx.users.removeCalled {
		t.Error("the phone was removed without a session")
	}
}

// TestPhoneRemoveAbsentWithoutStepUpService is the fail-closed guarantee for this
// route: without a step-up service it must not be reachable at all, rather than
// served without its gate.
func TestPhoneRemoveAbsentWithoutStepUpService(t *testing.T) {
	fx := newPhoneTestFixture(t, true, false)

	// Verification remains mounted because any usable challenge was already
	// issued under step-up and bound to a session. Sending and deletion must be
	// withheld when their gate cannot be constructed.
	if rec := fx.doPhone(t, "/api/v1/users/me/phone/verify",
		map[string]string{"verification_id": "missing", "code": "000000"}, fx.cookie, ""); rec.Code == http.StatusNotFound {
		t.Fatal("expected the session-bound verify route to remain mounted")
	}
	if rec := fx.doPhone(t, "/api/v1/users/me/phone/send-code",
		map[string]string{"phone": "+15550102020"}, fx.cookie, ""); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("send-code status = %d, want the route to be withheld", rec.Code)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/phone", nil)
	req.AddCookie(fx.cookie)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want the route to be withheld", rec.Code)
	}
	if fx.users.removeCalled {
		t.Error("an unmounted route removed the phone")
	}
}
