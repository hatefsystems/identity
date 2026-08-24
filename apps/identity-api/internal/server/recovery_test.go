package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

// --- Fakes ------------------------------------------------------------------

// recoveryStoredCode is one persisted row in the fake store: the surrogate id
// the physical delete keys on plus the stored hash the lookup matches. The
// plaintext is never held, mirroring the real table.
type recoveryStoredCode struct {
	id       uuid.UUID
	codeHash string
}

// recoveryFakeStore is an in-memory recovery.Store. The service is built without
// a Transacter, so runInTx executes its closure straight against this map and the
// full generate/verify/status logic runs with no database.
type recoveryFakeStore struct {
	users map[uuid.UUID]db.User
	codes map[uuid.UUID][]recoveryStoredCode
}

func newRecoveryFakeStore() *recoveryFakeStore {
	return &recoveryFakeStore{
		users: make(map[uuid.UUID]db.User),
		codes: make(map[uuid.UUID][]recoveryStoredCode),
	}
}

// addUser registers an active account and returns its id.
func (f *recoveryFakeStore) addUser() uuid.UUID {
	id := uuid.New()
	f.users[id] = db.User{ID: id, Email: id.String() + "@example.com", Status: "active"}
	return id
}

// setStatus rewrites an account's users.status, standing in for a moderator
// suspension or a deletion request landing while a session is already live.
func (f *recoveryFakeStore) setStatus(id uuid.UUID, status string) {
	u := f.users[id]
	u.Status = status
	f.users[id] = u
}

func (f *recoveryFakeStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *recoveryFakeStore) GetUserByEmail(_ context.Context, email string) (db.User, error) {
	for _, user := range f.users {
		if user.Email == email {
			return user, nil
		}
	}
	return db.User{}, pgx.ErrNoRows
}

func (f *recoveryFakeStore) CountActiveRecoveryCodes(_ context.Context, userID uuid.UUID) (int64, error) {
	return int64(len(f.codes[userID])), nil
}

func (f *recoveryFakeStore) CreateRecoveryCodes(_ context.Context, arg []db.CreateRecoveryCodesParams) (int64, error) {
	for _, p := range arg {
		f.codes[p.UserID] = append(f.codes[p.UserID], recoveryStoredCode{id: uuid.New(), codeHash: p.CodeHash})
	}
	return int64(len(arg)), nil
}

func (f *recoveryFakeStore) DeleteAllRecoveryCodesForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	n := int64(len(f.codes[userID]))
	delete(f.codes, userID)
	return n, nil
}

func (f *recoveryFakeStore) GetActiveRecoveryCodeForUpdate(_ context.Context, arg db.GetActiveRecoveryCodeForUpdateParams) (db.GetActiveRecoveryCodeForUpdateRow, error) {
	for _, c := range f.codes[arg.UserID] {
		if c.codeHash == arg.CodeHash {
			return db.GetActiveRecoveryCodeForUpdateRow{ID: c.id, UserID: arg.UserID, CodeHash: c.codeHash}, nil
		}
	}
	return db.GetActiveRecoveryCodeForUpdateRow{}, pgx.ErrNoRows
}

func (f *recoveryFakeStore) DeleteRecoveryCodePhysically(_ context.Context, id uuid.UUID) (int64, error) {
	for userID, list := range f.codes {
		for i, c := range list {
			if c.id == id {
				f.codes[userID] = append(list[:i], list[i+1:]...)
				return 1, nil
			}
		}
	}
	return 0, nil
}

// --- Fixture ----------------------------------------------------------------

const (
	recoveryGeneratePath = "/api/v1/auth/recovery-codes/generate"
	recoveryStatusPath   = "/api/v1/auth/recovery-codes/status"
	recoveryVerifyPath   = "/api/v1/auth/mfa/verify-recovery-code"
)

type recoveryTestFixture struct {
	server  *Server
	store   *recoveryFakeStore
	svc     *recovery.Service
	flow    *recovery.FlowService
	userID  uuid.UUID
	cookie  *http.Cookie
	sessMgr *session.Manager
	sess    session.Session
	stepUp  *stepup.Service
}

// newRecoverySessionManager builds an in-memory session manager, matching the
// MFA and phone fixtures so all three suites exercise the same cookie codec.
func newRecoverySessionManager(t *testing.T) *session.Manager {
	t.Helper()

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
	return sessMgr
}

// issueRecoverySession mints a session for userID and returns it with its cookie.
func issueRecoverySession(t *testing.T, sessMgr *session.Manager, userID uuid.UUID) (session.Session, *http.Cookie) {
	t.Helper()

	w := httptest.NewRecorder()
	sess, err := sessMgr.Issue(w, session.IssueParams{
		UserID:    userID.String(),
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("sessMgr.Issue: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			return sess, c
		}
	}
	t.Fatal("session cookie was not set")
	return session.Session{}, nil
}

func setupRecoveryTestFixture(t *testing.T) *recoveryTestFixture {
	t.Helper()

	store := newRecoveryFakeStore()
	userID := store.addUser()

	svc, err := recovery.New(recovery.Config{}, store)
	if err != nil {
		t.Fatalf("recovery.New: %v", err)
	}
	flow, err := recovery.NewFlowService(svc, store, recovery.NewMemoryTransactionStore(), 0)
	if err != nil {
		t.Fatalf("recovery.NewFlowService: %v", err)
	}

	sessMgr := newRecoverySessionManager(t)
	sess, cookie := issueRecoverySession(t, sessMgr, userID)

	// POST /generate is step-up gated, so the fixture always wires a step-up
	// service; without one the route would not be mounted at all.
	stepUpSvc, _ := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
		nil,
		&stepUpFakeTOTP{valid: "000000"},
	)

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		Recovery:       svc,
		RecoveryFlow:   flow,
		StepUp:         stepUpSvc,
	})

	return &recoveryTestFixture{
		server:  srv,
		store:   store,
		svc:     svc,
		flow:    flow,
		userID:  userID,
		cookie:  cookie,
		sessMgr: sessMgr,
		sess:    sess,
		stepUp:  stepUpSvc,
	}
}

// generate posts to the step-up gated generate route with a fresh single-use
// grant. Grants are single-use, so every call mints a new one.
func (fx *recoveryTestFixture) generate(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, recoveryGeneratePath, nil)
	req.AddCookie(fx.cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, mintTestGrant(t, fx.stepUp, fx.sess.UserID, fx.sess.ID))
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// do issues a request against the fixture's router, attaching the session cookie
// when one is supplied.
func (fx *recoveryTestFixture) do(t *testing.T, method, path string, body []byte, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// verifyBody marshals a verify request body for the given code.
func verifyBody(t *testing.T, transactionID, code string) []byte {
	t.Helper()

	body, err := json.Marshal(recoveryVerifyRequest{TransactionID: transactionID, Code: code})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return body
}

func (fx *recoveryTestFixture) startTransaction(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(recoveryStartRequest{Email: fx.store.users[fx.userID].Email})
	if err != nil {
		t.Fatalf("marshal recovery start: %v", err)
	}
	rec := fx.do(t, http.MethodPost, "/api/v1/auth/recovery/start", body, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("recovery start = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}
	var response recoveryStartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal recovery start: %v", err)
	}
	return response.TransactionID
}

func (fx *recoveryTestFixture) verifyBody(t *testing.T, code string) []byte {
	return verifyBody(t, fx.startTransaction(t), code)
}

// --- Route mounting ---------------------------------------------------------

// TestRecoveryRoutesAbsentWithoutService confirms the Deps gate: with no
// recovery service (no DATABASE_URL in a real deployment) none of the three
// routes exist, rather than 500ing on a nil service.
func TestRecoveryRoutesAbsentWithoutService(t *testing.T) {
	sessMgr := newRecoverySessionManager(t)
	srv := New(config.Config{Environment: "development"}, nil, Deps{SessionManager: sessMgr})

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, recoveryGeneratePath},
		{http.MethodGet, recoveryStatusPath},
		{http.MethodPost, recoveryVerifyPath},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s without a recovery service = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

func TestRecoveryRoutesRequireSession(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	for _, tc := range []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, recoveryGeneratePath, nil},
		{http.MethodGet, recoveryStatusPath, nil},
	} {
		rec := fx.do(t, tc.method, tc.path, tc.body, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s %s = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	if got := len(fx.store.codes[fx.userID]); got != 0 {
		t.Errorf("unauthenticated requests minted %d codes, want 0", got)
	}
}

func TestRecoveryStartIsOpaqueForKnownUnknownAndInactiveAccounts(t *testing.T) {
	fx := setupRecoveryTestFixture(t)
	cases := []struct {
		name  string
		email string
		setup func()
	}{
		{name: "active", email: fx.store.users[fx.userID].Email, setup: func() { fx.store.setStatus(fx.userID, "active") }},
		{name: "unknown", email: "nobody@example.com", setup: func() {}},
		{name: "inactive", email: fx.store.users[fx.userID].Email, setup: func() { fx.store.setStatus(fx.userID, "suspended") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			body, err := json.Marshal(recoveryStartRequest{Email: tc.email})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rec := fx.do(t, http.MethodPost, "/api/v1/auth/recovery/start", body, nil)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
			var response recoveryStartResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode: %v", err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(response.TransactionID)
			if err != nil || len(raw) != 32 {
				t.Fatalf("transaction_id is not 256-bit base64url: len=%d err=%v", len(raw), err)
			}
			if response.ExpiresIn != int(recovery.RecoveryTransactionTTL.Seconds()) || response.ExpiresAt.IsZero() {
				t.Fatalf("expiry = %v / %d, want timestamp / %d", response.ExpiresAt, response.ExpiresIn, int(recovery.RecoveryTransactionTTL.Seconds()))
			}
		})
	}
}

func TestRestrictedRecoverySessionCannotAccessNormalOrHighRiskRoutes(t *testing.T) {
	fx := setupRecoveryTestFixture(t)
	batchRec := fx.generate(t)
	var batch recoveryGenerateResponse
	if err := json.Unmarshal(batchRec.Body.Bytes(), &batch); err != nil {
		t.Fatalf("unmarshal batch: %v", err)
	}
	verified := fx.do(t, http.MethodPost, recoveryVerifyPath, fx.verifyBody(t, batch.Codes[0]), nil)
	if verified.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body: %s)", verified.Code, verified.Body.String())
	}
	var restricted *http.Cookie
	for _, cookie := range verified.Result().Cookies() {
		if cookie.Name == "session" {
			restricted = cookie
			break
		}
	}
	if restricted == nil {
		t.Fatal("successful recovery did not issue a restricted-session cookie")
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: recoveryStatusPath},
		{method: http.MethodPost, path: recoveryGeneratePath},
	} {
		rec := fx.do(t, tc.method, tc.path, nil, restricted)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("restricted %s %s = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

// --- Happy path -------------------------------------------------------------

func TestRecoveryGenerateReturnsOneTimeBatch(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	rec := fx.generate(t)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var resp recoveryGenerateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal generate response: %v", err)
	}
	if resp.Count != len(resp.Codes) {
		t.Errorf("count = %d but %d codes returned", resp.Count, len(resp.Codes))
	}
	// The batch size is policy, not a magic number: it must match what the
	// service actually persisted.
	if stored := len(fx.store.codes[fx.userID]); resp.Count != stored {
		t.Errorf("count = %d, want %d (rows persisted)", resp.Count, stored)
	}
	if resp.Count == 0 {
		t.Fatal("generate returned an empty batch")
	}

	seen := make(map[string]struct{}, len(resp.Codes))
	for _, code := range resp.Codes {
		if code == "" {
			t.Error("generate returned an empty code")
		}
		if _, dup := seen[code]; dup {
			t.Errorf("duplicate code %q in the batch", code)
		}
		seen[code] = struct{}{}
	}

	// One-time secrets must not be cacheable: a shared proxy cache or a
	// back-button replay would otherwise resurface the whole batch.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}

	// The plaintext must exist only in the response body, never in storage.
	for _, code := range resp.Codes {
		for _, stored := range fx.store.codes[fx.userID] {
			if stored.codeHash == code || stored.codeHash == recovery.Normalize(code) {
				t.Fatalf("plaintext %q leaked into storage", code)
			}
		}
	}
}

func TestRecoveryStatusTracksTheBatch(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	// No batch yet: zero remaining, and zero is at or below any threshold.
	rec := fx.do(t, http.MethodGet, recoveryStatusPath, nil, fx.cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status before generate = %d, want 200", rec.Code)
	}
	var before recoveryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &before); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if before.Remaining != 0 {
		t.Errorf("remaining before generate = %d, want 0", before.Remaining)
	}
	if !before.Low {
		t.Error("low = false with no codes at all, want true")
	}

	genRec := fx.generate(t)
	var gen recoveryGenerateResponse
	if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("unmarshal generate: %v", err)
	}

	rec = fx.do(t, http.MethodGet, recoveryStatusPath, nil, fx.cookie)
	var after recoveryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if after.Remaining != gen.Count {
		t.Errorf("remaining after generate = %d, want %d", after.Remaining, gen.Count)
	}
	if after.Low {
		t.Error("low = true for a full batch, want false")
	}

	// Spend codes down to the low-water mark and confirm the flag flips.
	for len(fx.store.codes[fx.userID]) > 0 {
		remaining := len(fx.store.codes[fx.userID])
		rec = fx.do(t, http.MethodGet, recoveryStatusPath, nil, fx.cookie)
		var st recoveryStatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("unmarshal status: %v", err)
		}
		if st.Remaining != remaining {
			t.Fatalf("remaining = %d, want %d", st.Remaining, remaining)
		}
		fx.store.codes[fx.userID] = fx.store.codes[fx.userID][:remaining-1]
	}

	rec = fx.do(t, http.MethodGet, recoveryStatusPath, nil, fx.cookie)
	var empty recoveryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if empty.Remaining != 0 || !empty.Low {
		t.Errorf("exhausted batch reported remaining=%d low=%v, want 0/true", empty.Remaining, empty.Low)
	}
}

func TestRecoveryVerifyConsumesCodeAndRejectsReplay(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	genRec := fx.generate(t)
	var gen recoveryGenerateResponse
	if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("unmarshal generate: %v", err)
	}
	code := gen.Codes[0]

	rec := fx.do(t, http.MethodPost, recoveryVerifyPath, fx.verifyBody(t, code), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var verified recoveryVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil {
		t.Fatalf("unmarshal verify: %v", err)
	}
	if verified.Next != "enroll_factor" {
		t.Errorf("next = %q, want %q", verified.Next, "enroll_factor")
	}
	if stored := len(fx.store.codes[fx.userID]); stored != gen.Count-1 {
		t.Errorf("stored codes = %d, want %d", stored, gen.Count-1)
	}

	// Replaying the very same code must fail: the row was physically deleted in
	// the same transaction that matched it.
	rec = fx.do(t, http.MethodPost, recoveryVerifyPath, fx.verifyBody(t, code), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("replayed verify = %d, want 401", rec.Code)
	}
	var failure recoveryErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
		t.Fatalf("unmarshal replay failure: %v", err)
	}
	if failure.Error != "invalid_credentials" {
		t.Errorf("replay error = %q, want %q", failure.Error, "invalid_credentials")
	}
	if stored := len(fx.store.codes[fx.userID]); stored != gen.Count-1 {
		t.Errorf("a rejected replay changed the batch: stored = %d, want %d", stored, gen.Count-1)
	}

	// A different, untouched code from the same batch still works.
	rec = fx.do(t, http.MethodPost, recoveryVerifyPath, fx.verifyBody(t, gen.Codes[1]), nil)
	if rec.Code != http.StatusOK {
		t.Errorf("verify of a second code = %d, want 200", rec.Code)
	}
}

// --- Opacity ----------------------------------------------------------------

// TestRecoveryVerifyFailuresAreIndistinguishable pins the single-failure-mode
// requirement: a wrong code, a replayed code, an absent code, and another
// account's code must produce byte-identical responses, so nothing in the reply
// tells an attacker which of those it hit.
func TestRecoveryVerifyFailuresAreIndistinguishable(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	genRec := fx.generate(t)
	var gen recoveryGenerateResponse
	if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("unmarshal generate: %v", err)
	}

	// Spend one code so a replay is available as a distinct failure mode.
	spent := gen.Codes[0]
	if rec := fx.do(t, http.MethodPost, recoveryVerifyPath, fx.verifyBody(t, spent), nil); rec.Code != http.StatusOK {
		t.Fatalf("priming verify = %d, want 200", rec.Code)
	}

	// A second account with its own live batch, to supply a foreign code.
	otherID := fx.store.addUser()
	otherBatch, err := fx.svc.Generate(context.Background(), otherID, "")
	if err != nil {
		t.Fatalf("Generate for the second account: %v", err)
	}

	cases := []struct {
		name string
		body []byte
	}{
		{name: "unknown code", body: fx.verifyBody(t, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ")},
		{name: "replayed code", body: fx.verifyBody(t, spent)},
		{name: "another account's code", body: fx.verifyBody(t, otherBatch.Codes[0])},
		{name: "empty code", body: fx.verifyBody(t, "")},
		{name: "separators only", body: fx.verifyBody(t, "----")},
		{name: "empty JSON object", body: []byte(`{}`)},
		{name: "absent body", body: nil},
		{name: "whitespace body", body: []byte("   ")},
	}

	var wantStatus int
	var wantBody string
	for i, tc := range cases {
		rec := fx.do(t, http.MethodPost, recoveryVerifyPath, tc.body, fx.cookie)
		if i == 0 {
			wantStatus = rec.Code
			wantBody = rec.Body.String()
			if wantStatus != http.StatusUnauthorized {
				t.Fatalf("%s = %d, want 401", tc.name, wantStatus)
			}
			continue
		}
		if rec.Code != wantStatus {
			t.Errorf("%s = %d, want %d (same as an unknown code)", tc.name, rec.Code, wantStatus)
		}
		if got := rec.Body.String(); got != wantBody {
			t.Errorf("%s body = %q, want %q (byte-identical, no oracle)", tc.name, got, wantBody)
		}
	}

	// The foreign account's batch must be untouched by the cross-user attempt.
	if got := len(fx.store.codes[otherID]); got != otherBatch.Count {
		t.Errorf("cross-user attempt consumed a victim code: stored = %d, want %d", got, otherBatch.Count)
	}
}

// TestRecoveryVerifyMalformedJSONReturns400 documents the one failure that is
// deliberately *not* folded into the opaque 401: a syntactically broken body is a
// request error, not a code guess. It reveals nothing about codes or accounts, and
// matches writeWebAuthnRegistrationError/writeWebAuthnLoginError, which likewise
// keep ErrInvalidResponse at 400 while collapsing every credential outcome to 401.
func TestRecoveryVerifyMalformedJSONReturns400(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	rec := fx.do(t, http.MethodPost, recoveryVerifyPath, []byte(`{"code":`), fx.cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp recoveryErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if resp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", resp.Error, "invalid_request")
	}
}

// --- Account status gate ----------------------------------------------------

// TestRecoveryNonActiveAccountUnauthorized guards the loadUser status gate at the
// HTTP boundary. Session validation never re-reads users.status, so without the
// gate a user suspended after their session was issued could keep minting and
// spending codes. The reply is the same opaque "unauthorized" used for a deleted
// account: naming the suspension would make account state an oracle.
func TestRecoveryNonActiveAccountUnauthorized(t *testing.T) {
	for _, status := range []string{"suspended", "pending_verification", "pending_deletion"} {
		t.Run(status, func(t *testing.T) {
			fx := setupRecoveryTestFixture(t)

			// Mint a batch while still active, then leave the active state.
			genRec := fx.generate(t)
			var gen recoveryGenerateResponse
			if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
				t.Fatalf("unmarshal generate: %v", err)
			}
			fx.store.setStatus(fx.userID, status)

			for _, tc := range []struct {
				name   string
				method string
				path   string
				body   []byte
				// gated marks the routes behind RequireStepUp, which must be
				// given a valid grant so the request reaches the handler where
				// the account-status gate lives. Without one the step-up
				// middleware would answer 403 first and the status gate under
				// test would never run.
				gated bool
			}{
				{name: "generate", method: http.MethodPost, path: recoveryGeneratePath, gated: true},
				{name: "status", method: http.MethodGet, path: recoveryStatusPath},
			} {
				var rec *httptest.ResponseRecorder
				if tc.gated {
					rec = fx.generate(t)
				} else {
					rec = fx.do(t, tc.method, tc.path, tc.body, fx.cookie)
				}
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s for a %s account = %d, want 401 (body: %s)", tc.name, status, rec.Code, rec.Body.String())
				}
				var resp recoveryErrorResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("unmarshal %s error: %v", tc.name, err)
				}
				if resp.Error != "unauthorized" {
					t.Errorf("%s for a %s account returned %q, want %q", tc.name, status, resp.Error, "unauthorized")
				}
			}

			// The refused verify must not have consumed anything, and the batch
			// must survive intact for a later reinstatement.
			if got := len(fx.store.codes[fx.userID]); got != gen.Count {
				t.Errorf("a %s account's refused requests changed the batch: stored = %d, want %d", status, got, gen.Count)
			}
		})
	}
}

// --- Co-mount regression guard ----------------------------------------------

// TestRecoveryAndMFACoMountedRoutes is the regression guard for the two chi
// Mounts that overlap on /api/v1/auth/mfa: registerMFARoutes mounts that prefix
// (so it owns a catch-all "/*" subtree) and registerRecoveryRoutes then mounts
// the deeper /api/v1/auth/mfa/verify-recovery-code.
//
// Two properties are locked in here, both of which are silent until they break:
//
//  1. New() must not panic. chi's Mount panics on an existing pattern, and
//     because New() registers routes inside the constructor a regression would
//     take down startup, not just one route. No other test in this package
//     builds Deps{MFA, Recovery} together, so nothing else exercises it.
//  2. Both routes must remain reachable. chi's findRoute walks a node's children
//     in nodeTyp order, so the static "verify-recovery-code" child is tried
//     before the MFA subtree's catch-all: the deeper mount wins its own path
//     while every other /api/v1/auth/mfa/* path still falls through to MFA.
//
// The two mounts are therefore left as they are (folding verify-recovery-code
// into registerMFARoutes would tie the route's existence to deps.MFA != nil and
// silently drop it in any deployment without TOTP).
func TestRecoveryAndMFACoMountedRoutes(t *testing.T) {
	recoveryStore := newRecoveryFakeStore()
	userID := recoveryStore.addUser()

	recoverySvc, err := recovery.New(recovery.Config{}, recoveryStore)
	if err != nil {
		t.Fatalf("recovery.New: %v", err)
	}
	recoveryFlow, err := recovery.NewFlowService(recoverySvc, recoveryStore, recovery.NewMemoryTransactionStore(), 0)
	if err != nil {
		t.Fatalf("recovery.NewFlowService: %v", err)
	}

	// The same account must exist in the MFA store, since both handlers resolve
	// the caller from the one session.
	mfaStore := &mfaFakeStore{
		users: map[uuid.UUID]*mfaTestUser{
			userID: {id: userID, email: "comount@example.com"},
		},
		enrollments: make(map[uuid.UUID]db.MfaTotpEnrollment),
	}
	mfaSvc, err := mfa.New(mfa.Config{Issuer: "Hatef Test"}, mfaStore, &mfaTestEncryptor{})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	sessMgr := newRecoverySessionManager(t)
	sess, cookie := issueRecoverySession(t, sessMgr, userID)

	// A step-up service is wired so the gated routes participate in the mount,
	// which is the arrangement most likely to expose a chi pattern conflict.
	stepUpSvc, _ := newTestStepUpService(t,
		newStepUpFakeUserStore(db.User{ID: userID, Status: "active", IsMfaEnabled: true}),
		nil,
		&stepUpFakeTOTP{valid: "000000"},
	)

	// Constructing the server registers every route; a Mount conflict would
	// panic right here.
	var srv *Server
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("New() panicked with MFA and Recovery co-mounted on /api/v1/auth/mfa: %v", p)
			}
		}()
		srv = New(config.Config{Environment: "development"}, nil, Deps{
			SessionManager: sessMgr,
			MFA:            mfaSvc,
			Recovery:       recoverySvc,
			RecoveryFlow:   recoveryFlow,
			StepUp:         stepUpSvc,
		})
	}()

	send := func(method, path string, body []byte) *httptest.ResponseRecorder {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req := httptest.NewRequest(method, path, reader)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// The MFA catch-all still serves its own paths: a TOTP setup secret comes
	// back, which only the MFA handler can produce.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
	req.AddCookie(cookie)
	req.Header.Set(stepup.HeaderStepUpAuth, mintTestGrant(t, stepUpSvc, sess.UserID, sess.ID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa/generate = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var setup mfa.SetupResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil {
		t.Fatalf("unmarshal mfa setup: %v", err)
	}
	if setup.Secret == "" {
		t.Error("mfa/generate returned no secret; the MFA handler was not reached")
	}

	// The deeper static mount wins its own path: only the recovery handler
	// answers verify-recovery-code, and only it can mint a batch that verifies.
	batch, err := recoverySvc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	transaction, err := recoveryFlow.Start(context.Background(), recoveryStore.users[userID].Email)
	if err != nil {
		t.Fatalf("Start recovery transaction: %v", err)
	}
	rec = send(http.MethodPost, "/api/v1/auth/mfa/verify-recovery-code", verifyBody(t, transaction.TransactionID, batch.Codes[0]))
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa/verify-recovery-code = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var verified recoveryVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil {
		t.Fatalf("unmarshal recovery verify: %v", err)
	}
	if verified.Next != "enroll_factor" {
		t.Errorf("next = %q, want %q; the recovery handler was not reached", verified.Next, "enroll_factor")
	}
	if got := len(recoveryStore.codes[userID]); got != batch.Count-1 {
		t.Errorf("stored codes = %d, want %d; the code was not consumed", got, batch.Count-1)
	}
}
