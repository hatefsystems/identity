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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
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
	f.users[id] = db.User{ID: id, Status: "active"}
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
	userID  uuid.UUID
	cookie  *http.Cookie
	sessMgr *session.Manager
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

// issueRecoverySession mints a session for userID and returns its cookie.
func issueRecoverySession(t *testing.T, sessMgr *session.Manager, userID uuid.UUID) *http.Cookie {
	t.Helper()

	w := httptest.NewRecorder()
	if _, err := sessMgr.Issue(w, session.IssueParams{
		UserID:    userID.String(),
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	}); err != nil {
		t.Fatalf("sessMgr.Issue: %v", err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	t.Fatal("session cookie was not set")
	return nil
}

func setupRecoveryTestFixture(t *testing.T) *recoveryTestFixture {
	t.Helper()

	store := newRecoveryFakeStore()
	userID := store.addUser()

	svc, err := recovery.New(recovery.Config{}, store)
	if err != nil {
		t.Fatalf("recovery.New: %v", err)
	}

	sessMgr := newRecoverySessionManager(t)
	cookie := issueRecoverySession(t, sessMgr, userID)

	srv := New(config.Config{Environment: "development"}, nil, Deps{
		SessionManager: sessMgr,
		Recovery:       svc,
	})

	return &recoveryTestFixture{
		server:  srv,
		store:   store,
		svc:     svc,
		userID:  userID,
		cookie:  cookie,
		sessMgr: sessMgr,
	}
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
func verifyBody(t *testing.T, code string) []byte {
	t.Helper()

	body, err := json.Marshal(recoveryVerifyRequest{Code: code})
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return body
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
		{http.MethodPost, recoveryVerifyPath, verifyBody(t, "ABCDE-ABCDE")},
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

// --- Happy path -------------------------------------------------------------

func TestRecoveryGenerateReturnsOneTimeBatch(t *testing.T) {
	fx := setupRecoveryTestFixture(t)

	rec := fx.do(t, http.MethodPost, recoveryGeneratePath, nil, fx.cookie)
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

	genRec := fx.do(t, http.MethodPost, recoveryGeneratePath, nil, fx.cookie)
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

	genRec := fx.do(t, http.MethodPost, recoveryGeneratePath, nil, fx.cookie)
	var gen recoveryGenerateResponse
	if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("unmarshal generate: %v", err)
	}
	code := gen.Codes[0]

	rec := fx.do(t, http.MethodPost, recoveryVerifyPath, verifyBody(t, code), fx.cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var verified recoveryVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil {
		t.Fatalf("unmarshal verify: %v", err)
	}
	if verified.Status != "verified" {
		t.Errorf("status = %q, want %q", verified.Status, "verified")
	}
	if verified.Remaining != gen.Count-1 {
		t.Errorf("remaining = %d, want %d", verified.Remaining, gen.Count-1)
	}
	if stored := len(fx.store.codes[fx.userID]); stored != gen.Count-1 {
		t.Errorf("stored codes = %d, want %d", stored, gen.Count-1)
	}

	// Replaying the very same code must fail: the row was physically deleted in
	// the same transaction that matched it.
	rec = fx.do(t, http.MethodPost, recoveryVerifyPath, verifyBody(t, code), fx.cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("replayed verify = %d, want 401", rec.Code)
	}
	var failure recoveryErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &failure); err != nil {
		t.Fatalf("unmarshal replay failure: %v", err)
	}
	if failure.Error != "invalid_code" {
		t.Errorf("replay error = %q, want %q", failure.Error, "invalid_code")
	}
	if stored := len(fx.store.codes[fx.userID]); stored != gen.Count-1 {
		t.Errorf("a rejected replay changed the batch: stored = %d, want %d", stored, gen.Count-1)
	}

	// A different, untouched code from the same batch still works.
	rec = fx.do(t, http.MethodPost, recoveryVerifyPath, verifyBody(t, gen.Codes[1]), fx.cookie)
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

	genRec := fx.do(t, http.MethodPost, recoveryGeneratePath, nil, fx.cookie)
	var gen recoveryGenerateResponse
	if err := json.Unmarshal(genRec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("unmarshal generate: %v", err)
	}

	// Spend one code so a replay is available as a distinct failure mode.
	spent := gen.Codes[0]
	if rec := fx.do(t, http.MethodPost, recoveryVerifyPath, verifyBody(t, spent), fx.cookie); rec.Code != http.StatusOK {
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
		{name: "unknown code", body: verifyBody(t, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ")},
		{name: "replayed code", body: verifyBody(t, spent)},
		{name: "another account's code", body: verifyBody(t, otherBatch.Codes[0])},
		{name: "empty code", body: verifyBody(t, "")},
		{name: "separators only", body: verifyBody(t, "----")},
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
			genRec := fx.do(t, http.MethodPost, recoveryGeneratePath, nil, fx.cookie)
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
			}{
				{name: "generate", method: http.MethodPost, path: recoveryGeneratePath},
				{name: "status", method: http.MethodGet, path: recoveryStatusPath},
				{name: "verify", method: http.MethodPost, path: recoveryVerifyPath, body: verifyBody(t, gen.Codes[0])},
			} {
				rec := fx.do(t, tc.method, tc.path, tc.body, fx.cookie)
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

	// The same account must exist in the MFA store, since both handlers resolve
	// the caller from the one session.
	mfaStore := &mfaFakeStore{users: map[uuid.UUID]*mfaTestUser{
		userID: {id: userID, email: "comount@example.com"},
	}}
	mfaSvc, err := mfa.New(mfa.Config{Issuer: "Hatef Test"}, mfaStore, &mfaTestEncryptor{})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	sessMgr := newRecoverySessionManager(t)
	cookie := issueRecoverySession(t, sessMgr, userID)

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
	rec := send(http.MethodPost, "/api/v1/auth/mfa/generate", nil)
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
	rec = send(http.MethodPost, "/api/v1/auth/mfa/verify-recovery-code", verifyBody(t, batch.Codes[0]))
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa/verify-recovery-code = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var verified recoveryVerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &verified); err != nil {
		t.Fatalf("unmarshal recovery verify: %v", err)
	}
	if verified.Status != "verified" {
		t.Errorf("status = %q, want %q; the recovery handler was not reached", verified.Status, "verified")
	}
	if got := len(recoveryStore.codes[userID]); got != batch.Count-1 {
		t.Errorf("stored codes = %d, want %d; the code was not consumed", got, batch.Count-1)
	}
}
