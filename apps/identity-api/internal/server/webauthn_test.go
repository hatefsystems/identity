package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// fakeWebAuthnUserStore is a minimal in-memory webauthn.UserStore for the
// handler tests. The webauthn package's own fakes are unexported, so the store
// seam is re-implemented here. Misses return pgx.ErrNoRows because that is what
// the generated :one queries propagate and what the service translates into
// ErrUserNotFound.
type fakeWebAuthnUserStore struct {
	byID    map[uuid.UUID]db.User
	byEmail map[string]uuid.UUID
}

func (f *fakeWebAuthnUserStore) GetUserByEmail(_ context.Context, email string) (db.User, error) {
	id, ok := f.byEmail[email]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return f.byID[id], nil
}

func (f *fakeWebAuthnUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeWebAuthnUserStore) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

// GetUserByIDForAdmin satisfies the soft-delete-blind lookup the reclaim ceremony
// requires. These handler tests do not drive reclaim, so it delegates.
func (f *fakeWebAuthnUserStore) GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

func (f *fakeWebAuthnUserStore) SetWebauthnUserHandle(_ context.Context, arg db.SetWebauthnUserHandleParams) (int64, error) {
	u, ok := f.byID[arg.ID]
	if !ok || len(u.WebauthnUserHandle) != 0 {
		return 0, nil
	}
	u.WebauthnUserHandle = arg.WebauthnUserHandle
	f.byID[u.ID] = u
	return 1, nil
}

// fakeWebAuthnCredentialStore is a minimal in-memory webauthn.CredentialStore.
type fakeWebAuthnCredentialStore struct {
	byUser map[uuid.UUID][]db.WebauthnCredential
}

func (f *fakeWebAuthnCredentialStore) CreateWebauthnCredential(_ context.Context, arg db.CreateWebauthnCredentialParams) (db.WebauthnCredential, error) {
	row := db.WebauthnCredential{
		ID:              arg.ID,
		UserID:          arg.UserID,
		PublicKey:       arg.PublicKey,
		AttestationType: arg.AttestationType,
		SignCount:       arg.SignCount,
		UserPresent:     arg.UserPresent,
		UserVerified:    arg.UserVerified,
		BackupEligible:  arg.BackupEligible,
		BackupState:     arg.BackupState,
		Aaguid:          arg.Aaguid,
	}
	f.byUser[arg.UserID] = append(f.byUser[arg.UserID], row)
	return row, nil
}

func (f *fakeWebAuthnCredentialStore) ListWebauthnCredentialsByUser(_ context.Context, userID uuid.UUID) ([]db.WebauthnCredential, error) {
	rows := f.byUser[userID]
	out := make([]db.WebauthnCredential, len(rows))
	copy(out, rows)
	return out, nil
}

func (f *fakeWebAuthnCredentialStore) GetWebauthnCredentialForUpdate(_ context.Context, id []byte) (db.WebauthnCredential, error) {
	for _, rows := range f.byUser {
		for _, row := range rows {
			if bytes.Equal(row.ID, id) {
				return row, nil
			}
		}
	}
	return db.WebauthnCredential{}, pgx.ErrNoRows
}

// GetUserByWebauthnUserHandle resolves the account a discoverable assertion
// names from its anonymised user handle.
func (f *fakeWebAuthnUserStore) GetUserByWebauthnUserHandle(_ context.Context, handle []byte) (db.User, error) {
	for _, u := range f.byID {
		if len(u.WebauthnUserHandle) > 0 && bytes.Equal(u.WebauthnUserHandle, handle) {
			return u, nil
		}
	}
	return db.User{}, pgx.ErrNoRows
}

func (f *fakeWebAuthnCredentialStore) LockWebauthnCredentialsByUser(_ context.Context, userID uuid.UUID) ([][]byte, error) {
	rows := f.byUser[userID]
	out := make([][]byte, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.ID)
	}
	return out, nil
}

func (f *fakeWebAuthnCredentialStore) DeleteWebauthnCredential(_ context.Context, arg db.DeleteWebauthnCredentialParams) (int64, error) {
	rows := f.byUser[arg.UserID]
	for i, row := range rows {
		if bytes.Equal(row.ID, arg.ID) {
			f.byUser[arg.UserID] = append(rows[:i:i], rows[i+1:]...)
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeWebAuthnCredentialStore) UpdateWebauthnSignCount(_ context.Context, arg db.UpdateWebauthnSignCountParams) (int64, error) {

	for userID, rows := range f.byUser {
		for i, row := range rows {
			if bytes.Equal(row.ID, arg.ID) {
				rows[i].SignCount = arg.SignCount
				f.byUser[userID] = rows
				return 1, nil
			}
		}
	}
	return 0, nil
}

// webAuthnTestServer bundles a Server wired with both a session manager and a
// real WebAuthn service over in-memory stores, plus the seeded account the
// authenticated routes act on.
type webAuthnTestServer struct {
	srv    *Server
	mgr    *session.Manager
	users  *fakeWebAuthnUserStore
	creds  *fakeWebAuthnCredentialStore
	user   db.User
	stepUp *stepup.Service
}

// newWebAuthnTestServer builds that fixture. The session cookie is non-Secure so
// it survives the plain-HTTP httptest transport, matching newSessionTestServer.
func newWebAuthnTestServer(t *testing.T) *webAuthnTestServer {
	t.Helper()
	return newWebAuthnTestServerWithStepUp(t, false)
}

// newWebAuthnTestServerWithStepUp additionally wires a step-up service, which is
// what mounts DELETE /api/v1/auth/webauthn/keys/{id} at all.
func newWebAuthnTestServerWithStepUp(t *testing.T, withStepUp bool) *webAuthnTestServer {
	t.Helper()

	codec, err := session.NewCookieCodec(session.CookieConfig{
		Name:   "session",
		Secure: false,
		TTL:    24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCookieCodec: %v", err)
	}

	mgr, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
		AbsoluteTTL: 24 * time.Hour,
		IdleTTL:     2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Only active accounts may authenticate, so the seeded account is active.
	user := db.User{ID: uuid.New(), Email: "passkey@example.com", Status: "active"}
	users := &fakeWebAuthnUserStore{
		byID:    map[uuid.UUID]db.User{user.ID: user},
		byEmail: map[string]uuid.UUID{user.Email: user.ID},
	}
	creds := &fakeWebAuthnCredentialStore{byUser: make(map[uuid.UUID][]db.WebauthnCredential)}

	svc, err := webauthn.New(webauthn.Config{
		RPID:             "localhost",
		RPDisplayName:    "Hatef Identity",
		RPOrigins:        []string{"http://localhost:8080"},
		ChallengeTTL:     5 * time.Minute,
		UserVerification: "preferred",
		ResidentKey:      "required",
		// A fixed, obviously-fake derivation key: these tests assert on HTTP
		// status codes, not on the decoy bytes themselves.
		MockChallengeKey: bytes.Repeat([]byte{0x2A}, 32),
		// No timing pad: the handler tests would otherwise sleep on every
		// user-named request for no assertion value.
		NamedLoginFloor: 0,
	}, users, creds, webauthn.NewMemoryChallengeStore())

	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	var stepUpSvc *stepup.Service
	if withStepUp {
		stepUpSvc, _ = newTestStepUpService(t,
			newStepUpFakeUserStore(db.User{ID: user.ID, Status: "active", IsMfaEnabled: true}),
			svc,
			&stepUpFakeTOTP{valid: "000000"},
		)
	}

	return &webAuthnTestServer{
		srv:    New(testConfig(t), nil, Deps{SessionManager: mgr, WebAuthn: svc, StepUp: stepUpSvc}),
		mgr:    mgr,
		users:  users,
		creds:  creds,
		user:   user,
		stepUp: stepUpSvc,
	}
}

// login issues a session for the seeded account and returns its cookies.
func (w *webAuthnTestServer) login(t *testing.T) []*http.Cookie {
	t.Helper()
	_, cookies := issueSession(t, w.mgr, session.IssueParams{UserID: w.user.ID.String()})
	return cookies
}

// do executes a request against the server and returns the recorder.
func (w *webAuthnTestServer) do(method, path string, body []byte, cookies []*http.Cookie) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	addCookies(req, cookies)
	rec := httptest.NewRecorder()
	w.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// doWithGrant executes a request carrying both the session cookies and a fresh
// single-use step-up grant.
func (w *webAuthnTestServer) doWithGrant(
	t *testing.T,
	method, path string,
	cookies []*http.Cookie,
	sess session.Session,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	addCookies(req, cookies)
	req.Header.Set(stepup.HeaderStepUpAuth, mintTestGrant(t, w.stepUp, sess.UserID, sess.ID))
	rec := httptest.NewRecorder()
	w.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// seedCredential inserts a credential directly, bypassing the ceremony, so the
// deletion tests are not coupled to attestation mechanics (covered in
// internal/webauthn).
func (w *webAuthnTestServer) seedCredential(id []byte) db.WebauthnCredential {
	row := db.WebauthnCredential{ID: id, UserID: w.user.ID, PublicKey: []byte("cose")}
	w.creds.byUser[w.user.ID] = append(w.creds.byUser[w.user.ID], row)
	return row
}

// decodeWebAuthnError reads the JSON error envelope from a response.
func decodeWebAuthnError(t *testing.T, rec *httptest.ResponseRecorder) webauthnErrorResponse {
	t.Helper()
	var resp webauthnErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return resp
}

// clientDataJSONFor builds a syntactically valid clientDataJSON quoting the
// given challenge, so a request reaches the challenge lookup instead of failing
// earlier in parsing.
func clientDataJSONFor(t *testing.T, ceremony, challenge string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   challenge,
		"origin":      "http://localhost:8080",
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return raw
}

// syntheticAuthData builds an authenticatorData blob of the minimum legal size
// (32-byte RP ID hash + flags + 4-byte counter). A shorter value is rejected by
// the parser before the challenge is ever consulted, which would mask the
// behaviour under test.
func syntheticAuthData() []byte {
	rpIDHash := sha256.Sum256([]byte("localhost"))
	out := make([]byte, 0, 37)
	out = append(out, rpIDHash[:]...)
	out = append(out, 0x05) // UP | UV
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 1)
	return append(out, counter...)
}

// assertionBodyFor builds a parsable assertion response quoting the supplied
// challenge. The signature is garbage: these tests assert on the ceremony
// bookkeeping (unknown challenge) that is checked before any signature work.
func assertionBodyFor(t *testing.T, challenge string) []byte {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    enc([]byte{0x01, 0x02, 0x03, 0x04}),
		"type":  "public-key",
		"rawId": enc([]byte{0x01, 0x02, 0x03, 0x04}),
		"response": map[string]any{
			"clientDataJSON":    enc(clientDataJSONFor(t, "webauthn.get", challenge)),
			"authenticatorData": enc(syntheticAuthData()),
			"signature":         enc([]byte("not-a-real-signature")),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion body: %v", err)
	}
	return body
}

// TestWebAuthnRoutesAbsentWithoutService proves the passkey routes are only
// mounted when a WebAuthn service is configured, mirroring the session and OIDC
// routes' dependency gating.
func TestWebAuthnRoutesAbsentWithoutService(t *testing.T) {
	srv := New(testConfig(t), nil, Deps{})

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/auth/webauthn/login/generate-options"},
		{http.MethodPost, "/api/v1/auth/webauthn/login/verify"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/generate-options"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/verify"},
		{http.MethodGet, "/api/v1/auth/webauthn/keys"},
	}
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
			}
			_, _ = io.Copy(io.Discard, rec.Body)
		})
	}
}

// TestWebAuthnAccountRoutesRequireSession proves enrolment and key listing are
// gated behind a live session: without one, an attacker could graft their own
// authenticator onto someone else's account.
func TestWebAuthnAccountRoutesRequireSession(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/auth/webauthn/register/generate-options"},
		{http.MethodPost, "/api/v1/auth/webauthn/register/verify"},
		{http.MethodGet, "/api/v1/auth/webauthn/keys"},
	}
	for _, route := range routes {
		t.Run(route.path, func(t *testing.T) {
			rec := fx.do(route.method, route.path, nil, nil)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			_, _ = io.Copy(io.Discard, rec.Body)
		})
	}
}

func TestRecoveryEnrollmentRoutesAcceptOnlyRestrictedSession(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	_, fullCookies := issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})
	_, recoveryCookies := issueSession(t, fx.mgr, session.IssueParams{
		UserID: fx.user.ID.String(),
		Kind:   session.KindRecoveryEnrollment,
	})
	path := "/api/v1/auth/enrollment/webauthn/register/generate-options"

	if rec := fx.do(http.MethodPost, path, nil, fullCookies); rec.Code != http.StatusUnauthorized {
		t.Fatalf("full session on recovery enrollment = %d, want 401", rec.Code)
	}
	rec := fx.do(http.MethodPost, path, nil, recoveryCookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("restricted session on recovery enrollment = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var options struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode recovery options: %v", err)
	}
	if options.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("recovery userVerification = %q, want required", options.PublicKey.AuthenticatorSelection.UserVerification)
	}

	if rec := fx.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, recoveryCookies); rec.Code != http.StatusUnauthorized {
		t.Fatalf("restricted session on normal key route = %d, want 401", rec.Code)
	}
}

// TestWebAuthnLoginRoutesAreUnauthenticated proves the login endpoints are
// reachable without a session — they are how a user signs in — rather than being
// short-circuited by the session guard that protects the enrolment routes.
func TestWebAuthnLoginRoutesAreUnauthenticated(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	// Since Task 4.3 this succeeds even though the account has no passkey: the
	// service answers with a mock ceremony rather than an error, which is what
	// makes the endpoint useless for enumeration. Reaching 200 without a cookie
	// is itself the proof the guard is not in front of this route.
	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{"email":"passkey@example.com"}`), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// The usernameless variant is likewise reachable unauthenticated.
	discoverable := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{}`), nil)
	if discoverable.Code != http.StatusOK {
		t.Fatalf("discoverable status = %d, want %d", discoverable.Code, http.StatusOK)
	}
}

// TestRegisterOptionsReturns200 proves the authenticated options handler emits a
// well-formed CredentialCreation payload.
func TestRegisterOptionsReturns200(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})

	rec := fx.doWithGrant(t, http.MethodPost, "/api/v1/auth/webauthn/register/generate-options", cookies, sess)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}

	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
			User struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&options); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if options.PublicKey.Challenge == "" {
		t.Error("publicKey.challenge is empty")
	}
	if options.PublicKey.RP.ID != "localhost" {
		t.Errorf("publicKey.rp.id = %q, want %q", options.PublicKey.RP.ID, "localhost")
	}
	if options.PublicKey.User.Name != fx.user.Email {
		t.Errorf("publicKey.user.name = %q, want %q", options.PublicKey.User.Name, fx.user.Email)
	}
	// The user handle on the wire is the anonymised value, never the account
	// UUID (docs/architecture.md, "Anonymized user.id Mapping").
	if options.PublicKey.User.ID == fx.user.ID.String() {
		t.Error("publicKey.user.id leaks the account UUID")
	}
}

// TestRegisterOptionsForDeletedAccountReturns401 proves a session that outlived
// its account cannot start an enrolment.
func TestRegisterOptionsForDeletedAccountReturns401(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, fx.mgr, session.IssueParams{UserID: fx.user.ID.String()})
	delete(fx.users.byID, fx.user.ID)

	rec := fx.doWithGrant(t, http.MethodPost, "/api/v1/auth/webauthn/register/generate-options", cookies, sess)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := decodeWebAuthnError(t, rec); got.Error != "unauthorized" {
		t.Errorf("error = %q, want %q", got.Error, "unauthorized")
	}
}

// TestRegisterVerifyMalformedBodyReturns400 proves an unparsable attestation
// response is a client error, distinguishable from a stale challenge because
// this route already runs inside an authenticated session.
func TestRegisterVerifyMalformedBodyReturns400(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	cookies := fx.login(t)

	bodies := map[string][]byte{
		"empty":        {},
		"not json":     []byte("nope"),
		"empty object": []byte(`{}`),
		"wrong type":   []byte(`{"id":"AAAA","type":"password","rawId":"AAAA","response":{}}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/register/verify", body, cookies)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := decodeWebAuthnError(t, rec); got.Error != "invalid_request" {
				t.Errorf("error = %q, want %q", got.Error, "invalid_request")
			}
		})
	}
}

func TestRegisterOptionsRejectsSessionWithoutStepUp(t *testing.T) {
	fx := newWebAuthnTestServerWithStepUp(t, true)
	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/register/generate-options", nil, fx.login(t))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("registration start without step-up = %d, want 403", rec.Code)
	}
}

// TestWebAuthnErrorMapping locks in the status/code matrix the two error
// writers implement. It exercises them directly because several branches
// (a cloned authenticator, an expired challenge) cannot be reached over HTTP
// without a live authenticator, yet their mapping is exactly what stops the
// endpoints from leaking why a ceremony failed.
func TestWebAuthnErrorMapping(t *testing.T) {
	srv := New(testConfig(t), nil, Deps{})

	t.Run("registration", func(t *testing.T) {
		tests := []struct {
			err        error
			wantStatus int
			wantCode   string
		}{
			{webauthn.ErrUserNotFound, http.StatusUnauthorized, "unauthorized"},
			{webauthn.ErrInvalidResponse, http.StatusBadRequest, "invalid_request"},
			{webauthn.ErrChallengeNotFound, http.StatusBadRequest, "challenge_invalid"},
			{webauthn.ErrChallengeExpired, http.StatusBadRequest, "challenge_invalid"},
			{webauthn.ErrVerification, http.StatusBadRequest, "verification_failed"},
			{errors.New("database on fire"), http.StatusInternalServerError, "server_error"},
		}
		for _, tc := range tests {
			t.Run(tc.wantCode+"/"+tc.err.Error(), func(t *testing.T) {
				rec := httptest.NewRecorder()
				srv.writeWebAuthnRegistrationError(rec, "test", tc.err)

				if rec.Code != tc.wantStatus {
					t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
				}
				if got := decodeWebAuthnError(t, rec); got.Error != tc.wantCode {
					t.Errorf("error = %q, want %q", got.Error, tc.wantCode)
				}
			})
		}
	})

	// Every login failure except a malformed body collapses into the same
	// opaque 401, so a caller cannot tell an unknown account from a replayed
	// challenge or a cloned authenticator.
	t.Run("login", func(t *testing.T) {
		opaque := []error{
			webauthn.ErrUserNotFound,
			webauthn.ErrNoCredentials,
			webauthn.ErrChallengeNotFound,
			webauthn.ErrChallengeExpired,
			webauthn.ErrVerification,
			webauthn.ErrCredentialCloned,
		}
		for _, err := range opaque {
			t.Run(err.Error(), func(t *testing.T) {
				rec := httptest.NewRecorder()
				srv.writeWebAuthnLoginError(rec, "test", err)

				if rec.Code != http.StatusUnauthorized {
					t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
				}
				if got := decodeWebAuthnError(t, rec); got.Error != "invalid_credentials" {
					t.Errorf("error = %q, want %q", got.Error, "invalid_credentials")
				}
			})
		}

		t.Run("malformed body", func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.writeWebAuthnLoginError(rec, "test", webauthn.ErrInvalidResponse)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := decodeWebAuthnError(t, rec); got.Error != "invalid_request" {
				t.Errorf("error = %q, want %q", got.Error, "invalid_request")
			}
		})

		t.Run("internal fault", func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.writeWebAuthnLoginError(rec, "test", errors.New("database on fire"))

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
			if got := decodeWebAuthnError(t, rec); got.Error != "server_error" {
				t.Errorf("error = %q, want %q", got.Error, "server_error")
			}
		})
	})
}

// TestLoginOptionsOmittedEmailRunsDiscoverableFlow proves a request that names
// no account is not an error but a request for the primary, usernameless
// ceremony: the response carries an empty allowCredentials list.
func TestLoginOptionsOmittedEmailRunsDiscoverableFlow(t *testing.T) {
	bodies := map[string][]byte{
		"absent body":  nil,
		"empty body":   {},
		"empty object": []byte(`{}`),
		"other field":  []byte(`{"other":"field"}`),
		"empty string": []byte(`{"email":""}`),
		"blank string": []byte(`{"email":"   "}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			fx := newWebAuthnTestServer(t)
			rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", body, nil)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			var options struct {
				PublicKey struct {
					Challenge          string `json:"challenge"`
					AllowedCredentials []struct {
						ID string `json:"id"`
					} `json:"allowCredentials"`
				} `json:"publicKey"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&options); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if options.PublicKey.Challenge == "" {
				t.Error("publicKey.challenge is empty")
			}
			if n := len(options.PublicKey.AllowedCredentials); n != 0 {
				t.Errorf("len(allowCredentials) = %d, want 0 for a usernameless ceremony", n)
			}
		})
	}
}

// TestLoginOptionsMalformedJSONReturns400 proves a body that is present but not
// valid JSON is still a client error: it cannot be silently reinterpreted as the
// discoverable flow, which would hide a broken client.
func TestLoginOptionsMalformedJSONReturns400(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte("nope"), nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := decodeWebAuthnError(t, rec); got.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", got.Error, "invalid_request")
	}
}

// TestLoginOptionsIsNotAnEnumerationOracle is the account-harvesting assertion
// at the HTTP boundary: a registered account, a registered account with no
// passkey, and an address that was never registered must all produce the same
// status and the same response shape, so the endpoint answers no question about
// who has an account (docs/api-design.md §1.3).
func TestLoginOptionsIsNotAnEnumerationOracle(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	// An account that can genuinely log in, so the comparison is against a real
	// ceremony rather than two flavours of failure.
	enrolled := db.User{
		ID:                 uuid.New(),
		Email:              "enrolled@example.com",
		Status:             "active",
		WebauthnUserHandle: bytes.Repeat([]byte{0x11}, 8),
	}
	fx.users.byID[enrolled.ID] = enrolled
	fx.users.byEmail[enrolled.Email] = enrolled.ID
	fx.creds.byUser[enrolled.ID] = []db.WebauthnCredential{{
		ID:     bytes.Repeat([]byte{0x22}, 32),
		UserID: enrolled.ID,
	}}

	shapes := make(map[string][]string)
	for _, email := range []string{
		enrolled.Email,        // real, usable
		"passkey@example.com", // real, no passkey
		"nobody@example.com",  // never registered
	} {
		body, err := json.Marshal(map[string]string{"email": email})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", body, nil)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want %d", email, rec.Code, http.StatusOK)
		}

		var wire struct {
			PublicKey struct {
				RelyingPartyID     string `json:"rpId"`
				UserVerification   string `json:"userVerification"`
				Timeout            int    `json:"timeout"`
				Challenge          string `json:"challenge"`
				AllowedCredentials []struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"allowCredentials"`
			} `json:"publicKey"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&wire); err != nil {
			t.Fatalf("%s: decode body: %v", email, err)
		}

		// The fingerprint deliberately excludes the challenge and credential ID
		// *values* (which must differ) but keeps their lengths and every other
		// field, since any of those differing would be an enumeration signal.
		fingerprint := []string{
			wire.PublicKey.RelyingPartyID,
			wire.PublicKey.UserVerification,
			fmt.Sprint(wire.PublicKey.Timeout),
			fmt.Sprint(len(wire.PublicKey.Challenge)),
			fmt.Sprint(len(wire.PublicKey.AllowedCredentials)),
		}
		for _, cred := range wire.PublicKey.AllowedCredentials {
			fingerprint = append(fingerprint, cred.Type, fmt.Sprint(len(cred.ID)))
		}
		shapes[email] = fingerprint
	}

	want := shapes[enrolled.Email]
	for email, got := range shapes {
		if !slices.Equal(got, want) {
			t.Errorf("%s response shape = %v, enrolled-account shape = %v; they must be identical",
				email, got, want)
		}
	}
}

// TestLoginVerifyMalformedBodyReturns400 proves an unparsable assertion is a
// client error rather than an opaque 401.
func TestLoginVerifyMalformedBodyReturns400(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	bodies := map[string][]byte{
		"empty":        {},
		"not json":     []byte("nope"),
		"empty object": []byte(`{}`),
		"wrong type":   []byte(`{"id":"AAAA","type":"password","rawId":"AAAA","response":{}}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/verify", body, nil)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := decodeWebAuthnError(t, rec); got.Error != "invalid_request" {
				t.Errorf("error = %q, want %q", got.Error, "invalid_request")
			}
		})
	}
}

// TestLoginVerifyUnknownChallengeReturns401 proves an assertion quoting a
// challenge that was never issued fails opaquely, and mints no session cookie.
func TestLoginVerifyUnknownChallengeReturns401(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	body := assertionBodyFor(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)))
	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/verify", body, nil)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := decodeWebAuthnError(t, rec); got.Error != "invalid_credentials" {
		t.Errorf("error = %q, want %q", got.Error, "invalid_credentials")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("a failed login set %d cookie(s), want none", len(cookies))
	}
}

// TestListKeysReturnsEmptyArray proves the listing endpoint returns a JSON array
// (not null) for an account with no enrolled authenticators.
func TestListKeysReturnsEmptyArray(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	rec := fx.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, fx.login(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	if got := bytes.TrimSpace(rec.Body.Bytes()); string(got) != "[]" {
		t.Errorf("body = %s, want an empty JSON array", got)
	}
}

// TestListKeysProjectsStoredCredentials proves the listing exposes the public
// projection of a stored credential and never the COSE public key.
func TestListKeysProjectsStoredCredentials(t *testing.T) {
	fx := newWebAuthnTestServer(t)
	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	fx.creds.byUser[fx.user.ID] = []db.WebauthnCredential{{
		ID:              credID,
		UserID:          fx.user.ID,
		PublicKey:       []byte("super-secret-cose-key"),
		AttestationType: "none",
		SignCount:       42,
		UserPresent:     true,
		UserVerified:    true,
		Aaguid:          uuid.Nil,
	}}

	rec := fx.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, fx.login(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	raw := rec.Body.Bytes()
	if bytes.Contains(raw, []byte("super-secret-cose-key")) {
		t.Error("the credential public key leaked into the listing response")
	}

	var list []webauthnCredentialResponse
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(list))
	}
	got := list[0]
	if got.ID != "3q2-7w" { // base64url(unpadded) of DE AD BE EF
		t.Errorf("id = %q, want the unpadded base64url credential id %q", got.ID, "3q2-7w")
	}
	if got.SignCount != 42 {
		t.Errorf("sign_count = %d, want 42", got.SignCount)
	}
	if !got.UserVerified {
		t.Error("user_verified = false, want true")
	}
	if got.AttestationType != "none" {
		t.Errorf("attestation_type = %q, want %q", got.AttestationType, "none")
	}
	if got.LastUsedAt != nil {
		t.Errorf("last_used_at = %v, want nil for a never-used credential", got.LastUsedAt)
	}
}

// TestListKeysIsScopedToTheSession proves one account never sees another's
// authenticators.
func TestListKeysIsScopedToTheSession(t *testing.T) {
	fx := newWebAuthnTestServer(t)
	other := uuid.New()
	fx.creds.byUser[other] = []db.WebauthnCredential{{
		ID:     []byte{0x01, 0x02},
		UserID: other,
	}}

	rec := fx.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, fx.login(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var list []webauthnCredentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("len(keys) = %d, want 0; another account's credentials were exposed", len(list))
	}
}

// --- DELETE /api/v1/auth/webauthn/keys/{id} (step-up gated) -----------------

// TestWebAuthnDeleteKeyRequiresAGrant confirms a live session alone cannot
// unenrol an authenticator: unenrolling is how an attacker holding a hijacked
// session locks the legitimate owner out.
func TestWebAuthnDeleteKeyRequiresAGrant(t *testing.T) {
	ts := newWebAuthnTestServerWithStepUp(t, true)
	cookies := ts.login(t)
	row := ts.seedCredential([]byte("cred-a"))
	ts.seedCredential([]byte("cred-b"))

	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)
	rec := ts.do(http.MethodDelete, path, nil, cookies)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(ts.creds.byUser[ts.user.ID]) != 2 {
		t.Error("a rejected request removed a credential")
	}
}

// TestWebAuthnDeleteKeyWithGrant is the happy path.
func TestWebAuthnDeleteKeyWithGrant(t *testing.T) {
	ts := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, ts.mgr, session.IssueParams{UserID: ts.user.ID.String()})
	row := ts.seedCredential([]byte("cred-a"))
	ts.seedCredential([]byte("cred-b"))

	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)
	rec := ts.doWithGrant(t, http.MethodDelete, path, cookies, sess)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body: %s)", rec.Code, rec.Body.String())
	}
	remaining := ts.creds.byUser[ts.user.ID]
	if len(remaining) != 1 || !bytes.Equal(remaining[0].ID, []byte("cred-b")) {
		t.Fatalf("expected only cred-b to remain, got %d credentials", len(remaining))
	}
}

// TestWebAuthnDeleteKeyRefusesTheLastFactor surfaces the lockout guard as a 409
// with a distinct code, since it is the one outcome the user must understand in
// order to act on it (enrol another passkey, enable TOTP, or set a password).
func TestWebAuthnDeleteKeyRefusesTheLastFactor(t *testing.T) {
	ts := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, ts.mgr, session.IssueParams{UserID: ts.user.ID.String()})
	row := ts.seedCredential([]byte("only-cred"))

	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)
	rec := ts.doWithGrant(t, http.MethodDelete, path, cookies, sess)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body: %s)", rec.Code, rec.Body.String())
	}
	if got := decodeWebAuthnError(t, rec).Error; got != "last_credential" {
		t.Fatalf("error = %q, want last_credential", got)
	}
	if len(ts.creds.byUser[ts.user.ID]) != 1 {
		t.Error("the last credential was removed despite the refusal")
	}
}

// TestWebAuthnDeleteKeyUnknownAndMalformedIDs confirms both render as 404, so a
// caller cannot probe for credential IDs belonging to other accounts.
func TestWebAuthnDeleteKeyUnknownAndMalformedIDs(t *testing.T) {
	ts := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, ts.mgr, session.IssueParams{UserID: ts.user.ID.String()})
	ts.seedCredential([]byte("cred-a"))
	ts.seedCredential([]byte("cred-b"))

	for _, tc := range []struct {
		name string
		id   string
	}{
		{"unknown credential", base64.RawURLEncoding.EncodeToString([]byte("nope"))},
		{"not base64url", "!!!not-base64!!!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := ts.doWithGrant(t, http.MethodDelete,
				"/api/v1/auth/webauthn/keys/"+tc.id, cookies, sess)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
			}
			if got := decodeWebAuthnError(t, rec).Error; got != "credential_not_found" {
				t.Fatalf("error = %q, want credential_not_found", got)
			}
		})
	}
}

// TestWebAuthnDeleteKeyIsScopedToTheOwner confirms one account cannot unenrol
// another's authenticator, and that the refusal is indistinguishable from "no
// such credential".
func TestWebAuthnDeleteKeyIsScopedToTheOwner(t *testing.T) {
	ts := newWebAuthnTestServerWithStepUp(t, true)
	sess, cookies := issueSession(t, ts.mgr, session.IssueParams{UserID: ts.user.ID.String()})
	ts.seedCredential([]byte("mine-a"))
	ts.seedCredential([]byte("mine-b"))

	// A credential owned by a different account.
	other := uuid.New()
	victimID := []byte{0x09, 0x09}
	ts.creds.byUser[other] = []db.WebauthnCredential{{ID: victimID, UserID: other}}

	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(victimID)
	rec := ts.doWithGrant(t, http.MethodDelete, path, cookies, sess)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	if len(ts.creds.byUser[other]) != 1 {
		t.Error("a foreign account's credential was removed")
	}
}

// TestWebAuthnDeleteKeyAbsentWithoutStepUpService is the fail-closed guarantee for
// this route: without a step-up service it must not be reachable at all.
func TestWebAuthnDeleteKeyAbsentWithoutStepUpService(t *testing.T) {
	ts := newWebAuthnTestServer(t)
	cookies := ts.login(t)
	row := ts.seedCredential([]byte("cred-a"))

	// The sibling listing route proves the group is otherwise mounted.
	if rec := ts.do(http.MethodGet, "/api/v1/auth/webauthn/keys", nil, cookies); rec.Code != http.StatusOK {
		t.Fatalf("GET /keys = %d, want 200", rec.Code)
	}

	path := "/api/v1/auth/webauthn/keys/" + base64.RawURLEncoding.EncodeToString(row.ID)
	rec := ts.do(http.MethodDelete, path, nil, cookies)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /keys/{id} = %d, want the route to be withheld", rec.Code)
	}
	if len(ts.creds.byUser[ts.user.ID]) != 1 {
		t.Error("the credential was removed by an unmounted route")
	}
}
