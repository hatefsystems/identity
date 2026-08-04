package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
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
	srv   *Server
	mgr   *session.Manager
	users *fakeWebAuthnUserStore
	creds *fakeWebAuthnCredentialStore
	user  db.User
}

// newWebAuthnTestServer builds that fixture. The session cookie is non-Secure so
// it survives the plain-HTTP httptest transport, matching newSessionTestServer.
func newWebAuthnTestServer(t *testing.T) *webAuthnTestServer {
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

	user := db.User{ID: uuid.New(), Email: "passkey@example.com"}
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
	}, users, creds, webauthn.NewMemoryChallengeStore())
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}

	return &webAuthnTestServer{
		srv:   New(testConfig(t), nil, Deps{SessionManager: mgr, WebAuthn: svc}),
		mgr:   mgr,
		users: users,
		creds: creds,
		user:  user,
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
	fx := newWebAuthnTestServer(t)

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

// TestWebAuthnLoginRoutesAreUnauthenticated proves the login endpoints are
// reachable without a session — they are how a user signs in — by asserting they
// fail on their own merits (400/401) rather than on the session guard.
func TestWebAuthnLoginRoutesAreUnauthenticated(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{"email":"passkey@example.com"}`), nil)
	// The account exists but has no passkeys yet, so this is a 401 from the
	// service, not the 401 the guard would produce before reaching it.
	if rec.Code == http.StatusOK {
		t.Fatal("login options succeeded for an account with no credentials")
	}
	if got := decodeWebAuthnError(t, rec); got.Error != "invalid_credentials" {
		t.Errorf("error = %q, want %q (proving the handler ran, not the session guard)", got.Error, "invalid_credentials")
	}
}

// TestRegisterOptionsReturns200 proves the authenticated options handler emits a
// well-formed CredentialCreation payload.
func TestRegisterOptionsReturns200(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/register/generate-options", nil, fx.login(t))

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
	fx := newWebAuthnTestServer(t)
	cookies := fx.login(t)
	delete(fx.users.byID, fx.user.ID)

	rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/register/generate-options", nil, cookies)

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
	fx := newWebAuthnTestServer(t)
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

// TestLoginOptionsRequiresEmail proves the user-named login path rejects a
// request that does not name an account.
func TestLoginOptionsRequiresEmail(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	bodies := map[string][]byte{
		"empty":        {},
		"not json":     []byte("nope"),
		"empty object": []byte(`{}`),
		"other field":  []byte(`{"other":"field"}`),
		"empty string": []byte(`{"email":""}`),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", body, nil)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if got := decodeWebAuthnError(t, rec); got.Error != "invalid_request" {
				t.Errorf("error = %q, want %q", got.Error, "invalid_request")
			}
		})
	}
}

// TestLoginOptionsIsNotAnEnumerationOracle proves an unknown account and a
// known-but-passkey-less account are indistinguishable on the wire. Task 4.3
// replaces this with a mock challenge, which removes the remaining signal that a
// 401 means "not registered".
func TestLoginOptionsIsNotAnEnumerationOracle(t *testing.T) {
	fx := newWebAuthnTestServer(t)

	unknown := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{"email":"nobody@example.com"}`), nil)
	known := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/generate-options", []byte(`{"email":"passkey@example.com"}`), nil)

	if unknown.Code != http.StatusUnauthorized {
		t.Errorf("unknown account status = %d, want %d", unknown.Code, http.StatusUnauthorized)
	}
	if known.Code != unknown.Code {
		t.Errorf("known-account status = %d, unknown-account status = %d; they must match", known.Code, unknown.Code)
	}
	if got, want := decodeWebAuthnError(t, known), decodeWebAuthnError(t, unknown); got != want {
		t.Errorf("known-account error = %+v, unknown-account error = %+v; they must match", got, want)
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
