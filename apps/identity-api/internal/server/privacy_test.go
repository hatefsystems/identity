package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

const (
	privacyDeletePath         = "/api/v1/users/me/"
	privacyReclaimOptionsPath = "/api/v1/auth/deletion/reclaim/options"
	privacyReclaimPath        = "/api/v1/auth/deletion/reclaim/"
)

// --- fakes ------------------------------------------------------------------

// privacyFakeStore is a minimal privacy.Store for the handler suite. The service's
// own behaviour is covered in internal/privacy; here only routing, middleware order,
// and status/response shapes are exercised.
type privacyFakeStore struct {
	users    map[uuid.UUID]db.User
	requests []db.DeletionRequest
	now      func() time.Time
}

func newPrivacyFakeStore(users ...db.User) *privacyFakeStore {
	byID := make(map[uuid.UUID]db.User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	return &privacyFakeStore{users: byID, now: time.Now}
}

func (f *privacyFakeStore) GetUserByIDForAdmin(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *privacyFakeStore) SoftDeleteUser(_ context.Context, id uuid.UUID) (int64, error) {
	u, ok := f.users[id]
	if !ok || u.DeletedAt.Valid {
		return 0, nil
	}
	u.Status = "pending_deletion"
	u.DeletedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
	f.users[id] = u
	return 1, nil
}

func (f *privacyFakeStore) ReclaimUser(_ context.Context, arg db.ReclaimUserParams) (int64, error) {
	u, ok := f.users[arg.ID]
	if !ok || u.Status != "pending_deletion" {
		return 0, nil
	}
	u.Status = "active"
	u.DeletedAt = pgtype.Timestamptz{}
	f.users[arg.ID] = u
	return 1, nil
}

func (f *privacyFakeStore) CreateDeletionRequest(_ context.Context, arg db.CreateDeletionRequestParams) (db.DeletionRequest, error) {
	row := db.DeletionRequest{
		ID:        uuid.New(),
		UserID:    arg.UserID,
		TokenHash: arg.TokenHash,
		ExpiresAt: arg.ExpiresAt,
		CreatedAt: pgtype.Timestamptz{Time: f.now(), Valid: true},
	}
	f.requests = append(f.requests, row)
	return row, nil
}

func (f *privacyFakeStore) active(r db.DeletionRequest) bool {
	return !r.ConsumedAt.Valid && r.ExpiresAt.Valid && r.ExpiresAt.Time.After(f.now())
}

func (f *privacyFakeStore) GetActiveDeletionRequestByTokenHashForUpdate(_ context.Context, tokenHash string) (db.DeletionRequest, error) {
	for _, r := range f.requests {
		if r.TokenHash == tokenHash && f.active(r) {
			return r, nil
		}
	}
	return db.DeletionRequest{}, pgx.ErrNoRows
}

func (f *privacyFakeStore) GetActiveDeletionRequestForUser(_ context.Context, userID uuid.UUID) (db.DeletionRequest, error) {
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].UserID == userID && f.active(f.requests[i]) {
			return f.requests[i], nil
		}
	}
	return db.DeletionRequest{}, pgx.ErrNoRows
}

func (f *privacyFakeStore) IncrementDeletionRequestFailedAttempts(_ context.Context, id uuid.UUID) (int64, error) {
	for i, r := range f.requests {
		if r.ID == id {
			f.requests[i].FailedAttempts++
			return 1, nil
		}
	}
	return 0, nil
}

func (f *privacyFakeStore) MarkDeletionRequestNotified(_ context.Context, id uuid.UUID) (int64, error) {
	for i, r := range f.requests {
		if r.ID == id {
			f.requests[i].NotifiedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			return 1, nil
		}
	}
	return 0, nil
}

func (f *privacyFakeStore) ConsumeDeletionRequest(_ context.Context, id uuid.UUID) (int64, error) {
	for i, r := range f.requests {
		if r.ID == id && !r.ConsumedAt.Valid {
			f.requests[i].ConsumedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			return 1, nil
		}
	}
	return 0, nil
}

func (f *privacyFakeStore) ExpireDeletionRequestsForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	for i, r := range f.requests {
		if r.UserID == userID && !r.ConsumedAt.Valid {
			f.requests[i].ConsumedAt = pgtype.Timestamptz{Time: f.now(), Valid: true}
			n++
		}
	}
	return n, nil
}

// privacyFakeNotifier keeps the plaintext token so a test can drive the reclaim
// endpoints with the value a real user would read from their mail.
type privacyFakeNotifier struct {
	notices []privacy.DeletionNotice
	err     error
}

func (f *privacyFakeNotifier) NotifyDeletionRequested(_ context.Context, notice privacy.DeletionNotice) error {
	if f.err != nil {
		return f.err
	}
	f.notices = append(f.notices, notice)
	return nil
}

func (f *privacyFakeNotifier) IsDevelopmentOnly() bool { return false }

// privacyFakePasskeys scripts the reclaim ceremony outcome.
type privacyFakePasskeys struct {
	beginErr  error
	finishErr error
}

func (f *privacyFakePasskeys) BeginReclaimAssertion(context.Context, uuid.UUID, string) (*protocol.CredentialAssertion, error) {
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

func (f *privacyFakePasskeys) FinishReclaimAssertion(context.Context, uuid.UUID, string, []byte) error {
	return f.finishErr
}

// privacyFakeLimiter denies any key in deny.
type privacyFakeLimiter struct {
	deny map[string]bool
}

func (f *privacyFakeLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	return !f.deny[key], nil
}

// --- fixture ----------------------------------------------------------------

type privacyFixture struct {
	server   *Server
	store    *privacyFakeStore
	notifier *privacyFakeNotifier
	passkeys *privacyFakePasskeys
	limiter  *privacyFakeLimiter
	stepUp   *stepup.Service
	sess     session.Session
	cookie   *http.Cookie
	userID   uuid.UUID
}

// privacyOptions carries the mounting matrix knobs.
type privacyOptions struct {
	// noStepUp omits the step-up service, which must leave the gated delete route
	// unmounted rather than served ungated.
	noStepUp bool
	// noSession omits the session manager.
	noSession bool
	// noPrivacy omits the privacy service entirely.
	noPrivacy bool
}

func newPrivacyFixture(t *testing.T, opts privacyOptions) *privacyFixture {
	t.Helper()

	userID := uuid.New()
	fx := &privacyFixture{
		userID:   userID,
		store:    newPrivacyFakeStore(db.User{ID: userID, Email: "delete@example.com", Status: "active"}),
		notifier: &privacyFakeNotifier{},
		passkeys: &privacyFakePasskeys{},
		limiter:  &privacyFakeLimiter{deny: make(map[string]bool)},
	}

	var sessMgr *session.Manager
	if !opts.noSession {
		sessMgr = newRecoverySessionManager(t)
		fx.sess, fx.cookie = issueRecoverySession(t, sessMgr, userID)
	}

	if !opts.noStepUp {
		fx.stepUp = newStepUpServiceForUser(t, userID)
	}

	var privacySvc *privacy.Service
	if !opts.noPrivacy {
		svc, err := privacy.New(privacy.Config{GracePeriod: 720 * time.Hour},
			fx.store, fx.notifier, audit.NewLogRecorder(nil),
			privacy.WithPasskeyReclaimer(fx.passkeys),
			privacy.WithRateLimiter(fx.limiter),
		)
		if err != nil {
			t.Fatalf("privacy.New: %v", err)
		}
		privacySvc = svc
	}

	deps := Deps{Privacy: privacySvc, StepUp: fx.stepUp}
	if sessMgr != nil {
		deps.SessionManager = sessMgr
	}
	fx.server = New(config.Config{Environment: "development"}, nil, deps)
	return fx
}

// deleteMe issues the step-up-gated deletion request, optionally with a grant.
func (fx *privacyFixture) deleteMe(t *testing.T, withGrant bool) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodDelete, privacyDeletePath, nil)
	if fx.cookie != nil {
		req.AddCookie(fx.cookie)
	}
	// A grant is bound to the session that earned it, so there is nothing to mint
	// when the fixture has no session manager.
	if withGrant && fx.stepUp != nil && fx.sess.ID != "" {
		req.Header.Set(stepup.HeaderStepUpAuth, mintTestGrant(t, fx.stepUp, fx.userID.String(), fx.sess.ID))
	}
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// post sends an anonymous JSON body to one of the reclaim endpoints.
func (fx *privacyFixture) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	return rec
}

// requestDeletionToken drives a successful deletion and returns the emailed token.
func (fx *privacyFixture) requestDeletionToken(t *testing.T) string {
	t.Helper()

	if rec := fx.deleteMe(t, true); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /users/me = %d (%s), want 204", rec.Code, rec.Body.String())
	}
	if len(fx.notifier.notices) == 0 {
		t.Fatal("no deletion notice was delivered")
	}
	return fx.notifier.notices[len(fx.notifier.notices)-1].ReclaimToken
}

// errorBody decodes the {"error": "..."} envelope.
func errorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body privacyErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

// --- Mounting matrix --------------------------------------------------------

// TestPrivacyRoutesMountingMatrix is the fail-closed contract in table form. Two
// independent absences must each leave the deletion route unreachable: no privacy
// service (no notifier can deliver the reclaim token) and no step-up service (the
// route is documented as gated, so "no gate" resolves to "no route").
func TestPrivacyRoutesMountingMatrix(t *testing.T) {
	tests := []struct {
		name           string
		opts           privacyOptions
		wantDelete     int
		wantReclaimOut int
	}{
		{
			name:           "fully configured",
			opts:           privacyOptions{},
			wantDelete:     http.StatusNoContent,
			wantReclaimOut: http.StatusUnauthorized, // anonymous, no token supplied
		},
		{
			name:           "no step-up service leaves the gated route unmounted",
			opts:           privacyOptions{noStepUp: true},
			wantDelete:     http.StatusNotFound,
			wantReclaimOut: http.StatusUnauthorized,
		},
		{
			name:           "no privacy service leaves every route unmounted",
			opts:           privacyOptions{noPrivacy: true},
			wantDelete:     http.StatusNotFound,
			wantReclaimOut: http.StatusNotFound,
		},
		{
			name:           "no session manager leaves the gated route unmounted",
			opts:           privacyOptions{noSession: true},
			wantDelete:     http.StatusNotFound,
			wantReclaimOut: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPrivacyFixture(t, tc.opts)

			if rec := fx.deleteMe(t, true); rec.Code != tc.wantDelete {
				t.Errorf("DELETE /users/me = %d (%s), want %d", rec.Code, rec.Body.String(), tc.wantDelete)
			}
			// The anonymous reclaim endpoints must stay reachable without a session
			// or a step-up service: the account they serve cannot log in at all.
			rec := fx.post(t, privacyReclaimOptionsPath, privacyReclaimRequest{})
			if rec.Code != tc.wantReclaimOut {
				t.Errorf("POST reclaim/options = %d (%s), want %d", rec.Code, rec.Body.String(), tc.wantReclaimOut)
			}
		})
	}
}

// TestPrivacyDeleteRequiresSessionThenStepUp pins the middleware order, which is
// load-bearing: the step-up middleware validates the grant against the caller's live
// session, so a missing session must be answered by the session guard (401) rather
// than reaching the step-up guard at all.
func TestPrivacyDeleteRequiresSessionThenStepUp(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})

	// No cookie: the session guard rejects first with a bare 401.
	req := httptest.NewRequest(http.MethodDelete, privacyDeletePath, nil)
	rec := httptest.NewRecorder()
	fx.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE without a session = %d (%s), want 401", rec.Code, rec.Body.String())
	}
	if len(fx.store.requests) != 0 {
		t.Fatal("an unauthenticated request created a deletion request")
	}

	// Session but no grant: the step-up guard answers 403 with the RFC 9470 code.
	rec = fx.deleteMe(t, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE without a grant = %d (%s), want 403", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "insufficient_user_authentication" {
		t.Errorf("error = %q, want insufficient_user_authentication", got)
	}
	if len(fx.store.requests) != 0 {
		t.Fatal("an ungated request created a deletion request")
	}
}

// --- DELETE /api/v1/users/me ------------------------------------------------

func TestPrivacyDeleteReturns204AndDeactivates(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})

	rec := fx.deleteMe(t, true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d (%s), want 204", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("204 carried a body: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if fx.store.users[fx.userID].Status != "pending_deletion" {
		t.Error("the account was not deactivated")
	}
	if len(fx.notifier.notices) != 1 {
		t.Errorf("notices = %d, want 1", len(fx.notifier.notices))
	}
}

// TestPrivacyDeleteIsIdempotent: a client retrying after a dropped response gets the
// same 204 and cannot use the difference to probe prior account state.
func TestPrivacyDeleteIsIdempotent(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})

	first := fx.deleteMe(t, true)
	second := fx.deleteMe(t, true)

	if first.Code != http.StatusNoContent || second.Code != http.StatusNoContent {
		t.Fatalf("statuses = %d then %d, want 204 both", first.Code, second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("bodies differ between a first and a repeat request: %q vs %q",
			first.Body.String(), second.Body.String())
	}
}

func TestPrivacyDeleteRateLimited(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	fx.limiter.deny["rate:privacy:delete:account:"+fx.userID.String()] = true

	rec := fx.deleteMe(t, true)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("DELETE = %d (%s), want 429", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "rate_limited" {
		t.Errorf("error = %q, want rate_limited", got)
	}
}

// TestPrivacyDeleteUnauthorizedWhenSessionOutlivedAccount covers the one case where
// a valid session and grant still cannot delete.
func TestPrivacyDeleteUnauthorizedWhenSessionOutlivedAccount(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	delete(fx.store.users, fx.userID)

	rec := fx.deleteMe(t, true)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE = %d (%s), want 401", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "unauthorized" {
		t.Errorf("error = %q, want unauthorized", got)
	}
}

// --- Reclaim endpoints ------------------------------------------------------

func TestPrivacyReclaimOptionsReturnsWebAuthnChallenge(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	token := fx.requestDeletionToken(t)

	rec := fx.post(t, privacyReclaimOptionsPath, privacyReclaimRequest{Token: token})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST reclaim/options = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var body privacyReclaimOptionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal options: %v", err)
	}
	if body.Factor != privacy.FactorWebAuthn {
		t.Errorf("factor = %q, want %q", body.Factor, privacy.FactorWebAuthn)
	}
	if body.WebAuthn == nil {
		t.Error("webauthn options missing for the webauthn factor")
	}
	if body.WebAuthn != nil && body.WebAuthn.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("userVerification = %q, want required", body.WebAuthn.Response.UserVerification)
	}
}

func TestPrivacyReclaimSucceedsAndReturns204(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	token := fx.requestDeletionToken(t)

	rec := fx.post(t, privacyReclaimPath, privacyReclaimRequest{
		Token:     token,
		Factor:    privacy.FactorWebAuthn,
		Assertion: json.RawMessage(`{"id":"x"}`),
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST reclaim = %d (%s), want 204", rec.Code, rec.Body.String())
	}
	if fx.store.users[fx.userID].Status != "active" {
		t.Error("the account was not restored")
	}
	// The response must carry no session: the user has to log in normally.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			t.Error("the reclaim response issued a session cookie")
		}
	}
}

// TestPrivacyReclaimTokenFailuresAreIndistinguishable is the no-oracle guard at the
// HTTP boundary for token-level failures: both endpoints must render them
// byte-identically, so nothing confirms that a given deletion exists.
func TestPrivacyReclaimTokenFailuresAreIndistinguishable(t *testing.T) {
	tests := []struct {
		name string
		body func(t *testing.T, fx *privacyFixture) privacyReclaimRequest
	}{
		{
			name: "missing token",
			body: func(*testing.T, *privacyFixture) privacyReclaimRequest {
				return privacyReclaimRequest{Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "unknown token",
			body: func(t *testing.T, _ *privacyFixture) privacyReclaimRequest {
				tok, _, err := privacy.NewReclaimToken()
				if err != nil {
					t.Fatalf("NewReclaimToken: %v", err)
				}
				return privacyReclaimRequest{Token: tok, Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "consumed token",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				token := fx.requestDeletionToken(t)
				if _, err := fx.store.ExpireDeletionRequestsForUser(context.Background(), fx.userID); err != nil {
					t.Fatalf("ExpireDeletionRequestsForUser: %v", err)
				}
				return privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "account no longer pending deletion",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				token := fx.requestDeletionToken(t)
				u := fx.store.users[fx.userID]
				u.Status = "active"
				fx.store.users[fx.userID] = u
				return privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn}
			},
		},
	}

	var optionsBodies, reclaimBodies []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPrivacyFixture(t, privacyOptions{})
			body := tc.body(t, fx)

			optionsRec := fx.post(t, privacyReclaimOptionsPath, body)
			if optionsRec.Code != http.StatusUnauthorized {
				t.Fatalf("POST reclaim/options = %d (%s), want 401", optionsRec.Code, optionsRec.Body.String())
			}
			if got := errorBody(t, optionsRec); got != "invalid_token" {
				t.Errorf("reclaim/options error = %q, want invalid_token", got)
			}

			reclaimRec := fx.post(t, privacyReclaimPath, body)
			if reclaimRec.Code != http.StatusUnauthorized {
				t.Fatalf("POST reclaim = %d (%s), want 401", reclaimRec.Code, reclaimRec.Body.String())
			}
			if got := errorBody(t, reclaimRec); got != "invalid_token" {
				t.Errorf("reclaim error = %q, want invalid_token", got)
			}

			optionsBodies = append(optionsBodies, optionsRec.Body.String())
			reclaimBodies = append(reclaimBodies, reclaimRec.Body.String())
		})
	}

	// Every failure mode must produce the identical body, not merely the same status.
	assertIdenticalBodies(t, "reclaim/options", optionsBodies)
	assertIdenticalBodies(t, "reclaim", reclaimBodies)
}

// TestPrivacyReclaimOptionsHidesFactorInventory: an account holding neither a
// passkey nor TOTP must be reported as an invalid token, byte-identically. Anything
// else would tell an anonymous caller that the account exists, is pending deletion,
// and has no recoverable factor — which is precisely the account worth targeting.
func TestPrivacyReclaimOptionsHidesFactorInventory(t *testing.T) {
	noFactor := newPrivacyFixture(t, privacyOptions{})
	token := noFactor.requestDeletionToken(t)
	noFactor.passkeys.beginErr = webauthn.ErrNoCredentials

	rec := noFactor.post(t, privacyReclaimOptionsPath, privacyReclaimRequest{Token: token})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST reclaim/options = %d (%s), want 401", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", got)
	}

	// Byte-identical to an outright unknown token.
	unknown := newPrivacyFixture(t, privacyOptions{})
	bogus, _, err := privacy.NewReclaimToken()
	if err != nil {
		t.Fatalf("NewReclaimToken: %v", err)
	}
	unknownRec := unknown.post(t, privacyReclaimOptionsPath, privacyReclaimRequest{Token: bogus})
	if unknownRec.Body.String() != rec.Body.String() {
		t.Errorf("no-factor body %q differs from unknown-token body %q",
			rec.Body.String(), unknownRec.Body.String())
	}
}

// TestPrivacyReclaimFactorFailuresAreIndistinguishable covers the verify endpoint's
// factor-level failures. These reach the endpoint with a *valid* token, so
// reclaim/options legitimately answers 200; only the verify response must be opaque.
func TestPrivacyReclaimFactorFailuresAreIndistinguishable(t *testing.T) {
	tests := []struct {
		name string
		body func(t *testing.T, fx *privacyFixture) privacyReclaimRequest
	}{
		{
			name: "wrong assertion",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				token := fx.requestDeletionToken(t)
				fx.passkeys.finishErr = webauthn.ErrVerification
				return privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "presence-only assertion",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				token := fx.requestDeletionToken(t)
				fx.passkeys.finishErr = webauthn.ErrUserVerificationRequired
				return privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "stale challenge",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				token := fx.requestDeletionToken(t)
				fx.passkeys.finishErr = webauthn.ErrChallengeExpired
				return privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn}
			},
		},
		{
			name: "unsupported factor",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				return privacyReclaimRequest{Token: fx.requestDeletionToken(t), Factor: "password"}
			},
		},
		{
			name: "factor omitted",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				return privacyReclaimRequest{Token: fx.requestDeletionToken(t)}
			},
		},
		{
			name: "totp presented but not enrolled",
			body: func(t *testing.T, fx *privacyFixture) privacyReclaimRequest {
				return privacyReclaimRequest{
					Token:  fx.requestDeletionToken(t),
					Factor: privacy.FactorTOTP,
					Code:   "123456",
				}
			},
		},
	}

	var bodies []string
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newPrivacyFixture(t, privacyOptions{})
			body := tc.body(t, fx)

			rec := fx.post(t, privacyReclaimPath, body)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("POST reclaim = %d (%s), want 401", rec.Code, rec.Body.String())
			}
			if got := errorBody(t, rec); got != "invalid_token" {
				t.Errorf("error = %q, want invalid_token", got)
			}
			if fx.store.users[fx.userID].Status != "pending_deletion" {
				t.Error("a failed factor still restored the account")
			}
			bodies = append(bodies, rec.Body.String())
		})
	}
	assertIdenticalBodies(t, "reclaim", bodies)
}

// assertIdenticalBodies fails when any two collected response bodies differ, which is
// the difference between "the same status" and "no oracle".
func assertIdenticalBodies(t *testing.T, label string, bodies []string) {
	t.Helper()
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("%s failure bodies differ: %q vs %q", label, bodies[0], bodies[i])
		}
	}
}

// TestPrivacyReclaimWrongFactorLeavesTokenUsable is the HTTP-level statement of the
// trade-off: a mistyped factor must not destroy the recovery path.
func TestPrivacyReclaimWrongFactorLeavesTokenUsable(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	token := fx.requestDeletionToken(t)

	fx.passkeys.finishErr = webauthn.ErrVerification
	if rec := fx.post(t, privacyReclaimPath, privacyReclaimRequest{
		Token: token, Factor: privacy.FactorWebAuthn,
	}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failed reclaim = %d (%s), want 401", rec.Code, rec.Body.String())
	}

	fx.passkeys.finishErr = nil
	if rec := fx.post(t, privacyReclaimPath, privacyReclaimRequest{
		Token: token, Factor: privacy.FactorWebAuthn,
	}); rec.Code != http.StatusNoContent {
		t.Fatalf("reclaim after a failed attempt = %d (%s), want 204", rec.Code, rec.Body.String())
	}
}

// TestPrivacyReclaimInfrastructureFaultIs500 pins the one distinction that is
// allowed: an unexpected verifier fault is a 500, not an opaque 401. Reporting an
// outage as "invalid credentials" would hide it among ordinary failed attempts.
func TestPrivacyReclaimInfrastructureFaultIs500(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	token := fx.requestDeletionToken(t)
	fx.passkeys.finishErr = errors.New("connection reset")

	rec := fx.post(t, privacyReclaimPath, privacyReclaimRequest{
		Token: token, Factor: privacy.FactorWebAuthn,
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST reclaim = %d (%s), want 500", rec.Code, rec.Body.String())
	}
	if got := errorBody(t, rec); got != "server_error" {
		t.Errorf("error = %q, want server_error", got)
	}
	// The token must survive an outage: it was never presented to a real check.
	if fx.store.requests[0].FailedAttempts != 0 {
		t.Error("an infrastructure fault was charged to the attempt budget")
	}
}

func TestPrivacyReclaimRateLimited(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})
	token := fx.requestDeletionToken(t)
	// The handler resolves 192.0.2.1 from httptest's default RemoteAddr.
	fx.limiter.deny["rate:privacy:reclaim:subnet:192.0.2.0/24"] = true

	for _, path := range []string{privacyReclaimOptionsPath, privacyReclaimPath} {
		rec := fx.post(t, path, privacyReclaimRequest{Token: token, Factor: privacy.FactorWebAuthn})
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("POST %s = %d (%s), want 429", path, rec.Code, rec.Body.String())
		}
		if got := errorBody(t, rec); got != "rate_limited" {
			t.Errorf("POST %s error = %q, want rate_limited", path, got)
		}
	}
}

func TestPrivacyReclaimRejectsMalformedJSON(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})

	for _, path := range []string{privacyReclaimOptionsPath, privacyReclaimPath} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte("{")))
		rec := httptest.NewRecorder()
		fx.server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d (%s), want 400", path, rec.Code, rec.Body.String())
		}
		if got := errorBody(t, rec); got != "invalid_request" {
			t.Errorf("POST %s error = %q, want invalid_request", path, got)
		}
	}
}

// TestPrivacyReclaimEmptyBodyIsOpaque: an empty body must follow the same 401 path
// as a wrong token rather than being reported as a distinguishable 400.
func TestPrivacyReclaimEmptyBodyIsOpaque(t *testing.T) {
	fx := newPrivacyFixture(t, privacyOptions{})

	for _, path := range []string{privacyReclaimOptionsPath, privacyReclaimPath} {
		rec := fx.post(t, path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("POST %s with an empty body = %d (%s), want 401", path, rec.Code, rec.Body.String())
		}
	}
}
