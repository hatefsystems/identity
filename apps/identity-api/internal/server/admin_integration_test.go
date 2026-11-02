//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type adminIntegration struct {
	pool         *pgxpool.Pool
	srv          *Server
	browser      *portalTestClient
	sessions     *session.Manager
	sessionStore *adminCountingSessionStore
	step         *stepup.Service
	enc          *envelope.Encryptor
	actors       map[string]session.Session
	cookies      map[string]*http.Cookie
	target       db.User
}

type adminCountingSessionStore struct {
	session.Store
	touches  atomic.Int64
	touchErr error
}

func (s *adminCountingSessionStore) Touch(ctx context.Context, hash string, expiry time.Time) error {
	s.touches.Add(1)
	if s.touchErr != nil {
		return s.touchErr
	}
	return s.Store.Touch(ctx, hash, expiry)
}

func newAdminIntegration(t *testing.T) *adminIntegration {
	t.Helper()
	ctx := context.Background()
	pool := openRecoveryHandlerIntegrationPool(ctx, t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewMockProvider(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	q := db.New(pool)
	actions, err := adminaction.New(pool, enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := legalhold.New(q, enc, legalhold.WithReleasedMetadataRetention(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	accounts := session.NewDBAccountState(pool)
	sessionStore := &adminCountingSessionStore{Store: session.NewMemoryStore()}
	sessions, err := session.NewManager(sessionStore, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: accounts})
	if err != nil {
		t.Fatal(err)
	}
	_, keys := newTestStepUpService(t, q, nil, &stepUpFakeTOTP{valid: "000000"})
	step, err := stepup.New(stepup.Config{Issuer: testStepUpIssuer, AccountState: accounts}, keys, q, nil, &stepUpFakeTOTP{valid: "000000"}, stepup.NewMemoryReplayGuard())
	if err != nil {
		t.Fatal(err)
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Fatal("REDIS_URL required for admin HTTP integration")
	}
	redisCfg, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	redisClient := redis.NewClient(redisCfg)
	t.Cleanup(func() { _ = redisClient.Close() })
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	limiter, err := ratelimit.NewRedisLimiter(redisClient)
	if err != nil {
		t.Fatal(err)
	}
	f := &adminIntegration{pool: pool, browser: newPortalTestClient(t, testPortalOrigin), sessions: sessions, sessionStore: sessionStore, step: step, enc: enc, actors: map[string]session.Session{}, cookies: map[string]*http.Cookie{}}
	f.srv = New(config.Config{Environment: "development", PortalOrigin: f.browser.origin, Admin: config.AdminConfig{
		Enabled: true, AllowedOrigins: []string{"https://identity.example"}, RequestTimeout: 5 * time.Second,
		PerActorPerMinute: 10000, PerSubnetPerMinute: 10000, PageSizeDefault: 50, PageSizeMax: 200,
		ChainVerifyMaxLimit: 5000, AuditMaxWindow: 31 * 24 * time.Hour,
	}}, nil, Deps{SessionManager: sessions, DPoPValidator: f.browser.validator, StepUp: step, AdminStore: q, AdminActions: actions, RBAC: q, LegalHold: holds, AdminLimiter: limiter, LedgerProofDB: pool})
	for _, role := range []string{"support", "moderator", "super_admin", "dpo", "ordinary"} {
		user := f.user(t)
		if role != "ordinary" {
			if _, err := pool.Exec(ctx, "UPDATE users SET is_mfa_enabled=true WHERE id=$1", user.ID); err != nil {
				t.Fatal(err)
			}
			if err := rbac.ProvisionRole(ctx, actions, uuid.New(), "spiffe://identity.test/operator", user.ID, role, false); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		sess, err := sessions.IssueContext(ctx, w, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true, DPoPJKT: f.browser.jkt})
		if err != nil {
			t.Fatal(err)
		}
		f.actors[role], f.cookies[role] = sess, w.Result().Cookies()[0]
	}
	f.target = f.user(t)
	return f
}

func (f *adminIntegration) user(t *testing.T) db.User {
	t.Helper()
	u, err := db.New(f.pool).CreateUser(context.Background(), db.CreateUserParams{Email: uuid.NewString() + "@admin-test.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", u.ID) })
	return u
}

func (f *adminIntegration) grant(t *testing.T, role string) string {
	t.Helper()
	s := f.actors[role]
	grant, _, err := f.step.MintContext(context.Background(), stepup.MintParams{UserID: s.UserID, SessionID: s.ID, AMR: []string{"otp"}, AuthVersion: s.AuthVersion, AuthVersionSet: true})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func (f *adminIntegration) request(t *testing.T, role, method, path, body, grant string) *httptest.ResponseRecorder {
	t.Helper()
	return f.requestWithKey(t, role, method, path, body, grant, uuid.NewString())
}

func (f *adminIntegration) requestWithKey(t *testing.T, role, method, path, body, grant, key string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "https://identity.example/api/v1/admin"+path, reader)
	r.Header.Set("Origin", "https://identity.example")
	f.browser.prepare(r)
	if cookie := f.cookies[role]; cookie != nil {
		f.browser.authorize(t, r, f.actors[role], cookie)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	r.Header.Set(stepup.HeaderStepUpAuth, grant)
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	return w
}

func TestAdminRolePrivacyAndLiveRevocationIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	for _, role := range []string{"support", "moderator", "super_admin", "dpo", "ordinary"} {
		for _, route := range []struct {
			path    string
			allowed bool
		}{
			{"/users", role == "support" || role == "moderator"},
			{"/users/" + f.target.ID.String(), role == "support" || role == "moderator"},
			{"/audit-logs?start_time=2020-01-01T00:00:00Z&end_time=2020-01-02T00:00:00Z", role == "dpo"},
			{"/audit-logs/verify", role == "dpo" || role == "super_admin"},
			{"/ledger/verify", role == "dpo" || role == "super_admin"},
			{"/legal-holds?account_ref=" + f.target.ID.String(), role == "dpo"},
		} {
			w := f.request(t, role, "GET", route.path, "", "")
			want := 403
			if route.allowed {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s %s: %d %s", role, route.path, w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("privacy headers absent")
			}
			if role == "support" && strings.Contains(route.path, "/users") {
				for _, field := range []string{"email", "roles", "legal_hold", "password", "encrypted", "blind_index", "auth_version"} {
					if strings.Contains(w.Body.String(), field) {
						t.Fatalf("support leaked %s", field)
					}
				}
			}
		}
	}
	grant := f.grant(t, "support")
	w := f.request(t, "support", "PATCH", "/users/"+f.target.ID.String()+"/status", adminStatusBody(t, "banned", "private", 0), grant)
	if w.Code != 403 {
		t.Fatalf("unauthorized mutation: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.step.Validate(context.Background(), grant, f.actors["support"]); err != nil {
		t.Fatalf("denial consumed grant: %v", err)
	}
	if err := rbac.ProvisionRole(context.Background(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", uuid.MustParse(f.actors["support"].UserID), "support", true); err != nil {
		t.Fatal(err)
	}
	if w := f.request(t, "support", "GET", "/users", "", ""); w.Code != 403 {
		t.Fatalf("revoked role retained access: %d", w.Code)
	}
	for _, path := range []string{"/roles/assign", "/users/" + f.target.ID.String() + "/trigger-reset"} {
		if w := f.request(t, "super_admin", "POST", path, `{}`, ""); w.Code != 404 && w.Code != 405 {
			t.Fatalf("out-of-scope route: %s %d %s", path, w.Code, w.Body.String())
		}
	}
}

type adminIntegrationBeginFunc func(context.Context) (pgx.Tx, error)

func (f adminIntegrationBeginFunc) Begin(ctx context.Context) (pgx.Tx, error) { return f(ctx) }

type rejectAuditBeginner struct{ pool *pgxpool.Pool }

func (b rejectAuditBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return rejectAuditTx{Tx: tx}, nil
}

type rejectAuditTx struct {
	pgx.Tx
	reject func(context.Context, pgx.Tx, []any) bool
}

func (tx rejectAuditTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "-- name: InsertAdminActionOutbox :exec") && (tx.reject == nil || tx.reject(ctx, tx.Tx, args)) {
		return pgconn.CommandTag{}, errors.New("injected admin audit outbox failure")
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func TestAdminAuditFailureRollsBackMutationAndWithholdsReadIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	// A committed read renews once. Tentative reads and mutations whose audit
	// commit fails must not call Touch at all, not merely fail to persist it.
	control := f.request(t, "moderator", "GET", "/users/"+f.target.ID.String(), "", "")
	if control.Code != http.StatusOK || f.sessionStore.touches.Load() != 1 {
		t.Fatalf("committed read: status=%d touches=%d body=%s", control.Code, f.sessionStore.touches.Load(), control.Body.String())
	}
	touches := f.sessionStore.touches.Load()
	counts := func() [4]int64 {
		t.Helper()
		var result [4]int64
		if err := f.pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND NOT admin_action),
			(SELECT count(*) FROM admin_action_contexts WHERE account_ref=$1),
			(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2 AND payload::jsonb->>'action_status'='success'),
			(SELECT count(*) FROM event_outbox WHERE admin_action AND payload::jsonb->>'actor_id'=$2 AND payload::jsonb->>'action_status'='failure')`,
			f.target.ID, f.actors["moderator"].UserID).Scan(&result[0], &result[1], &result[2], &result[3]); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := counts()
	var rejected int
	var mutationID uuid.UUID
	beginner := adminIntegrationBeginFunc(func(ctx context.Context) (pgx.Tx, error) {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		return rejectAuditTx{Tx: tx, reject: func(ctx context.Context, tx pgx.Tx, args []any) bool {
			var event audit.Envelope
			if err := json.Unmarshal([]byte(args[2].(string)), &event); err != nil {
				t.Fatal(err)
			}
			var metadata struct {
				HTTPStatus int `json:"http_status"`
			}
			if err := json.Unmarshal([]byte(event.Payload), &metadata); err != nil {
				t.Fatal(err)
			}
			// A separate failure receipt may commit; only tentative successful
			// responses encounter this injected disclosure/commit outage.
			if event.ActionStatus == audit.StatusFailure && metadata.HTTPStatus >= 400 {
				return false
			}
			rejected++
			if event.EventType == audit.EventAdminUserStatusChanged {
				mutationID = event.EventID
				user, err := db.New(tx).GetUserByIDForAdmin(ctx, f.target.ID)
				if err != nil || user.Status != "banned" || user.AuthVersion != f.target.AuthVersion+1 || user.AuthEpoch <= f.target.AuthEpoch || user.LifecycleRevision != f.target.LifecycleRevision+1 {
					t.Fatalf("audit injection did not reach the mutated account: %v", err)
				}
				var events int64
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND NOT admin_action", f.target.ID).Scan(&events); err != nil || events != before[0]+1 {
					t.Fatalf("audit injection preceded the lifecycle insert: events=%d err=%v", events, err)
				}
				var encrypted []byte
				if err := tx.QueryRow(ctx, "SELECT details_encrypted FROM admin_action_contexts WHERE action_id=$1 AND account_ref=$2", mutationID, f.target.ID).Scan(&encrypted); err != nil || len(encrypted) == 0 || bytes.Contains(encrypted, []byte("private case")) {
					t.Fatalf("audit injection preceded encrypted context storage: %v", err)
				}
			}
			return true
		}}, nil
	})
	actions, err := adminaction.New(beginner, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = actions
	for _, call := range []struct{ method, path, body, grant string }{
		{"GET", "/capabilities", "", ""},
		{"GET", "/users/" + f.target.ID.String(), "", ""},
		{"PATCH", "/users/" + f.target.ID.String() + "/status", adminStatusBody(t, "banned", "private case", 0), f.grant(t, "moderator")},
	} {
		w := f.request(t, "moderator", call.method, call.path, call.body, call.grant)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), f.target.Email) {
			t.Fatalf("audit failure disclosed/succeeded: %d %s", w.Code, w.Body.String())
		}
		if got := f.sessionStore.touches.Load(); got != touches {
			t.Fatalf("failed audit renewed %s activity: touches=%d, want %d", call.method, got, touches)
		}
	}
	// The ledger's independent read-only snapshot must not bypass the outer
	// durable disclosure receipt, even for a no-content/uninitialized response.
	w := f.request(t, "dpo", "GET", "/ledger/verify", "", "")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), "through_seq") {
		t.Fatalf("ledger proof escaped failed audit: %d %s", w.Code, w.Body.String())
	}
	if got := f.sessionStore.touches.Load(); got != touches {
		t.Fatalf("failed ledger disclosure audit renewed activity: touches=%d, want %d", got, touches)
	}
	u, err := db.New(f.pool).GetUserByIDForAdmin(context.Background(), f.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != f.target.Status || u.AuthVersion != f.target.AuthVersion || u.AuthEpoch != f.target.AuthEpoch || u.LifecycleRevision != f.target.LifecycleRevision {
		t.Fatal("failed audit committed moderation")
	}
	if rejected != 4 || mutationID == uuid.Nil {
		t.Fatalf("wrong audit failure boundary: rejected=%d mutation reached=%v", rejected, mutationID != uuid.Nil)
	}
	after := counts()
	for i, label := range []string{"lifecycle events", "encrypted context", "success audit intents"} {
		if after[i] != before[i] {
			t.Errorf("failed audit committed %s: before=%d after=%d", label, before[i], after[i])
		}
	}
	var remnants int64
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM admin_action_contexts WHERE action_id=$1) +
		(SELECT count(*) FROM event_outbox WHERE id=$1)`, mutationID).Scan(&remnants); err != nil || remnants != 0 {
		t.Fatalf("failed moderation retained operation context or intent: count=%d err=%v", remnants, err)
	}
	denied := f.request(t, "moderator", http.MethodPatch, "/users/"+f.target.ID.String()+"/status", `{"status":"banned","reason":"missing revision"}`, f.grant(t, "moderator"))
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("separate failure audit was unavailable: %d %s", denied.Code, denied.Body.String())
	}
	withFailure := counts()
	if withFailure[3] != after[3]+1 {
		t.Fatal("a rejected request did not commit its separate failure audit")
	}
	for i := range 3 {
		if withFailure[i] != before[i] {
			t.Fatal("failure auditing committed business state or a success intent")
		}
	}
}

func TestAdminModerationInvalidatesOtherInstanceAndEncryptsReasonIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	codec, _ := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
	other, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(f.pool)})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	_, err = other.IssueContext(context.Background(), w, session.IssueParams{UserID: f.target.ID.String(), AuthVersionSet: true, DPoPJKT: f.browser.jkt})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(w.Result().Cookies()[0])
	for revision, status := range []string{"banned", "active"} {
		w := f.request(t, "moderator", "PATCH", "/users/"+f.target.ID.String()+"/status", adminStatusBody(t, status, "sensitive-case-123", int64(revision)), f.grant(t, "moderator"))
		if w.Code != 204 {
			t.Fatalf("moderation: %d %s", w.Code, w.Body.String())
		}
		if _, err := other.Authenticate(r); err == nil {
			t.Fatal("stale credential revived on another instance")
		}
	}
	var payload, encrypted []byte
	err = f.pool.QueryRow(context.Background(), `SELECT o.payload,c.details_encrypted FROM event_outbox o JOIN admin_action_contexts c ON c.action_id=o.id WHERE c.account_ref=$1 ORDER BY c.created_at DESC LIMIT 1`, f.target.ID).Scan(&payload, &encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("sensitive-case-123")) || bytes.Contains(encrypted, []byte("sensitive-case-123")) {
		t.Fatal("plaintext reason escaped")
	}
	plain, err := f.enc.Decrypt(context.Background(), encrypted)
	if err != nil || !bytes.Contains(plain, []byte("sensitive-case-123")) {
		t.Fatal("restricted context unavailable")
	}
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
}

func TestAdminIndependentPreservationsAndReleasedReplayIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	account := uuid.New() // Preservation also works after all account data is absent.
	key := uuid.NewString()
	body := `{"account_ref":"` + account.String() + `","reason":"sealed reason","requesting_authority":"case authority","expires_at":"2000-01-01T00:00:00Z"}`
	send := func(key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://identity.example/api/v1/admin/preservation-requests", strings.NewReader(body))
		r.Header.Set("Origin", "https://identity.example")
		f.browser.authorize(t, r, f.actors["dpo"], f.cookies["dpo"])
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t, "dpo"))
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		return w
	}
	w := send(key, body)
	if w.Code != 201 {
		t.Fatalf("preserve absent: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"account_present":false`) || !strings.Contains(w.Body.String(), `"ledger_evidence_present":false`) {
		t.Fatalf("missing observations: %s", w.Body.String())
	}
	var holdID uuid.UUID
	if err := f.pool.QueryRow(context.Background(), "SELECT id FROM legal_holds WHERE account_ref=$1 AND idempotency_key=$2", account, key).Scan(&holdID); err != nil {
		t.Fatal(err)
	}
	if w := send(key, body); w.Code != 200 || !strings.Contains(w.Body.String(), `"replayed":true`) {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
	if w := send(key, strings.Replace(body, "sealed reason", "different reason", 1)); w.Code != 409 {
		t.Fatalf("conflicting replay: %d %s", w.Code, w.Body.String())
	}
	if w := send(uuid.NewString(), body); w.Code != 201 {
		t.Fatalf("independent request: %d %s", w.Code, w.Body.String())
	}
	for range 2 {
		if w := f.request(t, "dpo", "DELETE", "/legal-holds/"+holdID.String(), "", f.grant(t, "dpo")); w.Code != 204 {
			t.Fatalf("release: %d %s", w.Code, w.Body.String())
		}
	}
	if w := send(key, body); w.Code != 200 || !strings.Contains(w.Body.String(), `"is_active":false`) {
		t.Fatalf("released replay reactivated: %d %s", w.Code, w.Body.String())
	}
	var active int
	if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM legal_holds WHERE account_ref=$1 AND is_active", account).Scan(&active); err != nil || active != 1 {
		t.Fatalf("independent protection lost: %d %v", active, err)
	}
}

func TestAdminUnsupportedMethodsAreAuditedIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	// CONNECT uses authority-form rather than an admin resource path.
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodTrace} {
		t.Run(method, func(t *testing.T) {
			var before, after int64
			if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&before); err != nil {
				t.Fatal(err)
			}
			w := f.request(t, "support", method, "/users", "", "")
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("unsupported method returned %d: %s", w.Code, w.Body.String())
			}
			if err := f.pool.QueryRow(context.Background(), "SELECT count(*) FROM event_outbox WHERE admin_action").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before+1 {
				t.Fatalf("rejected request was not durably audited: before=%d after=%d", before, after)
			}
		})
	}
}
