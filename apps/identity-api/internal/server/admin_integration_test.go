//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
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
	pool     *pgxpool.Pool
	srv      *Server
	sessions *session.Manager
	step     *stepup.Service
	enc      *envelope.Encryptor
	actors   map[string]session.Session
	cookies  map[string]*http.Cookie
	target   db.User
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
	sessions, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: accounts})
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
	f := &adminIntegration{pool: pool, sessions: sessions, step: step, enc: enc, actors: map[string]session.Session{}, cookies: map[string]*http.Cookie{}}
	f.srv = New(config.Config{Environment: "development", Admin: config.AdminConfig{
		Enabled: true, AllowedOrigins: []string{"https://identity.example"}, RequestTimeout: 5 * time.Second,
		PerActorPerMinute: 10000, PerSubnetPerMinute: 10000, PageSizeDefault: 50, PageSizeMax: 200,
		ChainVerifyMaxLimit: 5000, AuditMaxWindow: 31 * 24 * time.Hour,
	}}, nil, Deps{SessionManager: sessions, StepUp: step, AdminStore: q, AdminActions: actions, RBAC: q, LegalHold: holds, AdminLimiter: limiter, LedgerProofDB: pool})
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
		sess, err := sessions.IssueContext(ctx, w, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true})
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

func (f *adminIntegration) request(role, method, path, body, grant string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://identity.example/api/v1/admin"+path, strings.NewReader(body))
	if cookie := f.cookies[role]; cookie != nil {
		r.AddCookie(cookie)
	}
	r.Header.Set("Origin", "https://identity.example")
	r.Header.Set("Idempotency-Key", uuid.NewString())
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
			w := f.request(role, "GET", route.path, "", "")
			want := 403
			if route.allowed {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s %s: %d %s", role, route.path, w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
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
	w := f.request("support", "PATCH", "/users/"+f.target.ID.String()+"/status", `{"status":"banned","reason":"private"}`, grant)
	if w.Code != 403 {
		t.Fatalf("unauthorized mutation: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.step.Validate(context.Background(), grant, f.actors["support"]); err != nil {
		t.Fatalf("denial consumed grant: %v", err)
	}
	if err := rbac.ProvisionRole(context.Background(), f.srv.deps.AdminActions, uuid.New(), "spiffe://identity.test/operator", uuid.MustParse(f.actors["support"].UserID), "support", true); err != nil {
		t.Fatal(err)
	}
	if w := f.request("support", "GET", "/users", "", ""); w.Code != 403 {
		t.Fatalf("revoked role retained access: %d", w.Code)
	}
	for _, path := range []string{"/roles/assign", "/users/" + f.target.ID.String() + "/trigger-reset"} {
		if w := f.request("super_admin", "POST", path, `{}`, ""); w.Code != 404 && w.Code != 405 {
			t.Fatalf("out-of-scope route: %s %d %s", path, w.Code, w.Body.String())
		}
	}
}

type rejectAuditBeginner struct{ pool *pgxpool.Pool }

func (b rejectAuditBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return rejectAuditTx{Tx: tx}, nil
}

type rejectAuditTx struct{ pgx.Tx }

func (tx rejectAuditTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "INSERT INTO event_outbox") {
		return pgconn.CommandTag{}, errors.New("injected outbox failure")
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func TestAdminAuditFailureRollsBackMutationAndWithholdsReadIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	actions, err := adminaction.New(rejectAuditBeginner{f.pool}, f.enc, "identity.audit.admin-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.deps.AdminActions = actions
	for _, call := range []struct{ method, path, body, grant string }{
		{"GET", "/users/" + f.target.ID.String(), "", ""},
		{"PATCH", "/users/" + f.target.ID.String() + "/status", `{"status":"banned","reason":"private case"}`, f.grant(t, "moderator")},
	} {
		w := f.request("moderator", call.method, call.path, call.body, call.grant)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), f.target.Email) {
			t.Fatalf("audit failure disclosed/succeeded: %d %s", w.Code, w.Body.String())
		}
	}
	// The ledger's independent read-only snapshot must not bypass the outer
	// durable disclosure receipt, even for a no-content/uninitialized response.
	w := f.request("dpo", "GET", "/ledger/verify", "", "")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), "through_seq") {
		t.Fatalf("ledger proof escaped failed audit: %d %s", w.Code, w.Body.String())
	}
	u, err := db.New(f.pool).GetUserByIDForAdmin(context.Background(), f.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "active" || u.AuthVersion != f.target.AuthVersion {
		t.Fatal("failed audit committed moderation")
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
	_, err = other.IssueContext(context.Background(), w, session.IssueParams{UserID: f.target.ID.String(), AuthVersionSet: true})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(w.Result().Cookies()[0])
	for _, status := range []string{"banned", "active"} {
		w := f.request("moderator", "PATCH", "/users/"+f.target.ID.String()+"/status", `{"status":"`+status+`","reason":"sensitive-case-123"}`, f.grant(t, "moderator"))
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
		r.AddCookie(f.cookies["dpo"])
		r.Header.Set("Origin", "https://identity.example")
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
		if w := f.request("dpo", "DELETE", "/legal-holds/"+holdID.String(), "", f.grant(t, "dpo")); w.Code != 204 {
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
			w := f.request("support", method, "/users", "", "")
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
