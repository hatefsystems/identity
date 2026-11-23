//go:build integration

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

// Shared integration fixtures use this deterministic indexer, never production keys.
type phoneFakeIndexer struct{}

func (phoneFakeIndexer) Compute(value string) string               { return "idx_" + value }
func (phoneFakeIndexer) ComputeEmail(value string) (string, error) { return "idx_" + value, nil }

func phoneIntegrationServices(t *testing.T) (context.Context, *pgxpool.Pool, *smsotp.RedisOTPStore) {
	t.Helper()
	dsn, redisURL := os.Getenv("DATABASE_URL"), os.Getenv("REDIS_URL")
	if dsn == "" || redisURL == "" {
		if os.Getenv("REQUIRE_SMS_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL and REDIS_URL are required for mandatory phone integration")
		}
		t.Skip("isolated PostgreSQL and Redis fixtures not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid fixture database configuration")
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		t.Fatal("configured fixture database unavailable")
	}
	name := "phone_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal("cannot create run-owned phone database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("cannot drop run-owned phone database")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	err = migrate.Up(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		t.Fatal("run-owned phone database migration failed")
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal("invalid Redis fixture configuration")
	}
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("configured Redis fixture unavailable")
	}
	store, err := smsotp.NewRedisOTPStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, store
}

type phoneIntegrationEncryptor struct {
	admitted chan struct{}
	release  chan struct{}
	once     sync.Once
	cipher   contactproof.Cipher
}

func (e *phoneIntegrationEncryptor) Encrypt(ctx context.Context, p []byte) ([]byte, error) {
	if e.admitted != nil {
		// Contact and evidence are separate envelopes in one admitted operation.
		e.once.Do(func() { close(e.admitted) })
		select {
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return e.cipher.Encrypt(ctx, p)
}

func (e *phoneIntegrationEncryptor) Decrypt(ctx context.Context, p []byte) ([]byte, error) {
	return e.cipher.Decrypt(ctx, p)
}

func phoneIntegrationCipher(t *testing.T) contactproof.Cipher {
	t.Helper()
	provider, err := kms.NewMockProvider([]byte(strings.Repeat("k", 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func contactIntegrationManager(t *testing.T, f *realPasswordFixture, cipher contactproof.Cipher, sending bool, dbPool contactmanager.Beginner) (*contactmanager.Service, *actionproof.Service) {
	t.Helper()
	var codes *contactcode.Service
	var proofs *actionproof.Service
	var err error
	policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
	if sending {
		users, err := smsotp.NewUserStore(f.pool, cipher)
		if err != nil {
			t.Fatal(err)
		}
		otps, err := smsotp.NewRedisOTPStore(f.client)
		if err != nil {
			t.Fatal(err)
		}
		sms, err := smsotp.New(smsotp.Config{HashPepper: []byte(strings.Repeat("p", 32)), ContactChangeSender: loginSMSCapture{f.delivery}, ContactRemovalSender: loginSMSCapture{f.delivery}, PerPhonePerMinute: 5, PerPhonePerHour: 20, PerSubnetPerHour: 100}, users, cipher, phoneFakeIndexer{}, f.limiter, otps, loginSMSCapture{f.delivery})
		if err != nil {
			t.Fatal(err)
		}
		codes, err = contactcode.New(contactcode.Config{HashKey: []byte(strings.Repeat("c", 32)), ContactChangeEmail: loginEmailCapture{f.delivery}, ContactRemovalEmail: loginEmailCapture{f.delivery}, ContactOwnershipEmail: loginEmailCapture{f.delivery}, PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}, f.codeStore, sms, nil)
		if err != nil {
			t.Fatal(err)
		}
		proofs, err = actionproof.NewContacts(actionproof.Config{BindingKey: []byte(strings.Repeat("b", 32)), ContactIssuanceEnabled: true}, actionproof.Deps{DB: f.pool, Queries: db.New(f.pool), Sessions: f.manager, Cipher: cipher, Codes: codes, Limiter: f.limiter})
		if err != nil {
			t.Fatal(err)
		}
		proofs.SetAccountPolicy(policy)
	}
	svc, err := contactmanager.New(contactmanager.Deps{DB: dbPool, Queries: db.New(f.pool), Sessions: f.manager, Cipher: cipher, Indexer: phoneFakeIndexer{}, Codes: codes, Proofs: proofs, Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	deps := f.server.deps
	deps.Contacts = svc
	deps.ContactManagementProofs = proofs
	deps.AuditRecorder = &phoneAuditRecorder{}
	// Do not place a typed nil in the public proof interface.
	if proofs == nil {
		deps.ContactManagementProofs = nil
	}
	f.server = New(f.server.cfg, f.server.logger, deps)
	return svc, proofs
}

func contactIntegrationStart(t *testing.T, f *realPasswordFixture, current session.Session, cookies []*http.Cookie, target, value, grant, proof string) phoneSendCodeResponse {
	t.Helper()
	headers := http.Header{}
	if grant != "" {
		headers.Set(stepup.HeaderStepUpAuth, grant)
	}
	if proof != "" {
		headers.Set("X-Action-Proof", proof)
	}
	w := contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/"+target+"/send-code", loginHTTPBody(t, map[string]string{target: value}), headers, 200)
	var result phoneSendCodeResponse
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "sent" || !canonicalContactHandle(result.VerificationID) || result.ExpiresAt.IsZero() {
		t.Fatal("known start did not return bounded handle")
	}
	return result
}

// Unlike generic fixture diagnostics, this helper never prints returned handles or contacts.
func contactIntegrationBound(t *testing.T, f *realPasswordFixture, current session.Session, cookies []*http.Cookie, method, path, body string, headers http.Header, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.8:12345"
	for name, values := range headers {
		r.Header[name] = append([]string(nil), values...)
	}
	f.browser.authorize(t, r, current, cookies...)
	w := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("contact HTTP status=%d want=%d", w.Code, want)
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("contact response lost private browser policy")
	}
	return w
}

func TestPhoneHTTPRealRedisPostgresRevocationFenceIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "password_only", true)
	current, cookies := f.issue(t, a, session.MethodPassword)
	gate := &phoneIntegrationEncryptor{cipher: f.cipher}
	contactIntegrationManager(t, f, gate, true, f.pool)
	grant := f.stepup(t, current, cookies, nil, a)
	start := contactIntegrationStart(t, f, current, cookies, "phone", "+989123456789", grant, "")
	gate.admitted, gate.release = make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	})
	body := loginHTTPBody(t, map[string]string{"verification_id": start.VerificationID, "code": f.delivery.last()})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/phone/verify", strings.NewReader(body))
	f.browser.authorize(t, r, current, cookies...)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { f.server.Handler().ServeHTTP(w, r); close(done) }()
	select {
	case <-gate.admitted:
	case <-f.ctx.Done():
		t.Fatal("HTTP encryption admission barrier timed out")
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("owned transaction rollback failed")
		}
	}()
	if err := pglock.LockAccount(f.ctx, tx, a.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", a.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	select {
	case <-done:
	case <-f.ctx.Done():
		t.Fatal("stale finish did not terminate")
	}
	if w.Code != 403 || f.server.deps.AuditRecorder.(*phoneAuditRecorder).count(audit.EventPhoneVerified) != 0 || w.Header().Get(session.HeaderAuthInvalidated) != "" {
		t.Fatal("stale admitted finish succeeded or audited success")
	}
	u, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || u.AuthVersion != current.AuthVersion+1 {
		t.Fatal("revocation fence did not preserve original account state")
	}
	plain, err := f.cipher.Decrypt(f.ctx, u.PhoneEncrypted)
	if err != nil || string(plain) != a.phone {
		t.Fatal("stale replacement persisted")
	}
	clear(plain)
}

func TestPhoneHTTPDisabledRealPostgresRemovalOneAuditIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	authenticator := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	contactIntegrationManager(t, f, f.cipher, false, f.pool)
	requests := make([]*http.Request, 2)
	for i := range requests {
		grant := f.stepup(t, current, cookies, authenticator, a)
		requests[i] = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/phone", nil)
		requests[i].Header.Set(stepup.HeaderStepUpAuth, grant)
		f.browser.authorize(t, requests[i], current, cookies...)
	}
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for _, r := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			f.server.Handler().ServeHTTP(w, r)
			responses <- w
		}()
	}
	wg.Wait()
	wins := 0
	for range requests {
		w := <-responses
		if w.Code == 204 {
			wins++
			if w.Header().Get(session.HeaderAuthInvalidated) != "true" {
				t.Fatal("known removal lost authentication invalidation")
			}
		} else if w.Code != 401 && w.Code != 403 {
			t.Fatal("concurrent removal did not fence stale authority")
		}
	}
	if wins != 1 || f.server.deps.AuditRecorder.(*phoneAuditRecorder).count(audit.EventPhoneRemoved) != 1 {
		t.Fatal("concurrent real removals did not have one committed/audited winner")
	}
	u, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || u.AuthVersion != current.AuthVersion+1 || u.PhoneEncrypted != nil || u.PhoneBlindIndex != nil {
		t.Fatal("removal did not revoke and clear exactly once")
	}
}

func TestPhoneHTTPDisabledLastVerifiedContactRequiresCurrentEmailEvidenceIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	authenticator := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	contactIntegrationManager(t, f, f.cipher, false, f.pool)
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM contact_verification_evidence WHERE user_id=$1 AND channel='email'", a.user.ID); err != nil {
		t.Fatal(err)
	}
	grant := f.stepup(t, current, cookies, authenticator, a)
	w := contactIntegrationBound(t, f, current, cookies, http.MethodDelete, "/api/v1/users/me/phone", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, 409)
	if errorBody(t, w) != "last_verified_contact" || f.server.deps.AuditRecorder.(*phoneAuditRecorder).count(audit.EventPhoneRemoved) != 0 {
		t.Fatal("populated unevidenced email authorized last-contact removal")
	}
	contactIntegrationBound(t, f, current, cookies, http.MethodDelete, "/api/v1/users/me/phone", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, 403)
	f.contact(t, a.user.ID, contactproof.Email, *a.user.Email)
	grant = f.stepup(t, current, cookies, authenticator, a)
	contactIntegrationBound(t, f, current, cookies, http.MethodDelete, "/api/v1/users/me/phone", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, 204)
	u, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || u.AuthVersion != current.AuthVersion+1 || u.PhoneEncrypted != nil {
		t.Fatal("evidenced-survivor removal did not revoke exactly once")
	}
}

func TestContactHTTPRealOwnershipAndForeignSessionNonburningIntegration(t *testing.T) {
	for _, target := range []string{"phone", "email"} {
		t.Run(target, func(t *testing.T) {
			f := newRealPasswordFixture(t, true)
			a := f.account(t, "dual", false)
			authenticator := f.authenticator(t, a)
			current, cookies := f.issue(t, a, session.MethodPasskey)
			contactIntegrationManager(t, f, f.cipher, true, f.pool)
			value := "+989123456789"
			if target == "email" {
				value = uuid.NewString() + "@contact.invalid"
			}
			grant := f.stepup(t, current, cookies, authenticator, a)
			start := contactIntegrationStart(t, f, current, cookies, target, value, grant, "")
			code := f.delivery.last()
			foreign, foreignCookies := f.issue(t, a, session.MethodPasskey)
			body := loginHTTPBody(t, map[string]string{"verification_id": start.VerificationID, "code": code})
			contactIntegrationBound(t, f, foreign, foreignCookies, http.MethodPost, "/api/v1/users/me/"+target+"/verify", body, nil, 403)
			// A second authority is forbidden and must not consume the legitimate code.
			contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/"+target+"/verify", body, http.Header{stepup.HeaderStepUpAuth: {grant}}, 403)
			w := contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/"+target+"/verify", body, nil, 200)
			if w.Header().Get(session.HeaderAuthInvalidated) != "true" {
				t.Fatal("ownership commit did not invalidate old authentication")
			}
			q := db.New(f.pool)
			u, err := q.GetUserByID(f.ctx, a.user.ID)
			if err != nil || u.AuthVersion != current.AuthVersion+1 {
				t.Fatal("ownership commit did not advance exactly once")
			}
			evidence, err := contactproof.Read(f.ctx, q, f.cipher, a.user.ID, target)
			if err != nil || evidence == nil || evidence.Destination != value {
				t.Fatal("ownership commit did not install exact matching evidence")
			}
			method := contactproof.SMSOTP
			if target == "email" {
				method = contactproof.EmailOTP
			}
			if evidence.Method != method {
				t.Fatal("ownership provenance method is not truthful")
			}
			current, cookies = f.issue(t, a, session.MethodPasskey)
			w = contactIntegrationBound(t, f, current, cookies, http.MethodGet, "/api/v1/users/me/contacts", "", nil, 200)
			var contacts contactmanager.Contacts
			if json.Unmarshal(w.Body.Bytes(), &contacts) != nil {
				t.Fatal("current contact read failed")
			}
			contact := contacts.Phone
			if target == "email" {
				contact = contacts.Email
			}
			if contact == nil || contact.Value != value || !contact.Verified || contact.VerifiedAt == nil || !contact.VerifiedAt.Equal(evidence.VerifiedAt) {
				t.Fatal("current-state inspection fabricated or lost committed provenance")
			}
			if target == "email" && f.server.deps.AuditRecorder.(*phoneAuditRecorder).count(audit.EventPhoneVerified) != 0 {
				t.Fatal("email mutation emitted phone audit")
			}
		})
	}
}

func TestContactHTTPRealTargetBoundPasswordProofAndEmailGateIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "password_only", false)
	current, cookies := f.issue(t, a, session.MethodPassword)
	contactIntegrationManager(t, f, f.cipher, true, f.pool)
	challengeBody := loginHTTPBody(t, map[string]string{"password": a.secret, "channel": "email", "target": "phone"})
	w := contactIntegrationBound(t, f, current, cookies, http.MethodPost, contactChangeProofPath+"/challenge", challengeBody, nil, 202)
	var challenge struct {
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &challenge) != nil {
		t.Fatal("proof challenge response invalid")
	}
	verifyBody := loginHTTPBody(t, map[string]string{"challenge": challenge.Challenge, "code": f.delivery.last()})
	contactIntegrationBound(t, f, current, cookies, http.MethodPost, contactRemovalProofPath+"/verify", verifyBody, nil, 400)
	w = contactIntegrationBound(t, f, current, cookies, http.MethodPost, contactChangeProofPath+"/verify", verifyBody, nil, 200)
	var proof struct {
		Proof     string    `json:"action_proof"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &proof) != nil || !proof.ExpiresAt.Equal(challenge.ExpiresAt) {
		t.Fatal("proof replaced original authorization deadline")
	}
	contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/email/send-code", loginHTTPBody(t, map[string]string{"email": "new@contact.invalid"}), http.Header{"X-Action-Proof": {proof.Proof}}, 403)
	start := contactIntegrationStart(t, f, current, cookies, "phone", "+989123456789", "", proof.Proof)
	w = contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/phone/verify", loginHTTPBody(t, map[string]string{"verification_id": start.VerificationID, "code": f.delivery.last()}), nil, 200)
	if w.Header().Get(session.HeaderAuthInvalidated) != "true" {
		t.Fatal("password/contact authority did not freeze through ownership commit")
	}
	current, cookies = f.issue(t, a, session.MethodPassword)
	w = contactIntegrationBound(t, f, current, cookies, http.MethodPost, contactRemovalProofPath+"/challenge", loginHTTPBody(t, map[string]string{"password": "deliberately wrong", "channel": "email", "target": "email"}), nil, 409)
	if errorBody(t, w) != "email_removal_unavailable" {
		t.Fatal("present-email removal was not operation gated")
	}
}

func TestContactHTTPRealAbsentEmailReadAuthorizedNoopAndAddIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	authenticator := f.authenticator(t, a)
	if _, err := f.pool.Exec(f.ctx, "UPDATE users SET email=NULL WHERE id=$1", a.user.ID); err != nil {
		t.Fatal("cannot prepare email-absent owned account")
	}
	current, cookies := f.issue(t, a, session.MethodPasskey)
	contactIntegrationManager(t, f, f.cipher, true, f.pool)
	before, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	w := contactIntegrationBound(t, f, current, cookies, http.MethodGet, "/api/v1/users/me/contacts", "", nil, 200)
	var contacts contactmanager.Contacts
	if json.Unmarshal(w.Body.Bytes(), &contacts) != nil || contacts.Email != nil || contacts.Phone == nil || !contacts.Phone.Verified {
		t.Fatal("email absence fabricated evidence or prevented current-state read")
	}
	grant := f.stepup(t, current, cookies, authenticator, a)
	w = contactIntegrationBound(t, f, current, cookies, http.MethodDelete, "/api/v1/users/me/email", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, 204)
	after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || after.Email != nil || after.AuthVersion != before.AuthVersion || after.LifecycleRevision != before.LifecycleRevision || !after.UpdatedAt.Time.Equal(before.UpdatedAt.Time) || w.Header().Get(session.HeaderAuthInvalidated) != "" {
		t.Fatal("authorized absent-email removal changed account or invalidated session")
	}
	if f.server.deps.AuditRecorder.(*phoneAuditRecorder).count(audit.EventPhoneRemoved) != 0 {
		t.Fatal("email no-op emitted phone audit")
	}
	contactIntegrationBound(t, f, current, cookies, http.MethodDelete, "/api/v1/users/me/email", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, 403)
	grant = f.stepup(t, current, cookies, authenticator, a)
	value := uuid.NewString() + "@contact.invalid"
	start := contactIntegrationStart(t, f, current, cookies, "email", value, grant, "")
	contactIntegrationBound(t, f, current, cookies, http.MethodPost, "/api/v1/users/me/email/verify", loginHTTPBody(t, map[string]string{"verification_id": start.VerificationID, "code": f.delivery.last()}), nil, 200)
	after, err = db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || after.Email == nil || *after.Email != value || after.AuthVersion != before.AuthVersion+1 {
		t.Fatal("email-absent account could not add owned primary email")
	}
}
