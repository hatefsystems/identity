//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/passwordmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// The barrier is after HTTP and step-up admission, either before the subject
// lock or just before commit while the subject/user/child locks are still held.
type credentialMutationBarrier struct {
	pool    *pgxpool.Pool
	phase   string
	entered chan struct{}
	release chan struct{}
}

func (b *credentialMutationBarrier) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if b.phase == "revocation_first" {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
			return nil, ctx.Err()
		}
	}
	return &credentialMutationTx{Tx: tx, barrier: b}, nil
}

type credentialMutationTx struct {
	pgx.Tx
	barrier *credentialMutationBarrier
}

func (tx *credentialMutationTx) Commit(ctx context.Context) error {
	if tx.barrier.phase == "mutation_first" {
		close(tx.barrier.entered)
		select {
		case <-tx.barrier.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return tx.Tx.Commit(ctx)
}

type credentialMutationSnapshot struct {
	enabled            bool
	secret             []byte
	codes, enrollments string
}

func credentialSnapshot(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) credentialMutationSnapshot {
	t.Helper()
	var s credentialMutationSnapshot
	err := pool.QueryRow(ctx, `SELECT is_mfa_enabled, mfa_totp_secret_encrypted,
 (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb)::text FROM recovery_codes r WHERE r.user_id=u.id),
 (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb)::text FROM mfa_totp_enrollments e WHERE e.user_id=u.id)
 FROM users u WHERE id=$1`, id).Scan(&s.enabled, &s.secret, &s.codes, &s.enrollments)
	if err != nil {
		t.Fatalf("read credential snapshot: %v", err)
	}
	return s
}

func revokeMutationCredentials(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return err
	}
	if err := db.New(tx).RevokeUserCredentials(ctx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func waitCredentialRevocationLock(ctx context.Context, t *testing.T, pool *pgxpool.Pool, pid uint32) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var locked bool
		if err := pool.QueryRow(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&locked); err != nil {
			t.Fatalf("inspect revocation lock barrier: %v", err)
		}
		if locked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("mutation context cancelled before lock contention")
		case <-timer.C:
			t.Fatal("revocation never contended on the mutation lock")
		case <-ticker.C:
		}
	}
}

func TestIntegrationCredentialMutationSessionFences(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		if os.Getenv("REQUIRE_PHASE2_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required for mutation session fences")
		}
		t.Skip("DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool := openRecoveryHandlerIntegrationPool(ctx, t)
	for _, operation := range []string{"recovery", "setup", "enable", "disable"} {
		for _, ordering := range []string{"revocation_first", "fresh", "mutation_first"} {
			t.Run(operation+"/"+ordering, func(t *testing.T) {
				q := db.New(pool)
				user, err := q.CreateUser(ctx, db.CreateUserParams{Email: new(uuid.NewString() + "@mutation.invalid"), Status: "active"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if _, err := pool.Exec(cleanup, `DELETE FROM users WHERE id=$1`, user.ID); err != nil {
						t.Errorf("clean owned mutation user: %v", err)
					}
				})
				// Factor maintenance must retain an independently usable primary credential.
				if _, err := pool.Exec(ctx, `INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)`, []byte(uuid.NewString()), user.ID, []byte("fixture-public-key"), uuid.Nil); err != nil {
					t.Fatal(err)
				}
				browser := newPortalTestClient(t, testPortalOrigin)
				codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour,
					AccountState: session.NewDBAccountState(pool)})
				if err != nil {
					t.Fatal(err)
				}
				current, cookies := browser.issueSession(t, manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true})
				initialMFA, err := mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(pool))
				if err != nil {
					t.Fatal(err)
				}
				initialMFA.SetSessions(manager)
				pending, err := initialMFA.GenerateSetup(ctx, current, mfaAuthorizationForSession(current, mfa.AuthorizationWebAuthnUV))
				if err != nil {
					t.Fatal(err)
				}
				code, err := totp.GenerateCode(pending.Secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if operation == "disable" {
					if err := initialMFA.VerifyAndEnable(ctx, current, pending.EnrollmentID, code); err != nil {
						t.Fatal(err)
					}
					user, err = q.GetUserByID(ctx, user.ID)
					if err != nil {
						t.Fatal(err)
					}
					loginCode, err := totp.GenerateCode(pending.Secret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if err := stepup.VerifyLoginTOTP(ctx, initialMFA, stepup.NewMemoryReplayGuard(), user.ID, loginCode, time.Now()); err != nil {
						t.Fatal(err)
					}
					// Enrollment does not restamp the old session: model a fresh MFA sign-in.
					current, cookies = browser.issueSession(t, manager, session.IssueParams{
						UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true,
						Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, TOTP: true, AuthenticatedAt: time.Now().UTC()},
					})
				}
				initialRecovery, err := recovery.New(recovery.Config{}, q, recovery.WithTransacter(pool))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := initialRecovery.Generate(ctx, user.ID, user.AuthVersion, ""); err != nil {
					t.Fatal(err)
				}
				_, signingKeys := newTestStepUpService(t, q, nil, initialMFA)
				earnedGrants, err := stepup.New(stepup.Config{Issuer: testStepUpIssuer, AccountState: session.NewDBAccountState(pool)}, signingKeys, q, nil, initialMFA, stepup.NewMemoryReplayGuard())
				if err != nil {
					t.Fatal(err)
				}
				earlierGrant, _, err := earnedGrants.MintContext(ctx, stepup.MintParams{UserID: current.UserID, SessionID: current.ID, AuthVersion: current.AuthVersion, AuthVersionSet: true, DPoPJKT: current.DPoPJKT, AMR: []string{"hwk", "user"}})
				if err != nil {
					t.Fatal("earlier step-up fixture could not earn authority", err)
				}
				before := credentialSnapshot(ctx, t, pool, user.ID)
				barrier := &credentialMutationBarrier{pool: pool, phase: ordering, entered: make(chan struct{}), release: make(chan struct{})}
				defer func() {
					select {
					case <-barrier.release:
					default:
						close(barrier.release)
					}
				}()
				mfaService, err := mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(barrier))
				if err != nil {
					t.Fatal(err)
				}
				recoveryService, err := recovery.New(recovery.Config{}, q, recovery.WithTransacter(barrier))
				if err != nil {
					t.Fatal(err)
				}
				recorder := &profileAuditRecorder{}
				grants := newStepUpServiceForUser(t, user.ID)
				srv := New(config.Config{Environment: "development", PortalOrigin: browser.origin}, nil, Deps{SessionManager: manager,
					DPoPValidator: browser.validator, StepUp: grants, MFA: mfaService, Recovery: recoveryService, AuditRecorder: recorder})
				method, path := http.MethodPost, "/api/v1/auth/mfa/generate"
				var body []byte
				switch operation {
				case "recovery":
					path = recoveryGeneratePath
				case "enable":
					path = "/api/v1/auth/mfa/verify"
					body, err = json.Marshal(mfaVerifyRequest{EnrollmentID: pending.EnrollmentID, Code: code})
					if err != nil {
						t.Fatal(err)
					}
				case "disable":
					method, path = http.MethodDelete, "/api/v1/auth/mfa"
				}
				request := httptest.NewRequest(method, path, bytes.NewReader(body)).WithContext(ctx)
				browser.authorize(t, request, current, cookies...)
				if operation != "enable" {
					request.Header.Set(stepup.HeaderStepUpAuth, mintMFAGrant(t, grants, current, []string{"hwk", "user"}))
				}
				response := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); srv.Handler().ServeHTTP(response, request) }()
				if ordering != "fresh" {
					select {
					case <-barrier.entered:
					case <-done:
						t.Fatalf("request did not reach post-admission barrier: status %d", response.Code)
					case <-ctx.Done():
						t.Fatal("request failed to reach mutation barrier")
					}
					revocation, err := pool.Begin(ctx)
					if err != nil {
						close(barrier.release)
						t.Fatal(err)
					}
					if ordering == "revocation_first" {
						if err := revokeMutationCredentials(ctx, revocation, user.ID); err != nil {
							close(barrier.release)
							t.Fatal(err)
						}
						close(barrier.release)
					} else {
						pid := revocation.Conn().PgConn().PID()
						revoked := make(chan error, 1)
						go func() { revoked <- revokeMutationCredentials(ctx, revocation, user.ID) }()
						waitCredentialRevocationLock(ctx, t, pool, pid)
						close(barrier.release)
						if err := <-revoked; err != nil {
							t.Fatal(err)
						}
					}
				}
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("mutation response timed out")
				}
				after := credentialSnapshot(ctx, t, pool, user.ID)
				locked, err := q.GetUserByID(ctx, user.ID)
				if err != nil {
					t.Fatal(err)
				}
				var versionChanges int64
				if ordering != "fresh" {
					versionChanges++
				}
				if ordering != "revocation_first" && (operation == "enable" || operation == "disable") {
					versionChanges++
					if response.Header().Get(session.HeaderAuthInvalidated) != "true" {
						t.Fatal("committed factor change did not report invalidated initiating authority")
					}
				}
				if locked.AuthVersion != user.AuthVersion+versionChanges {
					t.Fatal("factor mutation/revocation version transition was not exactly once per change")
				}
				_, grantErr := earnedGrants.Validate(ctx, earlierGrant, current)
				if versionChanges > 0 && !errors.Is(grantErr, stepup.ErrGrantNotForSession) {
					t.Fatal("earlier step-up grant survived committed authority change", grantErr)
				}
				if versionChanges == 0 && grantErr != nil {
					t.Fatal("pending/non-factor operation invalidated earlier step-up authority", grantErr)
				}
				if ordering == "revocation_first" {
					if response.Code != http.StatusUnauthorized || !reflect.DeepEqual(before, after) ||
						bytes.Contains(response.Body.Bytes(), []byte(`"secret"`)) || bytes.Contains(response.Body.Bytes(), []byte(`"codes"`)) {
						t.Fatalf("stale mutation changed credentials or returned success: status %d", response.Code)
					}
					for _, event := range recorder.events {
						if event.ActionStatus == audit.StatusSuccess {
							t.Fatal("stale mutation recorded success")
						}
					}
					return
				}
				want := http.StatusOK
				if operation == "disable" {
					want = http.StatusNoContent
				}
				if response.Code != want || reflect.DeepEqual(before, after) {
					t.Fatalf("ordered mutation failed: status %d", response.Code)
				}
				successes := 0
				for _, event := range recorder.events {
					if event.ActionStatus == audit.StatusSuccess {
						successes++
					}
				}
				wantSuccesses := 1
				if operation == "setup" {
					wantSuccesses = 0
				}
				if successes != wantSuccesses {
					t.Fatalf("success audits = %d, want %d", successes, wantSuccesses)
				}
			})
		}
	}
}

type mfaRollbackBegin struct{ pool *pgxpool.Pool }

func (b mfaRollbackBegin) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return mfaRollbackTx{tx}, nil
}

type mfaRollbackTx struct{ pgx.Tx }

var errMfaForcedRollback = errors.New("forced MFA rollback after write")

func (tx mfaRollbackTx) Commit(context.Context) error { return errMfaForcedRollback }

func TestTOTPChangesRollbackFactorPendingAndAuthorityIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := openRecoveryHandlerIntegrationPool(ctx, t)
	q := db.New(pool)
	for _, operation := range []string{"enable", "disable"} {
		t.Run(operation, func(t *testing.T) {
			user, err := q.CreateUser(ctx, db.CreateUserParams{Status: "active"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if _, err := pool.Exec(cleanup, "DELETE FROM users WHERE id=$1", user.ID); err != nil {
					t.Error("owned MFA rollback account teardown failed")
				}
			})
			if _, err := pool.Exec(ctx, `INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)`, []byte(uuid.NewString()), user.ID, []byte("fixture-public-key"), uuid.Nil); err != nil {
				t.Fatal(err)
			}
			svc, err := mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(pool))
			if err != nil {
				t.Fatal(err)
			}
			browser := newPortalTestClient(t, testPortalOrigin)
			codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(pool)})
			if err != nil {
				t.Fatal(err)
			}
			current, _ := browser.issueSession(t, manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true})
			svc.SetSessions(manager)
			pending, err := svc.GenerateSetup(ctx, current, mfaAuthorizationForSession(current, mfa.AuthorizationWebAuthnUV))
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(pending.Secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if operation == "disable" {
				if err := svc.VerifyAndEnable(ctx, current, pending.EnrollmentID, code); err != nil {
					t.Fatal(err)
				}
				user, err = q.GetUserByID(ctx, user.ID)
				if err != nil {
					t.Fatal(err)
				}
				current, _ = browser.issueSession(t, manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true,
					Evidence: session.Evidence{PrimaryMethod: session.MethodPassword, UV: session.UVNotApplicable, TOTPSet: true, TOTP: true, AuthenticatedAt: time.Now().UTC()}})
			}
			before := credentialSnapshot(ctx, t, pool, user.ID)
			svc, err = mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(mfaRollbackBegin{pool}))
			if err != nil {
				t.Fatal(err)
			}
			svc.SetSessions(manager)
			if operation == "enable" {
				err = svc.VerifyAndEnable(ctx, current, pending.EnrollmentID, code)
			} else {
				_, err = svc.Disable(ctx, current, mfaAuthorizationForSession(current, mfa.AuthorizationTOTP))
			}
			if !errors.Is(err, mfa.ErrOutcomeUnknown) {
				t.Fatal("forced post-write rollback was not reached", err)
			}
			after, err := q.GetUserByID(ctx, user.ID)
			if err != nil || after.AuthVersion != user.AuthVersion || !reflect.DeepEqual(before, credentialSnapshot(ctx, t, pool, user.ID)) {
				t.Fatal("rolled-back MFA change retained partial factor, enrollment or authority writes")
			}
		})
	}
}

func TestMFAPasswordOnlyDisableUsesLockedResultingPolicyIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	for _, state := range []string{"ordinary_password", "login_disabled", "unsupported_password", "missing_password", "unclaimed_username", "unreadable_username", "missing_policy", "custom_role", "retained_passkey", "role_with_retained_passkey", "uv_retained_passkey"} {
		t.Run(state, func(t *testing.T) {
			credential := "password_only"
			if state == "unclaimed_username" {
				credential = "password_unclaimed"
			}
			if state == "retained_passkey" || state == "role_with_retained_passkey" || state == "uv_retained_passkey" {
				credential = "dual"
			}
			a := f.account(t, credential, true)
			q := db.New(f.pool)
			if state == "custom_role" || state == "role_with_retained_passkey" {
				role := "mfa-" + uuid.NewString()
				if _, err := q.CreateRole(f.ctx, db.CreateRoleParams{ID: role, Description: "Fixture custom role"}); err != nil {
					t.Fatal(err)
				}
				if err := q.AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: a.user.ID, RoleID: role}); err != nil {
					t.Fatal(err)
				}
			}
			current, cookies := f.issue(t, a, session.MethodPassword)
			var grant string
			if state == "uv_retained_passkey" {
				grant = f.stepup(t, current, cookies, f.authenticator(t, a), a)
			} else {
				grant = f.stepup(t, current, cookies, nil, a)
			}
			policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
			want := http.StatusConflict
			switch state {
			case "ordinary_password", "retained_passkey", "role_with_retained_passkey", "uv_retained_passkey":
				want = http.StatusNoContent
			case "login_disabled":
				policy.PasswordLoginEnabled = false
			case "unsupported_password":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET password_hash='unsupported-fixture-hash' WHERE id=$1`, a.user.ID); err != nil {
					t.Fatal(err)
				}
			case "missing_password":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET password_hash=NULL WHERE id=$1`, a.user.ID); err != nil {
					t.Fatal(err)
				}
			case "unreadable_username":
				names, err := username.NewStore(f.pool, phoneIntegrationCipher(t), f.names.Normalizer())
				if err != nil {
					t.Fatal(err)
				}
				policy.Usernames, want = names, http.StatusServiceUnavailable
			case "missing_policy":
				policy.Usernames, want = nil, http.StatusServiceUnavailable
			}
			svc, err := mfa.New(mfa.Config{}, q, f.cipher, mfa.WithTransacter(f.pool))
			if err != nil {
				t.Fatal(err)
			}
			svc.SetSessions(f.manager)
			svc.SetAccountPolicy(policy)
			recorder := &profileAuditRecorder{}
			deps := f.server.deps
			deps.MFA, deps.AuditRecorder = svc, recorder
			f.server = New(f.server.cfg, f.server.logger, deps)
			before := credentialSnapshot(f.ctx, t, f.pool, a.user.ID)
			response := f.bound(t, current, cookies, http.MethodDelete, "/api/v1/auth/mfa", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, want)
			after, err := q.GetUserByID(f.ctx, a.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if want == http.StatusNoContent {
				if after.IsMfaEnabled || len(after.MfaTotpSecretEncrypted) != 0 || after.AuthVersion != a.user.AuthVersion+1 || response.Header().Get(session.HeaderAuthInvalidated) != "true" {
					t.Fatal("allowed removal did not atomically remove factor and revoke once")
				}
				if len(recorder.events) != 1 || recorder.events[0].EventType != audit.EventMFATOTPDisabled || recorder.events[0].ActionStatus != audit.StatusSuccess {
					t.Fatal("real removal did not emit exactly one disabled-factor audit")
				}
			} else {
				if after.AuthVersion != a.user.AuthVersion || !reflect.DeepEqual(before, credentialSnapshot(f.ctx, t, f.pool, a.user.ID)) || response.Header().Get(session.HeaderAuthInvalidated) != "" {
					t.Fatal("policy refusal wrote factor or account authority")
				}
				for _, event := range recorder.events {
					if event.ActionStatus == audit.StatusSuccess {
						t.Fatal("policy refusal emitted success audit")
					}
				}
				if state == "custom_role" && errorBody(t, response) != "last_factor" {
					t.Fatal("arbitrary role did not preserve privileged protection")
				}
			}
		})
	}
}

type mfaCommitFaultBegin struct {
	pool              *pgxpool.Pool
	commitBeforeError bool
	begins, commits   int
}

func (b *mfaCommitFaultBegin) Begin(ctx context.Context) (pgx.Tx, error) {
	b.begins++
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &mfaCommitFaultTx{Tx: tx, owner: b}, nil
}

type mfaCommitFaultTx struct {
	pgx.Tx
	owner *mfaCommitFaultBegin
}

func (tx *mfaCommitFaultTx) Commit(ctx context.Context) error {
	tx.owner.commits++
	if tx.owner.commitBeforeError {
		if err := tx.Tx.Commit(ctx); err != nil {
			return err
		}
	}
	return errMfaForcedRollback
}

func TestMFAUnknownCommitLostAcknowledgementAndRollbackDoNotPublishOrReplayIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool := openRecoveryHandlerIntegrationPool(ctx, t)
	q := db.New(pool)
	for _, commitFirst := range []bool{false, true} {
		for _, operation := range []string{"setup", "enable", "disable"} {
			name := "rollback"
			if commitFirst {
				name = "committed_lost_ack"
			}
			t.Run(operation+"/"+name, func(t *testing.T) {
				user, err := q.CreateUser(ctx, db.CreateUserParams{Status: "active"})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if _, err := pool.Exec(cleanup, `DELETE FROM users WHERE id=$1`, user.ID); err != nil {
						t.Error("MFA unknown-outcome owned account teardown failed")
					}
				})
				if _, err := pool.Exec(ctx, `INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES($1,$2,$3,'none',$4)`, []byte(uuid.NewString()), user.ID, []byte("fixture-public-key"), uuid.Nil); err != nil {
					t.Fatal(err)
				}
				browser := newPortalTestClient(t, testPortalOrigin)
				codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				store := &boundaryStore{Store: session.NewMemoryStore()}
				manager, err := session.NewManager(store, codec, session.ManagerConfig{AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(pool)})
				if err != nil {
					t.Fatal(err)
				}
				current, cookies := browser.issueSession(t, manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true,
					Evidence: session.Evidence{PrimaryMethod: session.MethodPasskey, UV: session.UVVerified, TOTPSet: true, AuthenticatedAt: time.Now().UTC()}})
				normal, err := mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(pool))
				if err != nil {
					t.Fatal(err)
				}
				normal.SetSessions(manager)
				var pending *mfa.SetupResponse
				var code string
				if operation != "setup" {
					pending, err = normal.GenerateSetup(ctx, current, mfaAuthorizationForSession(current, mfa.AuthorizationWebAuthnUV))
					if err != nil {
						t.Fatal(err)
					}
					code, err = totp.GenerateCode(pending.Secret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if operation == "disable" {
						if err := normal.VerifyAndEnable(ctx, current, pending.EnrollmentID, code); err != nil {
							t.Fatal(err)
						}
						user, err = q.GetUserByID(ctx, user.ID)
						if err != nil {
							t.Fatal(err)
						}
						current, cookies = browser.issueSession(t, manager, session.IssueParams{UserID: user.ID.String(), AuthVersion: user.AuthVersion, AuthVersionSet: true,
							Evidence: session.Evidence{PrimaryMethod: session.MethodPasskey, UV: session.UVVerified, TOTPSet: true, TOTP: true, AuthenticatedAt: time.Now().UTC()}})
					}
				}
				before := credentialSnapshot(ctx, t, pool, user.ID)
				fault := &mfaCommitFaultBegin{pool: pool, commitBeforeError: commitFirst}
				svc, err := mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(fault))
				if err != nil {
					t.Fatal(err)
				}
				svc.SetSessions(manager)
				grants := newStepUpServiceForUser(t, user.ID)
				grant := mintMFAGrant(t, grants, current, []string{"hwk", "user"})
				recorder := &profileAuditRecorder{}
				srv := New(config.Config{Environment: "development", PortalOrigin: browser.origin}, nil, Deps{SessionManager: manager, DPoPValidator: browser.validator, MFA: svc, StepUp: grants, AuditRecorder: recorder})
				method, path, body := http.MethodPost, "/api/v1/auth/mfa/generate", ""
				if operation == "enable" {
					path, body = "/api/v1/auth/mfa/verify", loginHTTPBody(t, map[string]string{"enrollment_id": pending.EnrollmentID, "code": code})
				}
				if operation == "disable" {
					method, path = http.MethodDelete, "/api/v1/auth/mfa"
				}
				request := func() *httptest.ResponseRecorder {
					r := httptest.NewRequest(method, path, bytes.NewBufferString(body)).WithContext(ctx)
					browser.authorize(t, r, current, cookies...)
					if operation != "enable" {
						r.Header.Set(stepup.HeaderStepUpAuth, grant)
					}
					w := httptest.NewRecorder()
					srv.Handler().ServeHTTP(w, r)
					return w
				}
				response := request()
				if response.Code != http.StatusServiceUnavailable || errorBody(t, response) != "outcome_unknown" || bytes.Contains(response.Body.Bytes(), []byte(`"secret"`)) || bytes.Contains(response.Body.Bytes(), []byte(`"status"`)) || response.Header().Get(session.HeaderAuthInvalidated) != "" || len(response.Result().Cookies()) != 0 || fault.begins != 1 || fault.commits != 1 {
					t.Fatalf("uncertain mutation published success, retried, or issued session: status %d", response.Code)
				}
				for _, event := range recorder.events {
					if event.ActionStatus == audit.StatusSuccess {
						t.Fatal("uncertain mutation published success audit")
					}
				}
				after, err := q.GetUserByID(ctx, user.ID)
				if err != nil {
					t.Fatal(err)
				}
				versionDelta := int64(0)
				if commitFirst && operation != "setup" {
					versionDelta = 1
				}
				if after.AuthVersion != user.AuthVersion+versionDelta {
					t.Fatal("uncertain commit advanced authority more or less than actual SQL commit")
				}
				if reflect.DeepEqual(before, credentialSnapshot(ctx, t, pool, user.ID)) == commitFirst {
					t.Fatal("commit-fault fixture did not distinguish actual commit from rollback")
				}
				if operation != "enable" {
					if _, err := grants.Validate(ctx, grant, current); !errors.Is(err, stepup.ErrGrantConsumed) {
						t.Fatal("uncertain SQL outcome restored spent strong grant", err)
					}
					if retry := request(); retry.Code != http.StatusForbidden && retry.Code != http.StatusUnauthorized {
						t.Fatal("spent-grant replay accepted")
					}
					if fault.begins != 1 || fault.commits != 1 {
						t.Fatal("spent-grant replay retried SQL mutation")
					}
				} else if commitFirst {
					if retry := request(); retry.Code != http.StatusUnauthorized || fault.begins != 1 {
						t.Fatal("uncertain enable replay accepted old version")
					}
				}
			})
		}
	}
}

func TestMFAPasswordContactFrozenPendingLifecycleIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	q := db.New(f.pool)
	policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{0x45}, 32), MFAEnrollmentEmail: loginEmailCapture{f.delivery}, PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}, f.codeStore, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := actionproof.NewMFAEnrollment(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x71}, 32)}, actionproof.Deps{DB: f.pool, Queries: q, Codes: codes, Cipher: f.cipher, Limiter: f.limiter, Sessions: f.manager})
	if err != nil {
		t.Fatal(err)
	}
	proofs.SetAccountPolicy(policy)
	for _, state := range []string{"complete_issuance_disabled", "contact_changed", "role_added", "password_removed", "version_revoked", "expired", "exhausted", "concurrent_confirmation", "concurrent_start"} {
		t.Run(state, func(t *testing.T) {
			a := f.account(t, "password_only", false)
			current, cookies := f.issue(t, a, session.MethodPassword)
			challenge, _, err := proofs.ChallengeMFAEnrollment(f.ctx, current, a.secret, "email", "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			proof, proofExpiry, err := proofs.VerifyMFAEnrollment(f.ctx, current, challenge, f.delivery.last())
			if err != nil {
				t.Fatal(err)
			}
			svc, err := mfa.New(mfa.Config{}, q, f.cipher, mfa.WithTransacter(f.pool))
			if err != nil {
				t.Fatal(err)
			}
			svc.SetSessions(f.manager)
			svc.SetAccountPolicy(policy)
			svc.SetEnrollmentProofs(proofs)
			recorder := &profileAuditRecorder{}
			deps := f.server.deps
			deps.MFA, deps.MFAEnrollmentProofs, deps.AuditRecorder = svc, proofs, recorder
			f.server = New(f.server.cfg, f.server.logger, deps)
			auth := mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proof}
			var setup *mfa.SetupResponse
			if state == "concurrent_start" {
				type result struct {
					setup *mfa.SetupResponse
					err   error
				}
				results := make(chan result, 2)
				start := make(chan struct{})
				for range 2 {
					go func() { <-start; setup, err := svc.GenerateSetup(f.ctx, current, auth); results <- result{setup, err} }()
				}
				close(start)
				wins := 0
				for range 2 {
					select {
					case result := <-results:
						if result.err == nil {
							wins++
							setup = result.setup
						} else if result.setup != nil || !errors.Is(result.err, actionproof.ErrInvalid) {
							t.Fatal("same-proof start had unexpected outcome", result.err)
						}
					case <-f.ctx.Done():
						t.Fatal("same-proof starts blocked on nested transaction")
					}
				}
				if wins != 1 {
					t.Fatal("same SQL proof started more or less than once")
				}
			} else {
				// Bounded syntax refusal must occur before the SQL proof is consumed.
				f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "{}", http.Header{"X-Action-Proof": {proof}}, http.StatusBadRequest)
				var remaining int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_enrollment_action_proofs WHERE user_id=$1`, a.user.ID).Scan(&remaining); err != nil || remaining != 1 {
					t.Fatal("malformed setup spent valid enrollment proof", err)
				}
				response := f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "", http.Header{"X-Action-Proof": {proof}}, http.StatusOK)
				if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil || setup == nil {
					t.Fatal("password-contact setup missing", err)
				}
			}
			id := uuid.MustParse(setup.EnrollmentID)
			row, err := q.GetMfaTotpEnrollmentForUpdate(f.ctx, db.GetMfaTotpEnrollmentForUpdateParams{ID: id, UserID: a.user.ID, SessionID: uuid.MustParse(current.ID), Purpose: "maintenance"})
			if err != nil {
				t.Fatal(err)
			}
			if !setup.ExpiresAt.Equal(proofExpiry) || row.AuthVersion == nil || *row.AuthVersion != current.AuthVersion || row.Jkt == nil || *row.Jkt != current.DPoPJKT || row.AuthorizationMethod == nil || *row.AuthorizationMethod != mfa.AuthorizationPasswordContact || row.Channel == nil || *row.Channel != "email" || len(row.ContactBinding) != 32 {
				t.Fatal("password-contact pending did not preserve original proof/session binding")
			}
			var proofCount, pendingCount int
			if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM mfa_enrollment_action_proofs WHERE user_id=$1),(SELECT count(*) FROM mfa_totp_enrollments WHERE user_id=$1)`, a.user.ID).Scan(&proofCount, &pendingCount); err != nil || proofCount != 0 || pendingCount != 1 {
				t.Fatal("proof consumption and one pending row were not atomic", err)
			}
			if state == "concurrent_start" {
				return
			}
			// The enrollment-only capability is never a disable bypass, including no-op cancellation.
			f.bound(t, current, cookies, http.MethodDelete, "/api/v1/auth/mfa", "", http.Header{"X-Action-Proof": {proof}}, http.StatusForbidden)
			wrong := wrongMFAHTTPCode(t, setup.Secret, time.Now())
			if err := svc.VerifyAndEnable(f.ctx, current, setup.EnrollmentID, wrong); !errors.Is(err, mfa.ErrInvalidCode) {
				t.Fatal(err)
			}
			var attempts int32
			if err := f.pool.QueryRow(f.ctx, `SELECT failed_attempts FROM mfa_totp_enrollments WHERE id=$1`, id).Scan(&attempts); err != nil || attempts != 1 {
				t.Fatal("domain error rolled back failed-attempt counter", err)
			}
			if state == "exhausted" {
				for range 4 {
					if err := svc.VerifyAndEnable(f.ctx, current, setup.EnrollmentID, wrong); !errors.Is(err, mfa.ErrInvalidCode) {
						t.Fatal(err)
					}
				}
			} else if state == "expired" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE mfa_totp_enrollments SET created_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
				if err := svc.VerifyAndEnable(f.ctx, current, setup.EnrollmentID, wrong); !errors.Is(err, mfa.ErrEnrollmentExpired) {
					t.Fatal("expiry deletion did not report domain outcome", err)
				}
			} else {
				code, err := totp.GenerateCode(setup.Secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				switch state {
				case "complete_issuance_disabled":
					readers, err := actionproof.NewMFAEnrollment(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x71}, 32)}, actionproof.Deps{DB: f.pool, Queries: q, Cipher: f.cipher, Sessions: f.manager})
					if err != nil {
						t.Fatal(err)
					}
					readers.SetAccountPolicy(policy)
					svc.SetEnrollmentProofs(readers)
				case "contact_changed":
					f.contact(t, a.user.ID, "email", uuid.NewString()+"@replacement.invalid")
				case "role_added":
					role := "mfa-pending-" + uuid.NewString()
					if _, err := q.CreateRole(f.ctx, db.CreateRoleParams{ID: role, Description: "Fixture role"}); err != nil {
						t.Fatal(err)
					}
					if err := q.AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: a.user.ID, RoleID: role}); err != nil {
						t.Fatal(err)
					}
				case "password_removed":
					if _, err := f.pool.Exec(f.ctx, `UPDATE users SET password_hash=NULL WHERE id=$1`, a.user.ID); err != nil {
						t.Fatal(err)
					}
				case "version_revoked":
					if err := q.RevokeUserCredentials(f.ctx, a.user.ID); err != nil {
						t.Fatal(err)
					}
				}
				if state == "complete_issuance_disabled" {
					body := loginHTTPBody(t, map[string]string{"enrollment_id": setup.EnrollmentID, "code": code})
					response := f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/verify", body, nil, http.StatusOK)
					if response.Header().Get(session.HeaderAuthInvalidated) != "true" || len(recorder.events) != 1 || recorder.events[0].EventType != audit.EventMFATOTPEnabled {
						t.Fatal("known enable did not invalidate and audit once")
					}
				} else if state == "concurrent_confirmation" {
					results := make(chan error, 2)
					start := make(chan struct{})
					for range 2 {
						go func() { <-start; results <- svc.VerifyAndEnable(f.ctx, current, setup.EnrollmentID, code) }()
					}
					close(start)
					wins := 0
					for range 2 {
						select {
						case err := <-results:
							if err == nil {
								wins++
							} else if !errors.Is(err, mfa.ErrAccountNotActive) && !errors.Is(err, mfa.ErrUnauthorized) {
								t.Fatal("concurrent confirmation unexpected error", err)
							}
						case <-f.ctx.Done():
							t.Fatal("confirmation race blocked on nested transaction")
						}
					}
					if wins != 1 {
						t.Fatal("confirmation did not have exactly one winner")
					}
				} else {
					err := svc.VerifyAndEnable(f.ctx, current, setup.EnrollmentID, code)
					want := actionproof.ErrUnauthorized
					if state == "version_revoked" {
						want = mfa.ErrAccountNotActive
					}
					if !errors.Is(err, want) {
						t.Fatal("stale frozen authorization enabled TOTP", err)
					}
					if err := f.pool.QueryRow(f.ctx, `SELECT failed_attempts FROM mfa_totp_enrollments WHERE id=$1`, id).Scan(&attempts); err != nil || attempts != 1 {
						t.Fatal("authority refusal burned pending budget", err)
					}
				}
			}
			after, err := q.GetUserByID(f.ctx, a.user.ID)
			if err != nil {
				t.Fatal(err)
			}
			changed := state == "complete_issuance_disabled" || state == "concurrent_confirmation"
			versionDelta := int64(0)
			if changed || state == "version_revoked" {
				versionDelta = 1
			}
			if after.IsMfaEnabled != changed || after.AuthVersion != a.user.AuthVersion+versionDelta {
				t.Fatal("pending lifecycle made partial or extra security change")
			}
			if state == "expired" || state == "exhausted" || changed {
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_totp_enrollments WHERE id=$1`, id).Scan(&pendingCount); err != nil || pendingCount != 0 {
					t.Fatal("terminal pending deletion was rolled back", err)
				}
			}
		})
	}
}

func TestMFAExistingPasskeyActuallyVerifiedUVEnrollmentIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "dual", false)
	authenticator := f.authenticator(t, a)
	current, cookies := f.issue(t, a, session.MethodPasskey)
	grant := f.stepup(t, current, cookies, authenticator, a)
	q := db.New(f.pool)
	svc, err := mfa.New(mfa.Config{}, q, f.cipher, mfa.WithTransacter(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetSessions(f.manager)
	svc.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names})
	recorder := &profileAuditRecorder{}
	deps := f.server.deps
	deps.MFA, deps.AuditRecorder = svc, recorder
	f.server = New(f.server.cfg, f.server.logger, deps)
	response := f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, http.StatusOK)
	var setup mfa.SetupResponse
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	row, err := q.GetMfaTotpEnrollmentForUpdate(f.ctx, db.GetMfaTotpEnrollmentForUpdateParams{ID: uuid.MustParse(setup.EnrollmentID), UserID: a.user.ID, SessionID: uuid.MustParse(current.ID), Purpose: "maintenance"})
	if err != nil {
		t.Fatal(err)
	}
	if row.AuthorizationMethod == nil || *row.AuthorizationMethod != mfa.AuthorizationWebAuthnUV || row.Channel != nil || len(row.ContactBinding) != 0 || !row.ExpiresAt.Time.Equal(setup.ExpiresAt) {
		t.Fatal("actually verified UV setup lost frozen strong-method evidence")
	}
	f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, http.StatusForbidden)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response = f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/verify", loginHTTPBody(t, map[string]string{"enrollment_id": setup.EnrollmentID, "code": code}), nil, http.StatusOK)
	after, err := q.GetUserByID(f.ctx, a.user.ID)
	if err != nil || !after.IsMfaEnabled || after.AuthVersion != a.user.AuthVersion+1 || response.Header().Get(session.HeaderAuthInvalidated) != "true" {
		t.Fatal("UV enrollment did not enable and invalidate exactly once", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].EventType != audit.EventMFATOTPEnabled {
		t.Fatal("UV enrollment emitted extra success audit")
	}
}

func mfaGapProofService(t *testing.T, f *realPasswordFixture, channel string) (*actionproof.Service, *loginDeliveryCapture) {
	t.Helper()
	otherPurpose := &loginDeliveryCapture{}
	var sms *smsotp.Service
	var email contactcode.Sender
	if channel == "sms" {
		users, err := smsotp.NewUserStore(f.pool, f.cipher)
		if err != nil {
			t.Fatal(err)
		}
		otps, err := smsotp.NewRedisOTPStore(f.client)
		if err != nil {
			t.Fatal(err)
		}
		sms, err = smsotp.New(smsotp.Config{HashPepper: bytes.Repeat([]byte{0x23}, 32), MFAEnrollmentSender: loginSMSCapture{f.delivery}, PerPhonePerMinute: 5, PerPhonePerHour: 20, PerSubnetPerHour: 100}, users, f.cipher, phoneFakeIndexer{}, f.limiter, otps, loginSMSCapture{otherPurpose})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		email = loginEmailCapture{f.delivery}
	}
	codes, err := contactcode.New(contactcode.Config{HashKey: bytes.Repeat([]byte{0x45}, 32), MFAEnrollmentEmail: email, PerDestinationPerMinute: 5, PerDestinationPerHour: 20, PerSourcePerHour: 100}, f.codeStore, sms, nil)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := actionproof.NewMFAEnrollment(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x71}, 32)}, actionproof.Deps{DB: f.pool, Queries: db.New(f.pool), Codes: codes, Cipher: f.cipher, Limiter: f.limiter, Sessions: f.manager})
	if err != nil {
		t.Fatal(err)
	}
	proofs.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names})
	return proofs, otherPurpose
}

func mfaGapIssueProof(t *testing.T, f *realPasswordFixture, proofs *actionproof.Service, a realLoginAccount, current session.Session, channel string) (string, time.Time) {
	t.Helper()
	challenge, deadline, err := proofs.ChallengeMFAEnrollment(f.ctx, current, a.secret, channel, "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	proof, expiry, err := proofs.VerifyMFAEnrollment(f.ctx, current, challenge, f.delivery.last())
	if err != nil || !expiry.Equal(deadline) {
		t.Fatal("enrollment proof changed original code deadline", err)
	}
	return proof, expiry
}

func mfaGapService(t *testing.T, f *realPasswordFixture, tx mfa.Transacter, proofs *actionproof.Service) *mfa.Service {
	t.Helper()
	svc, err := mfa.New(mfa.Config{}, db.New(f.pool), f.cipher, mfa.WithTransacter(tx))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetSessions(f.manager)
	svc.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names})
	if proofs != nil {
		svc.SetEnrollmentProofs(proofs)
	}
	return svc
}

type mfaAfterScanRow struct {
	pgx.Row
	after func() error
}

func (row mfaAfterScanRow) Scan(dest ...any) error {
	if err := row.Row.Scan(dest...); err != nil {
		return err
	}
	return row.after()
}

type mfaStartWriteFault struct {
	pool                                         *pgxpool.Pool
	stage                                        string
	expiry                                       time.Time
	proofDeletes, pendingDeletes, pendingInserts int
	confirmWrites                                int
	begins, commits                              int
}

func (b *mfaStartWriteFault) Begin(ctx context.Context) (pgx.Tx, error) {
	b.begins++
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &mfaStartWriteFaultTx{Tx: tx, owner: b}, nil
}

type mfaStartWriteFaultTx struct {
	pgx.Tx
	owner *mfaStartWriteFault
}

var errMFAStartWriteFault = errors.New("injected MFA start SQL write failure")

func (tx *mfaStartWriteFaultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if tx.owner.stage == "pending_expired" && strings.HasPrefix(sql, "-- name: CreateMfaTotpEnrollment ") {
		// Cross the original frozen deadline after the final Go fence but before
		// executing the real clock_timestamp INSERT predicate, without changing SQL.
		timer := time.NewTimer(max(time.Until(tx.owner.expiry)+10*time.Millisecond, 0))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return mfaAfterScanRow{Row: tx.Tx.QueryRow(ctx, sql, args...), after: func() error { return ctx.Err() }}
		}
		tx.owner.pendingInserts++
		return tx.Tx.QueryRow(ctx, sql, args...)
	}
	row := tx.Tx.QueryRow(ctx, sql, args...)
	stage := ""
	if strings.HasPrefix(sql, "-- name: ConsumeMFAEnrollmentActionProofStart ") {
		stage = "proof_delete"
	}
	if strings.HasPrefix(sql, "-- name: CreateMfaTotpEnrollment ") {
		stage = "pending_insert"
	}
	if stage == "" {
		return row
	}
	return mfaAfterScanRow{Row: row, after: func() error {
		if stage == "proof_delete" {
			tx.owner.proofDeletes++
		} else {
			tx.owner.pendingInserts++
		}
		if tx.owner.stage == stage {
			return errMFAStartWriteFault
		}
		return nil
	}}
}

func (tx *mfaStartWriteFaultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if tx.owner.stage == "confirm_expired" && strings.HasPrefix(sql, "-- name: CompleteMfaTotpEnrollment ") {
		timer := time.NewTimer(max(time.Until(tx.owner.expiry)+10*time.Millisecond, 0))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return pgconn.CommandTag{}, ctx.Err()
		}
		tx.owner.confirmWrites++
	}
	tag, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil && strings.HasPrefix(sql, "-- name: DeleteMfaTotpEnrollmentsForUser ") {
		tx.owner.pendingDeletes++
		if tx.owner.stage == "pending_delete" {
			return tag, errMFAStartWriteFault
		}
	}
	if err == nil && tx.owner.stage == "confirm_expired" && strings.HasPrefix(sql, "-- name: DeleteMfaTotpEnrollment ") {
		tx.owner.pendingDeletes++
	}
	return tag, err
}

func (tx *mfaStartWriteFaultTx) Commit(ctx context.Context) error {
	tx.owner.commits++
	return tx.Tx.Commit(ctx)
}

func mfaProofRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) string {
	t.Helper()
	var rows string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY proof_digest),'[]'::jsonb)::text FROM mfa_enrollment_action_proofs p WHERE user_id=$1`, userID).Scan(&rows); err != nil {
		t.Fatal("read owned proof snapshot failed")
	}
	return rows
}

func TestMFAStartRollbackRestoresConsumedProofAndExactPreviousEnrollmentIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	proofs, _ := mfaGapProofService(t, f, "email")
	for _, stage := range []string{"proof_delete", "pending_delete", "pending_insert", "pending_expired"} {
		t.Run(stage, func(t *testing.T) {
			a := f.account(t, "password_only", false)
			current, cookies := f.issue(t, a, session.MethodPassword)
			normal := mfaGapService(t, f, f.pool, proofs)
			oldProof, _ := mfaGapIssueProof(t, f, proofs, a, current, "email")
			previous, err := normal.GenerateSetup(f.ctx, current, mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: oldProof})
			if err != nil {
				t.Fatal(err)
			}
			proof, _ := mfaGapIssueProof(t, f, proofs, a, current, "email")
			var expiry time.Time
			if stage == "pending_expired" {
				digest := sha256.Sum256([]byte(proof))
				if err := f.pool.QueryRow(f.ctx, `UPDATE mfa_enrollment_action_proofs SET expires_at=clock_timestamp()+interval '2 seconds' WHERE proof_digest=$1 RETURNING expires_at`, digest[:]).Scan(&expiry); err != nil {
					t.Fatal("shorten owned expiry fixture failed")
				}
			}
			before := credentialSnapshot(f.ctx, t, f.pool, a.user.ID)
			beforeProofs := mfaProofRows(f.ctx, t, f.pool, a.user.ID)
			fault := &mfaStartWriteFault{pool: f.pool, stage: stage, expiry: expiry}
			svc := mfaGapService(t, f, fault, proofs)
			recorder := &profileAuditRecorder{}
			deps := f.server.deps
			deps.MFA, deps.MFAEnrollmentProofs, deps.AuditRecorder = svc, proofs, recorder
			f.server = New(f.server.cfg, f.server.logger, deps)
			wantStatus := http.StatusServiceUnavailable
			if stage == "pending_expired" {
				wantStatus = http.StatusForbidden
			}
			response := f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "", http.Header{"X-Action-Proof": {proof}}, wantStatus)
			if fault.begins != 1 || fault.commits != 0 || fault.proofDeletes != 1 || stage != "proof_delete" && fault.pendingDeletes != 1 || (stage == "pending_insert" || stage == "pending_expired") && fault.pendingInserts != 1 {
				t.Fatal("fault did not follow the actual SQL proof/pending writes")
			}
			if bytes.Contains(response.Body.Bytes(), []byte(`"secret"`)) || response.Header().Get(session.HeaderAuthInvalidated) != "" || len(response.Result().Cookies()) != 0 || len(recorder.events) != 0 {
				t.Fatal("rolled-back setup published secret, audit, or session authority")
			}
			after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
			if err != nil || after.AuthVersion != a.user.AuthVersion || !reflect.DeepEqual(before, credentialSnapshot(f.ctx, t, f.pool, a.user.ID)) || beforeProofs != mfaProofRows(f.ctx, t, f.pool, a.user.ID) {
				t.Fatal("rollback did not restore identical proof and previous enrollment bytes", err)
			}
			if stage == "pending_expired" {
				result, err := normal.GenerateSetup(f.ctx, current, mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proof})
				if result != nil || !errors.Is(err, actionproof.ErrInvalid) || !reflect.DeepEqual(before, credentialSnapshot(f.ctx, t, f.pool, a.user.ID)) {
					t.Fatal("restored expired proof gained freshness on retry", err)
				}
				code, err := totp.GenerateCode(previous.Secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err := normal.VerifyAndEnable(f.ctx, current, previous.EnrollmentID, code); err != nil {
					t.Fatal("SQL expiry refusal burned previous valid pending authority", err)
				}
				after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
				if err != nil || !after.IsMfaEnabled || after.AuthVersion != a.user.AuthVersion+1 {
					t.Fatal("previous enrollment did not retain exactly one legitimate enable", err)
				}
				return
			}
			// Retry is explicit after a known rollback, using the same restored SQL proof.
			replacement, err := normal.GenerateSetup(f.ctx, current, mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proof})
			if err != nil || replacement == nil || replacement.EnrollmentID == previous.EnrollmentID {
				t.Fatal("restored proof could not explicitly replace previous pending enrollment", err)
			}
			var pending, remainingProofs int
			if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM mfa_totp_enrollments WHERE user_id=$1),(SELECT count(*) FROM mfa_enrollment_action_proofs WHERE user_id=$1)`, a.user.ID).Scan(&pending, &remainingProofs); err != nil || pending != 1 || remainingProofs != 0 {
				t.Fatal("restored proof replacement was not atomic", err)
			}
			if after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID); err != nil || after.AuthVersion != a.user.AuthVersion || after.IsMfaEnabled {
				t.Fatal("pending replacement changed active authentication authority", err)
			}
		})
	}
}

func TestMFAConfirmationSQLDeadlineFenceCommitsOnlyExpiredCleanupIntegration(t *testing.T) {
	f := newRealPasswordFixture(t, true)
	a := f.account(t, "password_only", false)
	current, cookies := f.issue(t, a, session.MethodPassword)
	proofs, _ := mfaGapProofService(t, f, "sms")
	proof, _ := mfaGapIssueProof(t, f, proofs, a, current, "sms")
	setup, err := mfaGapService(t, f, f.pool, proofs).GenerateSetup(f.ctx, current, mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	var expiry time.Time
	if err := f.pool.QueryRow(f.ctx, `UPDATE mfa_totp_enrollments SET expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING expires_at`, uuid.MustParse(setup.EnrollmentID)).Scan(&expiry); err != nil {
		t.Fatal("shorten owned pending expiry fixture failed")
	}
	fault := &mfaStartWriteFault{pool: f.pool, stage: "confirm_expired", expiry: expiry}
	svc := mfaGapService(t, f, fault, proofs)
	recorder := &profileAuditRecorder{}
	deps := f.server.deps
	deps.MFA, deps.MFAEnrollmentProofs, deps.AuditRecorder = svc, proofs, recorder
	f.server = New(f.server.cfg, f.server.logger, deps)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	response := f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/verify", loginHTTPBody(t, map[string]string{"enrollment_id": setup.EnrollmentID, "code": code}), nil, http.StatusBadRequest)
	if errorBody(t, response) != "enrollment_expired" || response.Header().Get(session.HeaderAuthInvalidated) != "" || fault.begins != 1 || fault.confirmWrites != 1 || fault.pendingDeletes != 1 || fault.commits != 1 {
		t.Fatal("SQL-clock refusal did not commit only expired cleanup")
	}
	after, err := db.New(f.pool).GetUserByID(f.ctx, a.user.ID)
	if err != nil || after.IsMfaEnabled || len(after.MfaTotpSecretEncrypted) != 0 || after.AuthVersion != a.user.AuthVersion {
		t.Fatal("deadline crossed after Go fence promoted factor or revoked authority", err)
	}
	var pending int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_totp_enrollments WHERE user_id=$1`, a.user.ID).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("SQL-clock expired row cleanup rolled back", err)
	}
	for _, event := range recorder.events {
		if event.ActionStatus == audit.StatusSuccess {
			t.Fatal("SQL-clock rejected promotion emitted success audit")
		}
	}
}

// Each service keeps its own transaction owner. The barrier holds all three
// locks before application policy checks, so even a refused first writer races.
type mfaRaceDatabase struct {
	*pgxpool.Pool
	policy                  accountpolicy.Policy
	guardOnBegin            bool
	entered                 chan struct{}
	release                 <-chan struct{}
	lockAttempt             chan uint32
	barrierOnce             sync.Once
	begins, commits, active atomic.Int32
	badOrder                atomic.Bool
}

func (b *mfaRaceDatabase) Begin(ctx context.Context) (pgx.Tx, error) {
	return b.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (b *mfaRaceDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if !b.active.CompareAndSwap(0, 1) {
		b.badOrder.Store(true)
		return nil, errors.New("nested deciding transaction")
	}
	b.begins.Add(1)
	tx, err := b.Pool.BeginTx(ctx, options)
	if err != nil {
		b.active.Store(0)
		return nil, err
	}
	wrapped := &mfaRaceTx{Tx: tx, owner: b}
	// Phone storage does not consult password policy itself. Taking the shared
	// guard here precedes its real account/row locks without nesting a transaction.
	if b.guardOnBegin {
		if _, err := b.policy.Guard(ctx, wrapped); err != nil {
			_ = wrapped.Rollback(ctx)
			return nil, err
		}
	}
	return wrapped, nil
}

type mfaRaceTx struct {
	pgx.Tx
	owner                  *mfaRaceDatabase
	guarded, accountLocked bool
	closed                 atomic.Bool
}

func (tx *mfaRaceTx) Begin(context.Context) (pgx.Tx, error) {
	tx.owner.badOrder.Store(true)
	return nil, errors.New("nested deciding transaction")
}

func (tx *mfaRaceTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	accountLock := strings.Contains(sql, "pg_advisory_xact_lock")
	if accountLock {
		if !tx.guarded {
			tx.owner.badOrder.Store(true)
			return pgconn.CommandTag{}, errors.New("account lock preceded username guard")
		}
		if !tx.accountLocked && tx.owner.lockAttempt != nil {
			tx.owner.lockAttempt <- tx.Conn().PgConn().PID()
		}
	}
	tag, err := tx.Tx.Exec(ctx, sql, args...)
	if err == nil && accountLock {
		tx.accountLocked = true
	}
	return tag, err
}

func (tx *mfaRaceTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := tx.Tx.QueryRow(ctx, sql, args...)
	if strings.HasPrefix(sql, "-- name: LockUsernamePolicy ") {
		return mfaAfterScanRow{Row: row, after: func() error { tx.guarded = true; return nil }}
	}
	if !strings.HasPrefix(sql, "-- name: GetUserByIDForUpdate ") && !strings.HasPrefix(sql, "-- name: GetUserForUpdateIncludingDeleted ") {
		return row
	}
	return mfaAfterScanRow{Row: row, after: func() error {
		if !tx.guarded || !tx.accountLocked {
			tx.owner.badOrder.Store(true)
			return errors.New("user row lock preceded common guards")
		}
		var err error
		if tx.owner.entered != nil {
			tx.owner.barrierOnce.Do(func() {
				close(tx.owner.entered)
				select {
				case <-tx.owner.release:
				case <-ctx.Done():
					err = ctx.Err()
				}
			})
		}
		return err
	}}
}

func (tx *mfaRaceTx) Commit(ctx context.Context) error {
	err := tx.Tx.Commit(ctx)
	if err == nil {
		tx.owner.commits.Add(1)
	}
	if tx.closed.CompareAndSwap(false, true) {
		tx.owner.active.Store(0)
	}
	return err
}

func (tx *mfaRaceTx) Rollback(ctx context.Context) error {
	err := tx.Tx.Rollback(ctx)
	if tx.closed.CompareAndSwap(false, true) {
		tx.owner.active.Store(0)
	}
	return err
}

func mfaGapInstallRoleBaseline(t *testing.T, f *realPasswordFixture) {
	t.Helper()
	actions, err := adminaction.New(f.pool, f.cipher, "identity.audit.mfa-race", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = op.Rollback(context.WithoutCancel(f.ctx)) }()
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/mfa-race-policy"}
	baseline := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "mfa-race-fixture-only", Fixture: true, ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt, HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry}
	if err := legalpolicy.Install(f.ctx, op, baseline, "test"); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

// No public operator API grants arbitrary role names. This fixture exercises
// that database population through the same locked policy/audit boundary; it
// does not widen the production operator's supported-role allowlist.
func mfaGapOperatorMutation(ctx context.Context, f *realPasswordFixture, database *mfaRaceDatabase, id uuid.UUID, customRole string) error {
	var tx pgx.Tx
	var op *adminaction.Operation
	var err error
	if customRole == "" {
		tx, err = database.Begin(ctx)
	} else {
		actions, createErr := adminaction.New(database, f.cipher, "identity.audit.mfa-race", time.Hour)
		if createErr != nil {
			return createErr
		}
		op, err = actions.Begin(ctx)
		if err == nil {
			tx = op.Tx
		}
	}
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	guard, err := database.policy.Guard(ctx, tx)
	if err != nil {
		return err
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return err
	}
	q := db.New(tx)
	user, err := q.GetUserForUpdateIncludingDeleted(ctx, id)
	if err != nil {
		return err
	}
	if user.Status != "active" || user.DeletedAt.Valid {
		return session.ErrAccountIneligible
	}
	if customRole != "" {
		state, err := database.policy.Read(ctx, tx, user, guard)
		if err != nil {
			return err
		}
		state.Privileged = true
		if err := state.Check(); err != nil {
			return err
		}
		if err := q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: id, RoleID: customRole}); err != nil {
			return err
		}
	}
	if err := q.RevokeUserCredentials(ctx, id); err != nil {
		return err
	}
	if op == nil {
		return tx.Commit(ctx)
	}
	op.Event = audit.Event{EventType: "admin.role.granted", ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/mfa-custom-role", ActionStatus: audit.StatusSuccess,
		SubjectID: &id, Payload: map[string]any{"role_id": customRole, "noop": false}}
	ctx = adminaction.WithContext(ctx, op)
	if err := adminaction.SetDetails(ctx, struct {
		Target uuid.UUID `json:"target"`
	}{id}); err != nil {
		return err
	}
	return op.Commit(ctx)
}

func mfaGapSecondTOTPGrant(t *testing.T, f *realPasswordFixture, a realLoginAccount, current session.Session, cookies []*http.Cookie) string {
	t.Helper()
	now := time.Now()
	currentCode, err := totp.GenerateCode(a.totpSecret, now)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(a.totpSecret, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if code == currentCode {
		code, err = totp.GenerateCode(a.totpSecret, now.Add(-30*time.Second))
		if err != nil || code == currentCode {
			t.Fatal("distinct accepted TOTP steps unavailable", err)
		}
	}
	response := f.bound(t, current, cookies, http.MethodPost, stepUpVerifyPath, loginHTTPBody(t, map[string]string{"method": stepup.MethodTOTP, "code": code}), nil, http.StatusOK)
	var grant stepUpVerifyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &grant); err != nil || grant.Token == "" {
		t.Fatal("second independent TOTP step did not earn grant", err)
	}
	return grant.Token
}

func TestMFAMaintenanceOverlapsFencedAccountWritersBothOrdersIntegration(t *testing.T) {
	for _, mode := range []string{"start_password", "start_uv", "confirm_password", "confirm_uv", "disable_password", "disable_uv"} {
		t.Run(mode, func(t *testing.T) {
			f := newRealPasswordFixture(t, true)
			mfaGapInstallRoleBaseline(t, f)
			proofs, _ := mfaGapProofService(t, f, "sms")
			uv := strings.HasSuffix(mode, "_uv")
			startMode, confirmMode, disableMode := strings.HasPrefix(mode, "start_"), strings.HasPrefix(mode, "confirm_"), strings.HasPrefix(mode, "disable_")
			for _, writer := range []string{"password_remove", "passkey_remove", "contact_replace", "role_grant", "custom_role_grant", "version_revoke"} {
				// An unenrolled password-only account cannot earn the strong grant
				// required for password removal, and has no passkey to remove.
				if !uv && (writer == "passkey_remove" || !disableMode && writer == "password_remove") {
					continue
				}
				for _, ordering := range []string{"mfa_first", "writer_first"} {
					t.Run(writer+"/"+ordering, func(t *testing.T) {
						ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
						defer cancel()
						credential := "password_only"
						if uv {
							credential = "dual"
						}
						a := f.account(t, credential, disableMode)
						var authenticator *signupAuthenticator
						primary := session.MethodPassword
						if uv {
							authenticator = f.authenticator(t, a)
							primary = session.MethodPasskey
						}
						current, cookies := f.issue(t, a, primary)
						q := db.New(f.pool)
						var authorization mfa.Authorization
						if uv || disableMode {
							token := f.stepup(t, current, cookies, authenticator, a)
							grant, err := f.grants.Validate(ctx, token, current)
							if err != nil {
								t.Fatal(err)
							}
							method := mfa.AuthorizationTOTP
							if uv {
								method = mfa.AuthorizationWebAuthnUV
							}
							authorization = mfa.Authorization{UserID: grant.UserID, SessionID: grant.SessionID, JKT: grant.DPoPJKT, AuthVersion: grant.AuthVersion, Method: method, ExpiresAt: grant.ExpiresAt}
						} else {
							proof, _ := mfaGapIssueProof(t, f, proofs, a, current, "sms")
							authorization = mfa.Authorization{Method: mfa.AuthorizationPasswordContact, Proof: proof}
						}
						var pending *mfa.SetupResponse
						var pendingBefore db.MfaTotpEnrollment
						if confirmMode {
							var err error
							pending, err = mfaGapService(t, f, f.pool, proofs).GenerateSetup(ctx, current, authorization)
							if err != nil {
								t.Fatal(err)
							}
							pendingBefore, err = q.GetMfaTotpEnrollmentForUpdate(ctx, db.GetMfaTotpEnrollmentForUpdateParams{ID: uuid.MustParse(pending.EnrollmentID), UserID: a.user.ID, SessionID: uuid.MustParse(current.ID), Purpose: "maintenance"})
							if err != nil {
								t.Fatal(err)
							}
						}
						var passwordGrant *stepup.Grant
						if writer == "password_remove" {
							var token string
							if uv {
								token = f.stepup(t, current, cookies, authenticator, a)
							} else {
								token = mfaGapSecondTOTPGrant(t, f, a, current, cookies)
							}
							var err error
							passwordGrant, err = f.grants.Validate(ctx, token, current)
							if err != nil {
								t.Fatal(err)
							}
						}
						role := "support"
						if writer == "custom_role_grant" {
							role = "mfa-custom-" + uuid.NewString()
							if _, err := q.CreateRole(ctx, db.CreateRoleParams{ID: role, Description: "Fixture custom role"}); err != nil {
								t.Fatal(err)
							}
						}
						policy := accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names}
						releaseChannel := make(chan struct{})
						release := sync.OnceFunc(func() { close(releaseChannel) })
						first := &mfaRaceDatabase{Pool: f.pool, policy: policy, entered: make(chan struct{}), release: releaseChannel}
						second := &mfaRaceDatabase{Pool: f.pool, policy: policy, lockAttempt: make(chan uint32, 2)}
						mfaDB, writerDB := first, second
						if ordering == "writer_first" {
							mfaDB, writerDB = second, first
						}
						var workers sync.WaitGroup
						defer func() { release(); cancel(); workers.Wait() }()
						svc := mfaGapService(t, f, mfaDB, proofs)
						type result struct {
							setup   *mfa.SetupResponse
							changed bool
							err     error
						}
						mfaOperation := func() result {
							if startMode {
								setup, err := svc.GenerateSetup(ctx, current, authorization)
								return result{setup: setup, err: err}
							}
							if confirmMode {
								code, err := totp.GenerateCode(pending.Secret, time.Now())
								if err != nil {
									return result{err: err}
								}
								err = svc.VerifyAndEnable(ctx, current, pending.EnrollmentID, code)
								return result{changed: err == nil, err: err}
							}
							changed, err := svc.Disable(ctx, current, authorization)
							return result{changed: changed, err: err}
						}
						var writerOperation func() result
						switch writer {
						case "password_remove":
							service, err := passwordmanager.New(passwordmanager.Deps{DB: writerDB, Queries: q, Sessions: f.manager, Limiter: f.limiter, Policy: policy})
							if err != nil {
								t.Fatal(err)
							}
							writerOperation = func() result {
								changed, err := service.Mutate(ctx, current, "remove", "", passwordmanager.Authorization{Grant: passwordGrant}, "203.0.113.8")
								return result{changed: changed, err: err}
							}
						case "passkey_remove":
							credentials, err := q.ListWebauthnCredentialsByUser(ctx, a.user.ID)
							if err != nil || len(credentials) != 1 {
								t.Fatal("race requires exactly one passkey", err)
							}
							service, err := webauthn.New(webauthn.Config{RPID: "identity.example", RPDisplayName: "Identity", RPOrigins: []string{testPortalOrigin}, ChallengeTTL: time.Minute, MockChallengeKey: bytes.Repeat([]byte{0x67}, 32)}, q, q, webauthn.NewMemoryChallengeStore(), webauthn.WithTransacter(writerDB))
							if err != nil {
								t.Fatal(err)
							}
							service.SetAccountPolicy(policy)
							writerOperation = func() result {
								err := service.DeleteCredential(session.WithSession(ctx, current), a.user.ID, credentials[0].ID)
								return result{changed: err == nil, err: err}
							}
						case "contact_replace":
							writerDB.guardOnBegin = true
							users, err := smsotp.NewUserStore(writerDB, f.cipher)
							if err != nil {
								t.Fatal(err)
							}
							phone := "+989139876543"
							blob, err := f.cipher.Encrypt(ctx, []byte(phone))
							if err != nil {
								t.Fatal(err)
							}
							evidence, err := contactproof.Seal(ctx, f.cipher, a.user.ID, contactproof.Phone, phone, contactproof.SMSOTP, time.Now())
							if err != nil {
								t.Fatal(err)
							}
							writerOperation = func() result {
								err := users.SetPhoneIfCurrent(ctx, a.user.ID, current.AuthVersion, blob, phoneFakeIndexer{}.Compute(phone), evidence)
								return result{changed: err == nil, err: err}
							}
						case "role_grant":
							actions, err := adminaction.New(writerDB, f.cipher, "identity.audit.mfa-race", time.Hour)
							if err != nil {
								t.Fatal(err)
							}
							writerOperation = func() result {
								err := rbac.ProvisionRole(ctx, actions, uuid.New(), "spiffe://identity.test/mfa-role-race", a.user.ID, role, false, "test", policy)
								return result{changed: err == nil, err: err}
							}
						case "custom_role_grant", "version_revoke":
							custom := ""
							if writer == "custom_role_grant" {
								custom = role
							}
							writerOperation = func() result {
								err := mfaGapOperatorMutation(ctx, f, writerDB, a.user.ID, custom)
								return result{changed: err == nil, err: err}
							}
						}
						mfaResult, writerResult := make(chan result, 1), make(chan result, 1)
						firstOperation, nextOperation := mfaOperation, writerOperation
						firstResult, nextResult := mfaResult, writerResult
						if ordering == "writer_first" {
							firstOperation, nextOperation = writerOperation, mfaOperation
							firstResult, nextResult = writerResult, mfaResult
						}
						workers.Go(func() { firstResult <- firstOperation() })
						select {
						case <-first.entered:
						case r := <-firstResult:
							t.Fatalf("first writer missed lock barrier: %v", r.err)
						case <-ctx.Done():
							t.Fatal("first writer blocked before common lock barrier")
						}
						workers.Go(func() { nextResult <- nextOperation() })
						select {
						case pid := <-second.lockAttempt:
							waitCredentialRevocationLock(ctx, t, f.pool, pid)
						case <-ctx.Done():
							t.Fatal("contender did not acquire username guard and attempt account lock")
						}
						release()
						var mfaOutcome, writerOutcome result
						select {
						case mfaOutcome = <-mfaResult:
						case <-ctx.Done():
							t.Fatal("MFA deciding transaction deadlocked")
						}
						select {
						case writerOutcome = <-writerResult:
						case <-ctx.Done():
							t.Fatal("competing deciding transaction deadlocked")
						}
						workers.Wait()
						roleWriter := writer == "role_grant" || writer == "custom_role_grant"
						mfaSuccess := ordering == "mfa_first" || roleWriter && !uv && !disableMode
						writerSuccess := true
						if roleWriter && !uv && (startMode || ordering == "writer_first" && confirmMode || ordering == "mfa_first" && disableMode) {
							writerSuccess = false
						}
						if !roleWriter && writer != "version_revoke" && ordering == "mfa_first" && !startMode {
							writerSuccess = false
						}
						// Removing the only password never retains a usable primary, even with TOTP.
						if writer == "password_remove" && !uv {
							writerSuccess = false
							mfaSuccess = true
						}
						if (mfaOutcome.err == nil) != mfaSuccess || writerOutcome.changed != writerSuccess || (writerOutcome.err == nil) != writerSuccess || !mfaSuccess && mfaOutcome.setup != nil {
							t.Fatalf("ordered outcomes violate resulting policy: MFA=%v contender=%v", mfaOutcome.err, writerOutcome.err)
						}
						if !mfaSuccess && !errors.Is(mfaOutcome.err, mfa.ErrAccountNotActive) {
							t.Fatal("MFA admitted stale authority after competing commit", mfaOutcome.err)
						}
						if !writerSuccess && !errors.Is(writerOutcome.err, accountpolicy.ErrLastFactor) && !errors.Is(writerOutcome.err, accountpolicy.ErrLastCredential) && !errors.Is(writerOutcome.err, passwordmanager.ErrUnauthorized) && !errors.Is(writerOutcome.err, webauthn.ErrAccountNotActive) && !errors.Is(writerOutcome.err, smsotp.ErrStaleSession) {
							t.Fatal("competing writer failed outside invariant/version fence", writerOutcome.err)
						}
						if first.badOrder.Load() || second.badOrder.Load() || first.active.Load() != 0 || second.active.Load() != 0 || mfaDB.begins.Load() != 1 || mfaDB.commits.Load() != map[bool]int32{true: 1, false: 0}[mfaSuccess] {
							t.Fatal("MFA nested/retried a transaction or common lock order was violated")
						}
						final, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = final.Rollback(context.WithoutCancel(ctx)) }()
						guard, err := policy.Guard(ctx, final)
						if err != nil {
							t.Fatal(err)
						}
						if err := pglock.LockAccount(ctx, final, a.user.ID); err != nil {
							t.Fatal(err)
						}
						after, err := db.New(final).GetUserByIDForUpdate(ctx, a.user.ID)
						if err != nil {
							t.Fatal(err)
						}
						state, err := policy.Read(ctx, final, after, guard)
						if err != nil || state.Check() != nil {
							t.Fatal("race left unusable primary or unprotected role", err)
						}
						version := a.user.AuthVersion
						if mfaSuccess && !startMode {
							version++
						}
						if writerSuccess {
							version++
						}
						mfaEnabled := disableMode
						if mfaSuccess && !startMode {
							mfaEnabled = confirmMode
						}
						passkeys := int64(0)
						if uv {
							passkeys = 1
						}
						if writerSuccess && writer == "passkey_remove" {
							passkeys--
						}
						if after.AuthVersion != version || after.IsMfaEnabled != mfaEnabled || (len(after.MfaTotpSecretEncrypted) > 0) != mfaEnabled || state.Passkeys != passkeys || state.Password != !(writerSuccess && writer == "password_remove") || state.Privileged != (roleWriter && writerSuccess) {
							t.Fatal("race retained partial writes or extra version increments")
						}
						if writer == "contact_replace" && bytes.Equal(after.PhoneEncrypted, a.user.PhoneEncrypted) == writerSuccess {
							t.Fatal("contact race retained wrong encrypted destination")
						}
						var pendingCount, proofCount int
						if err := final.QueryRow(ctx, `SELECT (SELECT count(*) FROM mfa_totp_enrollments WHERE user_id=$1),(SELECT count(*) FROM mfa_enrollment_action_proofs WHERE user_id=$1)`, a.user.ID).Scan(&pendingCount, &proofCount); err != nil {
							t.Fatal(err)
						}
						wantPending := 0
						if startMode && mfaSuccess || confirmMode && !mfaSuccess {
							wantPending = 1
						}
						wantProof := 0
						if startMode && !uv && !mfaSuccess {
							wantProof = 1
						}
						if pendingCount != wantPending || proofCount != wantProof {
							t.Fatal("race partially consumed or replaced pending authorization")
						}
						if confirmMode && !mfaSuccess {
							row, err := db.New(final).GetMfaTotpEnrollmentForUpdate(ctx, db.GetMfaTotpEnrollmentForUpdateParams{ID: pendingBefore.ID, UserID: a.user.ID, SessionID: uuid.MustParse(current.ID), Purpose: "maintenance"})
							if err != nil || !reflect.DeepEqual(row, pendingBefore) {
								t.Fatal("stale confirmation burned or changed exact pending binding", err)
							}
						}
						if err := final.Commit(ctx); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		})
	}
}

func TestMFAIndependentSMSAndEmailChannelsCompleteEnrollmentAndDisableIntegration(t *testing.T) {
	for _, channel := range []string{"sms", "email"} {
		t.Run(channel+"_only", func(t *testing.T) {
			f := newRealPasswordFixture(t, true)
			a := f.account(t, "password_only", false)
			current, cookies := f.issue(t, a, session.MethodPassword)
			proofs, otherPurpose := mfaGapProofService(t, f, channel)
			svc := mfaGapService(t, f, f.pool, proofs)
			recorder := &profileAuditRecorder{}
			deps := f.server.deps
			deps.MFA, deps.MFAEnrollmentProofs, deps.AuditRecorder = svc, proofs, recorder
			f.server = New(f.server.cfg, f.server.logger, deps)
			disabled := "email"
			if channel == "email" {
				disabled = "sms"
			}
			f.bound(t, current, cookies, http.MethodPost, mfaEnrollmentProofPath+"/challenge", loginHTTPBody(t, map[string]string{"password": a.secret, "channel": disabled}), nil, http.StatusServiceUnavailable)
			if f.delivery.calls != 0 || otherPurpose.calls != 0 {
				t.Fatal("disabled channel used another purpose's transport")
			}
			response := f.bound(t, current, cookies, http.MethodPost, mfaEnrollmentProofPath+"/challenge", loginHTTPBody(t, map[string]string{"password": a.secret, "channel": channel}), nil, http.StatusAccepted)
			var challenge struct {
				Challenge string    `json:"challenge"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &challenge); err != nil || challenge.Challenge == "" || challenge.ExpiresAt.IsZero() {
				t.Fatal("selected channel challenge did not return bounded authority", err)
			}
			if f.delivery.calls != 1 || otherPurpose.calls != 0 || f.codeStore.record.Purpose != contactcode.PurposeMFAEnrollment || f.codeStore.record.Channel != channel {
				t.Fatal("MFA enrollment did not use the dedicated selected-purpose sender exactly once")
			}
			if channel == "sms" && f.codeStore.record.Destination != a.phone {
				t.Fatal("SMS delivery lost exactly evidenced canonical phone")
			}
			response = f.bound(t, current, cookies, http.MethodPost, mfaEnrollmentProofPath+"/verify", loginHTTPBody(t, map[string]string{"challenge": challenge.Challenge, "code": f.delivery.last()}), nil, http.StatusOK)
			var proof struct {
				ActionProof string    `json:"action_proof"`
				ExpiresAt   time.Time `json:"expires_at"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &proof); err != nil || proof.ActionProof == "" || !proof.ExpiresAt.Equal(challenge.ExpiresAt) || len(response.Result().Cookies()) != 0 {
				t.Fatal("contact proof changed deadline or issued login authority", err)
			}
			response = f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/generate", "", http.Header{"X-Action-Proof": {proof.ActionProof}}, http.StatusOK)
			var setup mfa.SetupResponse
			if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil || len(setup.Secret) != 32 || !setup.ExpiresAt.Equal(proof.ExpiresAt) {
				t.Fatal("selected-channel setup lost frozen proof deadline", err)
			}
			q := db.New(f.pool)
			row, err := q.GetMfaTotpEnrollmentForUpdate(f.ctx, db.GetMfaTotpEnrollmentForUpdateParams{ID: uuid.MustParse(setup.EnrollmentID), UserID: a.user.ID, SessionID: uuid.MustParse(current.ID), Purpose: "maintenance"})
			if err != nil {
				t.Fatal(err)
			}
			if row.AuthVersion == nil || *row.AuthVersion != current.AuthVersion || row.Jkt == nil || *row.Jkt != current.DPoPJKT || row.AuthorizationMethod == nil || *row.AuthorizationMethod != mfa.AuthorizationPasswordContact || row.Channel == nil || *row.Channel != channel || len(row.ContactBinding) != 32 || bytes.Contains(row.SecretEncrypted, []byte(setup.Secret)) {
				t.Fatal("selected-channel setup stored incomplete bindings or plaintext secret")
			}
			digest := sha256.Sum256([]byte(proof.ActionProof))
			var proofCount int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_enrollment_action_proofs WHERE proof_digest=$1`, digest[:]).Scan(&proofCount); err != nil || proofCount != 0 {
				t.Fatal("selected-channel proof was not consumed in pending transaction", err)
			}
			wrong := wrongMFAHTTPCode(t, setup.Secret, time.Now())
			f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/verify", loginHTTPBody(t, map[string]string{"enrollment_id": setup.EnrollmentID, "code": wrong}), nil, http.StatusBadRequest)
			var attempts int32
			if err := f.pool.QueryRow(f.ctx, `SELECT failed_attempts FROM mfa_totp_enrollments WHERE id=$1`, row.ID).Scan(&attempts); err != nil || attempts != 1 {
				t.Fatal("selected-channel wrong-code error rolled back attempt", err)
			}
			reader, err := actionproof.NewMFAEnrollment(actionproof.Config{BindingKey: bytes.Repeat([]byte{0x71}, 32)}, actionproof.Deps{DB: f.pool, Queries: q, Cipher: f.cipher, Sessions: f.manager})
			if err != nil {
				t.Fatal(err)
			}
			reader.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: true, Usernames: f.names})
			svc.SetEnrollmentProofs(reader)
			code, err := totp.GenerateCode(setup.Secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			response = f.bound(t, current, cookies, http.MethodPost, "/api/v1/auth/mfa/verify", loginHTTPBody(t, map[string]string{"enrollment_id": setup.EnrollmentID, "code": code}), nil, http.StatusOK)
			after, err := q.GetUserByID(f.ctx, a.user.ID)
			if err != nil || !after.IsMfaEnabled || after.AuthVersion != a.user.AuthVersion+1 || response.Header().Get(session.HeaderAuthInvalidated) != "true" {
				t.Fatal("provider-free selected-channel confirmation did not enable/invalidate once", err)
			}
			// Fresh active-TOTP Step-up, not the spent contact proof, authorizes removal.
			a.totpSecret = setup.Secret
			current, cookies = f.issue(t, a, session.MethodPassword)
			grant := f.stepup(t, current, cookies, nil, a)
			response = f.bound(t, current, cookies, http.MethodDelete, "/api/v1/auth/mfa", "", http.Header{stepup.HeaderStepUpAuth: {grant}}, http.StatusNoContent)
			after, err = q.GetUserByID(f.ctx, a.user.ID)
			if err != nil || after.IsMfaEnabled || len(after.MfaTotpSecretEncrypted) != 0 || after.AuthVersion != a.user.AuthVersion+2 || response.Header().Get(session.HeaderAuthInvalidated) != "true" {
				t.Fatal("selected-channel password-only factor removal failed guarded transaction", err)
			}
			var pendingCount int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mfa_totp_enrollments WHERE user_id=$1`, a.user.ID).Scan(&pendingCount); err != nil || pendingCount != 0 || f.delivery.calls != 1 || otherPurpose.calls != 0 {
				t.Fatal("terminal ceremony retained pending row or replayed delivery", err)
			}
			enabled, disabledEvents := 0, 0
			for _, event := range recorder.events {
				if event.ActionStatus != audit.StatusSuccess {
					continue
				}
				if event.EventType == audit.EventMFATOTPEnabled {
					enabled++
				}
				if event.EventType == audit.EventMFATOTPDisabled {
					disabledEvents++
				}
			}
			if enabled != 1 || disabledEvents != 1 {
				t.Fatal("selected-channel full transaction did not audit each real factor change exactly once")
			}
		})
	}
}
