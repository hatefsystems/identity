//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
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
				pending, err := initialMFA.GenerateSetup(ctx, user.ID, user.AuthVersion, current.ID)
				if err != nil {
					t.Fatal(err)
				}
				code, err := totp.GenerateCode(pending.Secret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if operation == "disable" {
					if err := initialMFA.VerifyAndEnable(ctx, user.ID, user.AuthVersion, current.ID, pending.EnrollmentID, code); err != nil {
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
				earlierGrant, _, err := earnedGrants.MintContext(ctx, stepup.MintParams{UserID: current.UserID, SessionID: current.ID, AuthVersion: current.AuthVersion, AuthVersionSet: true, DPoPJKT: current.DPoPJKT, AMR: []string{"webauthn"}})
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
					request.Header.Set(stepup.HeaderStepUpAuth, mintTestGrant(t, grants, current))
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
			sessionID := uuid.NewString()
			pending, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
			if err != nil {
				t.Fatal(err)
			}
			code, err := totp.GenerateCode(pending.Secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if operation == "disable" {
				if err := svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, pending.EnrollmentID, code); err != nil {
					t.Fatal(err)
				}
				user, err = q.GetUserByID(ctx, user.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := credentialSnapshot(ctx, t, pool, user.ID)
			svc, err = mfa.New(mfa.Config{}, q, &mfaTestEncryptor{}, mfa.WithTransacter(mfaRollbackBegin{pool}))
			if err != nil {
				t.Fatal(err)
			}
			if operation == "enable" {
				err = svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, pending.EnrollmentID, code)
			} else {
				err = svc.Disable(ctx, user.ID, user.AuthVersion)
			}
			if !errors.Is(err, errMfaForcedRollback) {
				t.Fatal("forced post-write rollback was not reached", err)
			}
			after, err := q.GetUserByID(ctx, user.ID)
			if err != nil || after.AuthVersion != user.AuthVersion || !reflect.DeepEqual(before, credentialSnapshot(ctx, t, pool, user.ID)) {
				t.Fatal("rolled-back MFA change retained partial factor, enrollment or authority writes")
			}
		})
	}
}
