//go:build integration

package webauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type fixedRegistrationSessions struct{ live session.Session }

func (f fixedRegistrationSessions) LookupByID(_ context.Context, user, id string) (session.Session, error) {
	if user != f.live.UserID || id != f.live.ID {
		return session.Session{}, session.ErrSessionNotFound
	}
	return f.live, nil
}

// A real LOGIN role has only the enrollment reader/writer grants. Provisioning
// remains in the unique child database opened by the existing owned fixture.
func restrictedRegistrationPool(ctx context.Context, t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	name := "first_passkey_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := strings.ReplaceAll(uuid.NewString(), "-", "")
	role := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '"+password+"'"); err != nil {
		t.Fatal("create owned restricted login failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP OWNED BY "+role); err != nil {
			t.Error("restricted grants teardown failed")
		}
		if _, err := admin.Exec(cleanup, "DROP ROLE "+role); err != nil {
			t.Error("restricted role teardown failed")
		}
	})
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA public TO " + role,
		"GRANT SELECT ON users, webauthn_credentials, user_roles, username_active_policy, username_policy_artifacts, username_lookup_keys TO " + role,
		"GRANT UPDATE (webauthn_user_handle, auth_version, updated_at) ON users TO " + role,
		"GRANT UPDATE (singleton) ON username_active_policy TO " + role,
		"GRANT INSERT ON webauthn_credentials TO " + role,
		"GRANT USAGE ON SEQUENCE account_auth_epoch_seq TO " + role,
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal("restricted enrollment grants failed")
		}
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = name, password
	cfg.ConnConfig.RuntimeParams["application_name"] = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("restricted pool construction failed")
	}
	t.Cleanup(pool.Close)
	var user string
	var privileged bool
	if err := pool.QueryRow(ctx, "SELECT current_user, rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname=current_user").Scan(&user, &privileged); err != nil || user != name || privileged {
		t.Fatal("restricted login authority not established")
	}
	var excessive bool
	if err := pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,'webauthn_credentials','DELETE') OR has_column_privilege(current_user,'users','password_hash','UPDATE') OR has_table_privilege(current_user,'username_active_policy','INSERT')").Scan(&excessive); err != nil || excessive {
		t.Fatal("restricted login has unrelated mutation authority")
	}
	return pool
}

func registrationIntegrationContext(user db.User) (context.Context, fixedRegistrationSessions) {
	live := fixtureSession(user, "test-session", time.Now())
	ctx := session.WithSession(dpop.WithProof(context.Background(), &dpop.Proof{JKT: testBrowserJKT}), live)
	return ctx, fixedRegistrationSessions{live}
}

func beginIntegrationFirst(ctx context.Context, svc *Service, user db.User, deadline time.Time) (*protocol.CredentialCreation, time.Time, error) {
	return svc.BeginAuthorizedRegistration(ctx, user.ID, "test-session", "Frozen", RegistrationAuthorization{
		UserID: user.ID, SessionID: "test-session", DPoPJKT: testBrowserJKT, AuthVersion: user.AuthVersion, ExpiresAt: deadline,
	})
}

func TestIntegrationFirstRegistrationProtectedIdentityIndependentOfLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	policy := factorAccountPolicy(ctx, t, admin)
	pool := restrictedRegistrationPool(ctx, t, admin)
	q := db.New(admin)
	for i, existingHandle := range []bool{false, true} {
		id := createFactorIntegrationUser(ctx, t, admin, "first-identity")
		user, err := q.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		assignFactorUsername(ctx, t, admin, policy, user, i)
		if existingHandle {
			if _, err := q.SetWebauthnUserHandle(ctx, db.SetWebauthnUserHandleParams{ID: id, WebauthnUserHandle: []byte("12345678")}); err != nil {
				t.Fatal(err)
			}
		}
		if existingHandle {
			if _, err := admin.Exec(ctx, "UPDATE users SET is_mfa_enabled=true,mfa_totp_secret_encrypted=$2 WHERE id=$1", id, []byte("strong-factor-fixture")); err != nil {
				t.Fatal(err)
			}
			role := "first-strong-" + uuid.NewString()
			if _, err := admin.Exec(ctx, "INSERT INTO roles(id,description) VALUES($1,'first strong fixture')", role); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(ctx, "INSERT INTO user_roles(user_id,role_id) VALUES($1,$2)", id, role); err != nil {
				t.Fatal(err)
			}
		}
		user, err = q.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		request, sessions := registrationIntegrationContext(user)
		svc := newFactorIntegrationWebAuthn(t, db.New(pool), pool)
		svc.SetAccountPolicy(accountpolicy.Policy{PasswordLoginEnabled: false})
		svc.SetFirstPasskeyDependencies(nil, sessions, policy.Usernames)
		options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Repeat("\u0633", i+1)
		if options.Response.User.Name != want || options.Response.User.DisplayName != want {
			t.Fatal("protected display depended on login/email/cosmetic label")
		}
		before, err := q.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before.WebauthnUserHandle, user.WebauthnUserHandle) || before.AuthVersion != user.AuthVersion {
			t.Fatal("options wrote handle/version")
		}
		auth := newSoftAuthenticator(t)
		auth.rpID, auth.origin = "identity.test", "https://identity.test"
		row, err := svc.FinishRegistration(request, id, "test-session", auth.attestation(challengeOf(options.Response.Challenge)))
		if err != nil || !row.UserVerified || !row.UserPresent {
			t.Fatal("first finish failed", err)
		}
		after, err := q.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if after.AuthVersion != user.AuthVersion+1 || after.LifecycleRevision != user.LifecycleRevision || !bytes.Equal(after.UsernameKey, user.UsernameKey) ||
			after.IsMfaEnabled != user.IsMfaEnabled || existingHandle && !bytes.Equal(after.WebauthnUserHandle, user.WebauthnUserHandle) {
			t.Fatal("first finish changed independent account state")
		}
		privileged, err := q.UserHasPrivilegedRole(ctx, id)
		if err != nil || privileged != existingHandle || !bytes.Equal(after.MfaTotpSecretEncrypted, user.MfaTotpSecretEncrypted) {
			t.Fatal("strong first enrollment changed role/MFA policy")
		}
	}
}

func TestIntegrationFirstRegistrationUnreadableUsernameFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	policy := factorAccountPolicy(ctx, t, admin)
	id := createFactorIntegrationUser(ctx, t, admin, "first-unreadable")
	user, err := db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	assignFactorUsername(ctx, t, admin, policy, user, 0)
	user, err = db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request, sessions := registrationIntegrationContext(user)
	svc := newFactorIntegrationWebAuthn(t, db.New(admin), admin)
	svc.SetFirstPasskeyDependencies(nil, sessions, nil)
	if options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute)); options != nil || !errors.Is(err, username.ErrUnavailable) {
		t.Fatal("unreadable protected identity fell back", err)
	}
}

type registrationFaultBeginner struct {
	pool  *pgxpool.Pool
	fault string
}

func (f registrationFaultBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &registrationFaultTx{Tx: tx, fault: f.fault}, nil
}

type registrationFaultTx struct {
	pgx.Tx
	fault string
}

func (f *registrationFaultTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := f.Tx.Exec(ctx, sql, args...)
	if err == nil && (f.fault == "handle" && strings.Contains(sql, "SET webauthn_user_handle") || f.fault == "revoke" && strings.Contains(sql, "SET auth_version = auth_version + 1")) {
		return tag, errBoom
	}
	return tag, err
}

func (f *registrationFaultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := f.Tx.QueryRow(ctx, sql, args...)
	if f.fault == "credential" && strings.Contains(sql, "INSERT INTO webauthn_credentials") {
		return registrationFaultRow{row}
	}
	return row
}

type registrationFaultRow struct{ pgx.Row }

func (r registrationFaultRow) Scan(dest ...any) error {
	if err := r.Row.Scan(dest...); err != nil {
		return err
	}
	return errBoom
}

func (f *registrationFaultTx) Commit(ctx context.Context) error {
	err := f.Tx.Commit(ctx)
	if err == nil && f.fault == "commit" {
		return errBoom
	}
	return err
}

func TestIntegrationFirstRegistrationRollbackAfterEveryWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	pool := restrictedRegistrationPool(ctx, t, admin)
	for _, fault := range []string{"handle", "credential", "revoke"} {
		t.Run(fault, func(t *testing.T) {
			id := createFactorIntegrationUser(ctx, t, admin, "first-rollback")
			user, err := db.New(admin).GetUserByID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			request, sessions := registrationIntegrationContext(user)
			svc := newFactorIntegrationWebAuthn(t, db.New(pool), pool)
			svc.SetFirstPasskeyDependencies(nil, sessions, nil)
			options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			svc.tx = registrationFaultBeginner{pool, fault}
			auth := newSoftAuthenticator(t)
			auth.rpID, auth.origin = "identity.test", "https://identity.test"
			if _, err := svc.FinishRegistration(request, id, "test-session", auth.attestation(challengeOf(options.Response.Challenge))); !errors.Is(err, errBoom) {
				t.Fatal("write fault did not surface", err)
			}
			after, err := db.New(admin).GetUserByID(ctx, id)
			count, countErr := db.New(admin).CountWebauthnCredentialsByUser(ctx, id)
			if err != nil || countErr != nil || len(after.WebauthnUserHandle) != 0 || count != 0 || after.AuthVersion != user.AuthVersion || after.LifecycleRevision != user.LifecycleRevision {
				t.Fatal("SQL rollback left partial state")
			}
			pending := svc.challenges.(*MemoryChallengeStore)
			if len(pending.firstSlots) != 1 {
				t.Fatal("rollback released slot")
			}
		})
	}
}

func TestIntegrationFirstRegistrationUnknownStartCommitPublishesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	pool := restrictedRegistrationPool(ctx, t, admin)
	id := createFactorIntegrationUser(ctx, t, admin, "first-commit")
	user, err := db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request, sessions := registrationIntegrationContext(user)
	svc := newFactorIntegrationWebAuthn(t, db.New(pool), registrationFaultBeginner{pool, "commit"})
	svc.SetFirstPasskeyDependencies(nil, sessions, nil)
	if options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute)); options != nil || !errors.Is(err, ErrRegistrationOutcomeUnknown) {
		t.Fatal("uncertain commit published options", err)
	}
	store := svc.challenges.(*MemoryChallengeStore)
	if len(store.byChallenge) != 0 || len(store.firstSlots) != 0 {
		t.Fatal("SQL commit uncertainty published pending authority")
	}
}

func TestIntegrationFirstRegistrationUnknownFinishCommitDoesNotReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	pool := restrictedRegistrationPool(ctx, t, admin)
	id := createFactorIntegrationUser(ctx, t, admin, "first-finish-commit")
	user, err := db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request, sessions := registrationIntegrationContext(user)
	svc := newFactorIntegrationWebAuthn(t, db.New(pool), pool)
	svc.SetFirstPasskeyDependencies(nil, sessions, nil)
	options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	svc.tx = registrationFaultBeginner{pool, "commit"}
	auth := newSoftAuthenticator(t)
	auth.rpID, auth.origin = "identity.test", "https://identity.test"
	body := auth.attestation(challengeOf(options.Response.Challenge))
	if _, err := svc.FinishRegistration(request, id, "test-session", body); !errors.Is(err, ErrRegistrationOutcomeUnknown) {
		t.Fatal("unknown finish commit was reported as definitive", err)
	}
	if _, err := svc.FinishRegistration(request, id, "test-session", body); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatal("unknown finish replayed authority", err)
	}
	after, err := db.New(admin).GetUserByID(ctx, id)
	count, countErr := db.New(admin).CountWebauthnCredentialsByUser(ctx, id)
	if err != nil || countErr != nil || count != 1 || len(after.WebauthnUserHandle) != userHandleByteLen || after.AuthVersion != user.AuthVersion+1 || after.LifecycleRevision != user.LifecycleRevision {
		t.Fatal("unknown finish was not one atomic security mutation")
	}
	if len(svc.challenges.(*MemoryChallengeStore).firstSlots) != 1 {
		t.Fatal("uncertain finish released account slot")
	}
}

func TestIntegrationFirstRegistrationGlobalCredentialCollisionRollsBackHandle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	pool := restrictedRegistrationPool(ctx, t, admin)
	id := createFactorIntegrationUser(ctx, t, admin, "first-global-collision")
	other := createFactorIntegrationUser(ctx, t, admin, "first-global-owner")
	user, err := db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request, sessions := registrationIntegrationContext(user)
	svc := newFactorIntegrationWebAuthn(t, db.New(pool), pool)
	svc.SetFirstPasskeyDependencies(nil, sessions, nil)
	options, _, err := beginIntegrationFirst(request, svc, user, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	auth := newSoftAuthenticator(t)
	auth.rpID, auth.origin = "identity.test", "https://identity.test"
	if _, err := db.New(admin).CreateWebauthnCredential(ctx, db.CreateWebauthnCredentialParams{ID: auth.credID, UserID: other, PublicKey: auth.coseKey(), AttestationType: "none", UserPresent: true, UserVerified: true, Aaguid: uuid.New()}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.FinishRegistration(request, id, "test-session", auth.attestation(challengeOf(options.Response.Challenge))); err == nil {
		t.Fatal("global credential collision accepted")
	}
	after, err := db.New(admin).GetUserByID(ctx, id)
	count, countErr := db.New(admin).CountWebauthnCredentialsByUser(ctx, id)
	if err != nil || countErr != nil || count != 0 || len(after.WebauthnUserHandle) != 0 || after.AuthVersion != user.AuthVersion {
		t.Fatal("global collision left partial account state")
	}
}

func TestIntegrationFirstRegistrationAccountLockOutlivesOriginalDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), factorIntegrationTimeout)
	defer cancel()
	admin := openFactorIntegrationPool(ctx, t)
	pool := restrictedRegistrationPool(ctx, t, admin)
	id := createFactorIntegrationUser(ctx, t, admin, "first-lock-expiry")
	user, err := db.New(admin).GetUserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request, sessions := registrationIntegrationContext(user)
	svc := newFactorIntegrationWebAuthn(t, db.New(pool), pool)
	svc.SetFirstPasskeyDependencies(nil, sessions, nil)
	options, deadline, err := beginIntegrationFirst(request, svc, user, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if err := username.AcquireOwnershipGuard(ctx, blocker); err != nil {
		t.Fatal(err)
	}
	if err := pglock.LockAccount(ctx, blocker, id); err != nil {
		t.Fatal(err)
	}
	auth := newSoftAuthenticator(t)
	auth.rpID, auth.origin = "identity.test", "https://identity.test"
	body := auth.attestation(challengeOf(options.Response.Challenge))
	result := make(chan error, 1)
	go func() { _, err := svc.FinishRegistration(request, id, "test-session", body); result <- err }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	waiting := false
	for !waiting {
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND wait_event='advisory')", pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if !waiting {
			select {
			case err := <-result:
				t.Fatal("finish did not wait on actual SQL account lock", err)
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	timer := time.NewTimer(time.Until(deadline.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("SQL account-lock waiter used transaction-start deadline")
	}
	after, err := db.New(admin).GetUserByID(ctx, id)
	count, countErr := db.New(admin).CountWebauthnCredentialsByUser(ctx, id)
	if err != nil || countErr != nil || count != 0 || len(after.WebauthnUserHandle) != 0 || after.AuthVersion != user.AuthVersion {
		t.Fatal("expired SQL waiter partially wrote account")
	}
}

type registrationWaitingUsers struct {
	UserStore
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *registrationWaitingUsers) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	f.once.Do(func() { close(f.reached) })
	select {
	case <-f.release:
		return f.UserStore.GetUserByIDForUpdate(ctx, id)
	case <-ctx.Done():
		return db.User{}, ctx.Err()
	}
}

func TestFirstRegistrationDeadlineRecheckedAfterDecidingWait(t *testing.T) {
	f := newFixture(t)
	options, err := f.beginRegistration(f.ctx(), f.user.ID, "test-session", "")
	if err != nil {
		t.Fatal(err)
	}
	waiting := &registrationWaitingUsers{UserStore: f.users, reached: make(chan struct{}), release: make(chan struct{})}
	f.svc.users = waiting
	result := make(chan error, 1)
	request := f.ctx()
	go func() {
		_, err := f.svc.FinishRegistration(request, f.user.ID, "test-session", f.auth.attestation(challengeOf(options.Response.Challenge)))
		result <- err
	}()
	<-waiting.reached
	f.advance(f.svc.challengeTTL)
	close(waiting.release)
	if err := <-result; err == nil {
		t.Fatal("deadline from before lock wait accepted")
	}
	if len(f.handle(t)) != 0 || f.creds.count(f.user.ID) != 0 {
		t.Fatal("deadline waiter wrote account state")
	}
}
