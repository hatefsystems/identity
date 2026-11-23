package mfa

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type fakeUserStore struct {
	users       map[uuid.UUID]db.User
	enrollments map[uuid.UUID]db.MfaTotpEnrollment
	passkeys    int64
	beforeLock  func()
	beforeCount func()
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		users:       make(map[uuid.UUID]db.User),
		enrollments: make(map[uuid.UUID]db.MfaTotpEnrollment),
		passkeys:    1,
	}
}

func (f *fakeUserStore) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	if f.beforeLock != nil {
		f.beforeLock()
	}
	return f.GetUserByID(ctx, id)
}

func (f *fakeUserStore) CountWebauthnCredentialsByUser(context.Context, uuid.UUID) (int64, error) {
	if f.beforeCount != nil {
		f.beforeCount()
	}
	return f.passkeys, nil
}

func (f *fakeUserStore) RevokeUserCredentials(_ context.Context, id uuid.UUID) error {
	u := f.users[id]
	u.AuthVersion++
	f.users[id] = u
	return nil
}

func (f *fakeUserStore) DeleteMfaTotpEnrollmentsForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	for id, enrollment := range f.enrollments {
		if enrollment.UserID == userID {
			delete(f.enrollments, id)
			count++
		}
	}
	return count, nil
}

func (f *fakeUserStore) CreateMfaTotpEnrollment(_ context.Context, arg db.CreateMfaTotpEnrollmentParams) (db.MfaTotpEnrollment, error) {
	row := db.MfaTotpEnrollment{
		ID:                  uuid.New(),
		UserID:              arg.UserID,
		SessionID:           arg.SessionID,
		Purpose:             arg.Purpose,
		SecretEncrypted:     arg.SecretEncrypted,
		ExpiresAt:           arg.ExpiresAt,
		AuthVersion:         arg.AuthVersion,
		Jkt:                 arg.Jkt,
		AuthorizationMethod: arg.AuthorizationMethod,
		Channel:             arg.Channel,
		ContactBinding:      append([]byte(nil), arg.ContactBinding...),
		CreatedAt:           pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}
	f.enrollments[row.ID] = row
	return row, nil
}

func (f *fakeUserStore) GetMfaTotpEnrollmentForUpdate(_ context.Context, arg db.GetMfaTotpEnrollmentForUpdateParams) (db.MfaTotpEnrollment, error) {
	row, ok := f.enrollments[arg.ID]
	if !ok || row.UserID != arg.UserID || row.SessionID != arg.SessionID || row.Purpose != arg.Purpose {
		return db.MfaTotpEnrollment{}, pgx.ErrNoRows
	}
	return row, nil
}

func (f *fakeUserStore) IncrementMfaTotpEnrollmentAttempts(_ context.Context, id uuid.UUID) (int64, error) {
	row, ok := f.enrollments[id]
	if !ok {
		return 0, nil
	}
	row.FailedAttempts++
	f.enrollments[id] = row
	return 1, nil
}

func (f *fakeUserStore) DeleteMfaTotpEnrollment(_ context.Context, id uuid.UUID) (int64, error) {
	if _, ok := f.enrollments[id]; !ok {
		return 0, nil
	}
	delete(f.enrollments, id)
	return 1, nil
}

func (f *fakeUserStore) CompleteMfaTotpEnrollment(_ context.Context, arg db.CompleteMfaTotpEnrollmentParams) (int64, error) {
	u, ok := f.users[arg.ID]
	if !ok || u.IsMfaEnabled {
		return 0, nil
	}
	u.MfaTotpSecretEncrypted = arg.MfaTotpSecretEncrypted
	u.IsMfaEnabled = true
	f.users[arg.ID] = u
	return 1, nil
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

// GetUserByIDForAdmin mirrors the soft-delete-blind query used by
// VerifyTOTPForReclaim. The fake stores rows in one map regardless of deleted_at,
// so it behaves the same as GetUserByID here; the distinction that matters for the
// reclaim tests is the status gate, not the deleted_at filter.
func (f *fakeUserStore) GetUserByIDForAdmin(_ context.Context, id uuid.UUID) (db.User, error) {
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeUserStore) SetMfaTotpSecret(_ context.Context, arg db.SetMfaTotpSecretParams) (int64, error) {
	u, ok := f.users[arg.ID]
	if !ok {
		return 0, nil
	}
	u.MfaTotpSecretEncrypted = arg.MfaTotpSecretEncrypted
	f.users[arg.ID] = u
	return 1, nil
}

func (f *fakeUserStore) EnableMfa(_ context.Context, id uuid.UUID) (int64, error) {
	u, ok := f.users[id]
	if !ok || len(u.MfaTotpSecretEncrypted) == 0 {
		return 0, nil
	}
	u.IsMfaEnabled = true
	f.users[id] = u
	return 1, nil
}

func (f *fakeUserStore) DisableMfa(_ context.Context, id uuid.UUID) (int64, error) {
	u, ok := f.users[id]
	if !ok {
		return 0, nil
	}
	u.IsMfaEnabled = false
	u.MfaTotpSecretEncrypted = nil
	f.users[id] = u
	return 1, nil
}

type fakeEncryptor struct {
	encryptErr    error
	decryptErr    error
	beforeDecrypt func()
	decrypts      int
}

func (f *fakeEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	if f.encryptErr != nil {
		return nil, f.encryptErr
	}
	// Prefix with mock_enc_
	return append([]byte("mock_enc_"), plaintext...), nil
}

func (f *fakeEncryptor) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	f.decrypts++
	if f.beforeDecrypt != nil {
		f.beforeDecrypt()
	}
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	if len(ciphertext) < 9 || string(ciphertext[:9]) != "mock_enc_" {
		return nil, errors.New("bad mock ciphertext")
	}
	return append([]byte(nil), ciphertext[9:]...), nil
}

type fakeSessions struct {
	rows map[string]session.Session
	err  error
}

func (f *fakeSessions) LookupByID(_ context.Context, userID, sessionID string) (session.Session, error) {
	if f.err != nil {
		return session.Session{}, f.err
	}
	sess, ok := f.rows[sessionID]
	if !ok || sess.UserID != userID {
		return session.Session{}, session.ErrSessionNotFound
	}
	return sess, nil
}

func testSession(svc *Service, user db.User) session.Session {
	sess := session.Session{
		ID: uuid.NewString(), UserID: user.ID.String(), Kind: session.KindAuthenticated,
		AuthVersion: user.AuthVersion, AuthVersionSet: true,
		DPoPJKT:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		IdleExpiry: svc.now().Add(time.Hour), AbsoluteExpiry: svc.now().Add(2 * time.Hour),
	}
	svc.sessions.(*fakeSessions).rows[sess.ID] = sess
	return sess
}

func testAuthorization(svc *Service, sess session.Session, method string) Authorization {
	return Authorization{UserID: sess.UserID, SessionID: sess.ID, JKT: sess.DPoPJKT,
		AuthVersion: sess.AuthVersion, Method: method, ExpiresAt: svc.now().Add(5 * time.Minute)}
}

func setupTestService() (*Service, *fakeUserStore, *fakeEncryptor, db.User) {
	store := newFakeUserStore()
	enc := &fakeEncryptor{}
	user := db.User{
		ID:     uuid.New(),
		Email:  new("user@example.com"),
		Status: "active",
	}
	store.users[user.ID] = user

	svc, _ := New(Config{Issuer: "Hatef Test", WindowSteps: 1}, store, enc)
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	svc.SetSessions(&fakeSessions{rows: make(map[string]session.Session)})
	return svc, store, enc, user
}

func TestGenerateSetupHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sess := testSession(svc, user)
	resp, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	if len(resp.Secret) != 32 {
		t.Errorf("expected 32-char secret, got %q", resp.Secret)
	}
	if resp.Issuer != "Hatef Test" {
		t.Errorf("expected issuer Hatef Test, got %q", resp.Issuer)
	}
	if resp.AccountName != "user@example.com" {
		t.Errorf("expected account user@example.com, got %q", resp.AccountName)
	}

	storedUser := store.users[user.ID]
	if len(storedUser.MfaTotpSecretEncrypted) != 0 {
		t.Error("pending secret leaked onto the active user row")
	}
	if storedUser.IsMfaEnabled {
		t.Error("IsMfaEnabled should remain false until verification")
	}
}

func TestGenerateSetupAlreadyEnabled(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	u := store.users[user.ID]
	u.IsMfaEnabled = true
	store.users[user.ID] = u

	sess := testSession(svc, user)
	_, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if !errors.Is(err, ErrMfaAlreadyEnabled) {
		t.Errorf("expected ErrMfaAlreadyEnabled, got %v", err)
	}
}

func TestVerifyAndEnableHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sess := testSession(svc, user)
	setupResp, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, err := totp.GenerateCode(setupResp.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, sess, setupResp.EnrollmentID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	updatedUser := store.users[user.ID]
	if !updatedUser.IsMfaEnabled {
		t.Error("expected IsMfaEnabled to be true after verification")
	}
	if updatedUser.AuthVersion != user.AuthVersion+1 {
		t.Fatal("completed enrollment did not revoke exactly once")
	}
}

func TestVerifyAndEnableInvalidCode(t *testing.T) {
	svc, _, _, user := setupTestService()
	ctx := context.Background()

	sess := testSession(svc, user)
	setupResp, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	err = svc.VerifyAndEnable(ctx, sess, setupResp.EnrollmentID, wrongEnrollmentCode(t, setupResp.Secret, svc.now()))
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestVerifyAndEnableIsBoundToInitiatingSessionWithoutBurningEnrollment(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()
	initiatingSession := testSession(svc, user)
	setup, err := svc.GenerateSetup(ctx, initiatingSession, testAuthorization(svc, initiatingSession, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	code, err := totp.GenerateCode(setup.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	foreign := testSession(svc, user)
	if err := svc.VerifyAndEnable(ctx, foreign, setup.EnrollmentID, code); !errors.Is(err, ErrMfaNotSetup) {
		t.Fatalf("foreign-session VerifyAndEnable = %v, want ErrMfaNotSetup", err)
	}
	enrollmentID, err := uuid.Parse(setup.EnrollmentID)
	if err != nil {
		t.Fatalf("Parse enrollment ID: %v", err)
	}
	if _, ok := store.enrollments[enrollmentID]; !ok {
		t.Fatal("foreign session burned the legitimate pending enrollment")
	}
	if err := svc.VerifyAndEnable(ctx, initiatingSession, setup.EnrollmentID, code); err != nil {
		t.Fatalf("legitimate VerifyAndEnable after foreign probe: %v", err)
	}
}

func TestVerifyAndEnableRejectsEnabledAccountBeforeInspectingPendingSecret(t *testing.T) {
	svc, store, encryptor, user := setupTestService()
	ctx := context.Background()
	sess := testSession(svc, user)
	setup, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	u := store.users[user.ID]
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = []byte("active-secret-ciphertext")
	store.users[user.ID] = u
	encryptor.decryptErr = errors.New("decrypt must not be called")

	err = svc.VerifyAndEnable(ctx, sess, setup.EnrollmentID, "123456")
	if !errors.Is(err, ErrMfaAlreadyEnabled) {
		t.Fatalf("VerifyAndEnable = %v, want ErrMfaAlreadyEnabled", err)
	}
	if errors.Is(err, encryptor.decryptErr) {
		t.Fatal("enabled-account verification inspected a pending or active secret")
	}
}

func TestVerifyCodeAndDisable(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sess := testSession(svc, user)
	setupResp, err := svc.GenerateSetup(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, _ := totp.GenerateCode(setupResp.Secret, now)
	if err := svc.VerifyAndEnable(ctx, sess, setupResp.EnrollmentID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	// Verify code when enabled
	if err := svc.VerifyEnabledCode(ctx, user.ID, code); err != nil {
		t.Fatalf("VerifyEnabledCode: %v", err)
	}

	// The previous authentication cannot authorize another security change.
	if _, err := svc.Disable(ctx, sess, testAuthorization(svc, sess, AuthorizationTOTP)); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("old authority survived enrollment: %v", err)
	}
	// Disable with fresh authentication at the committed version.
	sess = testSession(svc, store.users[user.ID])
	if changed, err := svc.Disable(ctx, sess, testAuthorization(svc, sess, AuthorizationTOTP)); err != nil || !changed {
		t.Fatalf("Disable: %v", err)
	}

	disabledUser := store.users[user.ID]
	if disabledUser.IsMfaEnabled {
		t.Error("expected IsMfaEnabled = false")
	}
	if len(disabledUser.MfaTotpSecretEncrypted) != 0 {
		t.Error("expected secret to be wiped after disable")
	}
	if disabledUser.AuthVersion != user.AuthVersion+2 {
		t.Fatal("factor disable did not revoke exactly once")
	}
	sess = testSession(svc, disabledUser)
	if changed, err := svc.Disable(ctx, sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV)); err != nil || changed || store.users[user.ID].AuthVersion != disabledUser.AuthVersion {
		t.Fatal("absent TOTP disable changed authority")
	}

	// Verify code after disable should fail
	err = svc.VerifyEnabledCode(ctx, user.ID, code)
	if !errors.Is(err, ErrMfaNotSetup) {
		t.Errorf("expected ErrMfaNotSetup, got %v", err)
	}
}

func TestTOTPDisableWithoutAuthoritativePasswordPolicyRejectsLastPrimary(t *testing.T) {
	svc, store, _, user := setupTestService()
	u := user
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = []byte("configured-secret")
	store.users[u.ID] = u
	store.passkeys = 0
	sess := testSession(svc, u)
	if changed, err := svc.Disable(t.Context(), sess, testAuthorization(svc, sess, AuthorizationTOTP)); !errors.Is(err, accountpolicy.ErrLastCredential) || changed {
		t.Fatalf("TOTP disable without passkey: %v", err)
	}
	if !store.users[u.ID].IsMfaEnabled || store.users[u.ID].AuthVersion != u.AuthVersion {
		t.Fatal("rejected TOTP removal wrote factor or version")
	}
}

func TestDatabaseMaintenanceCannotBypassTransaction(t *testing.T) {
	svc, _, _, user := setupTestService()
	svc.users = db.New(nil)
	called := false
	err := svc.runInTx(t.Context(), user.ID, func(context.Context, UserStore, pgx.Tx, username.GuardAuthority) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("database maintenance executed without transaction-bound policy")
	}
}

func TestMutationsFenceSessionBeforePendingOrFactorChanges(t *testing.T) {
	for _, operation := range []string{"setup", "enable", "disable"} {
		for _, state := range []string{"revoked", "deleted", "suspended", "negative_version"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				svc, store, encryptor, user := setupTestService()
				sess := testSession(svc, user)
				setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
				if err != nil {
					t.Fatal(err)
				}
				if operation == "disable" {
					u := store.users[user.ID]
					u.IsMfaEnabled, u.MfaTotpSecretEncrypted = true, []byte("active-secret")
					store.users[user.ID] = u
				}
				store.beforeLock = func() {
					u := store.users[user.ID]
					switch state {
					case "revoked":
						u.AuthVersion++
					case "deleted":
						u.DeletedAt.Valid = true
					case "suspended":
						u.Status = "suspended"
					}
					store.users[user.ID] = u
				}
				if state == "negative_version" {
					sess.AuthVersion = -1
				}
				encryptor.decryptErr = errors.New("must not inspect pending secret")
				switch operation {
				case "setup":
					var result *SetupResponse
					result, err = svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
					if result != nil {
						t.Fatal("refused setup returned a secret")
					}
				case "enable":
					err = svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456")
				case "disable":
					_, err = svc.Disable(t.Context(), sess, testAuthorization(svc, sess, AuthorizationTOTP))
				}
				if !errors.Is(err, ErrAccountNotActive) {
					t.Fatalf("mutation = %v", err)
				}
				pending := store.enrollments[uuid.MustParse(setup.EnrollmentID)]
				if len(store.enrollments) != 1 || pending.ID.String() != setup.EnrollmentID || pending.FailedAttempts != 0 {
					t.Fatal("refused mutation replaced, deleted or burned pending enrollment")
				}
				if store.users[user.ID].IsMfaEnabled != (operation == "disable") {
					t.Fatal("refused mutation changed active factor")
				}
			})
		}
	}
}

func wrongEnrollmentCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	for _, code := range []string{"000000", "111111", "222222", "333333"} {
		if !totp.ValidateCode(secret, code, now, 1) {
			return code
		}
	}
	t.Fatal("no invalid code outside the three-step window")
	return ""
}

func TestGenerateSetupFreezesEarliestDeadlineAndBinding(t *testing.T) {
	for _, earliest := range []string{"configured", "authorization", "session_idle", "session_absolute", "live_idle", "live_absolute"} {
		t.Run(earliest, func(t *testing.T) {
			svc, store, _, user := setupTestService()
			sess := testSession(svc, user)
			auth := testAuthorization(svc, sess, AuthorizationWebAuthnUV)
			auth.ExpiresAt = svc.now().Add(30 * time.Minute)
			want := svc.now().Add(2 * time.Minute)
			live := sess
			switch earliest {
			case "configured":
				svc.enrollmentTTL = 2 * time.Minute
			case "authorization":
				auth.ExpiresAt = want
			case "session_idle":
				sess.IdleExpiry = want
			case "session_absolute":
				sess.AbsoluteExpiry = want
			case "live_idle":
				live.IdleExpiry = want
			case "live_absolute":
				live.AbsoluteExpiry = want
			}
			svc.sessions.(*fakeSessions).rows[sess.ID] = live
			setup, err := svc.GenerateSetup(t.Context(), sess, auth)
			if err != nil {
				t.Fatal(err)
			}
			row := store.enrollments[uuid.MustParse(setup.EnrollmentID)]
			if !setup.ExpiresAt.Equal(want) || !row.ExpiresAt.Time.Equal(want) || row.AuthVersion == nil || *row.AuthVersion != sess.AuthVersion || row.Jkt == nil || *row.Jkt != sess.DPoPJKT || row.AuthorizationMethod == nil || *row.AuthorizationMethod != AuthorizationWebAuthnUV || row.Channel != nil || len(row.ContactBinding) != 0 {
				t.Fatal("setup did not persist the exact earliest deadline and strong binding")
			}
			// Renewal and explicit replacement under the same original authorization
			// cannot manufacture additional freshness.
			sess.IdleExpiry, sess.AbsoluteExpiry = svc.now().Add(time.Hour), svc.now().Add(2*time.Hour)
			svc.sessions.(*fakeSessions).rows[sess.ID] = sess
			if earliest == "authorization" {
				replacement, err := svc.GenerateSetup(t.Context(), sess, auth)
				if err != nil || !replacement.ExpiresAt.Equal(want) {
					t.Fatal("replacement extended original authorization deadline", err)
				}
				if _, exists := store.enrollments[row.ID]; exists {
					t.Fatal("replacement retained superseded enrollment")
				}
				setup = replacement
			}
			svc.now = func() time.Time { return want }
			if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456"); !errors.Is(err, ErrEnrollmentExpired) {
				t.Fatal("renewal extended the frozen pending deadline", err)
			}
			if len(store.enrollments) != 0 || store.users[user.ID].AuthVersion != user.AuthVersion {
				t.Fatal("expired enrollment cleanup changed account authority")
			}
		})
	}
}

func TestGenerateSetupRejectsExpiredAuthorizationAfterLockWait(t *testing.T) {
	svc, store, _, user := setupTestService()
	sess := testSession(svc, user)
	auth := testAuthorization(svc, sess, AuthorizationWebAuthnUV)
	store.beforeLock = func() { svc.now = func() time.Time { return auth.ExpiresAt } }
	setup, err := svc.GenerateSetup(t.Context(), sess, auth)
	if setup != nil || !errors.Is(err, ErrUnauthorized) || len(store.enrollments) != 0 {
		t.Fatal("authorization crossed during lock wait published or persisted setup", err)
	}
}

func TestStrongAuthorizationBindingAndMethodAreRequired(t *testing.T) {
	for _, operation := range []string{"setup", "disable"} {
		for _, mutation := range []string{"subject", "session", "jkt", "version", "expired", "proof", "password", "email", "sms", "recovery", "incomplete_webauthn", "missing_reader"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				svc, store, _, user := setupTestService()
				sess := testSession(svc, user)
				auth := testAuthorization(svc, sess, AuthorizationWebAuthnUV)
				switch mutation {
				case "subject":
					auth.UserID = uuid.NewString()
				case "session":
					auth.SessionID = uuid.NewString()
				case "jkt":
					auth.JKT = base64.RawURLEncoding.EncodeToString([]byte("another-key"))
				case "version":
					auth.AuthVersion++
				case "expired":
					auth.ExpiresAt = svc.now()
				case "proof":
					auth.Proof = "not-strong-authority"
				case "password", "email", "sms", "recovery":
					auth.Method = mutation
				case "incomplete_webauthn":
					auth.Method = "hwk"
				case "missing_reader":
					svc.SetSessions(nil)
				}
				var err error
				if operation == "setup" {
					var setup *SetupResponse
					setup, err = svc.GenerateSetup(t.Context(), sess, auth)
					if setup != nil {
						t.Fatal("unauthorized setup returned secret")
					}
				} else {
					u := store.users[user.ID]
					u.IsMfaEnabled, u.MfaTotpSecretEncrypted = true, []byte("active-secret")
					store.users[user.ID] = u
					var changed bool
					changed, err = svc.Disable(t.Context(), sess, auth)
					if changed || !store.users[user.ID].IsMfaEnabled {
						t.Fatal("unauthorized disable changed factor")
					}
				}
				if !errors.Is(err, ErrUnauthorized) || len(store.enrollments) != 0 || store.users[user.ID].AuthVersion != user.AuthVersion {
					t.Fatal("weak or mismatched authority accepted", err)
				}
			})
		}
	}
}

func TestVerifyRejectsMissingOrMismatchedMetadataBeforeDecrypt(t *testing.T) {
	for _, mutation := range []string{"absent", "version", "jkt", "method", "channel", "contact", "missing_contact", "invalid_channel", "invalid_expiry", "infinite_expiry", "negative_attempts"} {
		t.Run(mutation, func(t *testing.T) {
			svc, store, enc, user := setupTestService()
			sess := testSession(svc, user)
			setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.MustParse(setup.EnrollmentID)
			row := store.enrollments[id]
			switch mutation {
			case "absent":
				row.AuthVersion, row.Jkt, row.AuthorizationMethod = nil, nil, nil
			case "version":
				row.AuthVersion = new(sess.AuthVersion + 1)
			case "jkt":
				row.Jkt = new("different-jkt")
			case "method":
				row.AuthorizationMethod = new(AuthorizationTOTP)
			case "channel":
				row.Channel = new("email")
			case "contact":
				row.ContactBinding = make([]byte, 32)
			case "missing_contact":
				row.AuthorizationMethod, row.Channel = new(AuthorizationPasswordContact), new("email")
			case "invalid_channel":
				row.AuthorizationMethod, row.Channel, row.ContactBinding = new(AuthorizationPasswordContact), new("other"), make([]byte, 32)
			case "invalid_expiry":
				row.ExpiresAt.Valid = false
			case "infinite_expiry":
				row.ExpiresAt.InfinityModifier = pgtype.Infinity
			case "negative_attempts":
				row.FailedAttempts = -1
			}
			store.enrollments[id] = row
			if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456"); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("invalid pending binding accepted", err)
			}
			if enc.decrypts != 0 || store.enrollments[id].FailedAttempts != row.FailedAttempts || store.users[user.ID].IsMfaEnabled || len(store.enrollments) != 1 {
				t.Fatal("invalid pending binding decrypted, burned or promoted material")
			}
		})
	}
}

func TestVerifyWrongJKTDoesNotBurnLegitimateEnrollment(t *testing.T) {
	svc, store, enc, user := setupTestService()
	sess := testSession(svc, user)
	setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatal(err)
	}
	foreign := sess
	key := make([]byte, 32)
	key[0] = 1
	foreign.DPoPJKT = base64.RawURLEncoding.EncodeToString(key)
	svc.sessions.(*fakeSessions).rows[sess.ID] = foreign
	if err := svc.VerifyAndEnable(t.Context(), foreign, setup.EnrollmentID, "123456"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign JKT accepted", err)
	}
	if enc.decrypts != 0 || store.enrollments[uuid.MustParse(setup.EnrollmentID)].FailedAttempts != 0 {
		t.Fatal("foreign JKT burned legitimate pending authority")
	}
	svc.sessions.(*fakeSessions).rows[sess.ID] = sess
	code, err := totp.GenerateCode(setup.Secret, svc.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, code); err != nil {
		t.Fatal("legitimate JKT cannot confirm after foreign probe", err)
	}
}

func TestEnrollmentAttemptBudgetAndExactGrammar(t *testing.T) {
	svc, store, enc, user := setupTestService()
	sess := testSession(svc, user)
	setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.MustParse(setup.EnrollmentID)
	for _, code := range []string{"", "12345", "1234567", " 123456", "123456 ", "12a456", "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6"} {
		if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, code); !errors.Is(err, ErrInvalidCode) {
			t.Fatal("malformed code accepted", err)
		}
	}
	if enc.decrypts != 0 || store.enrollments[id].FailedAttempts != 0 {
		t.Fatal("malformed codes spent attempts or decrypted secret")
	}
	wrong := wrongEnrollmentCode(t, setup.Secret, svc.now())
	for attempt := int32(1); attempt <= 5; attempt++ {
		if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, wrong); !errors.Is(err, ErrInvalidCode) {
			t.Fatal(err)
		}
		row, exists := store.enrollments[id]
		if attempt < 5 && (!exists || row.FailedAttempts != attempt) || attempt == 5 && exists {
			t.Fatalf("failed attempt %d did not persist exact budget transition", attempt)
		}
	}
	if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, wrong); !errors.Is(err, ErrMfaNotSetup) {
		t.Fatal("exhausted enrollment remained usable", err)
	}
	if store.users[user.ID].IsMfaEnabled || store.users[user.ID].AuthVersion != user.AuthVersion {
		t.Fatal("wrong codes changed active authority")
	}
}

func TestEnrollmentExpiryCrossedDuringDecryptDeletesWithoutEnable(t *testing.T) {
	svc, store, enc, user := setupTestService()
	sess := testSession(svc, user)
	setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(setup.Secret, svc.now())
	if err != nil {
		t.Fatal(err)
	}
	enc.beforeDecrypt = func() { svc.now = func() time.Time { return setup.ExpiresAt } }
	if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, code); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatal("late confirmation accepted", err)
	}
	if len(store.enrollments) != 0 || store.users[user.ID].IsMfaEnabled || store.users[user.ID].AuthVersion != user.AuthVersion {
		t.Fatal("late verification promoted secret or retained expired enrollment")
	}
}

func TestExpiredAndExhaustedEnrollmentCleanupPrecedesDecryption(t *testing.T) {
	for _, cause := range []string{"expired_during_lock", "preexisting_exhausted"} {
		t.Run(cause, func(t *testing.T) {
			svc, store, enc, user := setupTestService()
			sess := testSession(svc, user)
			setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.MustParse(setup.EnrollmentID)
			if cause == "expired_during_lock" {
				store.beforeLock = func() { svc.now = func() time.Time { return setup.ExpiresAt } }
			} else {
				row := store.enrollments[id]
				row.FailedAttempts = 5
				store.enrollments[id] = row
			}
			if err := svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456"); !errors.Is(err, ErrEnrollmentExpired) {
				t.Fatal("terminal enrollment accepted", err)
			}
			if enc.decrypts != 0 || len(store.enrollments) != 0 || store.users[user.ID].AuthVersion != user.AuthVersion {
				t.Fatal("terminal enrollment decrypted or changed active authority")
			}
		})
	}
}

func TestRawSessionRevalidationFailsClosedWithoutBurningEnrollment(t *testing.T) {
	for _, operation := range []string{"setup", "enable", "disable"} {
		for _, mutation := range []string{"missing", "reader_error", "subject", "session", "jkt", "version", "uncaptured", "restricted_kind", "idle_expired", "absolute_expired"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				svc, store, enc, user := setupTestService()
				sess := testSession(svc, user)
				setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
				if err != nil {
					t.Fatal(err)
				}
				if operation == "disable" {
					u := store.users[user.ID]
					u.IsMfaEnabled, u.MfaTotpSecretEncrypted = true, []byte("active-secret")
					store.users[user.ID] = u
				}
				reader := svc.sessions.(*fakeSessions)
				live := sess
				switch mutation {
				case "missing":
					delete(reader.rows, sess.ID)
				case "reader_error":
					reader.err = session.ErrStoreUnavailable
				case "subject":
					live.UserID = uuid.NewString()
				case "session":
					live.ID = uuid.NewString()
				case "jkt":
					live.DPoPJKT = "different-key"
				case "version":
					live.AuthVersion++
				case "uncaptured":
					live.AuthVersionSet = false
				case "restricted_kind":
					live.Kind = session.KindRecoveryEnrollment
				case "idle_expired":
					live.IdleExpiry = svc.now()
				case "absolute_expired":
					live.AbsoluteExpiry = svc.now()
				}
				if mutation != "missing" {
					reader.rows[sess.ID] = live
				}
				switch operation {
				case "setup":
					var result *SetupResponse
					result, err = svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
					if result != nil {
						t.Fatal("invalid raw session published setup")
					}
				case "enable":
					err = svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456")
				case "disable":
					_, err = svc.Disable(t.Context(), sess, testAuthorization(svc, sess, AuthorizationTOTP))
				}
				if err == nil || enc.decrypts != 0 || len(store.enrollments) != 1 || store.enrollments[uuid.MustParse(setup.EnrollmentID)].FailedAttempts != 0 || store.users[user.ID].AuthVersion != user.AuthVersion || store.users[user.ID].IsMfaEnabled != (operation == "disable") {
					t.Fatal("raw session failure decrypted or mutated authority", err)
				}
			})
		}
	}
}

func TestDisableAuthorizationExpiredDuringLockWaitDoesNotRemoveFactor(t *testing.T) {
	svc, store, _, user := setupTestService()
	user.IsMfaEnabled, user.MfaTotpSecretEncrypted = true, []byte("active-secret")
	store.users[user.ID] = user
	sess := testSession(svc, user)
	auth := testAuthorization(svc, sess, AuthorizationTOTP)
	store.beforeLock = func() { svc.now = func() time.Time { return auth.ExpiresAt } }
	if changed, err := svc.Disable(t.Context(), sess, auth); changed || !errors.Is(err, ErrUnauthorized) {
		t.Fatal("lock wait extended disable freshness", err)
	}
	if !store.users[user.ID].IsMfaEnabled || store.users[user.ID].AuthVersion != user.AuthVersion {
		t.Fatal("expired disable changed active factor")
	}
}

type frozenEnrollmentProofs struct {
	consumes, validates int
	validationErr       error
	beforeValidate      func()
	binding             actionproof.MFAEnrollmentAuthorization
}

func (f *frozenEnrollmentProofs) ConsumeMFAEnrollmentStartTx(context.Context, pgx.Tx, session.Session, string, username.GuardAuthority) (actionproof.MFAEnrollmentAuthorization, error) {
	f.consumes++
	return f.binding, nil
}

func (f *frozenEnrollmentProofs) ValidateMFAEnrollmentTx(_ context.Context, _ pgx.Tx, _ session.Session, binding actionproof.MFAEnrollmentAuthorization, _ username.GuardAuthority) error {
	f.validates++
	f.binding = binding
	if f.beforeValidate != nil {
		f.beforeValidate()
	}
	return f.validationErr
}

func TestPasswordContactConfirmationRevalidatesFrozenBindingWithoutReconsumingProof(t *testing.T) {
	for _, outcome := range []string{"revoked_contact", "expiry_during_validation", "denial_coincident_expiry"} {
		t.Run(outcome, func(t *testing.T) {
			svc, store, enc, user := setupTestService()
			sess := testSession(svc, user)
			setup, err := svc.GenerateSetup(t.Context(), sess, testAuthorization(svc, sess, AuthorizationWebAuthnUV))
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.MustParse(setup.EnrollmentID)
			row := store.enrollments[id]
			row.AuthorizationMethod, row.Channel, row.ContactBinding = new(AuthorizationPasswordContact), new("email"), make([]byte, 32)
			store.enrollments[id] = row
			proofs := &frozenEnrollmentProofs{validationErr: actionproof.ErrUnauthorized}
			if outcome != "revoked_contact" {
				proofs.beforeValidate = func() { svc.now = func() time.Time { return setup.ExpiresAt } }
			}
			if outcome == "expiry_during_validation" {
				proofs.validationErr = actionproof.ErrMFAEnrollmentExpired
			}
			svc.SetEnrollmentProofs(proofs)
			err = svc.VerifyAndEnable(t.Context(), sess, setup.EnrollmentID, "123456")
			want := actionproof.ErrUnauthorized
			if outcome == "expiry_during_validation" {
				want = ErrEnrollmentExpired
			}
			if !errors.Is(err, want) || proofs.consumes != 0 || proofs.validates != 1 || proofs.binding.Channel != "email" || !proofs.binding.ExpiresAt.Equal(setup.ExpiresAt) || len(proofs.binding.ContactBinding) != 32 || enc.decrypts != 0 {
				t.Fatal("frozen callback binding/expiry contract violated", err)
			}
			_, exists := store.enrollments[id]
			if exists != (outcome != "expiry_during_validation") || store.users[user.ID].IsMfaEnabled {
				t.Fatal("authorization refusal burned pending row or expiry retained it")
			}
		})
	}
}

func TestDisableRevalidatesRawSessionAfterPolicyRead(t *testing.T) {
	for _, change := range []string{"revoked", "idle_expired", "absolute_expired", "version_changed", "jkt_changed"} {
		t.Run(change, func(t *testing.T) {
			svc, store, _, user := setupTestService()
			user.IsMfaEnabled, user.MfaTotpSecretEncrypted = true, []byte("active-secret")
			store.users[user.ID] = user
			sess := testSession(svc, user)
			reader := svc.sessions.(*fakeSessions)
			store.beforeCount = func() {
				live := reader.rows[sess.ID]
				switch change {
				case "revoked":
					delete(reader.rows, sess.ID)
					return
				case "idle_expired":
					live.IdleExpiry = svc.now()
				case "absolute_expired":
					live.AbsoluteExpiry = svc.now()
				case "version_changed":
					live.AuthVersion++
				case "jkt_changed":
					live.DPoPJKT = "revoked-key"
				}
				reader.rows[sess.ID] = live
			}
			if changed, err := svc.Disable(t.Context(), sess, testAuthorization(svc, sess, AuthorizationTOTP)); changed || err == nil {
				t.Fatal("policy work outlived raw authority and still disabled factor", err)
			}
			if !store.users[user.ID].IsMfaEnabled || store.users[user.ID].AuthVersion != user.AuthVersion || len(store.users[user.ID].MfaTotpSecretEncrypted) == 0 {
				t.Fatal("expired or revoked final-write authority changed factor")
			}
		})
	}
}

type contextRecordingTransaction struct {
	pgx.Tx
	beginCtx     context.Context
	execContexts []context.Context
}

func (tx *contextRecordingTransaction) Begin(ctx context.Context) (pgx.Tx, error) {
	tx.beginCtx = ctx
	return tx, nil
}

func (tx *contextRecordingTransaction) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	tx.execContexts = append(tx.execContexts, ctx)
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (*contextRecordingTransaction) Commit(context.Context) error   { return nil }
func (*contextRecordingTransaction) Rollback(context.Context) error { return nil }

func TestTransactionCorePassesBoundedChildContextToDependencies(t *testing.T) {
	svc, _, _, user := setupTestService()
	tx := &contextRecordingTransaction{}
	svc.tx = tx
	parent := context.Background()
	var operationContext context.Context
	if err := svc.runInTx(parent, user.ID, func(ctx context.Context, _ UserStore, _ pgx.Tx, _ username.GuardAuthority) error {
		operationContext = ctx
		deadline, bounded := ctx.Deadline()
		if !bounded || time.Until(deadline) > 10*time.Second || !deadline.After(time.Now()) {
			t.Fatal("transaction callback did not receive the bounded child deadline")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if operationContext == parent || operationContext != tx.beginCtx || len(tx.execContexts) != 2 {
		t.Fatal("transaction work escaped bounded child context")
	}
	for _, ctx := range tx.execContexts {
		if ctx != operationContext {
			t.Fatal("transaction dependency used unbounded caller context")
		}
	}
	if !errors.Is(operationContext.Err(), context.Canceled) {
		t.Fatal("transaction child context survived completed operation")
	}
}
