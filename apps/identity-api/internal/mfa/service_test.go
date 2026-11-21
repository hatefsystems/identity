package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type fakeUserStore struct {
	users       map[uuid.UUID]db.User
	enrollments map[uuid.UUID]db.MfaTotpEnrollment
	passkeys    int64
	beforeLock  func()
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
		ID:              uuid.New(),
		UserID:          arg.UserID,
		SessionID:       arg.SessionID,
		Purpose:         arg.Purpose,
		SecretEncrypted: arg.SecretEncrypted,
		ExpiresAt:       arg.ExpiresAt,
		CreatedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
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
	encryptErr error
	decryptErr error
}

func (f *fakeEncryptor) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	if f.encryptErr != nil {
		return nil, f.encryptErr
	}
	// Prefix with mock_enc_
	return append([]byte("mock_enc_"), plaintext...), nil
}

func (f *fakeEncryptor) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	if len(ciphertext) < 9 || string(ciphertext[:9]) != "mock_enc_" {
		return nil, errors.New("bad mock ciphertext")
	}
	return ciphertext[9:], nil
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
	return svc, store, enc, user
}

func TestGenerateSetupHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sessionID := uuid.NewString()
	resp, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
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

	_, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, uuid.NewString())
	if !errors.Is(err, ErrMfaAlreadyEnabled) {
		t.Errorf("expected ErrMfaAlreadyEnabled, got %v", err)
	}
}

func TestVerifyAndEnableHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sessionID := uuid.NewString()
	setupResp, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, err := totp.GenerateCode(setupResp.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, setupResp.EnrollmentID, code); err != nil {
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

	sessionID := uuid.NewString()
	setupResp, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	err = svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, setupResp.EnrollmentID, "000000")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestVerifyAndEnableIsBoundToInitiatingSessionWithoutBurningEnrollment(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()
	initiatingSession := uuid.NewString()
	setup, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, initiatingSession)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	code, err := totp.GenerateCode(setup.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, uuid.NewString(), setup.EnrollmentID, code); !errors.Is(err, ErrMfaNotSetup) {
		t.Fatalf("foreign-session VerifyAndEnable = %v, want ErrMfaNotSetup", err)
	}
	enrollmentID, err := uuid.Parse(setup.EnrollmentID)
	if err != nil {
		t.Fatalf("Parse enrollment ID: %v", err)
	}
	if _, ok := store.enrollments[enrollmentID]; !ok {
		t.Fatal("foreign session burned the legitimate pending enrollment")
	}
	if err := svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, initiatingSession, setup.EnrollmentID, code); err != nil {
		t.Fatalf("legitimate VerifyAndEnable after foreign probe: %v", err)
	}
}

func TestVerifyAndEnableRejectsEnabledAccountBeforeInspectingPendingSecret(t *testing.T) {
	svc, store, encryptor, user := setupTestService()
	ctx := context.Background()
	sessionID := uuid.NewString()
	setup, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	u := store.users[user.ID]
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = []byte("active-secret-ciphertext")
	store.users[user.ID] = u
	encryptor.decryptErr = errors.New("decrypt must not be called")

	err = svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, setup.EnrollmentID, "123456")
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

	sessionID := uuid.NewString()
	setupResp, err := svc.GenerateSetup(ctx, user.ID, user.AuthVersion, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, _ := totp.GenerateCode(setupResp.Secret, now)
	if err := svc.VerifyAndEnable(ctx, user.ID, user.AuthVersion, sessionID, setupResp.EnrollmentID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	// Verify code when enabled
	if err := svc.VerifyEnabledCode(ctx, user.ID, code); err != nil {
		t.Fatalf("VerifyEnabledCode: %v", err)
	}

	// The previous authentication cannot authorize another security change.
	if err := svc.Disable(ctx, user.ID, user.AuthVersion); !errors.Is(err, ErrAccountNotActive) {
		t.Fatalf("old authority survived enrollment: %v", err)
	}
	// Disable with fresh authentication at the committed version.
	if err := svc.Disable(ctx, user.ID, store.users[user.ID].AuthVersion); err != nil {
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
	if err := svc.Disable(ctx, user.ID, disabledUser.AuthVersion); err != nil || store.users[user.ID].AuthVersion != disabledUser.AuthVersion {
		t.Fatal("absent TOTP disable changed authority")
	}

	// Verify code after disable should fail
	err = svc.VerifyEnabledCode(ctx, user.ID, code)
	if !errors.Is(err, ErrMfaNotSetup) {
		t.Errorf("expected ErrMfaNotSetup, got %v", err)
	}
}

func TestTOTPDisableStillRequiresPasskey(t *testing.T) {
	svc, store, _, user := setupTestService()
	u := user
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = []byte("configured-secret")
	store.users[u.ID] = u
	store.passkeys = 0
	if err := svc.Disable(t.Context(), u.ID, u.AuthVersion); !errors.Is(err, ErrLastFactor) {
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
	err := svc.runInTx(t.Context(), user.ID, func(UserStore, pgx.Tx, username.GuardAuthority) error {
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
				sessionID := uuid.NewString()
				setup, err := svc.GenerateSetup(t.Context(), user.ID, user.AuthVersion, sessionID)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "disable" {
					u := store.users[user.ID]
					u.IsMfaEnabled, u.MfaTotpSecretEncrypted = true, []byte("active-secret")
					store.users[user.ID] = u
				}
				admittedVersion := user.AuthVersion
				store.beforeLock = func() {
					u := store.users[user.ID]
					switch state {
					case "revoked":
						u.AuthVersion++
					case "deleted":
						u.DeletedAt.Valid = true
					case "suspended":
						u.Status = "suspended"
					case "negative_version":
						admittedVersion = -1
					}
					store.users[user.ID] = u
				}
				if state == "negative_version" {
					admittedVersion = -1
				}
				encryptor.decryptErr = errors.New("must not inspect pending secret")
				switch operation {
				case "setup":
					var result *SetupResponse
					result, err = svc.GenerateSetup(t.Context(), user.ID, admittedVersion, sessionID)
					if result != nil {
						t.Fatal("refused setup returned a secret")
					}
				case "enable":
					err = svc.VerifyAndEnable(t.Context(), user.ID, admittedVersion, sessionID, setup.EnrollmentID, "123456")
				case "disable":
					err = svc.Disable(t.Context(), user.ID, admittedVersion)
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
