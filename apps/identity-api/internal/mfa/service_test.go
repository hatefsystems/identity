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
)

type fakeUserStore struct {
	users       map[uuid.UUID]db.User
	enrollments map[uuid.UUID]db.MfaTotpEnrollment
	passkeys    int64
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		users:       make(map[uuid.UUID]db.User),
		enrollments: make(map[uuid.UUID]db.MfaTotpEnrollment),
		passkeys:    1,
	}
}

func (f *fakeUserStore) GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error) {
	return f.GetUserByID(ctx, id)
}

func (f *fakeUserStore) CountWebauthnCredentialsByUser(context.Context, uuid.UUID) (int64, error) {
	return f.passkeys, nil
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
		Email:  "user@example.com",
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
	resp, err := svc.GenerateSetup(ctx, user.ID, sessionID)
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

	_, err := svc.GenerateSetup(ctx, user.ID, uuid.NewString())
	if !errors.Is(err, ErrMfaAlreadyEnabled) {
		t.Errorf("expected ErrMfaAlreadyEnabled, got %v", err)
	}
}

func TestVerifyAndEnableHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	sessionID := uuid.NewString()
	setupResp, err := svc.GenerateSetup(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, err := totp.GenerateCode(setupResp.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, user.ID, sessionID, setupResp.EnrollmentID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	updatedUser := store.users[user.ID]
	if !updatedUser.IsMfaEnabled {
		t.Error("expected IsMfaEnabled to be true after verification")
	}
}

func TestVerifyAndEnableInvalidCode(t *testing.T) {
	svc, _, _, user := setupTestService()
	ctx := context.Background()

	sessionID := uuid.NewString()
	setupResp, err := svc.GenerateSetup(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	err = svc.VerifyAndEnable(ctx, user.ID, sessionID, setupResp.EnrollmentID, "000000")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestVerifyAndEnableIsBoundToInitiatingSessionWithoutBurningEnrollment(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()
	initiatingSession := uuid.NewString()
	setup, err := svc.GenerateSetup(ctx, user.ID, initiatingSession)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	code, err := totp.GenerateCode(setup.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, user.ID, uuid.NewString(), setup.EnrollmentID, code); !errors.Is(err, ErrMfaNotSetup) {
		t.Fatalf("foreign-session VerifyAndEnable = %v, want ErrMfaNotSetup", err)
	}
	enrollmentID, err := uuid.Parse(setup.EnrollmentID)
	if err != nil {
		t.Fatalf("Parse enrollment ID: %v", err)
	}
	if _, ok := store.enrollments[enrollmentID]; !ok {
		t.Fatal("foreign session burned the legitimate pending enrollment")
	}
	if err := svc.VerifyAndEnable(ctx, user.ID, initiatingSession, setup.EnrollmentID, code); err != nil {
		t.Fatalf("legitimate VerifyAndEnable after foreign probe: %v", err)
	}
}

func TestVerifyAndEnableRejectsEnabledAccountBeforeInspectingPendingSecret(t *testing.T) {
	svc, store, encryptor, user := setupTestService()
	ctx := context.Background()
	sessionID := uuid.NewString()
	setup, err := svc.GenerateSetup(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}
	u := store.users[user.ID]
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = []byte("active-secret-ciphertext")
	store.users[user.ID] = u
	encryptor.decryptErr = errors.New("decrypt must not be called")

	err = svc.VerifyAndEnable(ctx, user.ID, sessionID, setup.EnrollmentID, "123456")
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
	setupResp, err := svc.GenerateSetup(ctx, user.ID, sessionID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, _ := totp.GenerateCode(setupResp.Secret, now)
	if err := svc.VerifyAndEnable(ctx, user.ID, sessionID, setupResp.EnrollmentID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	// Verify code when enabled
	if err := svc.VerifyEnabledCode(ctx, user.ID, code); err != nil {
		t.Fatalf("VerifyEnabledCode: %v", err)
	}

	// Disable MFA
	if err := svc.Disable(ctx, user.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	disabledUser := store.users[user.ID]
	if disabledUser.IsMfaEnabled {
		t.Error("expected IsMfaEnabled = false")
	}
	if len(disabledUser.MfaTotpSecretEncrypted) != 0 {
		t.Error("expected secret to be wiped after disable")
	}

	// Verify code after disable should fail
	err = svc.VerifyEnabledCode(ctx, user.ID, code)
	if !errors.Is(err, ErrMfaNotSetup) {
		t.Errorf("expected ErrMfaNotSetup, got %v", err)
	}
}
