package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
)

type fakeUserStore struct {
	users map[uuid.UUID]db.User
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		users: make(map[uuid.UUID]db.User),
	}
}

func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
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
		ID:    uuid.New(),
		Email: "user@example.com",
	}
	store.users[user.ID] = user

	svc, _ := New(Config{Issuer: "Hatef Test", WindowSteps: 1}, store, enc)
	return svc, store, enc, user
}

func TestGenerateSetupHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	resp, err := svc.GenerateSetup(ctx, user.ID)
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
	if len(storedUser.MfaTotpSecretEncrypted) == 0 {
		t.Error("expected encrypted secret stored on user row")
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

	_, err := svc.GenerateSetup(ctx, user.ID)
	if !errors.Is(err, ErrMfaAlreadyEnabled) {
		t.Errorf("expected ErrMfaAlreadyEnabled, got %v", err)
	}
}

func TestVerifyAndEnableHappyPath(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	setupResp, err := svc.GenerateSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, err := totp.GenerateCode(setupResp.Secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndEnable(ctx, user.ID, code); err != nil {
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

	_, err := svc.GenerateSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	err = svc.VerifyAndEnable(ctx, user.ID, "000000")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}
}

func TestVerifyCodeAndDisable(t *testing.T) {
	svc, store, _, user := setupTestService()
	ctx := context.Background()

	setupResp, err := svc.GenerateSetup(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateSetup: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	code, _ := totp.GenerateCode(setupResp.Secret, now)
	if err := svc.VerifyAndEnable(ctx, user.ID, code); err != nil {
		t.Fatalf("VerifyAndEnable: %v", err)
	}

	// Verify code when enabled
	if err := svc.VerifyCode(ctx, user.ID, code); err != nil {
		t.Fatalf("VerifyCode: %v", err)
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
	err = svc.VerifyCode(ctx, user.ID, code)
	if !errors.Is(err, ErrMfaNotSetup) {
		t.Errorf("expected ErrMfaNotSetup, got %v", err)
	}
}
