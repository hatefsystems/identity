package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
)

// setupReclaimService returns a service whose account is soft-deleted with TOTP
// already enabled, plus the current valid passcode.
//
// The secret is installed directly rather than driven through GenerateSetup /
// VerifyAndEnable, because those flows require an active account: the real sequence
// is "enable TOTP, then request deletion", and only the resulting state matters
// here.
func setupReclaimService(t *testing.T, status string) (*Service, *fakeUserStore, db.User, string) {
	t.Helper()

	svc, store, enc, user := setupTestService()

	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	encrypted, err := enc.Encrypt(context.Background(), []byte(secret))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	now := time.Now().UTC()
	svc.now = func() time.Time { return now }

	u := store.users[user.ID]
	u.Status = status
	u.IsMfaEnabled = true
	u.MfaTotpSecretEncrypted = encrypted
	store.users[user.ID] = u

	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return svc, store, u, code
}

func TestVerifyTOTPForReclaimAcceptsPendingDeletion(t *testing.T) {
	svc, _, user, code := setupReclaimService(t, "pending_deletion")

	if err := svc.VerifyTOTPForReclaim(context.Background(), user.ID, code); err != nil {
		t.Fatalf("VerifyTOTPForReclaim: %v", err)
	}
}

// TestVerifyTOTPForReclaimRejectsEveryOtherStatus is the inverse of every other
// method in this package. An active account has no deletion to cancel, and accepting
// a suspended one would let moderation be undone through the privacy flow.
func TestVerifyTOTPForReclaimRejectsEveryOtherStatus(t *testing.T) {
	for _, status := range []string{"active", "suspended", "pending_verification"} {
		t.Run(status, func(t *testing.T) {
			svc, _, user, code := setupReclaimService(t, status)

			err := svc.VerifyTOTPForReclaim(context.Background(), user.ID, code)
			if !errors.Is(err, ErrAccountNotActive) {
				t.Fatalf("VerifyTOTPForReclaim for %q = %v, want ErrAccountNotActive", status, err)
			}
		})
	}
}

func TestVerifyTOTPForReclaimRejectsWrongCode(t *testing.T) {
	svc, _, user, code := setupReclaimService(t, "pending_deletion")

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if err := svc.VerifyTOTPForReclaim(context.Background(), user.ID, wrong); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("VerifyTOTPForReclaim with a wrong code = %v, want ErrInvalidCode", err)
	}
}

// TestVerifyTOTPForReclaimRequiresAnEnabledSecret guards against a half-configured
// account being mistaken for one that can present TOTP.
func TestVerifyTOTPForReclaimRequiresAnEnabledSecret(t *testing.T) {
	cases := []struct {
		name  string
		apply func(u *db.User)
	}{
		{
			name:  "flag off",
			apply: func(u *db.User) { u.IsMfaEnabled = false },
		},
		{
			name:  "no stored secret",
			apply: func(u *db.User) { u.MfaTotpSecretEncrypted = nil },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, user, code := setupReclaimService(t, "pending_deletion")
			u := store.users[user.ID]
			tc.apply(&u)
			store.users[user.ID] = u

			err := svc.VerifyTOTPForReclaim(context.Background(), user.ID, code)
			if !errors.Is(err, ErrMfaNotSetup) {
				t.Fatalf("VerifyTOTPForReclaim = %v, want ErrMfaNotSetup", err)
			}
		})
	}
}

func TestVerifyTOTPForReclaimUnknownUser(t *testing.T) {
	svc, _, _, code := setupReclaimService(t, "pending_deletion")

	if err := svc.VerifyTOTPForReclaim(context.Background(), uuid.New(), code); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("VerifyTOTPForReclaim for an unknown account = %v, want ErrUserNotFound", err)
	}
}

// TestVerifyTOTPForReclaimUsesTheSoftDeleteBlindLookup is the reason
// GetUserByIDForAdmin was added to UserStore: the filtered GetUserByID cannot see a
// pending_deletion row at all, so VerifyEnabledCode is structurally unusable for
// this flow. The recording store pins which query is actually issued, so a future
// refactor cannot quietly swap it back and silently break every reclaim.
func TestVerifyTOTPForReclaimUsesTheSoftDeleteBlindLookup(t *testing.T) {
	svc, store, user, code := setupReclaimService(t, "pending_deletion")
	recorder := &lookupRecordingStore{fakeUserStore: store}
	svc.users = recorder

	if err := svc.VerifyTOTPForReclaim(context.Background(), user.ID, code); err != nil {
		t.Fatalf("VerifyTOTPForReclaim: %v", err)
	}
	if recorder.forAdmin != 1 {
		t.Errorf("GetUserByIDForAdmin calls = %d, want 1", recorder.forAdmin)
	}
	if recorder.filtered != 0 {
		t.Errorf("GetUserByID calls = %d, want 0; the filtered query cannot see a soft-deleted row",
			recorder.filtered)
	}
}

// lookupRecordingStore counts which user lookup a flow issues.
type lookupRecordingStore struct {
	*fakeUserStore
	filtered int
	forAdmin int
}

func (s *lookupRecordingStore) GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error) {
	s.filtered++
	return s.fakeUserStore.GetUserByID(ctx, id)
}

func (s *lookupRecordingStore) GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error) {
	s.forAdmin++
	return s.fakeUserStore.GetUserByIDForAdmin(ctx, id)
}
