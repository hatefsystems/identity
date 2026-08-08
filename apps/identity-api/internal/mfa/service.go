package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
)

const defaultIssuer = "Hatef Identity"

// UserStore defines the database query subset required by the MFA service.
type UserStore interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	SetMfaTotpSecret(ctx context.Context, arg db.SetMfaTotpSecretParams) (int64, error)
	EnableMfa(ctx context.Context, id uuid.UUID) (int64, error)
	DisableMfa(ctx context.Context, id uuid.UUID) (int64, error)
}

// Encryptor performs envelope encryption and decryption for sensitive PII/secrets.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Config carries MFA service configuration.
type Config struct {
	Issuer      string
	WindowSteps int
}

// SetupResponse contains the unencrypted TOTP secret and QR code URI returned
// during initial MFA setup (Task 4.4).
type SetupResponse struct {
	Secret      string `json:"secret"`
	OtpauthURL  string `json:"otpauth_url"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"account_name"`
}

// Service orchestrates TOTP MFA enrollment, verification, and teardown.
type Service struct {
	users       UserStore
	encryptor   Encryptor
	issuer      string
	windowSteps int
	now         func() time.Time
}

// New constructs a Service from dependencies and config.
func New(cfg Config, users UserStore, encryptor Encryptor) (*Service, error) {
	if users == nil {
		return nil, errors.New("mfa: user store is required")
	}
	if encryptor == nil {
		return nil, errors.New("mfa: encryptor is required")
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = defaultIssuer
	}

	windowSteps := cfg.WindowSteps
	if windowSteps <= 0 {
		windowSteps = 1 // ±1 time step (30 seconds) window drift
	}

	return &Service{
		users:       users,
		encryptor:   encryptor,
		issuer:      issuer,
		windowSteps: windowSteps,
		now:         time.Now,
	}, nil
}

// GenerateSetup initiates TOTP MFA setup for an account. It generates a fresh
// TOTP secret, envelope-encrypts it, persists it in the database, and returns
// the setup details including the otpauth:// URI for QR code mapping.
func (s *Service) GenerateSetup(ctx context.Context, userID uuid.UUID) (*SetupResponse, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("mfa: load user: %w", err)
	}

	if user.IsMfaEnabled {
		return nil, ErrMfaAlreadyEnabled
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("mfa: generate secret: %w", err)
	}

	encSecret, err := s.encryptor.Encrypt(ctx, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}

	affected, err := s.users.SetMfaTotpSecret(ctx, db.SetMfaTotpSecretParams{
		ID:                     user.ID,
		MfaTotpSecretEncrypted: encSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: store secret: %w", err)
	}
	if affected == 0 {
		return nil, ErrUserNotFound
	}

	uri := totp.GenerateURI(secret, user.Email, s.issuer)

	return &SetupResponse{
		Secret:      secret,
		OtpauthURL:  uri,
		Issuer:      s.issuer,
		AccountName: user.Email,
	}, nil
}

// VerifyAndEnable verifies the submitted 6-digit passcode against the pending
// stored TOTP secret and flips is_mfa_enabled to true.
func (s *Service) VerifyAndEnable(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("mfa: load user: %w", err)
	}

	if len(user.MfaTotpSecretEncrypted) == 0 {
		return ErrMfaNotSetup
	}

	rawSecret, err := s.encryptor.Decrypt(ctx, user.MfaTotpSecretEncrypted)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	if !totp.ValidateCode(string(rawSecret), code, s.now(), s.windowSteps) {
		return ErrInvalidCode
	}

	affected, err := s.users.EnableMfa(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("mfa: enable mfa: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// Disable disables TOTP MFA for the user, wiping the encrypted secret and
// setting is_mfa_enabled to false.
func (s *Service) Disable(ctx context.Context, userID uuid.UUID) error {
	affected, err := s.users.DisableMfa(ctx, userID)
	if err != nil {
		return fmt.Errorf("mfa: disable mfa: %w", err)
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// VerifyCode verifies a submitted 6-digit TOTP code for an already enabled
// account (used during login or step-up authentication).
func (s *Service) VerifyCode(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("mfa: load user: %w", err)
	}

	if !user.IsMfaEnabled || len(user.MfaTotpSecretEncrypted) == 0 {
		return ErrMfaNotSetup
	}

	rawSecret, err := s.encryptor.Decrypt(ctx, user.MfaTotpSecretEncrypted)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	if !totp.ValidateCode(string(rawSecret), code, s.now(), s.windowSteps) {
		return ErrInvalidCode
	}

	return nil
}
