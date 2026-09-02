package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
)

const defaultIssuer = "Hatef Identity"

// UserStore defines the database query subset required by the MFA service.
type UserStore interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	// GetUserByIDForAdmin resolves an account including soft-deleted ones. It is
	// used only by VerifyTOTPForReclaim, whose subject is by definition a
	// pending_deletion account that every other lookup here filters out.
	GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error)
	GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error)
	DisableMfa(ctx context.Context, id uuid.UUID) (int64, error)
	CountWebauthnCredentialsByUser(ctx context.Context, userID uuid.UUID) (int64, error)
	DeleteMfaTotpEnrollmentsForUser(ctx context.Context, userID uuid.UUID) (int64, error)
	CreateMfaTotpEnrollment(ctx context.Context, arg db.CreateMfaTotpEnrollmentParams) (db.MfaTotpEnrollment, error)
	GetMfaTotpEnrollmentForUpdate(ctx context.Context, arg db.GetMfaTotpEnrollmentForUpdateParams) (db.MfaTotpEnrollment, error)
	IncrementMfaTotpEnrollmentAttempts(ctx context.Context, id uuid.UUID) (int64, error)
	DeleteMfaTotpEnrollment(ctx context.Context, id uuid.UUID) (int64, error)
	CompleteMfaTotpEnrollment(ctx context.Context, arg db.CompleteMfaTotpEnrollmentParams) (int64, error)
}

// Transacter opens PostgreSQL transactions for enrollment completion and
// cross-factor teardown. *pgxpool.Pool satisfies it.
type Transacter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Encryptor performs envelope encryption and decryption for sensitive PII/secrets.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Config carries MFA service configuration.
type Config struct {
	Issuer                string
	WindowSteps           int
	EnrollmentTTL         time.Duration
	MaxEnrollmentAttempts int
}

// SetupResponse contains the unencrypted TOTP secret and QR code URI returned
// during initial MFA setup (Task 4.4).
type SetupResponse struct {
	EnrollmentID string `json:"enrollment_id"`
	Secret       string `json:"secret"`
	OtpauthURL   string `json:"otpauth_url"`
	Issuer       string `json:"issuer"`
	AccountName  string `json:"account_name"`
}

// Service orchestrates TOTP MFA enrollment, verification, and teardown.
type Service struct {
	users                 UserStore
	tx                    Transacter
	encryptor             Encryptor
	issuer                string
	windowSteps           int
	now                   func() time.Time
	enrollmentTTL         time.Duration
	maxEnrollmentAttempts int
}

// Option configures optional service behavior.
type Option func(*Service)

// WithTransacter enables the production ACID paths.
func WithTransacter(tx Transacter) Option {
	return func(s *Service) { s.tx = tx }
}

const (
	defaultEnrollmentTTL         = 10 * time.Minute
	defaultMaxEnrollmentAttempts = 5
)

// New constructs a Service from dependencies and config.
func New(cfg Config, users UserStore, encryptor Encryptor, opts ...Option) (*Service, error) {
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

	s := &Service{
		users:                 users,
		encryptor:             encryptor,
		issuer:                issuer,
		windowSteps:           windowSteps,
		now:                   time.Now,
		enrollmentTTL:         cfg.EnrollmentTTL,
		maxEnrollmentAttempts: cfg.MaxEnrollmentAttempts,
	}
	if s.enrollmentTTL <= 0 {
		s.enrollmentTTL = defaultEnrollmentTTL
	}
	if s.maxEnrollmentAttempts <= 0 {
		s.maxEnrollmentAttempts = defaultMaxEnrollmentAttempts
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// GenerateSetup initiates TOTP MFA setup for an account. It generates a fresh
// TOTP secret, envelope-encrypts it, persists it in the database, and returns
// the setup details including the otpauth:// URI for QR code mapping.
func (s *Service) GenerateSetup(ctx context.Context, userID uuid.UUID, sessionID string) (*SetupResponse, error) {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, ErrMfaNotSetup
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("mfa: generate secret: %w", err)
	}

	encSecret, err := s.encryptor.Encrypt(ctx, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptFailed, err)
	}

	var user db.User
	var enrollment db.MfaTotpEnrollment
	err = s.runInTx(ctx, func(store UserStore) error {
		user, err = store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.Status != "active" {
			return ErrAccountNotActive
		}
		if user.IsMfaEnabled {
			return ErrMfaAlreadyEnabled
		}
		if _, err := store.DeleteMfaTotpEnrollmentsForUser(ctx, userID); err != nil {
			return fmt.Errorf("mfa: replace pending enrollment: %w", err)
		}
		enrollment, err = store.CreateMfaTotpEnrollment(ctx, db.CreateMfaTotpEnrollmentParams{
			UserID:          userID,
			SessionID:       sessionUUID,
			Purpose:         "maintenance",
			SecretEncrypted: encSecret,
			ExpiresAt:       pgtype.Timestamptz{Time: s.now().Add(s.enrollmentTTL), Valid: true},
		})
		if err != nil {
			return fmt.Errorf("mfa: store pending enrollment: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	uri := totp.GenerateURI(secret, user.Email, s.issuer)

	return &SetupResponse{
		EnrollmentID: enrollment.ID.String(),
		Secret:       secret,
		OtpauthURL:   uri,
		Issuer:       s.issuer,
		AccountName:  user.Email,
	}, nil
}

// VerifyAndEnable verifies the submitted 6-digit passcode against the pending
// stored TOTP secret and flips is_mfa_enabled to true.
func (s *Service) VerifyAndEnable(ctx context.Context, userID uuid.UUID, sessionID, enrollmentID, code string) error {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return ErrMfaNotSetup
	}
	enrollmentUUID, err := uuid.Parse(enrollmentID)
	if err != nil {
		return ErrMfaNotSetup
	}
	var outcome error
	err = s.runInTx(ctx, func(store UserStore) error {
		user, err := store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.Status != "active" {
			return ErrAccountNotActive
		}
		// An enabled account is rejected before loading or decrypting any
		// pending material, so this endpoint can never test the active secret.
		if user.IsMfaEnabled {
			return ErrMfaAlreadyEnabled
		}

		enrollment, err := store.GetMfaTotpEnrollmentForUpdate(ctx, db.GetMfaTotpEnrollmentForUpdateParams{
			ID:        enrollmentUUID,
			UserID:    userID,
			SessionID: sessionUUID,
			Purpose:   "maintenance",
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMfaNotSetup
			}
			return fmt.Errorf("mfa: lock pending enrollment: %w", err)
		}
		if !enrollment.ExpiresAt.Valid || !s.now().Before(enrollment.ExpiresAt.Time) {
			if _, err := store.DeleteMfaTotpEnrollment(ctx, enrollment.ID); err != nil {
				return fmt.Errorf("mfa: delete expired enrollment: %w", err)
			}
			outcome = ErrEnrollmentExpired
			return nil
		}

		rawSecret, err := s.encryptor.Decrypt(ctx, enrollment.SecretEncrypted)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrDecryptFailed, err)
		}
		if !totp.ValidateCode(string(rawSecret), code, s.now(), s.windowSteps) {
			if int(enrollment.FailedAttempts)+1 >= s.maxEnrollmentAttempts {
				_, err = store.DeleteMfaTotpEnrollment(ctx, enrollment.ID)
			} else {
				_, err = store.IncrementMfaTotpEnrollmentAttempts(ctx, enrollment.ID)
			}
			if err != nil {
				return fmt.Errorf("mfa: record failed enrollment attempt: %w", err)
			}
			outcome = ErrInvalidCode
			return nil
		}

		affected, err := store.CompleteMfaTotpEnrollment(ctx, db.CompleteMfaTotpEnrollmentParams{
			ID:                     userID,
			MfaTotpSecretEncrypted: enrollment.SecretEncrypted,
		})
		if err != nil {
			return fmt.Errorf("mfa: enable mfa: %w", err)
		}
		if affected == 0 {
			return ErrMfaAlreadyEnabled
		}
		if _, err := store.DeleteMfaTotpEnrollment(ctx, enrollment.ID); err != nil {
			return fmt.Errorf("mfa: delete completed enrollment: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return outcome
}

// Disable disables TOTP MFA for the user, wiping the encrypted secret and
// setting is_mfa_enabled to false.
func (s *Service) Disable(ctx context.Context, userID uuid.UUID) error {
	return s.runInTx(ctx, func(store UserStore) error {
		user, err := store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.Status != "active" {
			return ErrAccountNotActive
		}
		if user.IsMfaEnabled && len(user.MfaTotpSecretEncrypted) > 0 {
			count, err := store.CountWebauthnCredentialsByUser(ctx, userID)
			if err != nil {
				return fmt.Errorf("mfa: count passkeys: %w", err)
			}
			if count == 0 {
				return ErrLastFactor
			}
		}
		affected, err := store.DisableMfa(ctx, userID)
		if err != nil {
			return fmt.Errorf("mfa: disable mfa: %w", err)
		}
		if affected == 0 {
			return ErrUserNotFound
		}
		if _, err := store.DeleteMfaTotpEnrollmentsForUser(ctx, userID); err != nil {
			return fmt.Errorf("mfa: clear pending enrollments: %w", err)
		}
		return nil
	})
}

// VerifyEnabledCode verifies a submitted 6-digit TOTP code only against an
// already enabled account (used during login or step-up authentication).
func (s *Service) VerifyEnabledCode(ctx context.Context, userID uuid.UUID, code string) error {
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

// VerifyTOTPForReclaim verifies a passcode against an account that is inside the
// 30-day deletion grace window (Task 5.1).
//
// It is a separate method rather than a flag on VerifyEnabledCode for the same
// reason there is no general-purpose /api/v1/auth/mfa/verify-code endpoint
// (docs/api-design.md §1.3): an enabled TOTP secret may only ever be checked
// inside a named, purpose-specific flow, so that no caller can turn code validity
// into an oracle. The purpose here is "cancel a pending deletion" and nothing else.
//
// The status gate is the inverse of every other method in this package: only
// pending_deletion is accepted. An active account has no deletion to cancel, and
// accepting a suspended one would let moderation be undone through the privacy
// flow. GetUserByIDForAdmin is required because GetUserByID cannot see a
// soft-deleted row at all.
//
// Replay protection is the caller's responsibility and lives in internal/privacy,
// which claims the canonical code in the shared single-use guard *before* calling
// this method — the same ordering internal/stepup uses, and the only one that
// stops two concurrent submissions of one code from both succeeding.
func (s *Service) VerifyTOTPForReclaim(ctx context.Context, userID uuid.UUID, code string) error {
	user, err := s.users.GetUserByIDForAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("mfa: load user: %w", err)
	}
	if user.Status != statusPendingDeletion {
		return ErrAccountNotActive
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

// statusPendingDeletion is the only users.status value VerifyTOTPForReclaim
// accepts.
const statusPendingDeletion = "pending_deletion"

func (s *Service) runInTx(ctx context.Context, fn func(UserStore) error) error {
	if s.tx == nil {
		return fn(s.users)
	}
	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("mfa: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("mfa: commit transaction: %w", err)
	}
	committed = true
	return nil
}
