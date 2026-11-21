package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
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
	RevokeUserCredentials(ctx context.Context, id uuid.UUID) error
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
	policy                accountpolicy.Policy
}

// Option configures optional service behavior.
type Option func(*Service)

// SetAccountPolicy binds maintenance to the login route's admitted authority at startup.
func (s *Service) SetAccountPolicy(policy accountpolicy.Policy) { s.policy = policy }

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
func (s *Service) GenerateSetup(ctx context.Context, userID uuid.UUID, authVersion int64, sessionID string) (*SetupResponse, error) {
	if userID == uuid.Nil || authVersion < 0 {
		return nil, ErrAccountNotActive
	}
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
	err = s.runInTx(ctx, userID, func(store UserStore, _ pgx.Tx, _ username.GuardAuthority) error {
		user, err = store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.ID != userID || user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != authVersion {
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

	accountName := user.ID.String()
	if user.Email != nil {
		accountName = *user.Email
	}
	uri := totp.GenerateURI(secret, accountName, s.issuer)

	return &SetupResponse{
		EnrollmentID: enrollment.ID.String(),
		Secret:       secret,
		OtpauthURL:   uri,
		Issuer:       s.issuer,
		AccountName:  accountName,
	}, nil
}

// VerifyAndEnable verifies the submitted 6-digit passcode against the pending
// stored TOTP secret and flips is_mfa_enabled to true.
func (s *Service) VerifyAndEnable(ctx context.Context, userID uuid.UUID, authVersion int64, sessionID, enrollmentID, code string) error {
	if userID == uuid.Nil || authVersion < 0 {
		return ErrAccountNotActive
	}
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return ErrMfaNotSetup
	}
	enrollmentUUID, err := uuid.Parse(enrollmentID)
	if err != nil {
		return ErrMfaNotSetup
	}
	var outcome error
	err = s.runInTx(ctx, userID, func(store UserStore, tx pgx.Tx, authority username.GuardAuthority) error {
		user, err := store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.ID != userID || user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != authVersion {
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

		state, err := s.protection(ctx, store, tx, user, authority)
		if err != nil {
			return err
		}
		state.TOTP = true
		if err := state.Check(); err != nil {
			return err
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
		return store.RevokeUserCredentials(ctx, userID)
	})
	if err != nil {
		return err
	}
	return outcome
}

// Disable disables TOTP MFA for the user, wiping the encrypted secret and
// setting is_mfa_enabled to false.
func (s *Service) Disable(ctx context.Context, userID uuid.UUID, authVersion int64) error {
	if userID == uuid.Nil || authVersion < 0 {
		return ErrAccountNotActive
	}
	var changed bool
	err := s.runInTx(ctx, userID, func(store UserStore, tx pgx.Tx, authority username.GuardAuthority) error {
		user, err := store.GetUserByIDForUpdate(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserNotFound
			}
			return fmt.Errorf("mfa: lock user: %w", err)
		}
		if user.ID != userID || user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != authVersion {
			return ErrAccountNotActive
		}
		changed = user.IsMfaEnabled || len(user.MfaTotpSecretEncrypted) > 0
		if changed {
			state, err := s.protection(ctx, store, tx, user, authority)
			if err != nil {
				return err
			}
			// This route retains its passkey requirement; password alternatives belong to T26.
			if state.Passkeys == 0 {
				return ErrLastFactor
			}
			state.TOTP = false
			if err := state.Check(); err != nil {
				return err
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
		if changed {
			return store.RevokeUserCredentials(ctx, userID)
		}
		return nil
	})
	if err == nil && changed {
		session.SecurityChangeCommitted(ctx)
	}
	return err
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

func (s *Service) protection(ctx context.Context, store UserStore, tx pgx.Tx, user db.User, authority username.GuardAuthority) (accountpolicy.State, error) {
	if tx != nil {
		return s.policy.Read(ctx, tx, user, authority)
	}
	count, err := store.CountWebauthnCredentialsByUser(ctx, user.ID)
	return accountpolicy.State{Passkeys: count, TOTP: user.IsMfaEnabled && len(user.MfaTotpSecretEncrypted) > 0}, err
}

func (s *Service) runInTx(ctx context.Context, userID uuid.UUID, fn func(UserStore, pgx.Tx, username.GuardAuthority) error) error {
	if s.tx == nil {
		if _, databaseStore := s.users.(*db.Queries); databaseStore {
			return errors.New("mfa: database mutations require a transaction")
		}
		return fn(s.users, nil, username.GuardAuthority{})
	}
	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("mfa: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}
	}()
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
		return err
	}
	authority, err := s.policy.Guard(ctx, tx)
	if err != nil {
		return err
	}
	if err := pglock.LockAccount(ctx, tx, userID); err != nil {
		return fmt.Errorf("mfa: lock subject: %w", err)
	}
	if err := fn(db.New(tx), tx, authority); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("mfa: commit transaction: %w", err)
	}
	committed = true
	return nil
}
