package actionproof

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// ErrMFAEnrollmentExpired identifies only expiry, never another authorization rejection.
var ErrMFAEnrollmentExpired = errors.New("actionproof: MFA enrollment authority expired")

// MFAEnrollmentAuthorization survives the single-use proof's deletion at start.
type MFAEnrollmentAuthorization struct {
	ExpiresAt      time.Time
	Channel        string
	ContactBinding []byte
}

// NewMFAEnrollment can read bounded pending authority with issuance disabled.
// Only code issuance needs a contact-code service and password-attempt limiter.
func NewMFAEnrollment(cfg Config, deps Deps) (*Service, error) {
	if len(cfg.BindingKey) < 32 || len(cfg.BindingKey) > 64 || bytes.Equal(cfg.BindingKey, make([]byte, len(cfg.BindingKey))) {
		return nil, ErrInvalid
	}
	if missing(deps.DB) || deps.Queries == nil || missing(deps.Cipher) || missing(deps.Sessions) || deps.Codes != nil && missing(deps.Limiter) {
		return nil, ErrUnavailable
	}
	return &Service{key: append([]byte(nil), cfg.BindingKey...), deps: deps}, nil
}

// SetAccountPolicy installs the authoritative admitted-password sign-in policy.
func (s *Service) SetAccountPolicy(policy accountpolicy.Policy) { s.policy = policy }

// ChallengeMFAEnrollment freshly verifies the password for enrollment-only contact delivery.
func (s *Service) ChallengeMFAEnrollment(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	return s.challenge(ctx, sess, secret, channel, sourceIP, contactcode.PurposeMFAEnrollment)
}

// VerifyMFAEnrollment exchanges one contact code for an enrollment-only proof.
func (s *Service) VerifyMFAEnrollment(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return s.verify(ctx, sess, challenge, code, contactcode.PurposeMFAEnrollment)
}

// The caller already holds username guard -> account advisory -> user row locks.
// This reads raw authority only, never renewing a session or reacquiring locks.
func (s *Service) mfaEnrollmentCurrent(ctx context.Context, tx pgx.Tx, sess session.Session, authority username.GuardAuthority) (contactcode.DeletionBinding, error) {
	binding, err := s.live(ctx, sess)
	if err != nil {
		return contactcode.DeletionBinding{}, err
	}
	q := s.deps.Queries.WithTx(tx)
	u, err := q.GetUserByID(ctx, binding.AccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	if err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	if err := s.eligible(ctx, q, u, binding.AccountID, binding.AuthVersion); err != nil {
		return contactcode.DeletionBinding{}, err
	}
	if !password.SupportedHash(*u.PasswordHash) || len(u.MfaTotpSecretEncrypted) != 0 || !s.policy.PasswordLoginEnabled {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	if s.policy.Usernames == nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	state, err := s.policy.Read(ctx, tx, u, authority)
	if err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	if !state.Password || state.Passkeys != 0 || state.TOTP || state.Privileged {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	return binding, nil
}

func (s *Service) mfaEnrollmentBinding(ctx context.Context, q *db.Queries, binding contactcode.DeletionBinding, authorization MFAEnrollmentAuthorization) error {
	if len(authorization.ContactBinding) != sha256.Size || authorization.Channel != contactcode.ChannelEmail && authorization.Channel != contactcode.ChannelSMS {
		return ErrUnauthorized
	}
	if !time.Now().Before(authorization.ExpiresAt) {
		return ErrMFAEnrollmentExpired
	}
	e, err := s.contact(ctx, q, binding, authorization.Channel)
	if err != nil {
		return err
	}
	if !hmac.Equal(authorization.ContactBinding, s.contactBindingFor(binding, contactcode.PurposeMFAEnrollment, authorization.Channel, *e)) {
		return ErrUnauthorized
	}
	if !time.Now().Before(authorization.ExpiresAt) {
		return ErrMFAEnrollmentExpired
	}
	return nil
}

// ConsumeMFAEnrollmentStartTx deletes one proof in the MFA-owned transaction.
// It returns the SQL row's original deadline and never owns locks/finalization.
func (s *Service) ConsumeMFAEnrollmentStartTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof string, authority username.GuardAuthority) (MFAEnrollmentAuthorization, error) {
	if s == nil {
		return MFAEnrollmentAuthorization{}, ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return MFAEnrollmentAuthorization{}, err
	}
	if !capability(proof) {
		return MFAEnrollmentAuthorization{}, ErrInvalid
	}
	binding, err := s.mfaEnrollmentCurrent(ctx, tx, sess, authority)
	if err != nil {
		return MFAEnrollmentAuthorization{}, err
	}
	q := s.deps.Queries.WithTx(tx)
	digest := sha256.Sum256([]byte(proof))
	row, err := q.GetMFAEnrollmentActionProofBinding(ctx, db.GetMFAEnrollmentActionProofBindingParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAEnrollmentAuthorization{}, ErrInvalid
	}
	if err != nil {
		return MFAEnrollmentAuthorization{}, ErrUnavailable
	}
	if !row.ExpiresAt.Valid || row.ExpiresAt.InfinityModifier != 0 {
		return MFAEnrollmentAuthorization{}, ErrInvalid
	}
	if err := s.mfaEnrollmentBinding(ctx, q, binding, MFAEnrollmentAuthorization{row.ExpiresAt.Time, row.Channel, row.ContactBinding}); err != nil {
		return MFAEnrollmentAuthorization{}, err
	}
	consumed, err := q.ConsumeMFAEnrollmentActionProofStart(ctx, db.ConsumeMFAEnrollmentActionProofStartParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: row.Channel, ContactBinding: row.ContactBinding,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAEnrollmentAuthorization{}, ErrInvalid
	}
	if err != nil {
		return MFAEnrollmentAuthorization{}, ErrUnavailable
	}
	if !consumed.ExpiresAt.Valid || consumed.ExpiresAt.InfinityModifier != 0 || !time.Now().Before(consumed.ExpiresAt.Time) || !consumed.ExpiresAt.Time.Equal(row.ExpiresAt.Time) || consumed.Channel != row.Channel || !hmac.Equal(consumed.ContactBinding, row.ContactBinding) {
		return MFAEnrollmentAuthorization{}, ErrUnauthorized
	}
	return MFAEnrollmentAuthorization{consumed.ExpiresAt.Time, consumed.Channel, append([]byte(nil), consumed.ContactBinding...)}, nil
}

// ValidateMFAEnrollmentTx revalidates frozen pending authority without proof lookup.
// Delivery switches and provider availability are deliberately irrelevant here.
func (s *Service) ValidateMFAEnrollmentTx(ctx context.Context, tx pgx.Tx, sess session.Session, authorization MFAEnrollmentAuthorization, authority username.GuardAuthority) error {
	if s == nil {
		return ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return err
	}
	binding, err := s.mfaEnrollmentCurrent(ctx, tx, sess, authority)
	if err != nil {
		return err
	}
	return s.mfaEnrollmentBinding(ctx, s.deps.Queries.WithTx(tx), binding, authorization)
}

// CleanupExpiredMFAEnrollment reclaims a bounded batch of expired unused start proofs.
func (s *Service) CleanupExpiredMFAEnrollment(ctx context.Context, batchSize int32) (int64, error) {
	return s.cleanupExpired(ctx, batchSize, contactcode.PurposeMFAEnrollment)
}
