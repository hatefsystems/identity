package actionproof

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// FirstPasskeyAuthorization is frozen one-start authority, not a reusable proof.
// Pending WebAuthn state retains these fields after the proof is deleted.
type FirstPasskeyAuthorization struct {
	ExpiresAt      time.Time
	Channel        string
	ContactBinding []byte
}

// firstPasskeyCurrent uses only the supplied reader and raw session lookup.
// Transactional callers already own username guard, account advisory and user row.
func (s *Service) firstPasskeyCurrent(ctx context.Context, q *db.Queries, sess session.Session) (contactcode.DeletionBinding, error) {
	binding, err := s.live(ctx, sess)
	if err != nil {
		return contactcode.DeletionBinding{}, err
	}
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
	if !password.SupportedHash(*u.PasswordHash) {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	return binding, nil
}

func (s *Service) firstPasskeyBinding(ctx context.Context, q *db.Queries, binding contactcode.DeletionBinding, authorization FirstPasskeyAuthorization) error {
	if !time.Now().Before(authorization.ExpiresAt) || len(authorization.ContactBinding) != sha256.Size || authorization.Channel != contactcode.ChannelEmail && authorization.Channel != contactcode.ChannelSMS {
		return ErrUnauthorized
	}
	e, err := s.contact(ctx, q, binding, authorization.Channel)
	if err != nil {
		return err
	}
	if !hmac.Equal(authorization.ContactBinding, s.contactBindingFor(binding, contactcode.PurposeFirstPasskey, authorization.Channel, *e)) || !time.Now().Before(authorization.ExpiresAt) {
		return ErrUnauthorized
	}
	return nil
}

// CheckFirstPasskey is a lock-free, non-consuming preflight. It cannot replace
// ConsumeFirstPasskeyStartTx's deciding transaction or confer final authority.
func (s *Service) CheckFirstPasskey(ctx context.Context, sess session.Session, proof string) error {
	if s == nil {
		return ErrUnavailable
	}
	if !capability(proof) {
		return ErrInvalid
	}
	q := s.deps.Queries
	binding, err := s.firstPasskeyCurrent(ctx, q, sess)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(proof))
	row, err := q.GetFirstPasskeyActionProofBinding(ctx, db.GetFirstPasskeyActionProofBindingParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return ErrUnavailable
	}
	if !row.ExpiresAt.Valid || row.ExpiresAt.InfinityModifier != 0 {
		return ErrInvalid
	}
	return s.firstPasskeyBinding(ctx, q, binding, FirstPasskeyAuthorization{row.ExpiresAt.Time, row.Channel, row.ContactBinding})
}

func firstPasskeyTransaction(ctx context.Context, tx pgx.Tx) error {
	if missing(tx) {
		return ErrTransaction
	}
	var isolation string
	if err := tx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "read committed" {
		return ErrTransaction
	}
	return nil
}

// ConsumeFirstPasskeyStartTx deletes exactly once and returns the original SQL
// expiry and frozen bindings. It acquires no locks and never owns tx finalization.
// A caller must confirm commit before publishing pending authority or options.
func (s *Service) ConsumeFirstPasskeyStartTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof string) (FirstPasskeyAuthorization, error) {
	if s == nil {
		return FirstPasskeyAuthorization{}, ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return FirstPasskeyAuthorization{}, err
	}
	if !capability(proof) {
		return FirstPasskeyAuthorization{}, ErrInvalid
	}
	q := s.deps.Queries.WithTx(tx)
	binding, err := s.firstPasskeyCurrent(ctx, q, sess)
	if err != nil {
		return FirstPasskeyAuthorization{}, err
	}
	digest := sha256.Sum256([]byte(proof))
	row, err := q.GetFirstPasskeyActionProofBinding(ctx, db.GetFirstPasskeyActionProofBindingParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return FirstPasskeyAuthorization{}, ErrInvalid
	}
	if err != nil {
		return FirstPasskeyAuthorization{}, ErrUnavailable
	}
	if !row.ExpiresAt.Valid || row.ExpiresAt.InfinityModifier != 0 {
		return FirstPasskeyAuthorization{}, ErrInvalid
	}
	if err := s.firstPasskeyBinding(ctx, q, binding, FirstPasskeyAuthorization{row.ExpiresAt.Time, row.Channel, row.ContactBinding}); err != nil {
		return FirstPasskeyAuthorization{}, err
	}
	consumed, err := q.ConsumeFirstPasskeyActionProofStart(ctx, db.ConsumeFirstPasskeyActionProofStartParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: row.Channel, ContactBinding: row.ContactBinding,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return FirstPasskeyAuthorization{}, ErrInvalid
	}
	if err != nil {
		return FirstPasskeyAuthorization{}, ErrUnavailable
	}
	if !consumed.ExpiresAt.Valid || consumed.ExpiresAt.InfinityModifier != 0 || !time.Now().Before(consumed.ExpiresAt.Time) || consumed.Channel != row.Channel || !hmac.Equal(consumed.ContactBinding, row.ContactBinding) {
		return FirstPasskeyAuthorization{}, ErrUnauthorized
	}
	return FirstPasskeyAuthorization{consumed.ExpiresAt.Time, consumed.Channel, append([]byte(nil), consumed.ContactBinding...)}, nil
}

// ValidateFirstPasskeyTx is a read-only final recheck of frozen pending authority,
// not a proof lookup/consumption. Delivery switches cannot revoke a spent start.
func (s *Service) ValidateFirstPasskeyTx(ctx context.Context, tx pgx.Tx, sess session.Session, authorization FirstPasskeyAuthorization) error {
	if s == nil {
		return ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return err
	}
	q := s.deps.Queries.WithTx(tx)
	binding, err := s.firstPasskeyCurrent(ctx, q, sess)
	if err != nil {
		return err
	}
	return s.firstPasskeyBinding(ctx, q, binding, authorization)
}
