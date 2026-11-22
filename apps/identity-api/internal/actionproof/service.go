// Package actionproof authorizes fixed-purpose, single-use mutations, never step-up.
package actionproof

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Failures contain no secrets, contacts, session IDs or dependency diagnostics.
var (
	ErrInvalid        = errors.New("actionproof: invalid input or proof")
	ErrUnauthorized   = errors.New("actionproof: authority unavailable")
	ErrRateLimited    = errors.New("actionproof: rate limited")
	ErrUnavailable    = errors.New("actionproof: dependency unavailable")
	ErrOutcomeUnknown = errors.New("actionproof: outcome unknown; restart ceremony")
	ErrTransaction    = errors.New("actionproof: open read committed transaction required")
)

// Beginner is implemented by pgxpool.Pool; no implicit retries are permitted.
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// SessionReader reads live authority without renewing activity or account locks.
type SessionReader interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// Config uses a separate keyed binding for complete verified-contact evidence.
type Config struct{ BindingKey []byte }

// Deps is the existing DB/contact delivery/crypto/rate/session infrastructure.
type Deps struct {
	DB       Beginner
	Queries  *db.Queries
	Codes    *contactcode.Service
	Cipher   contactproof.Cipher
	Limiter  ratelimit.Limiter
	Sessions SessionReader
}

// Service neither issues sessions nor changes authentication/step-up evidence.
type Service struct {
	key  []byte
	deps Deps
}

// New rejects missing protection; deletion channels remain independently enabled.
func New(cfg Config, deps Deps) (*Service, error) {
	return newService(cfg, deps, contactcode.PurposeAccountDeletion)
}

// NewPasswordChange requires independent password-change delivery, not deletion.
func NewPasswordChange(cfg Config, deps Deps) (*Service, error) {
	return newService(cfg, deps, contactcode.PurposePasswordChange)
}

// NewFirstPasskey requires independent first-passkey delivery and protection.
func NewFirstPasskey(cfg Config, deps Deps) (*Service, error) {
	return newService(cfg, deps, contactcode.PurposeFirstPasskey)
}

func newService(cfg Config, deps Deps, purpose string) (*Service, error) {
	if len(cfg.BindingKey) < 32 || len(cfg.BindingKey) > 64 {
		return nil, ErrInvalid
	}
	if missing(deps.DB) || deps.Queries == nil || deps.Codes == nil || missing(deps.Cipher) || missing(deps.Limiter) || missing(deps.Sessions) {
		return nil, ErrUnavailable
	}
	s := &Service{key: append([]byte(nil), cfg.BindingKey...), deps: deps}
	if !s.channelEnabled(purpose, contactcode.ChannelEmail) && !s.channelEnabled(purpose, contactcode.ChannelSMS) {
		return nil, ErrUnavailable
	}
	return s, nil
}

func (s *Service) channelEnabled(purpose, channel string) bool {
	if purpose == contactcode.PurposeFirstPasskey {
		return s.deps.Codes.FirstPasskeyChannelEnabled(channel)
	}
	if purpose == contactcode.PurposePasswordChange {
		return s.deps.Codes.PasswordChangeChannelEnabled(channel)
	}
	return purpose == contactcode.PurposeAccountDeletion && s.deps.Codes.DeletionChannelEnabled(channel)
}

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	return r.Kind() == reflect.Pointer && r.IsNil()
}

func capability(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

func (s *Service) live(ctx context.Context, sess session.Session) (contactcode.DeletionBinding, error) {
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil || sess.UserID != id.String() || sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.AuthVersion < 0 || sess.ID == "" || len(sess.ID) > 128 || !capability(sess.DPoPJKT) {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	live, err := s.deps.Sessions.LookupByID(ctx, sess.UserID, sess.ID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return contactcode.DeletionBinding{}, ErrUnauthorized
		}
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	now := time.Now()
	if live.UserID != sess.UserID || live.ID != sess.ID || live.Kind != session.KindAuthenticated || !live.AuthVersionSet || live.AuthVersion != sess.AuthVersion || live.DPoPJKT != sess.DPoPJKT || !now.Before(live.AbsoluteExpiry) || !now.Before(live.IdleExpiry) {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	return contactcode.DeletionBinding{AccountID: id, AuthVersion: sess.AuthVersion, SessionID: sess.ID, JKT: sess.DPoPJKT}, nil
}

func (s *Service) limitPassword(ctx context.Context, id uuid.UUID, source string) error {
	subnet := ratelimit.Subnet(source)
	if len(source) == 0 || len(source) > 128 || strings.HasPrefix(subnet, "invalid/") {
		return ErrInvalid
	}
	for _, budget := range []struct {
		kind, value string
		limit       int
	}{
		{"account", id.String(), 5},
		{"source", subnet, 20},
	} {
		mac := hmac.New(sha256.New, s.key)
		_, _ = mac.Write([]byte("actionproof:v1:password:" + budget.kind + "\x00" + budget.value))
		allowed, err := s.deps.Limiter.Allow(ctx, "rate:actionproof:password:"+budget.kind+":"+hex.EncodeToString(mac.Sum(nil)), budget.limit, time.Minute)
		if err != nil {
			return ErrOutcomeUnknown
		}
		if !allowed {
			return ErrRateLimited
		}
	}
	return nil
}

// locked checks fresh account and session authority after the permanent lock order.
func (s *Service) locked(ctx context.Context, tx pgx.Tx, sess session.Session) (contactcode.DeletionBinding, error) {
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	q := s.deps.Queries.WithTx(tx)
	u, err := q.GetUserByIDForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	if err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	if err := s.eligible(ctx, q, u, id, sess.AuthVersion); err != nil {
		return contactcode.DeletionBinding{}, err
	}
	return s.live(ctx, sess)
}

func (s *Service) eligible(ctx context.Context, q *db.Queries, u db.User, id uuid.UUID, version int64) error {
	if u.ID != id || u.Status != "active" || u.DeletedAt.Valid || u.PasswordHash == nil || *u.PasswordHash == "" || u.IsMfaEnabled || u.AuthVersion != version {
		return ErrUnauthorized
	}
	count, err := q.CountWebauthnCredentialsByUser(ctx, id)
	if err != nil {
		return ErrUnavailable
	}
	privileged, err := q.UserHasPrivilegedRole(ctx, id)
	if err != nil {
		return ErrUnavailable
	}
	if count != 0 || privileged {
		return ErrUnauthorized
	}
	return nil
}

func (s *Service) contact(ctx context.Context, q *db.Queries, binding contactcode.DeletionBinding, channel string) (*contactproof.Evidence, error) {
	proofChannel := contactproof.Email
	if channel == contactcode.ChannelSMS {
		proofChannel = contactproof.Phone
	} else if channel != contactcode.ChannelEmail {
		return nil, ErrInvalid
	}
	e, err := contactproof.Read(ctx, q, s.deps.Cipher, binding.AccountID, proofChannel)
	if err != nil || e == nil {
		return nil, ErrUnauthorized
	}
	return e, nil
}

func (s *Service) contactBinding(binding contactcode.DeletionBinding, channel string, evidence contactproof.Evidence) []byte {
	return s.contactBindingFor(binding, contactcode.PurposeAccountDeletion, channel, evidence)
}

func (s *Service) contactBindingFor(binding contactcode.DeletionBinding, purpose, channel string, evidence contactproof.Evidence) []byte {
	// Whole typed evidence preserves purpose, method, channel and original time,
	// not merely destination. Structured encoding prevents boundary ambiguity.
	bound, _ := json.Marshal(struct {
		Binding  contactcode.DeletionBinding
		Action   string
		Channel  string
		Evidence contactproof.Evidence
	}{binding, purpose, channel, evidence})
	defer clear(bound)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("actionproof:v1:contact\x00"))
	_, _ = mac.Write(bound)
	return mac.Sum(nil)
}

// Challenge verifies the exact password outside locks, then freezes authority.
// Provider I/O happens only after the account transaction has finished.
func (s *Service) Challenge(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	return s.challenge(ctx, sess, secret, channel, sourceIP, contactcode.PurposeAccountDeletion)
}

// ChallengePasswordChange verifies the current exact password without holding locks.
func (s *Service) ChallengePasswordChange(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	return s.challenge(ctx, sess, secret, channel, sourceIP, contactcode.PurposePasswordChange)
}

// ChallengeFirstPasskey freshly verifies the exact existing password, outside locks.
func (s *Service) ChallengeFirstPasskey(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	return s.challenge(ctx, sess, secret, channel, sourceIP, contactcode.PurposeFirstPasskey)
}

func (s *Service) challenge(ctx context.Context, sess session.Session, secret, channel, sourceIP, purpose string) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, ErrUnavailable
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	if !s.channelEnabled(purpose, channel) {
		return "", time.Time{}, contactcode.ErrDisabled
	}
	if err := s.limitPassword(ctx, binding.AccountID, sourceIP); err != nil {
		return "", time.Time{}, err
	}
	u, err := s.deps.Queries.GetUserByID(ctx, binding.AccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrUnauthorized
	}
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	if u.AuthVersion != binding.AuthVersion || u.PasswordHash == nil || u.Status != "active" || u.DeletedAt.Valid {
		return "", time.Time{}, ErrUnauthorized
	}
	if purpose == contactcode.PurposeFirstPasskey && !password.SupportedHash(*u.PasswordHash) {
		return "", time.Time{}, ErrUnauthorized
	}
	matched, err := password.VerifyContext(ctx, secret, *u.PasswordHash)
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	if !matched {
		return "", time.Time{}, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	defer rollback(ctx, tx)
	binding, err = s.locked(ctx, tx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	q := s.deps.Queries.WithTx(tx)
	// Also reject an unversioned password replacement during verification.
	current, err := q.GetUserByID(ctx, binding.AccountID)
	if err != nil || current.PasswordHash == nil || *current.PasswordHash != *u.PasswordHash {
		return "", time.Time{}, ErrUnauthorized
	}
	if purpose == contactcode.PurposeFirstPasskey && !password.SupportedHash(*current.PasswordHash) {
		return "", time.Time{}, ErrUnauthorized
	}
	e, err := s.contact(ctx, q, binding, channel)
	if err != nil {
		return "", time.Time{}, err
	}
	contactBinding := hex.EncodeToString(s.contactBindingFor(binding, purpose, channel, *e))
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	if purpose == contactcode.PurposeFirstPasskey {
		return s.deps.Codes.RequestFirstPasskey(ctx, binding, channel, e.Destination, contactBinding, sourceIP)
	}
	if purpose == contactcode.PurposePasswordChange {
		return s.deps.Codes.RequestPasswordChange(ctx, binding, channel, e.Destination, contactBinding, sourceIP)
	}
	return s.deps.Codes.RequestDeletion(ctx, binding, channel, e.Destination, contactBinding, sourceIP)
}

// Verify consumes the OTP once, then commits one digest-only deletion proof.
// No retry or proof escapes after a failed/ambiguous issuance or commit.
func (s *Service) Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return s.verify(ctx, sess, challenge, code, contactcode.PurposeAccountDeletion)
}

// VerifyPasswordChange issues one digest-only proof with the OTP's original deadline.
func (s *Service) VerifyPasswordChange(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return s.verify(ctx, sess, challenge, code, contactcode.PurposePasswordChange)
}

// VerifyFirstPasskey issues one start proof with the OTP's original expiry.
func (s *Service) VerifyFirstPasskey(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return s.verify(ctx, sess, challenge, code, contactcode.PurposeFirstPasskey)
}

func (s *Service) verify(ctx context.Context, sess session.Session, challenge, code, purpose string) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, ErrUnavailable
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	var rec contactcode.Record
	switch purpose {
	case contactcode.PurposeFirstPasskey:
		rec, err = s.deps.Codes.VerifyFirstPasskey(ctx, binding, challenge, code)
	case contactcode.PurposePasswordChange:
		rec, err = s.deps.Codes.VerifyPasswordChange(ctx, binding, challenge, code)
	default:
		rec, err = s.deps.Codes.VerifyDeletion(ctx, binding, challenge, code)
	}
	if err != nil {
		return "", time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	defer rollback(ctx, tx)
	binding, err = s.locked(ctx, tx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	q := s.deps.Queries.WithTx(tx)
	if purpose == contactcode.PurposeFirstPasskey {
		u, err := q.GetUserByID(ctx, binding.AccountID)
		if err != nil {
			return "", time.Time{}, ErrUnavailable
		}
		if u.PasswordHash == nil || !password.SupportedHash(*u.PasswordHash) {
			return "", time.Time{}, ErrUnauthorized
		}
	}
	e, err := s.contact(ctx, q, binding, rec.Channel)
	if err != nil {
		return "", time.Time{}, err
	}
	contactBinding := s.contactBindingFor(binding, purpose, rec.Channel, *e)
	if rec.Purpose != purpose || rec.AccountID != binding.AccountID || rec.AuthVersion != binding.AuthVersion || rec.SessionID != binding.SessionID || rec.JKT != binding.JKT || rec.Destination != e.Destination || !hmac.Equal([]byte(rec.ContactBinding), []byte(hex.EncodeToString(contactBinding))) {
		return "", time.Time{}, ErrUnauthorized
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	proof := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(proof))
	params := db.CreateAccountDeletionActionProofParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: rec.Channel, ContactBinding: contactBinding, ExpiresAt: pgtype.Timestamptz{Time: rec.ExpiresAt, Valid: true},
	}
	var rows int64
	switch purpose {
	case contactcode.PurposeFirstPasskey:
		rows, err = q.CreateFirstPasskeyActionProof(ctx, db.CreateFirstPasskeyActionProofParams(params))
	case contactcode.PurposePasswordChange:
		rows, err = q.CreatePasswordChangeActionProof(ctx, db.CreatePasswordChangeActionProofParams(params))
	default:
		rows, err = q.CreateAccountDeletionActionProof(ctx, params)
	}
	if err != nil || rows != 1 {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	return proof, rec.ExpiresAt, nil
}

// ConsumeTx requires READ COMMITTED and never begins, commits or rolls back a
// transaction. The caller's action and this deletion therefore share one outcome.
func (s *Service) ConsumeTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof string) error {
	return s.consumeTx(ctx, tx, sess, proof, contactcode.PurposeAccountDeletion)
}

// ConsumePasswordChangeTx consumes even an authorized no-op in the caller's
// READ COMMITTED transaction. It never begins, commits or rolls back that transaction.
func (s *Service) ConsumePasswordChangeTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof string) error {
	return s.consumeTx(ctx, tx, sess, proof, contactcode.PurposePasswordChange)
}

func (s *Service) consumeTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof, purpose string) error {
	if s == nil {
		return ErrUnavailable
	}
	if missing(tx) {
		return ErrTransaction
	}
	var isolation string
	if err := tx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil || isolation != "read committed" {
		return ErrTransaction
	}
	if !capability(proof) {
		return ErrInvalid
	}
	if _, err := s.live(ctx, sess); err != nil {
		return err
	}
	binding, err := s.locked(ctx, tx, sess)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(proof))
	q := s.deps.Queries.WithTx(tx)
	params := db.GetAccountDeletionActionProofBindingParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
	}
	var row db.GetAccountDeletionActionProofBindingRow
	if purpose == contactcode.PurposePasswordChange {
		var changeRow db.GetPasswordChangeActionProofBindingRow
		changeRow, err = q.GetPasswordChangeActionProofBinding(ctx, db.GetPasswordChangeActionProofBindingParams(params))
		row = db.GetAccountDeletionActionProofBindingRow(changeRow)
	} else {
		row, err = q.GetAccountDeletionActionProofBinding(ctx, params)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return ErrUnavailable
	}
	e, err := s.contact(ctx, q, binding, row.Channel)
	if err != nil {
		return err
	}
	contactBinding := s.contactBindingFor(binding, purpose, row.Channel, *e)
	if !hmac.Equal(row.ContactBinding, contactBinding) {
		return ErrUnauthorized
	}
	consume := db.ConsumeAccountDeletionActionProofParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: row.Channel, ContactBinding: contactBinding,
	}
	var rows int64
	if purpose == contactcode.PurposePasswordChange {
		rows, err = q.ConsumePasswordChangeActionProof(ctx, db.ConsumePasswordChangeActionProofParams(consume))
	} else {
		rows, err = q.ConsumeAccountDeletionActionProof(ctx, consume)
	}
	if err != nil {
		return ErrUnavailable
	}
	if rows != 1 {
		return ErrInvalid
	}
	return nil
}

// CheckPasswordChange is a non-consuming preflight before password hashing.
// It takes no account lock and cannot replace the transactional consumer recheck.
func (s *Service) CheckPasswordChange(ctx context.Context, sess session.Session, proof string) error {
	if s == nil {
		return ErrUnavailable
	}
	if !capability(proof) {
		return ErrInvalid
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return err
	}
	q := s.deps.Queries
	u, err := q.GetUserByID(ctx, binding.AccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return ErrUnavailable
	}
	if err := s.eligible(ctx, q, u, binding.AccountID, binding.AuthVersion); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(proof))
	row, err := q.GetPasswordChangeActionProofBinding(ctx, db.GetPasswordChangeActionProofBindingParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalid
	}
	if err != nil {
		return ErrUnavailable
	}
	e, err := s.contact(ctx, q, binding, row.Channel)
	if err != nil {
		return err
	}
	if !hmac.Equal(row.ContactBinding, s.contactBindingFor(binding, contactcode.PurposePasswordChange, row.Channel, *e)) {
		return ErrUnauthorized
	}
	return nil
}

// CleanupExpired reclaims one bounded batch, exposing only the affected count.
func (s *Service) CleanupExpired(ctx context.Context, batchSize int32) (int64, error) {
	return s.cleanupExpired(ctx, batchSize, contactcode.PurposeAccountDeletion)
}

// CleanupExpiredPasswordChange reclaims at most 1000 expired password-change proofs.
func (s *Service) CleanupExpiredPasswordChange(ctx context.Context, batchSize int32) (int64, error) {
	return s.cleanupExpired(ctx, batchSize, contactcode.PurposePasswordChange)
}

// CleanupExpiredFirstPasskey reclaims at most 1000 expired start proofs.
func (s *Service) CleanupExpiredFirstPasskey(ctx context.Context, batchSize int32) (int64, error) {
	return s.cleanupExpired(ctx, batchSize, contactcode.PurposeFirstPasskey)
}

func (s *Service) cleanupExpired(ctx context.Context, batchSize int32, purpose string) (int64, error) {
	if s == nil {
		return 0, ErrUnavailable
	}
	if batchSize < 1 || batchSize > 1000 {
		return 0, ErrInvalid
	}
	var rows int64
	var err error
	switch purpose {
	case contactcode.PurposeFirstPasskey:
		rows, err = s.deps.Queries.CleanupExpiredFirstPasskeyActionProofs(ctx, batchSize)
	case contactcode.PurposePasswordChange:
		rows, err = s.deps.Queries.CleanupExpiredPasswordChangeActionProofs(ctx, batchSize)
	default:
		rows, err = s.deps.Queries.CleanupExpiredAccountDeletionActionProofs(ctx, batchSize)
	}
	if err != nil {
		return 0, ErrUnavailable
	}
	return rows, nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
