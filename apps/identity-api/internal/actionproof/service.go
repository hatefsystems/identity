// Package actionproof authorizes one account-deletion mutation, never step-up.
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
	if len(cfg.BindingKey) < 32 || len(cfg.BindingKey) > 64 {
		return nil, ErrInvalid
	}
	if missing(deps.DB) || deps.Queries == nil || deps.Codes == nil || missing(deps.Cipher) || missing(deps.Limiter) || missing(deps.Sessions) {
		return nil, ErrUnavailable
	}
	if !deps.Codes.DeletionChannelEnabled(contactcode.ChannelEmail) && !deps.Codes.DeletionChannelEnabled(contactcode.ChannelSMS) {
		return nil, ErrUnavailable
	}
	return &Service{key: append([]byte(nil), cfg.BindingKey...), deps: deps}, nil
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
	if u.ID != id || u.Status != "active" || u.DeletedAt.Valid || u.PasswordHash == nil || *u.PasswordHash == "" || u.IsMfaEnabled || u.AuthVersion != sess.AuthVersion {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	count, err := q.CountWebauthnCredentialsByUser(ctx, id)
	if err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	privileged, err := q.UserHasPrivilegedRole(ctx, id)
	if err != nil {
		return contactcode.DeletionBinding{}, ErrUnavailable
	}
	if count != 0 || privileged {
		return contactcode.DeletionBinding{}, ErrUnauthorized
	}
	return s.live(ctx, sess)
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
	// Whole typed evidence preserves purpose, method, channel and original time,
	// not merely destination. Structured encoding prevents boundary ambiguity.
	bound, _ := json.Marshal(struct {
		Binding  contactcode.DeletionBinding
		Action   string
		Channel  string
		Evidence contactproof.Evidence
	}{binding, "account_deletion", channel, evidence})
	defer clear(bound)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("actionproof:v1:contact\x00"))
	_, _ = mac.Write(bound)
	return mac.Sum(nil)
}

// Challenge verifies the exact password outside locks, then freezes authority.
// Provider I/O happens only after the account transaction has finished.
func (s *Service) Challenge(ctx context.Context, sess session.Session, secret, channel, sourceIP string) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, ErrUnavailable
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	if !s.deps.Codes.DeletionChannelEnabled(channel) {
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
	e, err := s.contact(ctx, q, binding, channel)
	if err != nil {
		return "", time.Time{}, err
	}
	contactBinding := hex.EncodeToString(s.contactBinding(binding, channel, *e))
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	return s.deps.Codes.RequestDeletion(ctx, binding, channel, e.Destination, contactBinding, sourceIP)
}

// Verify consumes the OTP once, then commits one digest-only deletion proof.
// No retry or proof escapes after a failed/ambiguous issuance or commit.
func (s *Service) Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, ErrUnavailable
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	rec, err := s.deps.Codes.VerifyDeletion(ctx, binding, challenge, code)
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
	e, err := s.contact(ctx, q, binding, rec.Channel)
	if err != nil {
		return "", time.Time{}, err
	}
	contactBinding := s.contactBinding(binding, rec.Channel, *e)
	if rec.Purpose != contactcode.PurposeAccountDeletion || rec.AccountID != binding.AccountID || rec.AuthVersion != binding.AuthVersion || rec.SessionID != binding.SessionID || rec.JKT != binding.JKT || rec.Destination != e.Destination || !hmac.Equal([]byte(rec.ContactBinding), []byte(hex.EncodeToString(contactBinding))) {
		return "", time.Time{}, ErrUnauthorized
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	proof := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(proof))
	rows, err := q.CreateAccountDeletionActionProof(ctx, db.CreateAccountDeletionActionProofParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: rec.Channel, ContactBinding: contactBinding, ExpiresAt: pgtype.Timestamptz{Time: rec.ExpiresAt, Valid: true},
	})
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
	row, err := q.GetAccountDeletionActionProofBinding(ctx, db.GetAccountDeletionActionProofBindingParams{
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
	contactBinding := s.contactBinding(binding, row.Channel, *e)
	if !hmac.Equal(row.ContactBinding, contactBinding) {
		return ErrUnauthorized
	}
	rows, err := q.ConsumeAccountDeletionActionProof(ctx, db.ConsumeAccountDeletionActionProofParams{
		ProofDigest: digest[:], UserID: binding.AccountID, SessionID: binding.SessionID, Jkt: binding.JKT, AuthVersion: binding.AuthVersion,
		Channel: row.Channel, ContactBinding: contactBinding,
	})
	if err != nil {
		return ErrUnavailable
	}
	if rows != 1 {
		return ErrInvalid
	}
	return nil
}

// CleanupExpired reclaims one bounded batch, exposing only the affected count.
func (s *Service) CleanupExpired(ctx context.Context, batchSize int32) (int64, error) {
	if s == nil {
		return 0, ErrUnavailable
	}
	if batchSize < 1 || batchSize > 1000 {
		return 0, ErrInvalid
	}
	rows, err := s.deps.Queries.CleanupExpiredAccountDeletionActionProofs(ctx, batchSize)
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
