package actionproof

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/password"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

var (
	// ErrContactExpired identifies expiry of an otherwise bounded authorization.
	ErrContactExpired = errors.New("actionproof: contact authority expired")
	// ErrEmailRemovalUnavailable is the temporary operation-level T28/T41 gate.
	ErrEmailRemovalUnavailable = errors.New("actionproof: primary email removal unavailable")
)

// ContactAuthorization is frozen authority after single-use SQL consumption.
// It is neither a Step-up grant nor new-destination ownership evidence.
type ContactAuthorization struct {
	Action      string
	Target      string
	Channel     string
	EvidenceMAC []byte
	SessionID   string
	DPoPJKT     string
	AuthVersion int64
	ExpiresAt   time.Time
}

// NewContacts retains bounded SQL/code readers when issuance is disabled. The
// dedicated complete-evidence binding key is required independently of senders.
func NewContacts(cfg Config, deps Deps) (*Service, error) {
	if len(cfg.BindingKey) < 32 || len(cfg.BindingKey) > 64 || bytes.Equal(cfg.BindingKey, make([]byte, len(cfg.BindingKey))) {
		return nil, ErrInvalid
	}
	if missing(deps.DB) || deps.Queries == nil || missing(deps.Cipher) || missing(deps.Sessions) || cfg.ContactIssuanceEnabled && (deps.Codes == nil || missing(deps.Limiter)) {
		return nil, ErrUnavailable
	}
	return &Service{key: append([]byte(nil), cfg.BindingKey...), deps: deps, contactIssuance: cfg.ContactIssuanceEnabled}, nil
}

func validContactAction(action, target string) bool {
	return (action == contactcode.PurposeContactChange || action == contactcode.PurposeContactRemove) && (target == "email" || target == "phone")
}

// contactCurrent requires the caller's existing username/account/row lock order.
// The MFA-enrollment eligibility predicate includes supported usable password
// login, immutable admitted username, all-role refusal and configured MFA refusal.
func (s *Service) contactCurrent(ctx context.Context, tx pgx.Tx, sess session.Session, action, target string, authority username.GuardAuthority) (contactcode.DeletionBinding, error) {
	if !validContactAction(action, target) {
		return contactcode.DeletionBinding{}, ErrInvalid
	}
	binding, err := s.mfaEnrollmentCurrent(ctx, tx, sess, authority)
	if err != nil {
		return contactcode.DeletionBinding{}, err
	}
	if action == contactcode.PurposeContactRemove && target == "email" {
		u, err := s.deps.Queries.WithTx(tx).GetUserByID(ctx, binding.AccountID)
		if err != nil {
			return contactcode.DeletionBinding{}, ErrUnavailable
		}
		if u.Email != nil {
			return contactcode.DeletionBinding{}, ErrEmailRemovalUnavailable
		}
	}
	return binding, nil
}

func (s *Service) contactManagementMAC(binding contactcode.DeletionBinding, action, target, channel string, evidence contactproof.Evidence) []byte {
	bound, _ := json.Marshal(struct {
		Binding                 contactcode.DeletionBinding
		Action, Target, Channel string
		Evidence                contactproof.Evidence
	}{binding, action, target, channel, evidence})
	defer clear(bound)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("actionproof:contact-management:v1:complete-evidence\x00"))
	_, _ = mac.Write(bound)
	return mac.Sum(nil)
}

func (s *Service) contactAuthorization(ctx context.Context, tx pgx.Tx, binding contactcode.DeletionBinding, auth ContactAuthorization) error {
	if !validContactAction(auth.Action, auth.Target) || auth.Channel != contactcode.ChannelEmail && auth.Channel != contactcode.ChannelSMS || len(auth.EvidenceMAC) != sha256.Size || auth.SessionID != binding.SessionID || auth.DPoPJKT != binding.JKT || auth.AuthVersion != binding.AuthVersion || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.Equal(auth.ExpiresAt.Truncate(time.Millisecond)) {
		return ErrUnauthorized
	}
	if !time.Now().Before(auth.ExpiresAt) {
		return ErrContactExpired
	}
	evidence, err := s.contact(ctx, s.deps.Queries.WithTx(tx), binding, auth.Channel)
	if err != nil {
		return err
	}
	if !hmac.Equal(auth.EvidenceMAC, s.contactManagementMAC(binding, auth.Action, auth.Target, auth.Channel, *evidence)) {
		return ErrUnauthorized
	}
	if !time.Now().Before(auth.ExpiresAt) {
		return ErrContactExpired
	}
	return nil
}

// ContactChallenge checks exact bounded password bytes outside account locks.
// Delivery follows quota admission and one final deciding authority transaction.
func (s *Service) ContactChallenge(ctx context.Context, sess session.Session, secret, channel, action, target, source string) (string, time.Time, error) {
	if s == nil {
		return "", time.Time{}, ErrUnavailable
	}
	if !validContactAction(action, target) || len(secret) == 0 || len(secret) > password.MaxPasswordBytes || !utf8.ValidString(secret) {
		return "", time.Time{}, ErrInvalid
	}
	if !s.contactIssuance || s.deps.Codes == nil || !s.deps.Codes.ContactChannelEnabled(action, channel) {
		return "", time.Time{}, contactcode.ErrDisabled
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	u, err := s.deps.Queries.GetUserByID(ctx, binding.AccountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, ErrUnauthorized
	}
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	// T28/T41 admission is operation-level and precedes avoidable hashing/send.
	if action == contactcode.PurposeContactRemove && target == "email" && u.Email != nil {
		return "", time.Time{}, ErrEmailRemovalUnavailable
	}
	if err := s.eligible(ctx, s.deps.Queries, u, binding.AccountID, binding.AuthVersion); err != nil {
		return "", time.Time{}, err
	}
	if !s.policy.PasswordLoginEnabled || !password.SupportedHash(*u.PasswordHash) || len(u.MfaTotpSecretEncrypted) != 0 {
		return "", time.Time{}, ErrUnauthorized
	}
	deadline := time.Now().UTC().Add(s.deps.Codes.ContactChallengeTTL(action, channel))
	for _, limit := range []time.Time{sess.AbsoluteExpiry, sess.IdleExpiry} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	live, err := s.deps.Sessions.LookupByID(ctx, sess.UserID, sess.ID)
	if err != nil || live.AuthVersion != sess.AuthVersion || live.DPoPJKT != sess.DPoPJKT || live.ID != sess.ID || live.UserID != sess.UserID || live.Kind != session.KindAuthenticated || !live.AuthVersionSet {
		return "", time.Time{}, ErrUnauthorized
	}
	for _, limit := range []time.Time{live.AbsoluteExpiry, live.IdleExpiry} {
		if limit.Before(deadline) {
			deadline = limit
		}
	}
	deadline = deadline.UTC().Truncate(time.Millisecond)
	if !time.Now().Before(deadline) {
		return "", time.Time{}, ErrContactExpired
	}
	if err := s.limitPassword(ctx, binding.AccountID, source); err != nil {
		return "", time.Time{}, err
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
	var authorization ContactAuthorization
	var destination string
	check := func(ctx context.Context) error {
		tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return ErrUnavailable
		}
		defer rollback(ctx, tx)
		authority, err := s.policy.Guard(ctx, tx)
		if err != nil {
			return ErrUnavailable
		}
		if _, err := s.locked(ctx, tx, sess); err != nil {
			return err
		}
		binding, err := s.contactCurrent(ctx, tx, sess, action, target, authority)
		if err != nil {
			return err
		}
		current, err := s.deps.Queries.WithTx(tx).GetUserByID(ctx, binding.AccountID)
		if err != nil || current.PasswordHash == nil || *current.PasswordHash != *u.PasswordHash {
			return ErrUnauthorized
		}
		if authorization.Action == "" {
			evidence, err := s.contact(ctx, s.deps.Queries.WithTx(tx), binding, channel)
			if err != nil {
				return err
			}
			destination = evidence.Destination
			authorization = ContactAuthorization{action, target, channel, s.contactManagementMAC(binding, action, target, channel, *evidence), binding.SessionID, binding.JKT, binding.AuthVersion, deadline}
		}
		if err := s.contactAuthorization(ctx, tx, binding, authorization); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return ErrOutcomeUnknown
		}
		return nil
	}
	if err := check(ctx); err != nil {
		return "", time.Time{}, err
	}
	return s.deps.Codes.RequestContactAction(ctx, binding, action, target, channel, destination, hex.EncodeToString(authorization.EvidenceMAC), deadline, source, check)
}

// ContactVerify completes inventoried pending codes even with issuance/sending
// disabled, preserving their original expiry rather than issuing a fresh TTL.
func (s *Service) ContactVerify(ctx context.Context, sess session.Session, challenge, code, action string) (string, time.Time, error) {
	if s == nil || s.deps.Codes == nil {
		return "", time.Time{}, ErrUnavailable
	}
	if !capability(challenge) || !validContactAction(action, "email") || len(code) != 6 || !asciiCode(code) {
		return "", time.Time{}, ErrInvalid
	}
	binding, err := s.live(ctx, sess)
	if err != nil {
		return "", time.Time{}, err
	}
	rec, err := s.deps.Codes.VerifyContactAction(ctx, binding, challenge, code, action)
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
	guard, err := s.policy.Guard(ctx, tx)
	if err != nil {
		return "", time.Time{}, ErrUnavailable
	}
	if _, err := s.locked(ctx, tx, sess); err != nil {
		return "", time.Time{}, err
	}
	binding, err = s.contactCurrent(ctx, tx, sess, action, rec.Target, guard)
	if err != nil {
		return "", time.Time{}, err
	}
	mac, err := hex.DecodeString(rec.ContactBinding)
	if err != nil {
		return "", time.Time{}, ErrUnauthorized
	}
	auth := ContactAuthorization{action, rec.Target, rec.Channel, mac, rec.SessionID, rec.JKT, rec.AuthVersion, rec.ExpiresAt}
	if err := s.contactAuthorization(ctx, tx, binding, auth); err != nil {
		return "", time.Time{}, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	proof := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(proof))
	result, err := tx.Exec(ctx, `INSERT INTO public.contact_management_action_proofs
		(digest,user_id,session_id,dpop_jkt,auth_version,action,target,channel,contact_mac,expires_at)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz
		WHERE $10::timestamptz > clock_timestamp() AND $10::timestamptz <= clock_timestamp() + INTERVAL '3 minutes'`,
		digest[:], binding.AccountID, binding.SessionID, binding.JKT, binding.AuthVersion, auth.Action, auth.Target, auth.Channel, auth.EvidenceMAC, auth.ExpiresAt)
	if err != nil || result.RowsAffected() != 1 {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	if err := tx.Commit(ctx); err != nil {
		return "", time.Time{}, ErrOutcomeUnknown
	}
	return proof, auth.ExpiresAt, nil
}

func asciiCode(code string) bool {
	for _, b := range []byte(code) {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// ConsumeContactStartTx owns no locks or finalization. The caller has already
// acquired username guard -> account advisory -> user row. A DELETE matches the
// complete original SQL row, including its precise absolute deadline.
func (s *Service) ConsumeContactStartTx(ctx context.Context, tx pgx.Tx, sess session.Session, proof, action, target string, guard username.GuardAuthority) (ContactAuthorization, error) {
	if s == nil {
		return ContactAuthorization{}, ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return ContactAuthorization{}, err
	}
	if !capability(proof) || !validContactAction(action, target) {
		return ContactAuthorization{}, ErrInvalid
	}
	binding, err := s.contactCurrent(ctx, tx, sess, action, target, guard)
	if err != nil {
		return ContactAuthorization{}, err
	}
	digest := sha256.Sum256([]byte(proof))
	var expiry pgtype.Timestamptz
	var channel string
	var mac []byte
	err = tx.QueryRow(ctx, `SELECT expires_at,channel,contact_mac FROM public.contact_management_action_proofs
		WHERE digest=$1 AND user_id=$2 AND session_id=$3 AND dpop_jkt=$4 AND auth_version=$5
		AND action=$6 AND target=$7 AND expires_at > clock_timestamp()`, digest[:], binding.AccountID, binding.SessionID, binding.JKT, binding.AuthVersion, action, target).Scan(&expiry, &channel, &mac)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContactAuthorization{}, ErrInvalid
	}
	if err != nil {
		return ContactAuthorization{}, ErrUnavailable
	}
	if !expiry.Valid || expiry.InfinityModifier != 0 {
		return ContactAuthorization{}, ErrInvalid
	}
	auth := ContactAuthorization{action, target, channel, append([]byte(nil), mac...), binding.SessionID, binding.JKT, binding.AuthVersion, expiry.Time}
	if err := s.contactAuthorization(ctx, tx, binding, auth); err != nil {
		return ContactAuthorization{}, err
	}
	var consumedExpiry pgtype.Timestamptz
	var consumedChannel string
	var consumedMAC []byte
	err = tx.QueryRow(ctx, `DELETE FROM public.contact_management_action_proofs
		WHERE digest=$1 AND user_id=$2 AND session_id=$3 AND dpop_jkt=$4 AND auth_version=$5
		AND action=$6 AND target=$7 AND channel=$8 AND contact_mac=$9 AND expires_at=$10::timestamptz
		AND expires_at > clock_timestamp() RETURNING expires_at,channel,contact_mac`,
		digest[:], binding.AccountID, binding.SessionID, binding.JKT, binding.AuthVersion, action, target, channel, mac, expiry.Time).Scan(&consumedExpiry, &consumedChannel, &consumedMAC)
	if errors.Is(err, pgx.ErrNoRows) {
		return ContactAuthorization{}, ErrInvalid
	}
	if err != nil {
		return ContactAuthorization{}, ErrUnavailable
	}
	if !consumedExpiry.Valid || consumedExpiry.InfinityModifier != 0 || !consumedExpiry.Time.Equal(auth.ExpiresAt) || consumedChannel != auth.Channel || !hmac.Equal(consumedMAC, auth.EvidenceMAC) {
		return ContactAuthorization{}, ErrUnauthorized
	}
	if !time.Now().Before(auth.ExpiresAt) {
		return ContactAuthorization{}, ErrContactExpired
	}
	return auth, nil
}

// ValidateContactTx reads only frozen authority/current evidence; it never
// re-redeems the deleted proof, renews a session or requires a delivery provider.
func (s *Service) ValidateContactTx(ctx context.Context, tx pgx.Tx, sess session.Session, auth ContactAuthorization, guard username.GuardAuthority) error {
	if s == nil {
		return ErrUnavailable
	}
	if err := firstPasskeyTransaction(ctx, tx); err != nil {
		return err
	}
	binding, err := s.contactCurrent(ctx, tx, sess, auth.Action, auth.Target, guard)
	if err != nil {
		return err
	}
	return s.contactAuthorization(ctx, tx, binding, auth)
}

// CleanupExpiredContacts deletes at most 1000 expired, unused SQL proofs.
func (s *Service) CleanupExpiredContacts(ctx context.Context, batchSize int32) (int64, error) {
	if s == nil {
		return 0, ErrUnavailable
	}
	if batchSize < 1 || batchSize > 1000 {
		return 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, ErrUnavailable
	}
	defer rollback(ctx, tx)
	result, err := tx.Exec(ctx, `WITH expired AS (SELECT digest FROM public.contact_management_action_proofs
		WHERE expires_at <= clock_timestamp() ORDER BY expires_at,digest LIMIT $1)
		DELETE FROM public.contact_management_action_proofs p USING expired e WHERE p.digest=e.digest`, batchSize)
	if err != nil {
		return 0, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, ErrOutcomeUnknown
	}
	return result.RowsAffected(), nil
}
