// Package contactmanager owns the primary-contact maintenance transaction boundary.
package contactmanager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Errors are fixed public categories; underlying diagnostics may contain PII.
var (
	ErrInvalid                 = errors.New("contactmanager: invalid request")
	ErrUnauthorized            = errors.New("contactmanager: fresh authority unavailable")
	ErrConflict                = errors.New("contactmanager: contact conflicts with account state")
	ErrUnavailable             = errors.New("contactmanager: dependency unavailable")
	ErrOutcomeUnknown          = errors.New("contactmanager: outcome unknown")
	ErrEmailRemovalUnavailable = errors.New("contactmanager: email removal unavailable")
	ErrExpired                 = errors.New("contactmanager: authority or ownership expired")
	ErrInvalidCode             = errors.New("contactmanager: invalid ownership code")
	ErrRateLimited             = errors.New("contactmanager: bounded quota exhausted")
)

// Beginner opens short transactions, without automatic retries.
type Beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// SessionReader checks live Redis authority without renewal or SQL locking.
type SessionReader interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// Indexer preserves the existing, distinct email and maintenance-phone indexing rules.
type Indexer interface {
	Compute(string) string
	ComputeEmail(string) (string, error)
}

// Proofs consumes start authority once and revalidates its frozen bindings read-only.
type Proofs interface {
	ConsumeContactStartTx(context.Context, pgx.Tx, session.Session, string, string, string, username.GuardAuthority) (actionproof.ContactAuthorization, error)
	ValidateContactTx(context.Context, pgx.Tx, session.Session, actionproof.ContactAuthorization, username.GuardAuthority) error
}

// Deps shares current account, session, evidence and bounded code infrastructure.
type Deps struct {
	DB       Beginner
	Queries  *db.Queries
	Sessions SessionReader
	Cipher   contactproof.Cipher
	Indexer  Indexer
	Codes    *contactcode.Service
	Proofs   Proofs
	Policy   accountpolicy.Policy
}

// StrongAuthorization is genuinely earned and spent by the HTTP Step-up boundary.
// It is not an action-scoped grant and must never be reconstructed from a session.
type StrongAuthorization struct {
	UserID, SessionID, DPoPJKT string
	AuthVersion                int64
	Method                     string
	ExpiresAt                  time.Time
}

// Authorization carries exactly one already-spent strong grant or SQL action proof.
type Authorization struct {
	Grant *StrongAuthorization
	Proof string
}

// StartResult escapes only after acknowledged pending commit and exact code activation.
type StartResult struct {
	VerificationID string
	ExpiresAt      time.Time
}

// Contact reports current canonical value and only authenticated verification evidence.
type Contact struct {
	Value      string     `json:"value"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at"`
}

// Contacts excludes backup data, pending handles and authentication evidence.
type Contacts struct {
	Email *Contact `json:"email"`
	Phone *Contact `json:"phone"`
}

// Service owns contact transactions, never issuing sessions or nesting store mutations.
type Service struct{ deps Deps }

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	return (r.Kind() == reflect.Pointer || r.Kind() == reflect.Interface) && r.IsNil()
}

// New retains read/remove operation even when delivery and proof issuance are off.
func New(deps Deps) (*Service, error) {
	if missing(deps.DB) || deps.Queries == nil || missing(deps.Sessions) || missing(deps.Cipher) {
		return nil, ErrUnavailable
	}
	if missing(deps.Indexer) {
		deps.Indexer = nil
	}
	if missing(deps.Proofs) {
		deps.Proofs = nil
	}
	return &Service{deps}, nil
}

func validHandle(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}
func validTarget(target string) bool {
	return target == contactproof.Email || target == contactproof.Phone
}
func channelFor(target string) string {
	if target == contactproof.Phone {
		return contactcode.ChannelSMS
	}
	return contactcode.ChannelEmail
}
func stamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func rollback(ctx context.Context, tx pgx.Tx) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanup)
}

// Preflight must precede irreversible Step-up consumption, including SMS.ir policy.
func (s *Service) Preflight(target, value, sourceIP string) (string, error) {
	if s == nil || !validTarget(target) {
		return "", ErrInvalid
	}
	var canonical string
	var err error
	if target == contactproof.Email {
		canonical, err = emailaddress.Canonicalize(value)
	} else {
		canonical, err = smsotp.NormalizePhone(value)
	}
	if err != nil {
		return "", ErrInvalid
	}
	if target == contactproof.Phone && s.deps.Indexer == nil {
		return "", ErrUnavailable
	}
	if target == contactproof.Email && s.deps.Indexer != nil {
		if _, err = s.deps.Indexer.ComputeEmail(canonical); err != nil {
			return "", ErrInvalid
		}
	}
	if s.deps.Codes == nil {
		return "", contactcode.ErrDisabled
	}
	if !contactcode.OwnershipDestinationSupported(target, canonical) {
		return "", ErrInvalid
	}
	if !s.deps.Codes.OwnershipChannelEnabled(channelFor(target)) {
		return "", contactcode.ErrDisabled
	}
	if sourceIP == "" || len(sourceIP) > 128 || strings.HasPrefix(ratelimit.Subnet(sourceIP), "invalid/") {
		return "", ErrInvalid
	}
	return canonical, nil
}

func (s *Service) live(ctx context.Context, sess session.Session, user db.User) (session.Session, error) {
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil || id.String() != sess.UserID || user.ID != id || user.Status != "active" || user.DeletedAt.Valid || !sess.AuthVersionSet || sess.AuthVersion < 0 || user.AuthVersion != sess.AuthVersion || sess.Kind != session.KindAuthenticated || len(sess.ID) == 0 || len(sess.ID) > 128 || !validHandle(sess.DPoPJKT) {
		return session.Session{}, ErrUnauthorized
	}
	current, err := s.deps.Sessions.LookupByID(ctx, sess.UserID, sess.ID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return session.Session{}, ErrUnauthorized
		}
		return session.Session{}, ErrUnavailable
	}
	now := time.Now()
	if current.UserID != sess.UserID || current.ID != sess.ID || current.DPoPJKT != sess.DPoPJKT || !current.AuthVersionSet || current.AuthVersion != sess.AuthVersion || current.Kind != session.KindAuthenticated || !now.Before(current.IdleExpiry) || !now.Before(current.AbsoluteExpiry) || !now.Before(sess.IdleExpiry) || !now.Before(sess.AbsoluteExpiry) {
		return session.Session{}, ErrUnauthorized
	}
	return current, nil
}

// lock uses the shared username -> account -> row order before separate deciding reads.
func (s *Service) lock(ctx context.Context, tx pgx.Tx, sess session.Session) (*db.Queries, db.User, username.GuardAuthority, session.Session, error) {
	authority, err := s.deps.Policy.Guard(ctx, tx)
	if err != nil {
		return nil, db.User{}, authority, session.Session{}, ErrUnavailable
	}
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil || id.String() != sess.UserID {
		return nil, db.User{}, authority, session.Session{}, ErrUnauthorized
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return nil, db.User{}, authority, session.Session{}, ErrUnavailable
	}
	q := s.deps.Queries.WithTx(tx)
	u, err := q.GetUserByIDForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, db.User{}, authority, session.Session{}, ErrUnauthorized
	}
	if err != nil {
		return nil, db.User{}, authority, session.Session{}, ErrUnavailable
	}
	live, err := s.live(ctx, sess, u)
	return q, u, authority, live, err
}

func strong(sess session.Session, grant *StrongAuthorization) error {
	if grant == nil || grant.UserID != sess.UserID || grant.SessionID != sess.ID || grant.DPoPJKT != sess.DPoPJKT || grant.AuthVersion != sess.AuthVersion || grant.Method != "webauthn_uv" && grant.Method != "totp" {
		return ErrUnauthorized
	}
	if !time.Now().Before(grant.ExpiresAt) {
		return ErrExpired
	}
	return nil
}
func (s *Service) protection(ctx context.Context, tx pgx.Tx, u db.User, guard username.GuardAuthority, method string) error {
	state, err := s.deps.Policy.Read(ctx, tx, u, guard)
	if err != nil {
		return ErrUnavailable
	}
	if err := state.Check(); err != nil {
		return err
	}
	if method == "webauthn_uv" && state.Passkeys == 0 || method == "totp" && !state.TOTP {
		return ErrUnauthorized
	}
	return nil
}
func (s *Service) authorize(ctx context.Context, tx pgx.Tx, sess session.Session, u db.User, guard username.GuardAuthority, auth Authorization, action, target string) (actionproof.ContactAuthorization, string, error) {
	if (auth.Grant == nil) == (auth.Proof == "") {
		return actionproof.ContactAuthorization{}, "", ErrUnauthorized
	}
	method := "password_contact"
	if auth.Grant != nil {
		method = auth.Grant.Method
		if err := strong(sess, auth.Grant); err != nil {
			return actionproof.ContactAuthorization{}, "", err
		}
	}
	if err := s.protection(ctx, tx, u, guard, method); err != nil {
		return actionproof.ContactAuthorization{}, "", err
	}
	if auth.Grant != nil {
		return actionproof.ContactAuthorization{Action: action, Target: target, SessionID: sess.ID, DPoPJKT: sess.DPoPJKT, AuthVersion: sess.AuthVersion, ExpiresAt: auth.Grant.ExpiresAt}, method, nil
	}
	if s.deps.Proofs == nil || !validHandle(auth.Proof) {
		return actionproof.ContactAuthorization{}, "", ErrUnauthorized
	}
	proof, err := s.deps.Proofs.ConsumeContactStartTx(ctx, tx, sess, auth.Proof, action, target, guard)
	return proof, method, safeError(err)
}

// Read returns only current primary contacts, with truthful evidence from one snapshot.
func (s *Service) Read(ctx context.Context, sess session.Session) (Contacts, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil {
		return Contacts{}, ErrUnauthorized
	}
	row, err := s.deps.Queries.GetCurrentPrimaryContacts(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Contacts{}, ErrUnauthorized
	}
	if err != nil {
		return Contacts{}, ErrUnavailable
	}
	if _, err := s.live(ctx, sess, db.User{ID: row.ID, Status: row.Status, DeletedAt: row.DeletedAt, AuthVersion: row.AuthVersion}); err != nil {
		return Contacts{}, err
	}
	var out Contacts
	if row.Email != nil {
		out.Email = s.contact(ctx, id, contactproof.Email, *row.Email, row.EmailEvidence)
	}
	if len(row.PhoneEncrypted) != 0 {
		plain, err := s.deps.Cipher.Decrypt(ctx, row.PhoneEncrypted)
		if err != nil {
			clear(plain)
			return Contacts{}, ErrUnavailable
		}
		out.Phone = s.contact(ctx, id, contactproof.Phone, string(plain), row.PhoneEvidence)
		clear(plain)
	}
	return out, nil
}
func (s *Service) contact(ctx context.Context, id uuid.UUID, channel, value string, evidence []byte) *Contact {
	contact := &Contact{Value: value}
	proof, err := contactproof.Open(ctx, s.deps.Cipher, evidence, id, channel, value)
	if err == nil && proof != nil {
		contact.Verified = true
		at := proof.VerifiedAt
		contact.VerifiedAt = &at
	}
	return contact
}

// pendingEnvelope authenticates the exact destination and every frozen row binding.
type pendingEnvelope struct {
	Purpose                string    `json:"purpose"`
	Digest                 string    `json:"digest"`
	UserID                 uuid.UUID `json:"user_id"`
	SessionID              string    `json:"session_id"`
	DPoPJKT                string    `json:"dpop_jkt"`
	AuthVersion            int64     `json:"auth_version"`
	Target                 string    `json:"target"`
	Method                 string    `json:"method"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	Channel                *string   `json:"channel"`
	ContactMAC             []byte    `json:"contact_mac"`
	OriginalState          []byte    `json:"original_state"`
	ExpiresAt              time.Time `json:"expires_at"`
	Destination            string    `json:"destination"`
}

func envelopeFor(row db.ContactChangeAttempt, destination string) pendingEnvelope {
	// SQL preserves the instant, not Go's location; sealed bytes are canonical UTC.
	return pendingEnvelope{"contact_change_destination:v1", hex.EncodeToString(row.Digest), row.UserID, row.SessionID, row.DpopJkt, row.AuthVersion, row.Target, row.AuthorizationMethod, row.AuthorizationExpiresAt.Time.UTC(), row.Channel, row.ContactMac, row.OriginalStateDigest, row.ExpiresAt.Time.UTC(), destination}
}
func (s *Service) seal(ctx context.Context, row db.ContactChangeAttempt, destination string) ([]byte, error) {
	plain, err := json.Marshal(envelopeFor(row, destination))
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	blob, err := s.deps.Cipher.Encrypt(ctx, plain)
	if err != nil || len(blob) < 90 || len(blob) > 4096 {
		clear(blob)
		return nil, ErrUnavailable
	}
	return blob, nil
}
func (s *Service) open(ctx context.Context, row db.ContactChangeAttempt) (string, error) {
	if len(row.DestinationEncrypted) < 90 || len(row.DestinationEncrypted) > 4096 || !row.ExpiresAt.Valid || !row.AuthorizationExpiresAt.Valid || row.ExpiresAt.InfinityModifier != 0 || row.AuthorizationExpiresAt.InfinityModifier != 0 {
		return "", ErrUnauthorized
	}
	plain, err := s.deps.Cipher.Decrypt(ctx, row.DestinationEncrypted)
	defer clear(plain)
	if err != nil || len(plain) > 4007 {
		return "", ErrUnauthorized
	}
	var decoded pendingEnvelope
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", ErrUnauthorized
	}
	expected, err := json.Marshal(envelopeFor(row, decoded.Destination))
	defer clear(expected)
	if err != nil || !bytes.Equal(plain, expected) {
		return "", ErrUnauthorized
	}
	if row.Target == contactproof.Email {
		canonical, err := emailaddress.Canonicalize(decoded.Destination)
		if err != nil || canonical != decoded.Destination {
			return "", ErrUnauthorized
		}
	} else {
		canonical, err := smsotp.NormalizePhone(decoded.Destination)
		if row.Target != contactproof.Phone || err != nil || canonical != decoded.Destination {
			return "", ErrUnauthorized
		}
	}
	return decoded.Destination, nil
}
func (s *Service) originalState(ctx context.Context, q *db.Queries, u db.User, target string) ([]byte, error) {
	row, err := q.GetCurrentContactEvidence(ctx, db.GetCurrentContactEvidenceParams{UserID: u.ID, Channel: target})
	if err != nil || row.ID != u.ID {
		return nil, ErrUnavailable
	}
	state := struct {
		UserID   uuid.UUID
		Target   string
		Email    *string
		Phone    []byte
		Index    *string
		Evidence []byte
	}{UserID: u.ID, Target: target, Evidence: row.EvidenceEncrypted}
	if target == contactproof.Email {
		state.Email = u.Email
	} else {
		state.Phone = u.PhoneEncrypted
		state.Index = u.PhoneBlindIndex
	}
	plain, err := json.Marshal(state)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plain)
	digest := sha256.Sum256(plain)
	return digest[:], nil
}
func attemptParams(sess session.Session, target, handle string) db.GetContactChangeAttemptParams {
	digest := sha256.Sum256([]byte(handle))
	id, _ := uuid.Parse(sess.UserID)
	return db.GetContactChangeAttemptParams{Digest: digest[:], UserID: id, SessionID: sess.ID, DpopJkt: sess.DPoPJKT, AuthVersion: sess.AuthVersion, Target: target}
}
func (s *Service) validatePending(ctx context.Context, tx pgx.Tx, q *db.Queries, sess session.Session, u db.User, row db.ContactChangeAttempt, guard username.GuardAuthority) error {
	if !time.Now().Before(row.ExpiresAt.Time) || !time.Now().Before(row.AuthorizationExpiresAt.Time) {
		return ErrExpired
	}
	live, err := s.live(ctx, sess, u)
	if err != nil {
		return err
	}
	if live.IdleExpiry.Before(row.ExpiresAt.Time) || live.AbsoluteExpiry.Before(row.ExpiresAt.Time) {
		return ErrExpired
	}
	state, err := s.originalState(ctx, q, u, row.Target)
	if err != nil {
		return err
	}
	if !bytes.Equal(state, row.OriginalStateDigest) {
		return ErrUnauthorized
	}
	if err := s.protection(ctx, tx, u, guard, row.AuthorizationMethod); err != nil {
		return err
	}
	if row.AuthorizationMethod == "password_contact" {
		if s.deps.Proofs == nil || row.Channel == nil {
			return ErrUnauthorized
		}
		authorization := actionproof.ContactAuthorization{Action: "contact_change", Target: row.Target, Channel: *row.Channel, EvidenceMAC: row.ContactMac, SessionID: row.SessionID, DPoPJKT: row.DpopJkt, AuthVersion: row.AuthVersion, ExpiresAt: row.AuthorizationExpiresAt.Time}
		if err := s.deps.Proofs.ValidateContactTx(ctx, tx, sess, authorization, guard); err != nil {
			return safeError(err)
		}
	} else if row.AuthorizationMethod != "webauthn_uv" && row.AuthorizationMethod != "totp" {
		return ErrUnauthorized
	}
	if !time.Now().Before(row.ExpiresAt.Time) {
		return ErrExpired
	}
	return nil
}

// Start spends old authority once, commits pending state, then admits one exact send.
func (s *Service) Start(ctx context.Context, sess session.Session, target, value string, auth Authorization, sourceIP string) (StartResult, error) {
	destination, err := s.Preflight(target, value, sourceIP)
	if err != nil {
		return StartResult{}, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return StartResult{}, ErrUnavailable
	}
	handle := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	digest := sha256.Sum256([]byte(handle))
	deadlineCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(deadlineCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return StartResult{}, ErrUnavailable
	}
	defer rollback(deadlineCtx, tx)
	q, u, guard, live, err := s.lock(deadlineCtx, tx, sess)
	if err != nil {
		return StartResult{}, err
	}
	authority, method, err := s.authorize(deadlineCtx, tx, sess, u, guard, auth, "contact_change", target)
	if err != nil {
		return StartResult{}, err
	}
	expires := time.Now().UTC().Add(s.deps.Codes.OwnershipTTL(channelFor(target)))
	for _, limit := range []time.Time{authority.ExpiresAt, sess.IdleExpiry, sess.AbsoluteExpiry, live.IdleExpiry, live.AbsoluteExpiry} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	expires = expires.UTC().Truncate(time.Millisecond)
	if !time.Now().Before(expires) {
		return StartResult{}, ErrExpired
	}
	original, err := s.originalState(deadlineCtx, q, u, target)
	if err != nil {
		return StartResult{}, err
	}
	row := db.ContactChangeAttempt{Digest: digest[:], UserID: u.ID, SessionID: sess.ID, DpopJkt: sess.DPoPJKT, AuthVersion: sess.AuthVersion, Target: target, AuthorizationMethod: method, AuthorizationExpiresAt: stamp(authority.ExpiresAt.UTC().Truncate(time.Microsecond)), OriginalStateDigest: original, ExpiresAt: stamp(expires)}
	if method == "password_contact" {
		row.Channel = &authority.Channel
		row.ContactMac = authority.EvidenceMAC
	}
	row.DestinationEncrypted, err = s.seal(deadlineCtx, row, destination)
	if err != nil {
		return StartResult{}, err
	}
	defer clear(row.DestinationEncrypted)
	binding := contactcode.OwnershipBinding{DeletionBinding: contactcode.DeletionBinding{AccountID: u.ID, AuthVersion: sess.AuthVersion, SessionID: sess.ID, JKT: sess.DPoPJKT}, Target: target, Destination: destination}
	prepared, err := s.deps.Codes.PrepareOwnership(deadlineCtx, binding, handle, expires, sourceIP)
	if err != nil {
		return StartResult{}, safeError(err)
	}
	defer prepared.Clear()
	if !prepared.ExpiresAt().Equal(expires) {
		return StartResult{}, ErrUnavailable
	}
	if _, err := q.DeleteCurrentContactChangeAttempt(deadlineCtx, db.DeleteCurrentContactChangeAttemptParams{UserID: u.ID, Target: target}); err != nil {
		return StartResult{}, ErrUnavailable
	}
	count, err := q.CreateContactChangeAttempt(deadlineCtx, db.CreateContactChangeAttemptParams{Digest: row.Digest, UserID: row.UserID, SessionID: row.SessionID, DpopJkt: row.DpopJkt, AuthVersion: row.AuthVersion, Target: row.Target, AuthorizationMethod: row.AuthorizationMethod, AuthorizationExpiresAt: row.AuthorizationExpiresAt, Channel: row.Channel, ContactMac: row.ContactMac, OriginalStateDigest: row.OriginalStateDigest, DestinationEncrypted: row.DestinationEncrypted, ExpiresAt: row.ExpiresAt})
	if err != nil || count != 1 {
		return StartResult{}, ErrUnavailable
	}
	if !time.Now().Before(expires) {
		return StartResult{}, ErrExpired
	}
	if err := tx.Commit(deadlineCtx); err != nil {
		return StartResult{}, ErrOutcomeUnknown
	}
	err = s.deps.Codes.DispatchOwnership(ctx, prepared, func(checkCtx context.Context) error {
		checkCtx, stop := context.WithTimeout(checkCtx, 5*time.Second)
		defer stop()
		checkTx, err := s.deps.DB.BeginTx(checkCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return ErrUnavailable
		}
		defer rollback(checkCtx, checkTx)
		currentQ, currentUser, currentGuard, _, err := s.lock(checkCtx, checkTx, sess)
		if err != nil {
			return err
		}
		current, err := currentQ.GetContactChangeAttempt(checkCtx, attemptParams(sess, target, handle))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExpired
		}
		if err != nil {
			return ErrUnavailable
		}
		currentDestination, err := s.open(checkCtx, current)
		if err != nil || currentDestination != destination || !current.ExpiresAt.Time.Equal(expires) {
			return ErrUnauthorized
		}
		return s.validatePending(checkCtx, checkTx, currentQ, sess, currentUser, current, currentGuard)
	})
	if err != nil {
		return StartResult{}, safeError(err)
	}
	session.OutcomeCommitted(ctx)
	return StartResult{handle, expires}, nil
}

// Finish rejects foreign bindings before the one irreversible ownership consume.
// SQL finalization revalidates frozen authority read-only, never replaying start proofs.
func (s *Service) Finish(ctx context.Context, sess session.Session, target, handle, code string) (bool, error) {
	if !validTarget(target) || !validHandle(handle) || len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return false, ErrInvalid
	}
	if s.deps.Codes == nil {
		return false, ErrUnavailable
	}
	if target == contactproof.Phone && s.deps.Indexer == nil {
		return false, ErrUnavailable
	}
	row, err := s.deps.Queries.GetContactChangeAttempt(ctx, attemptParams(sess, target, handle))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrExpired
	}
	if err != nil {
		return false, ErrUnavailable
	}
	destination, err := s.open(ctx, row)
	if err != nil {
		return false, err
	}
	owned, err := s.deps.Codes.VerifyOwnership(ctx, contactcode.OwnershipBinding{DeletionBinding: contactcode.DeletionBinding{AccountID: row.UserID, AuthVersion: row.AuthVersion, SessionID: row.SessionID, JKT: row.DpopJkt}, Target: target, Destination: destination}, handle, code)
	if err != nil {
		return false, safeError(err)
	}
	if !owned.ExpiresAt.Equal(row.ExpiresAt.Time) {
		return false, ErrUnauthorized
	}
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)
	method := contactproof.SMSOTP
	if target == contactproof.Email {
		method = contactproof.EmailOTP
	}
	evidence, err := contactproof.Seal(ctx, s.deps.Cipher, row.UserID, target, destination, method, verifiedAt)
	if err != nil {
		return false, ErrUnavailable
	}
	defer clear(evidence)
	var encrypted []byte
	var index string
	if target == contactproof.Phone {
		encrypted, err = s.deps.Cipher.Encrypt(ctx, []byte(destination))
		if err != nil {
			return false, ErrUnavailable
		}
		defer clear(encrypted)
		index = s.deps.Indexer.Compute(destination)
	} else if s.deps.Indexer != nil {
		if _, err = s.deps.Indexer.ComputeEmail(destination); err != nil {
			return false, ErrUnavailable
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, ErrUnavailable
	}
	defer rollback(ctx, tx)
	q, u, guard, _, err := s.lock(ctx, tx, sess)
	if err != nil {
		return false, err
	}
	current, err := q.GetContactChangeAttempt(ctx, attemptParams(sess, target, handle))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrExpired
	}
	if err != nil {
		return false, ErrUnavailable
	}
	if !bytes.Equal(current.DestinationEncrypted, row.DestinationEncrypted) {
		return false, ErrUnauthorized
	}
	currentDestination, err := s.open(ctx, current)
	if err != nil || currentDestination != destination {
		return false, ErrUnauthorized
	}
	if err := s.validatePending(ctx, tx, q, sess, u, current, guard); err != nil {
		return false, err
	}
	var count int64
	if target == contactproof.Email {
		count, err = q.SetUserEmailIfAuthorized(ctx, db.SetUserEmailIfAuthorizedParams{UserID: u.ID, Email: destination, AuthVersion: u.AuthVersion, ExpiresAt: current.ExpiresAt})
	} else {
		count, err = q.SetManagedUserPhone(ctx, db.SetManagedUserPhoneParams{UserID: u.ID, PhoneEncrypted: encrypted, PhoneBlindIndex: index, AuthVersion: u.AuthVersion, ExpiresAt: current.ExpiresAt})
	}
	if err != nil {
		return false, writeError(err)
	}
	if count != 1 {
		return false, ErrExpired
	}
	// Contact UPDATE must run first: the existing trigger invalidates old evidence.
	if err := q.PutContactVerificationEvidence(ctx, db.PutContactVerificationEvidenceParams{UserID: u.ID, Channel: target, EvidenceEncrypted: evidence}); err != nil {
		return false, ErrUnavailable
	}
	if err := q.RevokeUserCredentials(ctx, u.ID); err != nil {
		return false, ErrUnavailable
	}
	if target == contactproof.Email && (u.Email == nil || *u.Email != destination) {
		if _, err := lifecycle.EnqueueEmailChange(ctx, q, u.ID, u.Status); err != nil {
			return false, ErrUnavailable
		}
	}
	count, err = q.ConsumeContactChangeAttempt(ctx, db.ConsumeContactChangeAttemptParams{Digest: current.Digest, UserID: u.ID, SessionID: current.SessionID, DpopJkt: current.DpopJkt, AuthVersion: current.AuthVersion, Target: current.Target})
	if err != nil {
		return false, ErrUnavailable
	}
	if count != 1 || !time.Now().Before(current.ExpiresAt.Time) {
		return false, ErrExpired
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrOutcomeUnknown
	}
	session.SecurityChangeCommitted(ctx)
	return true, nil
}

// Remove remains provider-free. Present primary email is temporarily operation-gated.
func (s *Service) Remove(ctx context.Context, sess session.Session, target string, auth Authorization) (bool, error) {
	if !validTarget(target) {
		return false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.deps.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, ErrUnavailable
	}
	defer rollback(ctx, tx)
	q, u, guard, live, err := s.lock(ctx, tx, sess)
	if err != nil {
		return false, err
	}
	if target == contactproof.Email && u.Email != nil {
		return false, ErrEmailRemovalUnavailable
	}
	if target == contactproof.Phone {
		if err := accountpolicy.CheckPhoneRemoval(ctx, q, s.deps.Cipher, u); err != nil {
			if errors.Is(err, accountpolicy.ErrLastVerifiedContact) {
				return false, err
			}
			return false, ErrUnavailable
		}
	}
	authority, _, err := s.authorize(ctx, tx, sess, u, guard, auth, "contact_remove", target)
	if err != nil {
		return false, err
	}
	expires := authority.ExpiresAt
	for _, limit := range []time.Time{sess.IdleExpiry, sess.AbsoluteExpiry, live.IdleExpiry, live.AbsoluteExpiry} {
		if limit.Before(expires) {
			expires = limit
		}
	}
	expires = expires.UTC().Truncate(time.Millisecond)
	currentLive, err := s.live(ctx, sess, u)
	if err != nil {
		return false, err
	}
	for _, limit := range []time.Time{currentLive.IdleExpiry, currentLive.AbsoluteExpiry} {
		if limit.Before(expires) {
			expires = limit.UTC().Truncate(time.Millisecond)
		}
	}
	if !time.Now().Before(expires) {
		return false, ErrExpired
	}
	var count int64
	if target == contactproof.Phone {
		count, err = q.RemoveManagedUserPhone(ctx, db.RemoveManagedUserPhoneParams{UserID: u.ID, AuthVersion: u.AuthVersion, ExpiresAt: stamp(expires)})
	} else {
		count, err = q.RemoveUserEmailIfAuthorized(ctx, db.RemoveUserEmailIfAuthorizedParams{UserID: u.ID, AuthVersion: u.AuthVersion, ExpiresAt: stamp(expires)})
	}
	if err != nil || count < 0 || count > 1 {
		return false, ErrUnavailable
	}
	if count == 1 {
		if err := q.RevokeUserCredentials(ctx, u.ID); err != nil {
			return false, ErrUnavailable
		}
		if _, err := q.DeleteCurrentContactChangeAttempt(ctx, db.DeleteCurrentContactChangeAttemptParams{UserID: u.ID, Target: target}); err != nil {
			return false, ErrUnavailable
		}
	}
	if !time.Now().Before(expires) {
		return false, ErrExpired
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrOutcomeUnknown
	}
	if count == 1 {
		session.SecurityChangeCommitted(ctx)
	} else {
		session.OutcomeCommitted(ctx)
	}
	return count == 1, nil
}

// CleanupExpired removes only bounded expired SQL state, without refunding authority.
func (s *Service) CleanupExpired(ctx context.Context, batchSize int32) (int64, error) {
	if batchSize < 1 || batchSize > 1000 {
		return 0, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	n, err := s.deps.Queries.CleanupExpiredContactChangeAttempts(ctx, batchSize)
	if err != nil {
		return 0, ErrUnavailable
	}
	return n, nil
}
func writeError(err error) error {
	var e *pgconn.PgError
	if errors.As(err, &e) && e.Code == "23505" {
		return ErrConflict
	}
	return ErrUnavailable
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrInvalid, ErrUnauthorized, ErrConflict, ErrUnavailable, ErrOutcomeUnknown, ErrEmailRemovalUnavailable, ErrExpired, accountpolicy.ErrLastCredential, accountpolicy.ErrLastFactor, accountpolicy.ErrLastVerifiedContact} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, contactcode.ErrInvalidCode) {
		return ErrInvalidCode
	}
	if errors.Is(err, contactcode.ErrNoActiveCode) {
		return ErrExpired
	}
	if errors.Is(err, contactcode.ErrRateLimited) || errors.Is(err, contactcode.ErrLockedOut) {
		return ErrRateLimited
	}
	if errors.Is(err, contactcode.ErrInvalid) {
		return ErrInvalid
	}
	if errors.Is(err, contactcode.ErrDisabled) {
		return contactcode.ErrDisabled
	}
	if errors.Is(err, contactcode.ErrOutcomeUnknown) {
		return ErrOutcomeUnknown
	}
	if errors.Is(err, actionproof.ErrInvalid) || errors.Is(err, actionproof.ErrUnauthorized) {
		return ErrUnauthorized
	}
	if errors.Is(err, actionproof.ErrContactExpired) {
		return ErrExpired
	}
	if errors.Is(err, actionproof.ErrOutcomeUnknown) {
		return ErrOutcomeUnknown
	}
	if errors.Is(err, actionproof.ErrRateLimited) {
		return ErrRateLimited
	}
	if errors.Is(err, actionproof.ErrEmailRemovalUnavailable) {
		return ErrEmailRemovalUnavailable
	}
	return ErrUnavailable
}
