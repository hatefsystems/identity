// Package registration stores purpose-bound signup authority, never sessions.
package registration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// Purpose and lifetime limits bound signup authority and retained receipts.
const (
	Purpose            = "registration"
	PendingLifetime    = 15 * time.Minute
	EmailLifetime      = 10 * time.Minute
	PasskeyLifetime    = 5 * time.Minute
	ReceiptLifetime    = time.Hour
	MaxPendingCapacity = 10000
)

// ErrInvalid and the other sentinel errors report fixed registration failure categories.
var (
	ErrInvalid      = errors.New("registration: invalid state or binding")
	ErrUnauthorized = errors.New("registration: invalid authority")
	ErrExpired      = errors.New("registration: authority expired")
	ErrConflict     = errors.New("registration: completion or revision conflict")
	ErrCapacity     = errors.New("registration: pending capacity exhausted")
	ErrUnavailable  = errors.New("registration: storage unavailable")
	phonePattern    = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
)

// Encryptor provides authenticated envelope encryption for pending signup material.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

// Database combines query access with explicit transaction creation.
type Database interface {
	db.DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Details is authenticated plaintext inside the existing envelope format.
// Ceremony is server-produced WebAuthn session data, not an authenticator key.
type Details struct {
	AttemptID        uuid.UUID       `json:"attempt_id"`
	JKT              string          `json:"jkt"`
	Purpose          string          `json:"purpose"`
	Email            string          `json:"email"`
	Phone            string          `json:"phone"`
	UserHandle       []byte          `json:"user_handle"`
	Ceremony         json.RawMessage `json:"ceremony,omitempty"`
	CeremonyRevision int64           `json:"ceremony_revision,omitempty"`
}

// Attempt contains SQL authority and authenticated pending details, if retained.
type Attempt struct {
	Record  db.RegistrationAttempt
	Details Details
}

// Store persists purpose-bound signup attempts without granting login authority.
type Store struct {
	database Database
	cipher   Encryptor
	capacity int32
	now      func() time.Time
}

// NewStore binds SQL storage and envelope encryption to a finite pending ceiling.
func NewStore(database Database, cipher Encryptor, capacity int32) (*Store, error) {
	if database == nil || cipher == nil || capacity < 1 || capacity > MaxPendingCapacity {
		return nil, ErrInvalid
	}
	return &Store{database: database, cipher: cipher, capacity: capacity, now: time.Now}, nil
}

// NewCapability returns an independent 256-bit secret. Only HashCapability is
// persisted; HTTP encoders may use unpadded base64url for this exact byte string.
func NewCapability() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, ErrUnavailable
	}
	return secret, nil
}

// HashCapability hashes an exact 256-bit capability for storage.
func HashCapability(secret []byte) ([]byte, error) {
	if len(secret) != 32 {
		return nil, ErrUnauthorized
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

// ValidJKT accepts only canonical unpadded base64url SHA-256 thumbprints.
func ValidJKT(jkt string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(jkt)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == jkt
}

// Create commits pending authority before any provider send. The capacity count
// is read after the shared transaction lock, not from a pre-wait CTE snapshot.
func (s *Store) Create(ctx context.Context, email, phone, jkt string) (Attempt, []byte, error) {
	if !emailaddress.ValidCanonicalMailbox(email) || !phonePattern.MatchString(phone) || !ValidJKT(jkt) {
		return Attempt{}, nil, ErrInvalid
	}
	capability, err := NewCapability()
	if err != nil {
		return Attempt{}, nil, err
	}
	success := false
	defer func() {
		if !success {
			clear(capability)
		}
	}()
	hash, _ := HashCapability(capability)
	handle := make([]byte, 8)
	if _, err := rand.Read(handle); err != nil {
		return Attempt{}, nil, ErrUnavailable
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	details := Details{AttemptID: uuid.New(), JKT: jkt, Purpose: Purpose, Email: email, Phone: phone, UserHandle: handle}
	blob, err := s.seal(ctx, details)
	if err != nil {
		return Attempt{}, nil, err
	}
	tx, err := begin(ctx, s.database)
	if err != nil {
		return Attempt{}, nil, err
	}
	defer rollback(tx)
	q := db.New(tx)
	if err := q.LockRegistrationAdmission(ctx); err != nil {
		return Attempt{}, nil, ErrUnavailable
	}
	row, err := q.CreateRegistrationAttempt(ctx, db.CreateRegistrationAttemptParams{
		ID: details.AttemptID, CapabilityHash: hash, Jkt: jkt, DetailsEncrypted: blob,
		CreatedAt: timestamp(now), ExpiresAt: timestamp(now.Add(PendingLifetime)), PendingCapacity: s.capacity,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, nil, ErrCapacity
	}
	if err != nil {
		return Attempt{}, nil, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return Attempt{}, nil, ErrUnavailable
	}
	success = true
	return Attempt{Record: row, Details: details}, capability, nil
}

// Get checks capability/JKT binding and opens unexpired pending state or a receipt.
func (s *Store) Get(ctx context.Context, id uuid.UUID, capability []byte, jkt string) (Attempt, error) {
	if id == uuid.Nil || len(capability) != 32 || !ValidJKT(jkt) {
		return Attempt{}, ErrUnauthorized
	}
	row, err := db.New(s.database).GetRegistrationAttempt(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrUnauthorized
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	return s.authorize(ctx, row, capability, jkt)
}

// Lock uses a caller-owned READ COMMITTED transaction. Final account birth and
// Complete must share that transaction; this store never commits caller writes.
func (s *Store) Lock(ctx context.Context, tx pgx.Tx, id uuid.UUID, capability []byte, jkt string) (Attempt, error) {
	if tx == nil || id == uuid.Nil || len(capability) != 32 || !ValidJKT(jkt) {
		return Attempt{}, ErrUnauthorized
	}
	row, err := db.New(tx).LockRegistrationAttempt(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrUnauthorized
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	return s.authorize(ctx, row, capability, jkt)
}

// LockEmailProof is the only capability-free lookup. A separate 256-bit email
// token and the original JKT authorize ownership proof only, never a receipt.
func (s *Store) LockEmailProof(ctx context.Context, tx pgx.Tx, id uuid.UUID, token []byte, jkt string) (Attempt, error) {
	if tx == nil || id == uuid.Nil || len(token) != 32 || !ValidJKT(jkt) {
		return Attempt{}, ErrUnauthorized
	}
	row, err := db.New(tx).LockRegistrationAttempt(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrUnauthorized
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	hash, _ := HashCapability(token)
	if row.State != "pending" || row.Jkt != jkt || subtle.ConstantTimeCompare(hash, row.EmailTokenHash) != 1 {
		return Attempt{}, ErrUnauthorized
	}
	if validateRecord(row) != nil {
		return Attempt{}, ErrInvalid
	}
	now := s.now()
	if validateAt(row, now) != nil {
		return Attempt{}, ErrInvalid
	}
	if !now.Before(row.ExpiresAt.Time) || !row.EmailTokenExpiresAt.Valid || !now.Before(row.EmailTokenExpiresAt.Time) {
		return Attempt{}, ErrExpired
	}
	return s.open(ctx, row)
}

func (s *Store) authorize(ctx context.Context, row db.RegistrationAttempt, capability []byte, jkt string) (Attempt, error) {
	hash, err := HashCapability(capability)
	if err != nil || subtle.ConstantTimeCompare(hash, row.CapabilityHash) != 1 || row.Jkt != jkt {
		return Attempt{}, ErrUnauthorized
	}
	if err := validateRecord(row); err != nil {
		return Attempt{}, err
	}
	now := s.now()
	if validateAt(row, now) != nil {
		return Attempt{}, ErrInvalid
	}
	if row.State == "pending" && !now.Before(row.ExpiresAt.Time) || row.State != "pending" && !now.Before(row.ReceiptExpiresAt.Time) {
		return Attempt{}, ErrExpired
	}
	return s.open(ctx, row)
}

// Save accepts only a locked pending snapshot, preserves identity and absolute
// expiry, and compare-and-swaps the row revision. Resends cannot reset the clock.
func (s *Store) Save(ctx context.Context, tx pgx.Tx, attempt Attempt) (Attempt, error) {
	if tx == nil || attempt.Record.ID == uuid.Nil || attempt.Record.State != "pending" {
		return Attempt{}, ErrInvalid
	}
	current, err := db.New(tx).LockRegistrationAttempt(ctx, attempt.Record.ID)
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	old, err := s.open(ctx, current)
	if err != nil {
		return Attempt{}, err
	}
	r := attempt.Record
	if current.State != "pending" || r.RowRevision != current.RowRevision {
		return Attempt{}, ErrConflict
	}
	if !sameIdentity(old.Details, attempt.Details) || !bytes.Equal(r.CapabilityHash, current.CapabilityHash) ||
		r.Jkt != current.Jkt || !r.CreatedAt.Time.Equal(current.CreatedAt.Time) || !r.ExpiresAt.Time.Equal(current.ExpiresAt.Time) ||
		r.ChallengeRevision < current.ChallengeRevision || r.ChallengeRevision > current.ChallengeRevision+1 {
		return Attempt{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if !now.Before(r.ExpiresAt.Time) {
		return Attempt{}, ErrExpired
	}
	blob, err := s.seal(ctx, attempt.Details)
	if err != nil {
		return Attempt{}, err
	}
	r.DetailsEncrypted = blob
	if err := validateRecord(r); err != nil {
		return Attempt{}, err
	}
	if validateAt(r, now) != nil {
		return Attempt{}, ErrInvalid
	}
	if err := validateCeremony(attempt.Details, r); err != nil {
		return Attempt{}, err
	}
	row, err := db.New(tx).SaveRegistrationAttempt(ctx, db.SaveRegistrationAttemptParams{
		ID: r.ID, RowRevision: r.RowRevision, DetailsEncrypted: blob, EmailTokenHash: r.EmailTokenHash,
		EmailTokenIssuedAt: r.EmailTokenIssuedAt, EmailTokenExpiresAt: r.EmailTokenExpiresAt,
		EmailVerifiedAt: r.EmailVerifiedAt, SmsVerificationRef: r.SmsVerificationRef, PhoneVerifiedAt: r.PhoneVerifiedAt,
		ChallengeRevision: r.ChallengeRevision, PasskeyCreatedAt: r.PasskeyCreatedAt, PasskeyExpiresAt: r.PasskeyExpiresAt, Now: timestamp(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrConflict
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	return Attempt{Record: row, Details: attempt.Details}, nil
}

// CheckReplay permits only an identical completion fingerprint. A receipt is
// informational authority, not permission to create a second account or log in.
func CheckReplay(attempt Attempt, fingerprint []byte) (uuid.UUID, bool, error) {
	if len(fingerprint) != 32 {
		return uuid.Nil, false, ErrInvalid
	}
	if attempt.Record.State != "completed" {
		return uuid.Nil, false, nil
	}
	if validateRecord(attempt.Record) != nil {
		return uuid.Nil, false, ErrInvalid
	}
	if subtle.ConstantTimeCompare(attempt.Record.CompletionFingerprint, fingerprint) != 1 {
		return uuid.Nil, false, ErrConflict
	}
	return attempt.Record.ResultUserID.UUID, true, nil
}

// Complete rechecks the frozen snapshot under its lock, then atomically clears
// transient material. The caller must insert the new account in this same tx.
func (s *Store) Complete(ctx context.Context, tx pgx.Tx, attempt Attempt, userID uuid.UUID, fingerprint []byte) (Attempt, error) {
	if tx == nil || userID == uuid.Nil || len(fingerprint) != 32 {
		return Attempt{}, ErrInvalid
	}
	current, err := db.New(tx).LockRegistrationAttempt(ctx, attempt.Record.ID)
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	fresh, err := s.open(ctx, current)
	if err != nil {
		return Attempt{}, err
	}
	if current.State != "pending" || current.RowRevision != attempt.Record.RowRevision || !sameIdentity(fresh.Details, attempt.Details) ||
		current.ChallengeRevision != attempt.Record.ChallengeRevision || !bytes.Equal(fresh.Details.Ceremony, attempt.Details.Ceremony) {
		return Attempt{}, ErrConflict
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if validateAt(current, now) != nil {
		return Attempt{}, ErrInvalid
	}
	if !now.Before(current.ExpiresAt.Time) || !current.EmailVerifiedAt.Valid || !current.PhoneVerifiedAt.Valid ||
		!current.EmailTokenExpiresAt.Valid || !now.Before(current.EmailTokenExpiresAt.Time) ||
		!current.PasskeyExpiresAt.Valid || !now.Before(current.PasskeyExpiresAt.Time) {
		return Attempt{}, ErrExpired
	}
	row, err := db.New(tx).CompleteRegistrationAttempt(ctx, db.CompleteRegistrationAttemptParams{
		ID: current.ID, RowRevision: current.RowRevision, Now: timestamp(now), ReceiptExpiresAt: timestamp(now.Add(ReceiptLifetime)),
		CompletionFingerprint: fingerprint, ResultUserID: uuid.NullUUID{UUID: userID, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrConflict
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	return Attempt{Record: row}, nil
}

// Fail clears transient material and records a failure receipt in the caller's transaction.
func (s *Store) Fail(ctx context.Context, tx pgx.Tx, attempt Attempt) (Attempt, error) {
	if tx == nil || attempt.Record.State != "pending" {
		return Attempt{}, ErrInvalid
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	row, err := db.New(tx).FailRegistrationAttempt(ctx, db.FailRegistrationAttemptParams{
		ID: attempt.Record.ID, RowRevision: attempt.Record.RowRevision, Now: timestamp(now), ReceiptExpiresAt: timestamp(now.Add(ReceiptLifetime)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrConflict
	}
	if err != nil {
		return Attempt{}, ErrUnavailable
	}
	return Attempt{Record: row}, nil
}

func (s *Store) seal(ctx context.Context, details Details) ([]byte, error) {
	if validateDetails(details) != nil {
		return nil, ErrInvalid
	}
	plain, err := json.Marshal(details)
	if err != nil || len(plain) > 32679 {
		return nil, ErrInvalid
	}
	defer clear(plain)
	blob, err := s.cipher.Encrypt(ctx, plain)
	if err != nil || len(blob) < 90 || len(blob) > 32768 {
		return nil, ErrUnavailable
	}
	return blob, nil
}

func (s *Store) open(ctx context.Context, row db.RegistrationAttempt) (Attempt, error) {
	if validateRecord(row) != nil {
		return Attempt{}, ErrInvalid
	}
	result := Attempt{Record: row}
	if row.State != "pending" {
		return result, nil
	}
	plain, err := s.cipher.Decrypt(ctx, row.DetailsEncrypted)
	if err != nil || len(plain) == 0 || len(plain) > 32679 {
		return Attempt{}, ErrInvalid
	}
	defer clear(plain)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result.Details) != nil || decoder.Decode(new(any)) != io.EOF || validateDetails(result.Details) != nil ||
		result.Details.AttemptID != row.ID || result.Details.JKT != row.Jkt || validateCeremony(result.Details, row) != nil {
		return Attempt{}, ErrInvalid
	}
	canonical, err := json.Marshal(result.Details)
	if err != nil || !bytes.Equal(plain, canonical) {
		return Attempt{}, ErrInvalid
	}
	return result, nil
}

func validateDetails(d Details) error {
	if d.AttemptID == uuid.Nil || d.Purpose != Purpose || !ValidJKT(d.JKT) || !emailaddress.ValidCanonicalMailbox(d.Email) ||
		!phonePattern.MatchString(d.Phone) || len(d.UserHandle) != 8 || d.CeremonyRevision < 0 || d.CeremonyRevision > 1000000 ||
		len(d.Ceremony) > 24000 || len(d.Ceremony) > 0 && (!json.Valid(d.Ceremony) || d.Ceremony[0] != '{') {
		return ErrInvalid
	}
	return nil
}

func validateCeremony(d Details, r db.RegistrationAttempt) error {
	if r.PasskeyExpiresAt.Valid != (len(d.Ceremony) > 0) || len(d.Ceremony) > 0 && d.CeremonyRevision != r.ChallengeRevision ||
		len(d.Ceremony) == 0 && d.CeremonyRevision != 0 {
		return ErrInvalid
	}
	return nil
}

func sameIdentity(a, b Details) bool {
	return a.AttemptID == b.AttemptID && a.JKT == b.JKT && a.Purpose == b.Purpose && a.Email == b.Email &&
		a.Phone == b.Phone && bytes.Equal(a.UserHandle, b.UserHandle)
}

func timestamp(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}
func finite(t pgtype.Timestamptz) bool {
	return t.Valid && t.InfinityModifier == pgtype.Finite && t.Time.Year() >= 1 && t.Time.Year() <= 9999
}

func validateAt(r db.RegistrationAttempt, now time.Time) error {
	for _, occurred := range []pgtype.Timestamptz{r.CreatedAt, r.EmailTokenIssuedAt, r.EmailVerifiedAt, r.PhoneVerifiedAt, r.PasskeyCreatedAt, r.TerminalAt} {
		if occurred.Valid && occurred.Time.After(now) {
			return ErrInvalid
		}
	}
	return nil
}

func validateRecord(r db.RegistrationAttempt) error {
	if r.ID == uuid.Nil || len(r.CapabilityHash) != 32 || !ValidJKT(r.Jkt) || !finite(r.CreatedAt) || !finite(r.ExpiresAt) ||
		!r.ExpiresAt.Time.Equal(r.CreatedAt.Time.Add(PendingLifetime)) || r.RowRevision < 0 || r.RowRevision > 1000000 ||
		r.ChallengeRevision < 0 || r.ChallengeRevision > 1000000 {
		return ErrInvalid
	}
	for _, proof := range []pgtype.Timestamptz{r.EmailVerifiedAt, r.PhoneVerifiedAt} {
		if proof.Valid && (!finite(proof) || proof.Time.Before(r.CreatedAt.Time) || !proof.Time.Before(r.ExpiresAt.Time)) {
			return ErrInvalid
		}
	}
	if r.PhoneVerifiedAt.Valid && (!r.EmailVerifiedAt.Valid || r.PhoneVerifiedAt.Time.Before(r.EmailVerifiedAt.Time)) {
		return ErrInvalid
	}
	if r.State == "pending" {
		if len(r.DetailsEncrypted) < 90 || len(r.DetailsEncrypted) > 32768 || r.TerminalAt.Valid || r.ReceiptExpiresAt.Valid ||
			r.ResultUserID.Valid || len(r.CompletionFingerprint) != 0 {
			return ErrInvalid
		}
		if r.EmailTokenIssuedAt.Valid != r.EmailTokenExpiresAt.Valid || len(r.EmailTokenHash) != 0 && len(r.EmailTokenHash) != 32 {
			return ErrInvalid
		}
		if r.EmailTokenIssuedAt.Valid && (!finite(r.EmailTokenIssuedAt) || !finite(r.EmailTokenExpiresAt) ||
			r.EmailTokenIssuedAt.Time.Before(r.CreatedAt.Time) || !r.EmailTokenExpiresAt.Time.After(r.EmailTokenIssuedAt.Time) ||
			r.EmailTokenExpiresAt.Time.After(r.EmailTokenIssuedAt.Time.Add(EmailLifetime)) || r.EmailTokenExpiresAt.Time.After(r.ExpiresAt.Time)) {
			return ErrInvalid
		}
		if len(r.EmailTokenHash) != 0 && (!r.EmailTokenIssuedAt.Valid || r.EmailVerifiedAt.Valid) {
			return ErrInvalid
		}
		if r.EmailVerifiedAt.Valid && (!r.EmailTokenIssuedAt.Valid || r.EmailVerifiedAt.Time.Before(r.EmailTokenIssuedAt.Time) ||
			!r.EmailVerifiedAt.Time.Before(r.EmailTokenExpiresAt.Time)) {
			return ErrInvalid
		}
		if r.PhoneVerifiedAt.Valid && !r.SmsVerificationRef.Valid {
			return ErrInvalid
		}
		if r.SmsVerificationRef.Valid && (r.SmsVerificationRef.UUID == uuid.Nil || !r.EmailVerifiedAt.Valid || r.ChallengeRevision == 0) {
			return ErrInvalid
		}
		if r.PasskeyCreatedAt.Valid != r.PasskeyExpiresAt.Valid {
			return ErrInvalid
		}
		if r.PasskeyCreatedAt.Valid && (!finite(r.PasskeyCreatedAt) || !finite(r.PasskeyExpiresAt) || !r.PhoneVerifiedAt.Valid ||
			r.PasskeyCreatedAt.Time.Before(r.PhoneVerifiedAt.Time) || !r.PasskeyExpiresAt.Time.After(r.PasskeyCreatedAt.Time) ||
			r.PasskeyExpiresAt.Time.After(r.PasskeyCreatedAt.Time.Add(PasskeyLifetime)) || r.PasskeyExpiresAt.Time.After(r.ExpiresAt.Time) || r.ChallengeRevision == 0) {
			return ErrInvalid
		}
		return nil
	}
	if r.State != "completed" && r.State != "failed" || !finite(r.TerminalAt) || !finite(r.ReceiptExpiresAt) ||
		r.TerminalAt.Time.Before(r.CreatedAt.Time) || !r.TerminalAt.Time.Before(r.ExpiresAt.Time) ||
		!r.ReceiptExpiresAt.Time.Equal(r.TerminalAt.Time.Add(ReceiptLifetime)) || len(r.DetailsEncrypted) != 0 ||
		len(r.EmailTokenHash) != 0 || r.EmailTokenIssuedAt.Valid || r.EmailTokenExpiresAt.Valid || r.SmsVerificationRef.Valid ||
		r.PasskeyCreatedAt.Valid || r.PasskeyExpiresAt.Valid {
		return ErrInvalid
	}
	if r.State == "completed" && (len(r.CompletionFingerprint) != 32 || !r.ResultUserID.Valid || r.ResultUserID.UUID == uuid.Nil ||
		!r.EmailVerifiedAt.Valid || !r.PhoneVerifiedAt.Valid || r.EmailVerifiedAt.Time.After(r.TerminalAt.Time) || r.PhoneVerifiedAt.Time.After(r.TerminalAt.Time)) {
		return ErrInvalid
	}
	if r.State == "failed" && (len(r.CompletionFingerprint) != 0 || r.ResultUserID.Valid) {
		return ErrInvalid
	}
	return nil
}

func begin(ctx context.Context, database interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}) (pgx.Tx, error) {
	tx, err := database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '250ms'; SET LOCAL statement_timeout = '2s'`); err != nil {
		rollback(tx)
		return nil, ErrUnavailable
	}
	return tx, nil
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
