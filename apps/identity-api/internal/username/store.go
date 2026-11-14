package username

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Storage errors contain no identity, ciphertext, digest or database diagnostics.
var (
	ErrUnavailable  = errors.New("username: storage unavailable")
	ErrConflict     = errors.New("username: assignment conflict")
	ErrUnauthorized = errors.New("username: account authority unavailable")
	ErrNotFound     = errors.New("username: not found")
)

// Database supports caller-owned assignment and bounded independent read transactions.
type Database interface {
	db.DBTX
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Store never owns an assignment transaction or provides a public claim boundary.
type Store struct {
	database   Database
	cipher     Cipher
	normalizer *Normalizer
}

// GuardAuthority includes the database activation epoch, not another namespace.
type GuardAuthority struct {
	Authority
	Epoch int64 `json:"epoch"`
}

// ReadResult is the only public username projection. Keys/provenance remain internal.
type ReadResult struct {
	Display string `json:"display"`
}

type storageDetails struct {
	AccountID    uuid.UUID      `json:"account_id"`
	Purpose      string         `json:"purpose"`
	Display      string         `json:"display"`
	SecurityName string         `json:"security_name"`
	Authority    GuardAuthority `json:"authority"`
}

const storagePurpose = "hatef.identity.username.assignment"

// NewStore binds an immutable normalizer and existing authenticated envelope cipher.
func NewStore(database Database, cipher Cipher, normalizer *Normalizer) (*Store, error) {
	if database == nil || cipher == nil || normalizer == nil {
		return nil, ErrUnavailable
	}
	return &Store{database: database, cipher: cipher, normalizer: normalizer}, nil
}

// Normalizer returns the immutable core used for every namespace consumer.
func (s *Store) Normalizer() *Normalizer { return s.normalizer }

// Guard must precede account/attempt locks and remain held until caller commit.
func (s *Store) Guard(ctx context.Context, tx pgx.Tx) error {
	_, err := s.GuardAuthority(ctx, tx)
	return err
}

// GuardAuthority verifies actual key material and the immutable artifact in the
// operation's transaction, not just startup/readiness or environment labels.
func (s *Store) GuardAuthority(ctx context.Context, tx pgx.Tx) (GuardAuthority, error) {
	if tx == nil {
		return GuardAuthority{}, ErrUnavailable
	}
	row, err := db.New(tx).LockUsernamePolicy(ctx)
	if err != nil {
		return GuardAuthority{}, ErrUnavailable
	}
	a, err := s.checkAuthority(ctx, tx, row)
	if err != nil {
		return GuardAuthority{}, err
	}
	if row.AdmissionState != "open" {
		return GuardAuthority{}, ErrUnavailable
	}
	return a, nil
}

func (s *Store) checkAuthority(ctx context.Context, q db.DBTX, row db.UsernameActivePolicy) (GuardAuthority, error) {
	expected := s.normalizer.Authority()
	if !row.PolicyID.Valid || row.KeyID == nil || !row.Guard || row.Epoch < 1 {
		return GuardAuthority{}, ErrUnavailable
	}
	if row.PolicyID.UUID != expected.PolicyID || !bytes.Equal(row.Fingerprint, expected.Fingerprint[:]) ||
		*row.KeyID != expected.KeyID || !bytes.Equal(row.KeyVerifier, expected.KeyVerifier[:]) {
		return GuardAuthority{}, ErrPolicyMismatch
	}
	artifact, err := db.New(q).GetUsernameArtifact(ctx, expected.PolicyID)
	if err != nil || !bytes.Equal(artifact.Fingerprint, expected.Fingerprint[:]) ||
		!bytes.Equal(artifact.Artifact, s.normalizer.CanonicalArtifact()) {
		return GuardAuthority{}, ErrPolicyMismatch
	}
	key, err := db.New(q).GetUsernameLookupKey(ctx, expected.KeyID)
	if err != nil || !bytes.Equal(key.KeyVerifier, expected.KeyVerifier[:]) {
		return GuardAuthority{}, ErrPolicyMismatch
	}
	return GuardAuthority{Authority: expected, Epoch: row.Epoch}, nil
}

// AcquireOwnershipGuard coordinates purge without requiring a lookup secret.
// An uninstalled baseline may delete genuinely unclaimed accounts. A closed
// cutover gate blocks all guarded ownership changes, including physical release.
func AcquireOwnershipGuard(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return ErrUnavailable
	}
	row, err := db.New(tx).LockUsernamePolicy(ctx)
	if err != nil || !row.Guard || (row.AdmissionState != "open" && row.AdmissionState != "uninstalled") {
		return ErrUnavailable
	}
	return nil
}

// Validate is advisory only. No account or namespace reservation is created.
func (s *Store) Validate(ctx context.Context, input string) (Value, bool, error) {
	v, err := s.normalizer.Normalize(input)
	if err != nil {
		return Value{}, false, err
	}
	available, err := s.Available(ctx, v)
	return v, available, err
}

// Available includes every surviving status and soft-deleted owner.
func (s *Store) Available(ctx context.Context, v Value) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, ErrUnavailable
	}
	defer rollbackUsername(tx)
	if err := s.Guard(ctx, tx); err != nil {
		return false, err
	}
	if err := s.normalizer.Validate(v); err != nil {
		if errors.Is(err, ErrReserved) {
			return false, nil
		}
		return false, err
	}
	key := v.Key()
	reserved, err := db.New(tx).UsernameReserved(ctx, key[:])
	if err != nil {
		return false, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return false, ErrUnavailable
	}
	return !reserved, nil
}

// Assign accepts only the caller's transaction. Lock arbitration and the deciding
// read are separate statements so a waiter sees committed moderation/auth changes.
func (s *Store) Assign(ctx context.Context, tx pgx.Tx, id uuid.UUID, expectedAuthVersion int64, v Value) error {
	authority, err := s.GuardAuthority(ctx, tx)
	if err != nil {
		return err
	}
	if err := s.normalizer.Validate(v); err != nil {
		if errors.Is(err, ErrReserved) {
			return ErrConflict
		}
		return err
	}
	if id == uuid.Nil || expectedAuthVersion < 0 {
		return ErrUnauthorized
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return ErrUnavailable
	}
	user, err := db.New(tx).GetUserForUpdateIncludingDeleted(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return ErrUnavailable
	}
	if user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != expectedAuthVersion {
		return ErrUnauthorized
	}
	if user.UsernameKey != nil {
		return ErrConflict
	}
	blob, err := s.sealStorage(ctx, id, v, authority)
	if err != nil {
		return err
	}
	key := v.Key()
	count, err := db.New(tx).AssignUsername(ctx, db.AssignUsernameParams{
		ID: id, UsernameKey: key[:], UsernameDetailsEncrypted: blob,
		UsernamePolicyID:          uuid.NullUUID{UUID: authority.PolicyID, Valid: true},
		UsernamePolicyFingerprint: authority.Fingerprint[:], UsernamePolicyEpoch: &authority.Epoch,
		UsernameLookupKeyID: &authority.KeyID, AuthVersion: expectedAuthVersion,
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_username_key_unique" {
		return ErrConflict
	}
	if err != nil {
		return ErrUnavailable
	}
	if count != 1 {
		return ErrConflict
	}
	return nil
}

// Get truthfully returns nil for an unclaimed active account, not a fabricated name.
func (s *Store) Get(ctx context.Context, id uuid.UUID, expectedAuthVersion int64) (*ReadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rollbackUsername(tx)
	authority, err := s.GuardAuthority(ctx, tx)
	if err != nil {
		return nil, err
	}
	if id == uuid.Nil || expectedAuthVersion < 0 {
		return nil, ErrUnauthorized
	}
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return nil, ErrUnavailable
	}
	user, err := db.New(tx).GetUserForUpdateIncludingDeleted(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if user.Status != "active" || user.DeletedAt.Valid || user.AuthVersion != expectedAuthVersion {
		return nil, ErrUnauthorized
	}
	row, err := db.New(tx).ReadUsername(ctx, id)
	if err != nil {
		return nil, ErrUnavailable
	}
	var result *ReadResult
	if row.UsernameKey != nil {
		value, err := s.openStorage(ctx, row, authority)
		if err != nil {
			return nil, err
		}
		result = &ReadResult{Display: value.Display()}
	} else if !nullStorageTuple(row) {
		return nil, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// Lookup resolves namespace ownership first. Consumers must independently check
// account/login policy; suspended/deleted identifiers are never reported absent.
func (s *Store) Lookup(ctx context.Context, input string) (uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	defer rollbackUsername(tx)
	authority, err := s.GuardAuthority(ctx, tx)
	if err != nil {
		return uuid.Nil, err
	}
	value, err := s.normalizer.NormalizeLookup(input)
	if err != nil {
		return uuid.Nil, err
	}
	key := value.Key()
	row, err := db.New(tx).LookupUsername(ctx, key[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	stored, err := s.openStorage(ctx, db.ReadUsernameRow(row), authority)
	if err != nil {
		return uuid.Nil, err
	}
	if stored.SecurityName() != value.SecurityName() {
		return uuid.Nil, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, ErrUnavailable
	}
	return row.ID, nil
}

func (s *Store) sealStorage(ctx context.Context, id uuid.UUID, v Value, a GuardAuthority) ([]byte, error) {
	raw, err := json.Marshal(storageDetails{AccountID: id, Purpose: storagePurpose, Display: v.Display(), SecurityName: v.SecurityName(), Authority: a})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(raw)
	blob, err := s.cipher.Encrypt(ctx, raw)
	if err != nil || len(blob) < 90 || len(blob) > 16384 {
		return nil, ErrUnavailable
	}
	return blob, nil
}

func (s *Store) openStorage(ctx context.Context, row db.ReadUsernameRow, a GuardAuthority) (Value, error) {
	if row.ID == uuid.Nil || len(row.UsernameKey) != 32 || !row.UsernamePolicyID.Valid ||
		row.UsernamePolicyID.UUID != a.PolicyID || !bytes.Equal(row.UsernamePolicyFingerprint, a.Fingerprint[:]) ||
		row.UsernamePolicyEpoch == nil || *row.UsernamePolicyEpoch != a.Epoch || row.UsernameLookupKeyID == nil ||
		*row.UsernameLookupKeyID != a.KeyID || len(row.UsernameDetailsEncrypted) < 90 || len(row.UsernameDetailsEncrypted) > 16384 {
		return Value{}, ErrUnavailable
	}
	raw, err := s.cipher.Decrypt(ctx, row.UsernameDetailsEncrypted)
	if err != nil || len(raw) > 16384 {
		clear(raw)
		return Value{}, ErrUnavailable
	}
	defer clear(raw)
	var details storageDetails
	if strictJSON(raw, &details, 16384) != nil || details.AccountID != row.ID ||
		details.Purpose != storagePurpose || details.Authority != a {
		return Value{}, ErrUnavailable
	}
	value, err := s.normalizer.NormalizeLookup(details.Display)
	key := value.Key()
	if err != nil || value.Display() != details.Display || value.SecurityName() != details.SecurityName ||
		!bytes.Equal(key[:], row.UsernameKey) || value.Authority() != a.Authority {
		return Value{}, ErrUnavailable
	}
	return value, nil
}

func nullStorageTuple(row db.ReadUsernameRow) bool {
	return row.UsernameKey == nil && row.UsernameDetailsEncrypted == nil && !row.UsernamePolicyID.Valid &&
		row.UsernamePolicyFingerprint == nil && row.UsernamePolicyEpoch == nil && row.UsernameLookupKeyID == nil
}

func rollbackUsername(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
