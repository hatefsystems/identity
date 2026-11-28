package profile

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// ErrUnreadable is distinct from a missing, uninitialized profile. Its static
// text is safe; authentication failures never expose ciphertext or private data.
var ErrUnreadable = errors.New("profile: protected private data unreadable")

// ErrOutcomeUnknown means an edit reached COMMIT without a definitive result.
// The caller must read a fresh snapshot before attempting another edit.
var ErrOutcomeUnknown = errors.New("profile: private edit outcome unknown")

const privatePurpose = "hatef.identity.private-profile"

// PrivateData contains the protected attributes, independent of public names.
type PrivateData struct {
	GivenName  string                      `json:"given_name"`
	FamilyName string                      `json:"family_name"`
	Birthday   PrivateBirthday             `json:"birthday"`
	Gender     Gender                      `json:"gender"`
	Location   geography.ValidatedLocation `json:"location"`
}

// PrivateBirthday exposes one server-derived date-only pair.
type PrivateBirthday struct {
	Gregorian string `json:"gregorian"`
	Jalali    string `json:"jalali"`
}

// PrivateSnapshot projects protected data, username and revision together.
type PrivateSnapshot struct {
	PrivateData       *PrivateData         `json:"private_data"`
	Username          *username.ReadResult `json:"username"`
	LifecycleRevision string               `json:"lifecycle_revision"`
}

// PrivateUpdateResult distinguishes a committed edit from a normalized no-op.
type PrivateUpdateResult struct {
	Snapshot PrivateSnapshot
	Changed  bool
}

// LocationValidator resolves a selection against an authoritative catalog.
type LocationValidator interface {
	ValidateForUpdate(context.Context, pgx.Tx, geography.LocationInput) (geography.ValidatedLocation, error)
}

// SessionAuthority does not reacquire the account lock or renew activity.
// Manager.LookupByID checks the individual live record and both expiry bounds.
type SessionAuthority interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// PrivateService owns authenticated encrypted account snapshots and edits.
type PrivateService struct {
	database Database
	cipher   username.Cipher
	names    *username.Store
	location LocationValidator
	sessions SessionAuthority
}

// NewPrivate requires storage, encryption, location and live-session authority.
func NewPrivate(database Database, cipher username.Cipher, names *username.Store, location LocationValidator, sessions SessionAuthority) (*PrivateService, error) {
	for _, dependency := range []any{database, cipher, location, sessions} {
		if dependency == nil || reflect.ValueOf(dependency).Kind() == reflect.Pointer && reflect.ValueOf(dependency).IsNil() {
			return nil, ErrUnavailable
		}
	}
	return &PrivateService{database, cipher, names, location, sessions}, nil
}

type privatePayload struct {
	AccountID string      `json:"account_id"`
	Purpose   string      `json:"purpose"`
	Revision  string      `json:"revision"`
	Data      PrivateData `json:"data"`
}

func (s *PrivateService) seal(ctx context.Context, id uuid.UUID, revision int64, data PrivateData) ([]byte, error) {
	raw, err := json.Marshal(privatePayload{id.String(), privatePurpose, strconv.FormatInt(revision, 10), data})
	if err != nil || len(raw) > 8192 {
		return nil, ErrUnavailable
	}
	defer clear(raw)
	blob, err := s.cipher.Encrypt(ctx, raw)
	if err != nil || len(blob) < 90 || len(blob) > 16384 {
		return nil, ErrUnavailable
	}
	return blob, nil
}

func (s *PrivateService) open(ctx context.Context, id uuid.UUID, revision int64, blob []byte) (*PrivateData, error) {
	if id == uuid.Nil || revision <= 0 || len(blob) < 90 || len(blob) > 16384 {
		return nil, ErrUnreadable
	}
	raw, err := s.cipher.Decrypt(ctx, blob)
	defer clear(raw)
	if err != nil {
		return nil, ErrUnreadable
	}
	var payload privatePayload
	if privateJSON(raw, &payload) != nil || payload.AccountID != id.String() || payload.Purpose != privatePurpose ||
		payload.Revision != strconv.FormatInt(revision, 10) || validPrivateData(payload.Data) != nil {
		return nil, ErrUnreadable
	}
	return &payload.Data, nil
}

func positivePrivateDecimal(raw string) bool {
	n, err := parseRevision(raw)
	return err == nil && n > 0
}

func validPrivateData(data PrivateData) error {
	given, err := NormalizePersonalName(data.GivenName)
	if err != nil || given != data.GivenName {
		return ErrUnreadable
	}
	family, err := NormalizePersonalName(data.FamilyName)
	if err != nil || family != data.FamilyName {
		return ErrUnreadable
	}
	birthday, err := NormalizeBirthday("gregorian", data.Birthday.Gregorian, time.Now())
	if err != nil || birthday.Gregorian != data.Birthday.Gregorian || birthday.Jalali != data.Birthday.Jalali {
		return ErrUnreadable
	}
	if _, err := ValidateGender(string(data.Gender)); err != nil {
		return ErrUnreadable
	}
	l := data.Location
	if l.Country != "IR" || !positivePrivateDecimal(l.ProvinceID) || l.LocalityID != "" && !positivePrivateDecimal(l.LocalityID) || !positivePrivateDecimal(l.CatalogRevision) {
		return ErrUnreadable
	}
	return nil
}

func privateSubject(sess session.Session) (uuid.UUID, error) {
	id, err := uuid.Parse(sess.UserID)
	if err != nil || id == uuid.Nil || id.String() != sess.UserID || sess.ID == "" || sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.AuthVersion < 0 || sess.DPoPJKT == "" {
		return uuid.Nil, ErrUnauthorized
	}
	return id, nil
}

func (s *PrivateService) recheck(ctx context.Context, captured session.Session) error {
	live, err := s.sessions.LookupByID(ctx, captured.UserID, captured.ID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return ErrUnauthorized
		}
		return ErrUnavailable
	}
	now := time.Now()
	if live.ID != captured.ID || live.UserID != captured.UserID || live.Kind != session.KindAuthenticated || !live.AuthVersionSet || live.AuthVersion != captured.AuthVersion || live.DPoPJKT != captured.DPoPJKT || !live.AbsoluteExpiry.Equal(captured.AbsoluteExpiry) || !now.Before(live.AbsoluteExpiry) || !now.Before(live.IdleExpiry) {
		return ErrUnauthorized
	}
	return nil
}

// locked uses READ COMMITTED deciding statements AFTER the policy/account locks.
// Every projected field and revision stays stable until this transaction ends.
func (s *PrivateService) locked(ctx context.Context, tx pgx.Tx, sess session.Session, id uuid.UUID) (db.User, username.GuardAuthority, error) {
	var authority username.GuardAuthority
	var err error
	if s.names == nil {
		err = username.AcquireOwnershipGuard(ctx, tx)
	} else {
		authority, err = s.names.GuardAuthority(ctx, tx)
	}
	if err != nil {
		return db.User{}, authority, ErrUnavailable
	}
	if pglock.LockAccount(ctx, tx, id) != nil {
		return db.User{}, authority, ErrUnavailable
	}
	u, err := db.New(tx).GetUserForUpdateIncludingDeleted(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, authority, ErrUnauthorized
	}
	if err != nil || u.LifecycleRevision < 0 {
		return db.User{}, authority, ErrUnavailable
	}
	if u.Status != "active" || u.DeletedAt.Valid || u.AuthVersion != sess.AuthVersion {
		return db.User{}, authority, ErrUnauthorized
	}
	if err := s.recheck(ctx, sess); err != nil {
		return db.User{}, authority, err
	}
	return u, authority, nil
}

func (s *PrivateService) snapshot(ctx context.Context, tx pgx.Tx, u db.User, authority username.GuardAuthority) (PrivateSnapshot, error) {
	names, err := s.names.GetInTx(ctx, tx, u.ID, u.AuthVersion, authority)
	if err != nil {
		return PrivateSnapshot{}, ErrUnavailable
	}
	result := PrivateSnapshot{Username: names, LifecycleRevision: strconv.FormatInt(u.LifecycleRevision, 10)}
	stored, err := db.New(tx).ReadPrivateProfile(ctx, u.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return PrivateSnapshot{}, ErrUnavailable
	}
	if stored.ProfileRevision > u.LifecycleRevision {
		return PrivateSnapshot{}, ErrUnreadable
	}
	result.PrivateData, err = s.open(ctx, u.ID, stored.ProfileRevision, stored.DetailsEncrypted)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	return result, nil
}

func rollbackPrivate(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Get reads one consistent snapshot after checking current account and session.
func (s *PrivateService) Get(ctx context.Context, sess session.Session) (PrivateSnapshot, error) {
	id, err := privateSubject(sess)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PrivateSnapshot{}, ErrUnavailable
	}
	defer rollbackPrivate(tx)
	u, authority, err := s.locked(ctx, tx, sess, id)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	result, err := s.snapshot(ctx, tx, u, authority)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	if tx.Commit(ctx) != nil {
		return PrivateSnapshot{}, ErrUnavailable
	}
	return result, nil
}

func (s *PrivateService) merge(ctx context.Context, tx pgx.Tx, current *PrivateData, in PrivateUpdate) (PrivateData, error) {
	if current == nil && (in.GivenName == nil || in.FamilyName == nil || in.Birthday == nil || in.Gender == nil || in.Location == nil) {
		return PrivateData{}, ErrInvalidPrivateData
	}
	var data PrivateData
	if current != nil {
		data = *current
	}
	var err error
	if in.GivenName != nil {
		data.GivenName, err = NormalizePersonalName(*in.GivenName)
		if err != nil {
			return PrivateData{}, err
		}
	}
	if in.FamilyName != nil {
		data.FamilyName, err = NormalizePersonalName(*in.FamilyName)
		if err != nil {
			return PrivateData{}, err
		}
	}
	if in.Birthday != nil {
		b, err := NormalizeBirthday(in.Birthday.Calendar, in.Birthday.Date, time.Now())
		if err != nil {
			return PrivateData{}, err
		}
		data.Birthday = PrivateBirthday(b)
	}
	if in.Gender != nil {
		data.Gender, err = ValidateGender(*in.Gender)
		if err != nil {
			return PrivateData{}, err
		}
	}
	if in.Location != nil && (current == nil || *in.Location != current.Location.LocationInput) {
		data.Location, err = s.location.ValidateForUpdate(ctx, tx, *in.Location)
		if err != nil {
			if errors.Is(err, geography.ErrInvalid) || errors.Is(err, geography.ErrNotFound) {
				return PrivateData{}, ErrInvalidPrivateData
			}
			return PrivateData{}, ErrUnavailable
		}
		if data.Location.LocationInput != *in.Location {
			return PrivateData{}, ErrUnavailable
		}
	}
	if validPrivateData(data) != nil {
		return PrivateData{}, ErrInvalidPrivateData
	}
	return data, nil
}

// Update commits a real edit and its single lifecycle intent atomically.
func (s *PrivateService) Update(ctx context.Context, sess session.Session, in PrivateUpdate) (PrivateUpdateResult, error) {
	id, err := privateSubject(sess)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	revision, err := parseRevision(in.ExpectedRevision)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	if in.GivenName == nil && in.FamilyName == nil && in.Birthday == nil && in.Gender == nil && in.Location == nil {
		return PrivateUpdateResult{}, ErrInvalidPrivateData
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PrivateUpdateResult{}, ErrUnavailable
	}
	defer rollbackPrivate(tx)
	u, authority, err := s.locked(ctx, tx, sess, id)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	if u.LifecycleRevision != revision {
		return PrivateUpdateResult{}, ErrConflict
	}
	current, err := s.snapshot(ctx, tx, u, authority)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	data, err := s.merge(ctx, tx, current.PrivateData, in)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	if current.PrivateData != nil && data == *current.PrivateData {
		return PrivateUpdateResult{Snapshot: current}, nil
	}
	if revision == math.MaxInt64 {
		return PrivateUpdateResult{}, ErrUnavailable
	}
	blob, err := s.seal(ctx, id, revision+1, data)
	if err != nil {
		return PrivateUpdateResult{}, err
	}
	q := db.New(tx)
	count, err := q.SavePrivateProfile(ctx, db.SavePrivateProfileParams{
		AccountID: id, DetailsEncrypted: blob, ProfileRevision: revision + 1,
	})
	if err != nil || count != 1 {
		return PrivateUpdateResult{}, ErrUnavailable
	}
	next, err := lifecycle.EnqueuePrivateProfileChange(ctx, q, id, u.Status)
	if err != nil || next != revision+1 {
		return PrivateUpdateResult{}, ErrUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		// An explicit rollback or SQL statement error establishes rejection.
		// A closed connection can have lost the acknowledgement of a commit.
		var pgErr *pgconn.PgError
		if errors.Is(err, pgx.ErrTxCommitRollback) || (errors.As(err, &pgErr) && pgErr.Severity == "ERROR") {
			return PrivateUpdateResult{}, ErrUnavailable
		}
		return PrivateUpdateResult{}, ErrOutcomeUnknown
	}
	current.PrivateData, current.LifecycleRevision = &data, strconv.FormatInt(next, 10)
	return PrivateUpdateResult{Snapshot: current, Changed: true}, nil
}
