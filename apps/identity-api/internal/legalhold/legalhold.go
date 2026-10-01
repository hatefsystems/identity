// Package legalhold manages independent, encrypted retention requests. Advisory
// dates never release a hold, and preservation never restores purged evidence.
package legalhold

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Store is the bounded query surface for encrypted preservation requests.
type Store interface {
	CreateEncryptedLegalHold(context.Context, db.CreateEncryptedLegalHoldParams) (db.LegalHold, error)
	GetLegalHoldByRequest(context.Context, db.GetLegalHoldByRequestParams) (db.LegalHold, error)
	GetLegalHold(context.Context, uuid.UUID) (db.LegalHold, error)
	ReleaseLegalHold(context.Context, db.ReleaseLegalHoldParams) (db.LegalHold, error)
	ListLegalHolds(context.Context, db.ListLegalHoldsParams) (db.ListLegalHoldsRow, error)
	ObserveLegalSubject(context.Context, uuid.UUID) (db.ObserveLegalSubjectRow, error)
	LookupLegalAttribution(context.Context, db.LookupLegalAttributionParams) ([]db.SecurityEventLedger, error)
	LegalAttributionHighWater(context.Context) (int64, error)
	CountUnencryptedLegalHolds(context.Context) (int64, error)
}

// Encryptor is implemented by the existing envelope Encryptor. Record identity
// lives inside its authenticated plaintext and is checked after every decrypt.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

// BlindIndexer uses the existing shared normalization and HMAC key.
type BlindIndexer interface{ Compute(string) string }

// Legal request kinds and input bounds form the persisted API contract.
const (
	LegalBasisPreservation = "preservation_request"
	IdentifierTypeEmail    = "email"
	KindHold               = "legal_hold"
	KindPreservation       = "preservation"
	MaxReasonBytes         = 4096
	MaxContextBytes        = 255
)

// Service manages independent retention locks and restricted attribution.
type Service struct {
	store             Store
	encryptor         Encryptor
	indexer           BlindIndexer
	lookupVerified    bool
	releasedRetention time.Duration
	maxWindow         time.Duration
	now               func() time.Time
}

// Option configures preservation and lookup policies.
type Option func(*Service)

// WithLookup requires an explicit signer/lookup synthetic-fixture verification;
// merely constructing a non-nil indexer is not evidence of a matching pepper.
func WithLookup(indexer BlindIndexer, verified bool) Option {
	return func(s *Service) { s.indexer, s.lookupVerified = indexer, verified }
}

// WithReleasedMetadataRetention enables intake only with an approved schedule.
// CleanupReleased must run with that same schedule. Opaque request tombstones
// are retained to prevent a cleaned-up key from silently reapplying a hold.
func WithReleasedMetadataRetention(d time.Duration) Option {
	return func(s *Service) { s.releasedRetention = d }
}

// WithMaxQueryWindow caps attribution windows at no more than 31 days.
func WithMaxQueryWindow(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 && d <= 31*24*time.Hour {
			s.maxWindow = d
		}
	}
}

// New constructs hold management independently of lookup availability.
func New(store Store, encryptor Encryptor, opts ...Option) (*Service, error) {
	if store == nil || encryptor == nil {
		return nil, ErrUnavailable
	}
	s := &Service{store: store, encryptor: encryptor, maxWindow: 31 * 24 * time.Hour, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// CryptoReady reports whether an encryption dependency is configured.
func (s *Service) CryptoReady() bool { return s != nil && s.encryptor != nil }

// IntakeEnabled requires an explicit released-metadata retention schedule.
func (s *Service) IntakeEnabled() bool { return s.CryptoReady() && s.releasedRetention > 0 }

// LookupEnabled additionally requires a verified shared indexer.
func (s *Service) LookupEnabled() bool {
	return s.IntakeEnabled() && s.indexer != nil && s.lookupVerified
}

// CheckCrypto fails readiness on inaccessible keys or legacy plaintext. Run the
// controlled Backfill first; no runtime path falls back to reading plaintext.
func (s *Service) CheckCrypto(ctx context.Context) error {
	probe := []byte(uuid.NewString())
	enc, err := s.encryptor.Encrypt(ctx, probe)
	if err != nil {
		return ErrUnavailable
	}
	dec, err := s.encryptor.Decrypt(ctx, enc)
	if err != nil || string(dec) != string(probe) {
		return ErrUnavailable
	}
	n, err := s.store.CountUnencryptedLegalHolds(ctx)
	if err != nil || n != 0 {
		return ErrBackfillRequired
	}
	return nil
}

// queries never falls back to pool-bound queries in production. The request
// middleware alone commits business changes and the durable audit outbox.
func (s *Service) queries(ctx context.Context) (Store, pgx.Tx, error) {
	if op, ok := adminaction.FromContext(ctx); ok {
		if op.Tx == nil || op.Queries == nil {
			return nil, nil, ErrTransactionRequired
		}
		return op.Queries, op.Tx, nil
	}
	if _, production := s.store.(*db.Queries); production {
		return nil, nil, ErrTransactionRequired
	}
	return s.store, nil, nil // narrow fake stores are permitted for unit tests only
}

func lock(ctx context.Context, tx pgx.Tx, actor, account uuid.UUID) error {
	if tx != nil {
		sess, ok := session.FromContext(ctx)
		if !ok || !sess.AuthVersionSet || sess.UserID != actor.String() {
			return rbac.ErrForbidden
		}
		if err := rbac.LockAuthorized(ctx, tx, actor, []uuid.UUID{account}, "legal.holds.write", sess.AuthVersion); err != nil {
			if errors.Is(err, rbac.ErrForbidden) {
				return rbac.ErrForbidden
			}
			return ErrUnavailable
		}
	}
	return nil
}

// Details contains legal narrative sealed inside the record envelope.
type Details struct {
	RecordID            uuid.UUID `json:"record_id"`
	AccountRef          uuid.UUID `json:"account_ref"`
	Kind                string    `json:"kind"`
	Reason              string    `json:"reason"`
	RequestingAuthority string    `json:"requesting_authority"`
	LegalBasis          string    `json:"legal_basis"`
}

// Hold combines storage state with its authorized decrypted details.
type Hold struct {
	Record        db.LegalHold
	Details       Details
	DetailsPurged bool
}

// ApplyRequest identifies one independent legal request and its replay key.
type ApplyRequest struct {
	AccountRef          uuid.UUID
	Reason              string
	RequestingAuthority string
	LegalBasis          string
	AppliedBy           uuid.UUID
	ReviewAt            time.Time
	IdempotencyKey      uuid.UUID
}

// ApplyResult reports the current hold and whether this is an idempotent replay.
type ApplyResult struct {
	Hold     Hold
	Replayed bool
}

func bounded(s string, maximum int) bool { return strings.TrimSpace(s) != "" && len(s) <= maximum }

func (r ApplyRequest) validate() error {
	if r.AccountRef == uuid.Nil || r.AppliedBy == uuid.Nil || r.IdempotencyKey == uuid.Nil ||
		!bounded(r.Reason, MaxReasonBytes) || !bounded(r.RequestingAuthority, MaxContextBytes) ||
		!bounded(r.LegalBasis, MaxContextBytes) {
		return ErrInvalidRequest
	}
	if !r.ReviewAt.IsZero() && (r.ReviewAt.Year() < 1 || r.ReviewAt.Year() > 9999) {
		return ErrInvalidRequest
	}
	return nil
}

// Apply creates or replays one independent legal hold.
func (s *Service) Apply(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	return s.apply(ctx, req, KindHold)
}

func (s *Service) apply(ctx context.Context, req ApplyRequest, kind string) (ApplyResult, error) {
	if err := req.validate(); err != nil {
		return ApplyResult{}, err
	}
	if !s.IntakeEnabled() {
		return ApplyResult{}, ErrUnavailable
	}
	q, tx, err := s.queries(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := lock(ctx, tx, req.AppliedBy, req.AccountRef); err != nil {
		return ApplyResult{}, err
	}
	review := timestamptz(req.ReviewAt)
	details := Details{AccountRef: req.AccountRef, Kind: kind, Reason: strings.TrimSpace(req.Reason),
		RequestingAuthority: strings.TrimSpace(req.RequestingAuthority), LegalBasis: strings.TrimSpace(req.LegalBasis)}
	existing, err := q.GetLegalHoldByRequest(ctx, db.GetLegalHoldByRequestParams{
		AccountRef: req.AccountRef, RequestKind: kind,
		IdempotencyKey: uuid.NullUUID{UUID: req.IdempotencyKey, Valid: true},
	})
	if err == nil {
		hold, err := s.openHold(ctx, existing)
		if err != nil {
			return ApplyResult{}, err
		}
		details.RecordID = existing.ID
		if hold.DetailsPurged || hold.Details != details || existing.ReviewAt.Valid != review.Valid ||
			(review.Valid && !existing.ReviewAt.Time.Equal(review.Time)) {
			return ApplyResult{}, ErrIdempotencyConflict
		}
		return ApplyResult{Hold: hold, Replayed: true}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ApplyResult{}, ErrUnavailable
	}
	details.RecordID = uuid.New()
	blob, err := s.seal(ctx, details)
	if err != nil {
		return ApplyResult{}, err
	}
	row, err := q.CreateEncryptedLegalHold(ctx, db.CreateEncryptedLegalHoldParams{
		ID: details.RecordID, AccountRef: req.AccountRef, AppliedBy: req.AppliedBy,
		ReviewAt: review, RequestKind: kind,
		IdempotencyKey: uuid.NullUUID{UUID: req.IdempotencyKey, Valid: true}, DetailsEncrypted: blob,
	})
	if err != nil {
		return ApplyResult{}, ErrUnavailable
	}
	return ApplyResult{Hold: Hold{Record: row, Details: details}}, nil
}

func (s *Service) seal(ctx context.Context, details Details) ([]byte, error) {
	plain, err := json.Marshal(details)
	if err != nil {
		return nil, ErrUnavailable
	}
	blob, err := s.encryptor.Encrypt(ctx, plain)
	clear(plain)
	if err != nil {
		return nil, ErrUnavailable
	}
	return blob, nil
}

func (s *Service) openHold(ctx context.Context, row db.LegalHold) (Hold, error) {
	h := Hold{Record: row, DetailsPurged: row.DetailsPurgedAt.Valid}
	if row.Reason != nil || row.RequestingAuthority != nil || row.LegalBasis != nil {
		return Hold{}, ErrBackfillRequired
	}
	if h.DetailsPurged && !row.IsActive && len(row.DetailsEncrypted) == 0 {
		return h, nil
	}
	plain, err := s.encryptor.Decrypt(ctx, row.DetailsEncrypted)
	if err != nil {
		return Hold{}, ErrUnavailable
	}
	defer clear(plain)
	if json.Unmarshal(plain, &h.Details) != nil || h.Details.RecordID != row.ID ||
		h.Details.AccountRef != row.AccountRef || h.Details.Kind != row.RequestKind {
		return Hold{}, ErrUnavailable
	}
	return h, nil
}

// PreserveRequest records preservation without requiring a surviving account.
type PreserveRequest struct {
	AccountRef          uuid.UUID
	RequestingAuthority string
	Reason              string
	AppliedBy           uuid.UUID
	ExpiresAt           time.Time
	IdempotencyKey      uuid.UUID
}

// PreserveResult includes observations under the shared subject lock.
type PreserveResult struct {
	ApplyResult
	AccountPresent        bool
	LedgerEvidencePresent bool
	ObservedAt            time.Time
}

// Preserve applies a retention lock and observes existing evidence atomically.
func (s *Service) Preserve(ctx context.Context, req PreserveRequest) (PreserveResult, error) {
	result, err := s.apply(ctx, ApplyRequest{AccountRef: req.AccountRef, Reason: req.Reason,
		RequestingAuthority: req.RequestingAuthority, LegalBasis: LegalBasisPreservation,
		AppliedBy: req.AppliedBy, ReviewAt: req.ExpiresAt, IdempotencyKey: req.IdempotencyKey}, KindPreservation)
	if err != nil {
		return PreserveResult{}, err
	}
	q, _, err := s.queries(ctx)
	if err != nil {
		return PreserveResult{}, err
	}
	// The subject advisory lock is still held, including on an idempotent replay.
	observation, err := q.ObserveLegalSubject(ctx, req.AccountRef)
	if err != nil {
		return PreserveResult{}, ErrUnavailable
	}
	return PreserveResult{ApplyResult: result, AccountPresent: observation.AccountPresent,
		LedgerEvidencePresent: observation.LedgerEvidencePresent, ObservedAt: s.now().UTC()}, nil
}

// ReleaseResult distinguishes a release from an already released retry.
type ReleaseResult struct {
	Hold     Hold
	Replayed bool
}

// Release removes only the specified request protection.
func (s *Service) Release(ctx context.Context, id, actor uuid.UUID) (ReleaseResult, error) {
	if id == uuid.Nil || actor == uuid.Nil {
		return ReleaseResult{}, ErrInvalidRequest
	}
	q, tx, err := s.queries(ctx)
	if err != nil {
		return ReleaseResult{}, err
	}
	row, err := q.GetLegalHold(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReleaseResult{}, ErrHoldNotFound
	}
	if err != nil {
		return ReleaseResult{}, ErrUnavailable
	}
	// The initial read resolves only the immutable account reference. Re-read the
	// mutable state in a fresh statement after obtaining the subject lock.
	if err := lock(ctx, tx, actor, row.AccountRef); err != nil {
		return ReleaseResult{}, err
	}
	row, err = q.GetLegalHold(ctx, id)
	if err != nil {
		return ReleaseResult{}, ErrUnavailable
	}
	replayed := !row.IsActive
	if !replayed {
		row, err = q.ReleaseLegalHold(ctx, db.ReleaseLegalHoldParams{ID: id, ReleasedBy: uuid.NullUUID{UUID: actor, Valid: true}})
		if err != nil {
			return ReleaseResult{}, ErrUnavailable
		}
	}
	h, err := s.openHold(ctx, row)
	return ReleaseResult{Hold: h, Replayed: replayed}, err
}

// ListRequest bounds and filters the legal-hold snapshot.
type ListRequest struct {
	AccountRef    uuid.NullUUID
	Status        string
	Limit, Offset int32
}

// ListResult returns a page and the count from the same query snapshot.
type ListResult struct {
	Holds []Hold
	Total int64
}

// List returns an authorized page and total from one database snapshot.
func (s *Service) List(ctx context.Context, req ListRequest) (ListResult, error) {
	if req.Status == "" {
		req.Status = "active"
	}
	if (req.Status != "active" && req.Status != "released" && req.Status != "all") ||
		req.Limit < 1 || req.Limit > 200 || req.Offset < 0 {
		return ListResult{}, ErrInvalidRequest
	}
	q, _, err := s.queries(ctx)
	if err != nil {
		return ListResult{}, err
	}
	page, err := q.ListLegalHolds(ctx, db.ListLegalHoldsParams{AccountRef: req.AccountRef,
		Status: req.Status, PageLimit: req.Limit, PageOffset: req.Offset})
	if err != nil {
		return ListResult{}, ErrUnavailable
	}
	var rows []db.LegalHold
	if err := json.Unmarshal(page.Items, &rows); err != nil {
		return ListResult{}, ErrUnavailable
	}
	result := ListResult{Holds: make([]Hold, 0, len(rows)), Total: page.Total}
	for _, row := range rows {
		hold, err := s.openHold(ctx, row)
		if err != nil {
			return ListResult{}, err
		}
		result.Holds = append(result.Holds, hold)
	}
	return result, nil
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC().Truncate(time.Microsecond), Valid: true}
}
