package legalhold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type fakeStore struct {
	holds          map[uuid.UUID]db.LegalHold
	events         []db.SecurityEventLedger
	accountPresent bool
	lookupParams   db.LookupLegalAttributionParams
	err            error
}

func newFakeStore() *fakeStore { return &fakeStore{holds: make(map[uuid.UUID]db.LegalHold)} }

func (f *fakeStore) CreateEncryptedLegalHold(_ context.Context, p db.CreateEncryptedLegalHoldParams) (db.LegalHold, error) {
	if f.err != nil {
		return db.LegalHold{}, f.err
	}
	h := db.LegalHold{ID: p.ID, AccountRef: p.AccountRef, AppliedBy: p.AppliedBy, ReviewAt: p.ReviewAt,
		IsActive: true, AppliedAt: timestamptz(time.Now()), RequestKind: p.RequestKind,
		IdempotencyKey: p.IdempotencyKey, DetailsEncrypted: p.DetailsEncrypted}
	f.holds[h.ID] = h
	return h, nil
}
func (f *fakeStore) GetLegalHoldByRequest(_ context.Context, p db.GetLegalHoldByRequestParams) (db.LegalHold, error) {
	if f.err != nil {
		return db.LegalHold{}, f.err
	}
	for _, h := range f.holds {
		if h.AccountRef == p.AccountRef && h.RequestKind == p.RequestKind && h.IdempotencyKey == p.IdempotencyKey {
			return h, nil
		}
	}
	return db.LegalHold{}, pgx.ErrNoRows
}
func (f *fakeStore) GetLegalHold(_ context.Context, id uuid.UUID) (db.LegalHold, error) {
	h, ok := f.holds[id]
	if !ok {
		return h, pgx.ErrNoRows
	}
	return h, nil
}
func (f *fakeStore) ReleaseLegalHold(_ context.Context, p db.ReleaseLegalHoldParams) (db.LegalHold, error) {
	h, ok := f.holds[p.ID]
	if !ok || !h.IsActive {
		return h, pgx.ErrNoRows
	}
	h.IsActive, h.ReleasedBy, h.ReleasedAt = false, p.ReleasedBy, timestamptz(time.Now())
	f.holds[h.ID] = h
	return h, nil
}
func (f *fakeStore) ListLegalHolds(_ context.Context, p db.ListLegalHoldsParams) (db.ListLegalHoldsRow, error) {
	rows := []db.LegalHold{}
	for _, h := range f.holds {
		if p.AccountRef.Valid && h.AccountRef != p.AccountRef.UUID {
			continue
		}
		if (p.Status == "active" && !h.IsActive) || (p.Status == "released" && h.IsActive) {
			continue
		}
		rows = append(rows, h)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID.String() < rows[j].ID.String() })
	total := len(rows)
	start := min(int(p.PageOffset), len(rows))
	end := min(start+int(p.PageLimit), len(rows))
	blob, _ := json.Marshal(rows[start:end])
	return db.ListLegalHoldsRow{Total: int64(total), Items: blob}, nil
}
func (f *fakeStore) ObserveLegalSubject(_ context.Context, id uuid.UUID) (db.ObserveLegalSubjectRow, error) {
	result := db.ObserveLegalSubjectRow{AccountPresent: f.accountPresent}
	for _, e := range f.events {
		if e.AccountRef == id {
			result.LedgerEvidencePresent = true
		}
	}
	return result, nil
}
func (f *fakeStore) LookupLegalAttribution(_ context.Context, p db.LookupLegalAttributionParams) ([]db.SecurityEventLedger, error) {
	f.lookupParams = p
	var result []db.SecurityEventLedger
	for _, e := range f.events {
		held := false
		for _, h := range f.holds {
			if h.AccountRef == e.AccountRef && h.IsActive {
				held = true
			}
		}
		if e.IdentityBlindIndex == nil || *e.IdentityBlindIndex != p.BlindIndex || e.Seq <= p.AfterSeq || e.Seq > p.ThroughSeq ||
			e.Timestamp.Time.Before(p.StartTime.Time) || e.Timestamp.Time.After(p.EndTime.Time) ||
			(e.RetainUntil.Time.Before(p.AsOf.Time) && !held) {
			continue
		}
		result = append(result, e)
		if len(result) == int(p.PageLimit) {
			break
		}
	}
	return result, f.err
}
func (f *fakeStore) LegalAttributionHighWater(context.Context) (int64, error) {
	var maxSeq int64
	for _, e := range f.events {
		maxSeq = max(maxSeq, e.Seq)
	}
	return maxSeq, f.err
}
func (f *fakeStore) CountUnencryptedLegalHolds(context.Context) (int64, error) {
	var count int64
	for _, h := range f.holds {
		if h.Reason != nil || len(h.DetailsEncrypted) == 0 && !h.DetailsPurgedAt.Valid {
			count++
		}
	}
	return count, f.err
}

func testEncryptor(t *testing.T) *envelope.Encryptor {
	t.Helper()
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{0x51}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	e, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func testService(t *testing.T) (*Service, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	indexer, err := blindindex.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(store, testEncryptor(t), WithLookup(indexer, true), WithReleasedMetadataRetention(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC) }
	return s, store
}
func validApply() ApplyRequest {
	return ApplyRequest{AccountRef: uuid.New(), AppliedBy: uuid.New(), IdempotencyKey: uuid.New(),
		Reason: " investigation ", RequestingAuthority: " court ", LegalBasis: " order "}
}

func TestIndependentHoldsAndIdempotentReplay(t *testing.T) {
	s, store := testService(t)
	ctx := context.Background()
	req := validApply()
	first, err := s.Apply(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replayed || first.Hold.Details.Reason != "investigation" {
		t.Fatal("unexpected first result")
	}
	row := store.holds[first.Hold.Record.ID]
	if row.Reason != nil || row.RequestingAuthority != nil || row.LegalBasis != nil || bytes.Contains(row.DetailsEncrypted, []byte("investigation")) {
		t.Fatal("plaintext retained")
	}
	replay, err := s.Apply(ctx, req)
	if err != nil || !replay.Replayed || replay.Hold.Record.ID != first.Hold.Record.ID {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	other := req
	other.IdempotencyKey = uuid.New()
	second, err := s.Apply(ctx, other)
	if err != nil || second.Hold.Record.ID == first.Hold.Record.ID {
		t.Fatal("independent request collapsed")
	}
	if _, err := s.Release(ctx, first.Hold.Record.ID, req.AppliedBy); err != nil {
		t.Fatal(err)
	}
	if !store.holds[second.Hold.Record.ID].IsActive {
		t.Fatal("releasing one released another")
	}
	replay, err = s.Apply(ctx, req)
	if err != nil || !replay.Replayed || replay.Hold.Record.IsActive {
		t.Fatalf("released replay resurrected hold: %v", err)
	}
	release, err := s.Release(ctx, first.Hold.Record.ID, req.AppliedBy)
	if err != nil || !release.Replayed {
		t.Fatal("release retry not no-op")
	}
	req.Reason = "different"
	if _, err := s.Apply(ctx, req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("changed payload accepted")
	}
}

func TestPreservePostDeletionAndAdvisoryExpiry(t *testing.T) {
	for _, evidence := range []bool{false, true} {
		t.Run(fmt.Sprint(evidence), func(t *testing.T) {
			s, store := testService(t)
			req := validApply()
			if evidence {
				store.events = []db.SecurityEventLedger{{AccountRef: req.AccountRef}}
			}
			res, err := s.Preserve(context.Background(), PreserveRequest{AccountRef: req.AccountRef, AppliedBy: req.AppliedBy,
				Reason: req.Reason, RequestingAuthority: req.RequestingAuthority, IdempotencyKey: req.IdempotencyKey, ExpiresAt: s.now().Add(-time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if res.AccountPresent || res.LedgerEvidencePresent != evidence || !res.Hold.Record.IsActive || res.ObservedAt.IsZero() {
				t.Fatal("incorrect presence or expiry")
			}
		})
	}
}

func TestValidationAndReadiness(t *testing.T) {
	s, store := testService(t)
	ctx := context.Background()
	for _, mutate := range []func(*ApplyRequest){func(r *ApplyRequest) { r.Reason = "" }, func(r *ApplyRequest) { r.AppliedBy = uuid.Nil },
		func(r *ApplyRequest) { r.IdempotencyKey = uuid.Nil }, func(r *ApplyRequest) { r.RequestingAuthority = strings.Repeat("x", 256) }} {
		r := validApply()
		mutate(&r)
		if _, err := s.Apply(ctx, r); !errors.Is(err, ErrInvalidRequest) {
			t.Fatal("invalid request accepted")
		}
	}
	s.indexer = nil
	if !s.IntakeEnabled() || s.LookupEnabled() {
		t.Fatal("hold depends on pepper")
	}
	if err := s.CheckCrypto(ctx); err != nil {
		t.Fatal(err)
	}
	s.releasedRetention = 0
	if _, err := s.Apply(ctx, validApply()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("intake without policy")
	}
	store.holds[uuid.New()] = db.LegalHold{}
	if err := s.CheckCrypto(ctx); !errors.Is(err, ErrBackfillRequired) {
		t.Fatal("plaintext readiness accepted")
	}
	prod, err := New(db.New(nil), testEncryptor(t), WithReleasedMetadataRetention(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prod.Apply(ctx, validApply()); !errors.Is(err, ErrTransactionRequired) {
		t.Fatal("pool fallback allowed")
	}
	if _, _, err := s.queries(adminaction.WithContext(ctx, &adminaction.Operation{})); err == nil {
		t.Fatal("broken tx context accepted")
	}
}

func TestCiphertextBindingAndTombstone(t *testing.T) {
	s, store := testService(t)
	ctx := context.Background()
	req := validApply()
	res, err := s.Apply(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	row := res.Hold.Record
	row.ID = uuid.New()
	if _, err := s.openHold(ctx, row); err == nil {
		t.Fatal("ciphertext transplanted")
	}
	row = res.Hold.Record
	row.IsActive = false
	row.DetailsEncrypted = nil
	row.DetailsPurgedAt = timestamptz(s.now())
	store.holds[row.ID] = row
	if _, err := s.Apply(ctx, req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("tombstone reapplied")
	}
}

func TestListTrueTotalAndStatuses(t *testing.T) {
	s, _ := testService(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r, err := s.Apply(ctx, validApply())
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			_, err = s.Release(ctx, r.Hold.Record.ID, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for status, total := range map[string]int64{"all": 3, "active": 2, "released": 1} {
		res, err := s.List(ctx, ListRequest{Status: status, Limit: 1, Offset: 0})
		if err != nil || res.Total != total || len(res.Holds) != 1 {
			t.Fatalf("%s: %+v %v", status, res, err)
		}
		res, err = s.List(ctx, ListRequest{Status: status, Limit: 1, Offset: 100})
		if err != nil || res.Total != total || len(res.Holds) != 0 {
			t.Fatal("empty offset lost total")
		}
	}
	if _, err := s.List(ctx, ListRequest{Status: "nonsense", Limit: 1}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("invalid status")
	}
}

func lookupFixture(t *testing.T) (*Service, *fakeStore, LookupRequest) {
	s, store := testService(t)
	r := LookupRequest{IdentifierType: "email", Identifier: "alice@example.test", RequestingAuthority: "court", CaseReference: "case", Purpose: "investigation", ActorID: uuid.New(), StartTime: s.now().Add(-time.Hour), EndTime: s.now(), Limit: 2}
	index := s.indexer.Compute(r.Identifier)
	for i := int64(1); i <= 4; i++ {
		store.events = append(store.events, db.SecurityEventLedger{ID: uuid.New(), AccountRef: uuid.New(), Seq: i,
			IdentityBlindIndex: &index, Timestamp: timestamptz(s.now().Add(-time.Minute)), RetainUntil: timestamptz(s.now().Add(time.Hour))})
	}
	return s, store, r
}

func TestLookupRetentionKeysetScopeAndCoverage(t *testing.T) {
	s, store, req := lookupFixture(t)
	ctx := context.Background()
	store.events[0].RetainUntil = timestamptz(s.now().Add(-time.Hour)) // expired unheld excluded
	store.events[1].RetainUntil = timestamptz(s.now())                 // exact retention boundary included
	store.events[2].RetainUntil = timestamptz(s.now().Add(-time.Hour))
	hold := validApply()
	hold.AccountRef = store.events[2].AccountRef
	applied, err := s.Apply(ctx, hold)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Lookup(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || first.Events[0].Seq != 2 || first.Events[1].Seq != 3 || first.NextCursor == "" || first.Coverage.ThroughSeq != 4 {
		t.Fatal("wrong retained page")
	}
	if strings.Contains(first.NextCursor, req.Identifier) || strings.Contains(first.NextCursor, *store.events[0].IdentityBlindIndex) {
		t.Fatal("cursor leaks index")
	}
	req.Cursor = first.NextCursor
	changed := req
	changed.Identifier = "bob@example.test"
	if _, err := s.Lookup(ctx, changed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("cursor crossed query scope")
	}
	changed = req
	changed.Fields = []string{"client_ip"}
	if _, err := s.Lookup(ctx, changed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("cursor expanded disclosure")
	}
	second, err := s.Lookup(ctx, req)
	if err != nil || len(second.Events) != 1 || second.Events[0].Seq != 4 || second.NextCursor != "" {
		t.Fatal("wrong final page")
	}
	_, err = s.Release(ctx, applied.Hold.Record.ID, hold.AppliedBy)
	if err != nil {
		t.Fatal(err)
	}
	req.Cursor = ""
	last, err := s.Lookup(ctx, req)
	if err != nil || len(last.Events) != 2 || last.Events[1].Seq != 4 {
		t.Fatal("release did not restore original clock")
	}
}

func TestLookupValidationAndPrivateErrors(t *testing.T) {
	s, store, req := lookupFixture(t)
	for _, mutate := range []func(*LookupRequest){func(r *LookupRequest) { r.IdentifierType = "phone" }, func(r *LookupRequest) { r.Purpose = "" },
		func(r *LookupRequest) { r.Fields = []string{"identity_blind_index"} }, func(r *LookupRequest) { r.Fields = []string{"client_ip", "client_ip"} },
		func(r *LookupRequest) { r.StartTime = r.EndTime.Add(-32 * 24 * time.Hour) }, func(r *LookupRequest) { r.Limit = 201 }} {
		r := req
		mutate(&r)
		if _, err := s.Lookup(context.Background(), r); err == nil {
			t.Fatal("invalid lookup accepted")
		}
	}
	store.err = errors.New("database error raw alice@example.test secret-index")
	_, err := s.Lookup(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "secret-index") {
		t.Fatal("private storage error escaped")
	}
	s.lookupVerified = false
	store.err = nil
	if _, err := s.Lookup(context.Background(), req); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unverified pepper enabled")
	}
}
