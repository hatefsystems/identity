package geography

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Plan emits aggregate counts and digests only, never source labels or full rows.
type Plan struct {
	BaseRevision     *string `json:"base_revision"`
	CatalogRevision  string  `json:"catalog_revision"`
	Additions        int     `json:"additions"`
	Edits            int     `json:"edits"`
	Reparenting      int     `json:"reparenting"`
	Retirements      int     `json:"retirements"`
	Reactivations    int     `json:"reactivations"`
	TypeEdits        int     `json:"type_edits"`
	NoOp             bool    `json:"no_op"`
	PlanDigest       string  `json:"plan_digest"`
	RetirementDigest string  `json:"retirement_digest"`
}
type change struct {
	ID            int64
	Kind          string
	Before, After string
}

func baseOf(snapshot *Snapshot) int64 {
	if snapshot.manifest.ExpectedCurrentRevision == nil {
		return 0
	}
	n, _ := decimal(*snapshot.manifest.ExpectedCurrentRevision)
	return n
}
func sameParent(a, b *int64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func recordHash(r record) string  { raw, _ := json.Marshal(r); return digest(raw) }
func catalogMatches(c db.GeographyCatalog, s *Snapshot) bool {
	return hex.EncodeToString(c.CitiesSha256) == s.manifest.CitiesSHA256 && hex.EncodeToString(c.TypesSha256) == s.manifest.TypesSHA256
}

func compare(ctx context.Context, q *db.Queries, s *Snapshot, base int64) (Plan, error) {
	plan := Plan{BaseRevision: s.manifest.ExpectedCurrentRevision}
	events := make([]change, 0)
	previous := make(map[int64]record)
	known := make(map[int64]bool)
	oldTypes := make(map[int64]string)
	if base > 0 {
		catalog, err := q.GeographyCatalog(ctx, base)
		if errors.Is(err, pgx.ErrNoRows) {
			return Plan{}, ErrCatalogChanged
		}
		if err != nil {
			return Plan{}, ErrUnavailable
		}
		plan.CatalogRevision = number(base)
		plan.NoOp = catalogMatches(catalog, s)
		versions, err := q.GeographySnapshot(ctx, base)
		if err != nil {
			return Plan{}, ErrUnavailable
		}
		for _, p := range versions {
			previous[p.ID] = record{p.ID, p.Label, p.TypeID, p.ParentID, p.ProvinceID, p.SearchLabel}
		}
		identities, err := q.GeographyIdentities(ctx)
		if err != nil {
			return Plan{}, ErrUnavailable
		}
		for _, p := range identities {
			if p.FirstSeenRevision <= base {
				known[p.ID] = true
			}
		}
		types, err := q.GeographyTypes(ctx, base)
		if err != nil {
			return Plan{}, ErrUnavailable
		}
		for _, t := range types {
			oldTypes[t.ID] = t.Label
		}
	}
	if !plan.NoOp {
		for _, p := range s.places {
			old, exists := previous[p.ID]
			if !exists {
				kind := "addition"
				plan.Additions++
				if known[p.ID] {
					kind = "reactivation"
					plan.Additions--
					plan.Reactivations++
				}
				events = append(events, change{p.ID, kind, "", recordHash(p)})
			} else {
				if old.Label != p.Label || old.TypeID != p.TypeID {
					plan.Edits++
					events = append(events, change{p.ID, "edit", recordHash(old), recordHash(p)})
				}
				if !sameParent(old.ParentID, p.ParentID) || old.ProvinceID != p.ProvinceID {
					plan.Reparenting++
					events = append(events, change{p.ID, "reparent", recordHash(old), recordHash(p)})
				}
				delete(previous, p.ID)
			}
		}
		for _, p := range previous {
			plan.Retirements++
			events = append(events, change{p.ID, "retirement", recordHash(p), ""})
		}
		for _, t := range s.types {
			old, exists := oldTypes[*t.ID]
			if !exists || old != *t.Name {
				plan.TypeEdits++
				events = append(events, change{*t.ID, "type", digest([]byte(old)), digest([]byte(*t.Name))})
			}
			delete(oldTypes, *t.ID)
		}
		for id, label := range oldTypes {
			plan.TypeEdits++
			events = append(events, change{id, "type-retirement", digest([]byte(label)), ""})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].ID != events[j].ID {
			return events[i].ID < events[j].ID
		}
		return events[i].Kind < events[j].Kind
	})
	raw, _ := json.Marshal(struct {
		Version  string
		Manifest Manifest
		NoOp     bool
		Changes  []change
	}{ImporterVersion + ":" + NormalizationVersion, s.manifest, plan.NoOp, events})
	plan.PlanDigest = digest(raw)
	if plan.Retirements > 0 {
		retired := make([]change, 0, plan.Retirements)
		for _, e := range events {
			if e.Kind == "retirement" {
				retired = append(retired, e)
			}
		}
		raw, _ := json.Marshal(struct {
			Plan        string
			Retirements []change
		}{plan.PlanDigest, retired})
		plan.RetirementDigest = digest(raw)
	}
	return plan, nil
}

// Check uses a read-only transaction and never runs migrations or acquires write locks.
func (s *Service) Check(ctx context.Context, snapshot *Snapshot) (Plan, error) {
	if snapshot == nil {
		return Plan{}, ErrInvalid
	}
	if s == nil || s.database == nil {
		return Plan{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	defer rollback(tx)
	q := db.New(tx)
	active, err := q.GeographyActiveRevision(ctx)
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	base := baseOf(snapshot)
	if active == nil && base != 0 || active != nil && *active != base {
		return Plan{}, ErrCatalogChanged
	}
	return compare(ctx, q, snapshot, base)
}

// Import acquires shared migration exclusion, exclusive import exclusion, then
// the state row. All locks are transaction-scoped and bounded, including rollback.
func (s *Service) Import(ctx context.Context, snapshot *Snapshot, applyPlan, retirementDigest string) (Plan, error) {
	if snapshot == nil || !validDigest(applyPlan) || retirementDigest != "" && !validDigest(retirementDigest) {
		return Plan{}, ErrInvalid
	}
	if s == nil || s.database == nil {
		return Plan{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// Read committed is essential: a waiter must see the winner's committed state.
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	defer rollback(tx)
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='120s'`); err != nil {
		return Plan{}, ErrUnavailable
	}
	locked, stop := context.WithTimeout(ctx, 10*time.Second)
	for i, key := range []int64{pglock.MigrationKey, pglock.GeographyImportKey} {
		query := `SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)`
		if i == 1 {
			query = `SELECT pg_catalog.pg_try_advisory_xact_lock($1)`
		}
		for {
			var acquired bool
			err = tx.QueryRow(locked, query, key).Scan(&acquired)
			if err != nil || acquired {
				break
			}
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-locked.Done():
				timer.Stop()
				err = locked.Err()
			case <-timer.C:
			}
			if err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	stop()
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	q := db.New(tx)
	active, err := q.GeographyLockState(ctx)
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	base := baseOf(snapshot)
	identical := false
	if active != nil {
		catalog, err := q.GeographyCatalog(ctx, *active)
		if err != nil {
			return Plan{}, ErrUnavailable
		}
		identical = catalogMatches(catalog, snapshot)
	}
	if !identical && (active == nil && base != 0 || active != nil && *active != base) {
		return Plan{}, ErrCatalogChanged
	}
	// On an identical concurrent import, reconstruct the checked historical base
	// rather than accepting an arbitrary digest or duplicating the snapshot.
	plan, err := compare(ctx, q, snapshot, base)
	if err != nil {
		return Plan{}, err
	}
	if applyPlan != plan.PlanDigest || retirementDigest != plan.RetirementDigest {
		return Plan{}, ErrInvalid
	}
	if identical {
		plan.NoOp = true
		plan.CatalogRevision = number(*active)
		return plan, nil
	}
	revision, err := q.GeographyNextRevision(ctx)
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	m := snapshot.manifest
	if m.PlaceCount < 1 || m.PlaceCount > MaxPlaces || m.TypeCount < 1 || m.TypeCount > MaxTypes || m.ProvinceCount < 1 || m.ProvinceCount > MaxPlaces {
		return Plan{}, ErrInvalid
	}
	citiesHash, _ := hex.DecodeString(m.CitiesSHA256)
	typesHash, _ := hex.DecodeString(m.TypesSHA256)
	err = q.GeographyInsertCatalog(ctx, db.GeographyInsertCatalogParams{Revision: revision, Country: m.Country, SourceRelease: m.SourceRelease,
		CitiesSha256: citiesHash, TypesSha256: typesHash, CitiesBytes: m.CitiesBytes, TypesBytes: m.TypesBytes,
		PlaceCount: int32(m.PlaceCount), TypeCount: int32(m.TypeCount), ProvinceCount: int32(m.ProvinceCount), ImporterVersion: ImporterVersion, NormalizationVersion: NormalizationVersion})
	if err != nil {
		return Plan{}, ErrUnavailable
	}
	// Batches amortize round-trips while using the generated storage contract.
	// Each bounded chunk is drained before the next chunk or pointer switch.
	for _, t := range snapshot.types {
		if q.GeographyInsertType(ctx, db.GeographyInsertTypeParams{Revision: revision, ID: *t.ID, Label: *t.Name}) != nil {
			return Plan{}, ErrUnavailable
		}
	}
	for start := 0; start < len(snapshot.places); start += 500 {
		end := min(start+500, len(snapshot.places))
		identities := make([]db.GeographyUpsertIdentityParams, 0, end-start)
		versions := make([]db.GeographyInsertVersionParams, 0, end-start)
		for _, p := range snapshot.places[start:end] {
			identities = append(identities, db.GeographyUpsertIdentityParams{ID: p.ID, FirstSeenRevision: revision})
			versions = append(versions, db.GeographyInsertVersionParams{Revision: revision, ID: p.ID, Label: p.Label, TypeID: p.TypeID, ParentID: p.ParentID, ProvinceID: p.ProvinceID, SearchLabel: p.SearchLabel})
		}
		if q.GeographyUpsertIdentity(ctx, identities).Close() != nil || q.GeographyInsertVersion(ctx, versions).Close() != nil {
			return Plan{}, ErrUnavailable
		}
	}
	if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
		return Plan{}, ErrUnavailable
	}
	if q.GeographyActivate(ctx, &revision) != nil {
		return Plan{}, ErrUnavailable
	}
	if tx.Commit(ctx) != nil {
		return Plan{}, ErrUnavailable
	}
	plan.CatalogRevision = number(revision)
	return plan, nil
}
