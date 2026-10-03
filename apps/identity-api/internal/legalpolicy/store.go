package legalpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// Load revalidates a persisted policy and its immutable baseline on every call.
// Use the current operation's transaction for mutation and stored-policy checks.
func Load(ctx context.Context, q db.DBTX, id uuid.UUID, environment string) (Policy, error) {
	p, err := loadPolicy(ctx, q, id, environment)
	if err != nil {
		return Policy{}, err
	}
	baseline, err := LoadBaseline(ctx, q, uuid.Nil, environment)
	if err != nil {
		return Policy{}, err
	}
	if !sameBaseline(p, baseline) {
		return Policy{}, ErrMismatch
	}
	return p, nil
}

// LoadBaseline requires the configured version to be the singleton binding.
// Maintenance passes uuid.Nil to resolve the stored binding independently of
// feature flags/configuration. No existing row or retention clock is rewritten.
func LoadBaseline(ctx context.Context, q db.DBTX, configuredID uuid.UUID, environment string) (Policy, error) {
	if q == nil {
		return Policy{}, ErrUnavailable
	}
	id, err := db.New(q).GetLegalGovernanceBaseline(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, ErrNotApproved
		}
		return Policy{}, ErrUnavailable
	}
	if configuredID != uuid.Nil && configuredID != id {
		return Policy{}, ErrMismatch
	}
	return loadPolicy(ctx, q, id, environment)
}

func loadPolicy(ctx context.Context, q db.DBTX, id uuid.UUID, environment string) (Policy, error) {
	if q == nil {
		return Policy{}, ErrUnavailable
	}
	if id == uuid.Nil {
		return Policy{}, ErrNotApproved
	}
	row, err := db.New(q).GetLegalGovernancePolicy(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, ErrNotApproved
		}
		return Policy{}, ErrUnavailable
	}
	p, err := Decode(strings.NewReader(string(row.Artifact)))
	if err != nil || p.ID != id {
		return Policy{}, ErrInvalidPolicy
	}
	if err := p.Validate(environment); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Install is exclusively for the controlled non-HTTP operator path using a
// separately provisioned DB role. The launcher attests Event actor/SPIFFE fields;
// those fields and approval references are not credentials. Caller MUST commit
// via Operation.Commit so installation, binding and audit intent are atomic.
func Install(ctx context.Context, op *adminaction.Operation, p Policy, environment string) error {
	if op == nil || op.Tx == nil || op.ID == uuid.Nil {
		return adminaction.ErrNoOperation
	}
	u, err := url.Parse(op.Event.ActorSPIFFEID)
	if op.Event.ActorID == uuid.Nil || err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || len(op.Event.ActorSPIFFEID) > 255 || strings.ContainsAny(op.Event.ActorSPIFFEID, " \t\r\n") {
		return ErrOperatorRequired
	}
	if err := p.Validate(environment); err != nil {
		return err
	}
	p = canonical(p)
	// Only installers take this lock. It serializes first binding and ID replays;
	// it is unrelated to account and cryptographic-ledger lock namespaces.
	if _, err := op.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(550512, 1)`); err != nil {
		return ErrUnavailable
	}
	baseline, err := LoadBaseline(ctx, op.Tx, uuid.Nil, environment)
	firstBinding := errors.Is(err, ErrNotApproved)
	if err != nil && !firstBinding {
		return err
	}
	if !firstBinding && !sameBaseline(p, baseline) {
		return ErrMismatch
	}
	queries := db.New(op.Tx)
	if firstBinding {
		inventory, err := queries.InspectLegalGovernanceLegacyInventory(ctx, float64(p.ContextRetentionSeconds))
		if err != nil || inventory.HasLegacyRecords == nil {
			return ErrUnavailable
		}
		if *inventory.HasLegacyRecords && p.LegacyInventoryReference == "" {
			return ErrInventoryRequired
		}
		if inventory.HasInconsistentContextClocks {
			return ErrMismatch
		}
	}
	stored, err := loadPolicy(ctx, op.Tx, p.ID, environment)
	replayed := err == nil
	if err != nil && !errors.Is(err, ErrNotApproved) {
		return err
	}
	if replayed && !reflect.DeepEqual(canonical(stored), p) {
		return ErrConflict
	}
	if !replayed {
		artifact, err := json.Marshal(p)
		if err != nil {
			return ErrInvalidPolicy
		}
		if err := queries.InsertLegalGovernancePolicy(ctx, db.InsertLegalGovernancePolicyParams{
			ID: p.ID, Artifact: artifact, InstalledBy: op.Event.ActorID,
			OperatorIdentity: op.Event.ActorSPIFFEID, ActionID: op.ID, InstalledEnvironment: environment,
		}); err != nil {
			return ErrUnavailable
		}
	}
	if firstBinding {
		if err := queries.BindLegalGovernanceBaseline(ctx, p.ID); err != nil {
			return ErrUnavailable
		}
	}
	op.Event.EventType = "legal.policy.installed"
	op.Event.ActionStatus = audit.StatusSuccess
	op.Event.Payload = map[string]any{"operation_id": op.ID, "noop": replayed}
	return nil
}

func canonical(p Policy) Policy {
	p.HoldTombstoneFields = slices.Clone(p.HoldTombstoneFields)
	slices.Sort(p.HoldTombstoneFields)
	if p.Workflow != nil {
		w := *p.Workflow
		w.ReplayFields = slices.Clone(w.ReplayFields)
		slices.Sort(w.ReplayFields)
		p.Workflow = &w
	}
	return p
}
