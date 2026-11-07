package legalpolicy

import (
	"context"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// ProbeInstaller includes the read inventory needed on FIRST baseline binding,
// not just the weaker read/write surface needed to replay an installed policy.
func ProbeInstaller(ctx context.Context, q db.DBTX) error {
	if err := dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{
			{Name: "legal_governance_policies", Select: true, Insert: true},
			{Name: "legal_governance_baseline", Select: true, Insert: true},
			{Name: "legal_holds", Select: true},
			{Name: "admin_action_contexts", Select: true},
			{Name: "event_outbox", Insert: true},
		},
		Guards: []dbprivilege.Guard{
			{Table: "legal_governance_policies", Name: "legal_governance_policy_immutable", Function: "legal_governance_immutable()", Type: 27},
			{Table: "legal_governance_policies", Name: "legal_governance_policy_no_truncate", Function: "legal_governance_immutable()", Type: 34},
			{Table: "legal_governance_baseline", Name: "legal_governance_baseline_immutable", Function: "legal_governance_immutable()", Type: 27},
			{Table: "legal_governance_baseline", Name: "legal_governance_baseline_no_truncate", Function: "legal_governance_immutable()", Type: 34},
		},
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}

// ProbeMetadataMaintenance permits released-detail minimization, not hold
// creation/release or tombstone deletion. Policy reads do not authorize a policy
// mutation and require no decryption or signing credentials.
func ProbeMetadataMaintenance(ctx context.Context, q db.DBTX) error {
	if err := dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{
			{Name: "public.legal_holds", Select: true, UpdateColumns: []string{"details_encrypted", "details_purged_at"}},
			{Name: "public.legal_governance_policies", Select: true},
			{Name: "public.legal_governance_baseline", Select: true},
		},
		Guards: dbprivilege.EvidenceGuards(),
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}
