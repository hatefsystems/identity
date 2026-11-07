//go:build integration

package legalworkflow

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestWorkflowEffectiveMaintenancePrivilegeNegatives(t *testing.T) {
	f := integrationFixture(t)
	login, _ := f.maintenance(t)
	name := pgx.Identifier{login.Config().ConnConfig.User}.Sanitize()
	probe := func() error {
		tx, err := login.Begin(f.ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		return ProbeMaintenance(f.ctx, tx)
	}
	changes := []struct{ name, grant, revoke string }{
		{"PUBLIC policy column", "GRANT UPDATE(artifact) ON legal_governance_policies TO PUBLIC", "REVOKE UPDATE(artifact) ON legal_governance_policies FROM PUBLIC"},
		{"PUBLIC role write", "GRANT INSERT ON user_roles TO PUBLIC", "REVOKE INSERT ON user_roles FROM PUBLIC"},
		{"replay identity", "GRANT UPDATE(idempotency_key) ON legal_workflow_replays TO " + name, "REVOKE UPDATE(idempotency_key) ON legal_workflow_replays FROM " + name},
		{"evidence insert column", "GRANT INSERT(seq) ON security_event_ledger TO " + name, "REVOKE INSERT(seq) ON security_event_ledger FROM " + name},
		{"outbox delivery update", "GRANT UPDATE(last_error) ON event_outbox TO " + name, "REVOKE UPDATE(last_error) ON event_outbox FROM " + name},
		{"sequence", "GRANT USAGE ON SEQUENCE security_ledger_chain_seq TO " + name, "REVOKE USAGE ON SEQUENCE security_ledger_chain_seq FROM " + name},
		{"replication bypass", "GRANT SET ON PARAMETER session_replication_role TO " + name, "REVOKE SET ON PARAMETER session_replication_role FROM " + name},
		{"database CREATE", "GRANT CREATE ON DATABASE " + pgx.Identifier{login.Config().ConnConfig.Database}.Sanitize() + " TO " + name, "REVOKE CREATE ON DATABASE " + pgx.Identifier{login.Config().ConnConfig.Database}.Sanitize() + " FROM " + name},
		{"PUBLIC schema CREATE", "GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
		{"owner SET ROLE membership", "GRANT " + pgx.Identifier{f.pool.Config().ConnConfig.User}.Sanitize() + " TO " + name, "REVOKE " + pgx.Identifier{f.pool.Config().ConnConfig.User}.Sanitize() + " FROM " + name},
		{"disarmed policy", "ALTER TABLE legal_governance_policies DISABLE TRIGGER legal_governance_policy_immutable", "ALTER TABLE legal_governance_policies ENABLE TRIGGER legal_governance_policy_immutable"},
		{"replica-only evidence", "ALTER TABLE security_ledger_chain ENABLE REPLICA TRIGGER trg_security_ledger_chain_append_only", "ALTER TABLE security_ledger_chain ENABLE TRIGGER trg_security_ledger_chain_append_only"},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			if _, err := f.pool.Exec(f.ctx, change.grant); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := f.pool.Exec(context.Background(), change.revoke); err != nil {
					t.Error(err)
				}
			})
			if err := probe(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted forbidden effective authority: %v", err)
			}
		})
		if err := probe(); err != nil {
			t.Fatalf("restricted maintenance restart after revoke: %v", err)
		}
	}
}
