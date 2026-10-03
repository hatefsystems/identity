-- name: GetLegalGovernancePolicy :one
SELECT id, artifact, installed_by, operator_identity, action_id, installed_environment, installed_at
FROM legal_governance_policies WHERE id = $1;

-- name: GetLegalGovernanceBaseline :one
SELECT policy_id FROM legal_governance_baseline WHERE singleton;

-- name: InsertLegalGovernancePolicy :exec
INSERT INTO legal_governance_policies (id, artifact, installed_by, operator_identity, action_id, installed_environment)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: BindLegalGovernanceBaseline :exec
INSERT INTO legal_governance_baseline (singleton, policy_id) VALUES (true, $1);

-- name: InspectLegalGovernanceLegacyInventory :one
SELECT
    EXISTS (SELECT 1 FROM legal_holds) OR EXISTS (SELECT 1 FROM admin_action_contexts) AS has_legacy_records,
    EXISTS (SELECT 1 FROM admin_action_contexts
        WHERE retain_until - created_at <> make_interval(secs => sqlc.arg(context_retention_seconds)::double precision)) AS has_inconsistent_context_clocks;
