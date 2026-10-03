-- +goose Up
-- Approval artifacts are supplied by an externally authorized operator. This
-- migration deliberately seeds no approval, duration, or legacy attestation.
-- +goose StatementBegin
CREATE FUNCTION legal_policy_artifact_valid(p JSONB, policy_id UUID) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE AS $$
    SELECT COALESCE(
        jsonb_typeof(p) = 'object'
        AND p ?& ARRAY['id','approval_reference','fixture','context_retention_seconds',
            'released_hold_retention_seconds','context_clock','released_hold_clock',
            'hold_tombstone_fields','hold_tombstone_lifetime']
        AND p - ARRAY['id','approval_reference','fixture','context_retention_seconds',
            'released_hold_retention_seconds','context_clock','released_hold_clock',
            'hold_tombstone_fields','hold_tombstone_lifetime','legacy_inventory_reference','workflow'] = '{}'::jsonb
        AND (p->>'id')::uuid = policy_id
        AND jsonb_typeof(p->'approval_reference') = 'string'
        AND p->>'approval_reference' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND jsonb_typeof(p->'fixture') = 'boolean'
        AND jsonb_typeof(p->'context_retention_seconds') = 'number'
        AND p->>'context_retention_seconds' ~ '^[0-9]+$'
        AND (p->>'context_retention_seconds')::numeric BETWEEN 1 AND 9223372036
        AND jsonb_typeof(p->'released_hold_retention_seconds') = 'number'
        AND p->>'released_hold_retention_seconds' ~ '^[0-9]+$'
        AND (p->>'released_hold_retention_seconds')::numeric BETWEEN 1 AND 9223372036
        AND p->>'context_clock' = 'created_at'
        AND p->>'released_hold_clock' = 'released_at'
        AND p->>'hold_tombstone_lifetime' = 'no_expiry'
        AND jsonb_array_length(p->'hold_tombstone_fields') = 11
        AND p->'hold_tombstone_fields' @> '["id","account_ref","applied_by","is_active","applied_at","review_at","released_at","released_by","request_kind","idempotency_key","details_purged_at"]'::jsonb
        AND (NOT p ? 'legacy_inventory_reference' OR
            (jsonb_typeof(p->'legacy_inventory_reference') = 'string'
            AND p->>'legacy_inventory_reference' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'))
        AND (NOT p ? 'workflow' OR (
            jsonb_typeof(p->'workflow') = 'object'
            AND p->'workflow' ?& ARRAY['max_case_age_seconds','closed_case_retention_seconds','case_clock','replay_fields','replay_lifetime']
            AND (p->'workflow') - ARRAY['max_case_age_seconds','closed_case_retention_seconds','case_clock','replay_fields','replay_lifetime'] = '{}'::jsonb
            AND jsonb_typeof(p->'workflow'->'max_case_age_seconds') = 'number'
            AND p->'workflow'->>'max_case_age_seconds' ~ '^[0-9]+$'
            AND (p->'workflow'->>'max_case_age_seconds')::numeric BETWEEN 1 AND 9223372036
            AND jsonb_typeof(p->'workflow'->'closed_case_retention_seconds') = 'number'
            AND p->'workflow'->>'closed_case_retention_seconds' ~ '^[0-9]+$'
            AND (p->'workflow'->>'closed_case_retention_seconds')::numeric BETWEEN 1 AND 9223372036
            AND p->'workflow'->>'case_clock' = 'created_at_max_closed_at_min'
            AND p->'workflow'->>'replay_lifetime' = 'no_expiry'
            AND jsonb_array_length(p->'workflow'->'replay_fields') = 5
            AND p->'workflow'->'replay_fields' @> '["operation","scope","idempotency_key","result_id","erased"]'::jsonb
        )), false);
$$;
-- +goose StatementEnd

CREATE TABLE legal_governance_policies (
    id UUID PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    artifact JSONB NOT NULL CHECK (octet_length(artifact::text) <= 16384),
    installed_by UUID NOT NULL CHECK (installed_by <> '00000000-0000-0000-0000-000000000000'),
    operator_identity TEXT NOT NULL CHECK (length(operator_identity) BETWEEN 10 AND 255 AND operator_identity LIKE 'spiffe://%'),
    action_id UUID NOT NULL UNIQUE CHECK (action_id <> '00000000-0000-0000-0000-000000000000'),
    installed_environment TEXT NOT NULL CHECK (length(installed_environment) BETWEEN 1 AND 100),
    installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (legal_policy_artifact_valid(artifact, id)),
    CHECK (artifact->>'fixture' = 'false' OR installed_environment IN ('development','test'))
);

-- Historical hold clocks are not stored per row. The one immutable binding
-- prevents runtime configuration or a newly installed version from changing
-- those clocks. A future rebind requires a separately designed audited rollout.
CREATE TABLE legal_governance_baseline (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    policy_id UUID NOT NULL UNIQUE REFERENCES legal_governance_policies(id),
    bound_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- +goose StatementBegin
CREATE FUNCTION legal_governance_immutable() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'legal governance records are immutable: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER legal_governance_policy_immutable BEFORE UPDATE OR DELETE
    ON legal_governance_policies FOR EACH ROW EXECUTE FUNCTION legal_governance_immutable();
CREATE TRIGGER legal_governance_policy_no_truncate BEFORE TRUNCATE
    ON legal_governance_policies FOR EACH STATEMENT EXECUTE FUNCTION legal_governance_immutable();
CREATE TRIGGER legal_governance_baseline_immutable BEFORE UPDATE OR DELETE
    ON legal_governance_baseline FOR EACH ROW EXECUTE FUNCTION legal_governance_immutable();
CREATE TRIGGER legal_governance_baseline_no_truncate BEFORE TRUNCATE
    ON legal_governance_baseline FOR EACH STATEMENT EXECUTE FUNCTION legal_governance_immutable();

-- Deployment grants SELECT to API/maintenance and SELECT, INSERT to the
-- controlled installer only. None may own tables, inherit the owner, or have
-- schema CREATE, role management, trigger bypass, or ledger-purge privileges.
REVOKE ALL ON legal_governance_policies, legal_governance_baseline FROM PUBLIC;
REVOKE ALL ON FUNCTION legal_governance_immutable() FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM legal_governance_policies) OR EXISTS (SELECT 1 FROM legal_governance_baseline) THEN
        RAISE EXCEPTION 'cannot discard legal governance approvals; disable intake instead';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE legal_governance_baseline;
DROP TABLE legal_governance_policies;
DROP FUNCTION legal_governance_immutable();
DROP FUNCTION legal_policy_artifact_valid(JSONB, UUID);
