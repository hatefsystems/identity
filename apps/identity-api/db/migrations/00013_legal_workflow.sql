-- +goose Up
-- Restricted metadata has no users FK: hard deletion cannot rewrite attribution.
CREATE TABLE legal_cases (
    id uuid PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('open','closed','erased')),
    version bigint NOT NULL CHECK (version >= 0),
    content_revision bigint NOT NULL DEFAULT 0 CHECK (content_revision >= 0),
    proposal_revision bigint NOT NULL DEFAULT 0 CHECK (proposal_revision >= 0),
    decision text NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','needs_information','accepted','rejected')),
    reviewed_revision bigint NOT NULL DEFAULT 0,
    response_content_revision bigint NOT NULL DEFAULT 0,
    approved_proposal_revision bigint NOT NULL DEFAULT 0,
    policy_id uuid REFERENCES legal_governance_policies(id),
    received_at timestamptz,
    created_at timestamptz,
    closed_at timestamptz,
    next_review_at timestamptz,
    expires_at timestamptz,
    content_event uuid,
    response_event uuid,
    preparer uuid,
    preparer_auth_version bigint,
    approver uuid,
    approver_auth_version bigint,
    CHECK ((preparer IS NULL) = (preparer_auth_version IS NULL)),
    CHECK ((approver IS NULL) = (approver_auth_version IS NULL)),
    CHECK (approver IS NULL OR approver <> preparer),
    CHECK (status = 'erased' OR (policy_id IS NOT NULL AND received_at IS NOT NULL AND created_at IS NOT NULL AND expires_at IS NOT NULL)),
    CHECK (status <> 'erased' OR (version=0 AND content_revision=0 AND proposal_revision=0 AND
        policy_id IS NULL AND received_at IS NULL AND created_at IS NULL AND closed_at IS NULL AND
        next_review_at IS NULL AND expires_at IS NULL AND content_event IS NULL AND response_event IS NULL AND preparer IS NULL AND approver IS NULL))
);
CREATE INDEX legal_cases_due ON legal_cases(next_review_at,id) WHERE status='open';
CREATE INDEX legal_cases_expiry ON legal_cases(expires_at,id) WHERE status<>'erased';

CREATE TABLE legal_case_subjects (
    case_id uuid NOT NULL REFERENCES legal_cases(id),
    account_ref uuid NOT NULL,
    current boolean NOT NULL,
    PRIMARY KEY(case_id,account_ref)
);
CREATE TABLE legal_case_holds (
    case_id uuid NOT NULL REFERENCES legal_cases(id),
    hold_id uuid NOT NULL REFERENCES legal_holds(id),
    account_ref uuid NOT NULL,
    current boolean NOT NULL,
    PRIMARY KEY(case_id,hold_id),
    FOREIGN KEY(case_id,account_ref) REFERENCES legal_case_subjects(case_id,account_ref)
);

-- Only insertion is allowed to the API. DELETE belongs to metadata maintenance.
CREATE TABLE legal_workflow_events (
    id uuid PRIMARY KEY,
    scope uuid NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('case','hold')),
    revision bigint NOT NULL CHECK (revision > 0),
    purpose text NOT NULL CHECK (purpose IN ('create','revise','review','prepare','approve','deliver','close','hold_review')),
    actor uuid NOT NULL,
    auth_version bigint NOT NULL,
    action_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    body_encrypted bytea NOT NULL CHECK (octet_length(body_encrypted)>0),
    UNIQUE(scope_kind,scope,revision)
);
-- +goose StatementBegin
CREATE FUNCTION legal_workflow_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legal workflow history is immutable';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER legal_workflow_events_immutable BEFORE UPDATE ON legal_workflow_events
    FOR EACH ROW EXECUTE FUNCTION legal_workflow_event_immutable();

CREATE TABLE legal_hold_reviews (
    hold_id uuid PRIMARY KEY REFERENCES legal_holds(id),
    account_ref uuid NOT NULL,
    policy_id uuid NOT NULL REFERENCES legal_governance_policies(id),
    version bigint NOT NULL CHECK(version > 0),
    next_review_at timestamptz
);
CREATE TABLE legal_workflow_replays (
    operation text NOT NULL CHECK (operation IN ('create','revise','review','prepare','approve','deliver','close','hold_review')),
    scope uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    result_id uuid NOT NULL,
    erased boolean NOT NULL DEFAULT false,
    event_id uuid REFERENCES legal_workflow_events(id),
    PRIMARY KEY(operation,scope,idempotency_key),
    CHECK (erased = (event_id IS NULL))
);
CREATE INDEX legal_workflow_replays_result ON legal_workflow_replays(result_id);

REVOKE ALL ON legal_cases,legal_case_subjects,legal_case_holds,legal_workflow_events,
    legal_hold_reviews,legal_workflow_replays FROM PUBLIC;
REVOKE ALL ON FUNCTION legal_workflow_event_immutable() FROM PUBLIC;

INSERT INTO permissions(id,description) VALUES
    ('legal.cases.read','Read restricted legal case workflow metadata.'),
    ('legal.cases.write','Receive, review and attest legal case responses.'),
    ('legal.responses.approve','Approve an exact legal response prepared by a distinct DPO.')
ON CONFLICT(id) DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id) VALUES
    ('dpo','legal.cases.read'),('dpo','legal.cases.write'),('dpo','legal.responses.approve')
ON CONFLICT DO NOTHING;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM legal_cases) OR EXISTS(SELECT 1 FROM legal_workflow_replays)
        OR EXISTS(SELECT 1 FROM legal_hold_reviews) OR EXISTS(SELECT 1 FROM legal_workflow_events) THEN
        RAISE EXCEPTION 'cannot downgrade populated legal workflow; disable intake instead';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE legal_workflow_replays,legal_hold_reviews,legal_workflow_events,legal_case_holds,legal_case_subjects,legal_cases;
DROP FUNCTION legal_workflow_event_immutable();
