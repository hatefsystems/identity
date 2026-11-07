-- Fresh-install baseline for the Hatef Identity Platform.
-- Canonical/event formats and operator approval boundaries are unchanged.
-- Future changes start at 00002; legacy databases require separately scoped setup.

-- +goose Up
SET LOCAL search_path = public, pg_catalog;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;

-- The auth epoch is independent. Chain sequences are owned nextval sources,
-- not identity columns: signers allocate sequence values before writing payloads.
CREATE SEQUENCE public.account_auth_epoch_seq AS BIGINT
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1 NO CYCLE;
CREATE SEQUENCE public.audit_log_chain_seq AS BIGINT
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1 NO CYCLE;
CREATE SEQUENCE public.security_ledger_chain_seq AS BIGINT
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1 NO CYCLE;

-- Validate immutable policy artifacts before defining their table CHECK.
-- +goose StatementBegin
CREATE FUNCTION public.legal_policy_artifact_valid(p jsonb, policy_id uuid) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
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

-- Core identity: encrypted PII and SHA-256 blind indexes, nullable password and
-- WebAuthn handle, monotonic auth state, and nonunique 80-code-point profile names.
-- Column order is the final visible order of the previous migration lineage.
CREATE TABLE public.users (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    backup_email_encrypted BYTEA,
    backup_email_blind_index VARCHAR(64),
    phone_encrypted BYTEA,
    phone_blind_index VARCHAR(64),
    mfa_totp_secret_encrypted BYTEA,
    is_mfa_enabled BOOLEAN DEFAULT false NOT NULL,
    status VARCHAR(50) DEFAULT 'active'::character varying NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMPTZ,
    webauthn_user_handle BYTEA,
    auth_version BIGINT DEFAULT 0 NOT NULL,
    auth_epoch BIGINT DEFAULT 0 NOT NULL,
    lifecycle_revision BIGINT DEFAULT 0 NOT NULL,
    display_name TEXT DEFAULT ''::text NOT NULL,
    CONSTRAINT users_auth_version_check CHECK (auth_version >= 0),
    CONSTRAINT users_display_name_length CHECK (char_length(display_name) <= 80),
    CONSTRAINT users_lifecycle_revision_check CHECK (lifecycle_revision >= 0),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'suspended', 'pending_verification', 'pending_deletion', 'banned')),
    CONSTRAINT users_webauthn_user_handle_key UNIQUE (webauthn_user_handle)
);
-- Pending deletion reserves identifiers throughout the recovery grace period.
CREATE UNIQUE INDEX idx_users_backup_email_blind ON public.users (backup_email_blind_index)
    WHERE (deleted_at IS NULL OR status::text = 'pending_deletion'::text) AND backup_email_blind_index IS NOT NULL;
CREATE UNIQUE INDEX idx_users_email ON public.users (email)
    WHERE deleted_at IS NULL OR status::text = 'pending_deletion'::text;
CREATE UNIQUE INDEX idx_users_phone_blind ON public.users (phone_blind_index)
    WHERE (deleted_at IS NULL OR status::text = 'pending_deletion'::text) AND phone_blind_index IS NOT NULL;
CREATE INDEX idx_users_status ON public.users (status);
CREATE INDEX idx_users_webauthn_handle ON public.users (webauthn_user_handle) WHERE webauthn_user_handle IS NOT NULL;

CREATE TABLE public.roles (
    id VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT roles_pkey PRIMARY KEY (id)
);
CREATE TABLE public.permissions (
    id VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT permissions_pkey PRIMARY KEY (id)
);
CREATE TABLE public.role_permissions (
    role_id VARCHAR(50) NOT NULL,
    permission_id VARCHAR(100) NOT NULL,
    CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE,
    CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id),
    CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE
);
CREATE TABLE public.user_roles (
    user_id UUID NOT NULL,
    role_id VARCHAR(50) NOT NULL,
    assigned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id),
    CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE,
    CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE TABLE public.webauthn_credentials (
    id BYTEA NOT NULL,
    user_id UUID NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    sign_count BIGINT DEFAULT 0 NOT NULL,
    user_present BOOLEAN DEFAULT true NOT NULL,
    user_verified BOOLEAN DEFAULT false NOT NULL,
    backup_eligible BOOLEAN DEFAULT false NOT NULL,
    backup_state BOOLEAN DEFAULT false NOT NULL,
    aaguid UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMPTZ,
    name TEXT DEFAULT ''::text NOT NULL,
    CONSTRAINT webauthn_credentials_name_length CHECK (char_length(name) <= 80),
    CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE INDEX idx_webauthn_user_id ON public.webauthn_credentials (user_id);
CREATE TABLE public.recovery_codes (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id UUID NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    used_at TIMESTAMPTZ,
    CONSTRAINT recovery_codes_pkey PRIMARY KEY (id),
    CONSTRAINT recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
-- High-entropy recovery codes are SHA-256 hashed; only unused hashes are unique.
CREATE UNIQUE INDEX idx_recovery_codes_hash ON public.recovery_codes (code_hash) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_user_id ON public.recovery_codes (user_id);
CREATE TABLE public.mfa_totp_enrollments (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    secret_encrypted BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT mfa_totp_enrollments_failed_attempts_check CHECK (failed_attempts >= 0),
    CONSTRAINT mfa_totp_enrollments_pkey PRIMARY KEY (id),
    CONSTRAINT mfa_totp_enrollments_purpose_check CHECK (purpose::text = 'maintenance'::text),
    CONSTRAINT mfa_totp_enrollments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE INDEX idx_mfa_totp_enrollments_expires ON public.mfa_totp_enrollments (expires_at);
CREATE INDEX idx_mfa_totp_enrollments_user ON public.mfa_totp_enrollments (user_id);

-- Deletion confirmation, delivery leases, and lifecycle outbox ordering.
CREATE TABLE public.deletion_requests (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    requested_ip VARCHAR(50),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    notified_at TIMESTAMPTZ,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    requested_auth_version BIGINT,
    CONSTRAINT deletion_requests_failed_attempts_check CHECK (failed_attempts >= 0),
    CONSTRAINT deletion_requests_pkey PRIMARY KEY (id),
    CONSTRAINT deletion_requests_requested_auth_version_check CHECK (requested_auth_version >= 0 AND requested_auth_version < '9223372036854775807'::bigint),
    CONSTRAINT deletion_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE INDEX idx_deletion_requests_active ON public.deletion_requests (user_id) WHERE consumed_at IS NULL;
CREATE UNIQUE INDEX idx_deletion_requests_token ON public.deletion_requests (token_hash);
CREATE TABLE public.deletion_notifications (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    request_id UUID NOT NULL,
    recipient_role VARCHAR(10) NOT NULL,
    payload_encrypted BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER DEFAULT 0 NOT NULL,
    next_attempt_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    lease_token UUID,
    lease_until TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error_code VARCHAR(32),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT deletion_notifications_attempts_check CHECK (attempts >= 0),
    CONSTRAINT deletion_notifications_check CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CONSTRAINT deletion_notifications_check1 CHECK (accepted_at IS NULL OR failed_at IS NULL),
    CONSTRAINT deletion_notifications_last_error_code_check CHECK (last_error_code IN ('relay_temporary', 'relay_permanent', 'payload_unavailable', 'payload_invalid', 'request_invalid')),
    CONSTRAINT deletion_notifications_payload_encrypted_check CHECK (payload_encrypted IS NULL OR octet_length(payload_encrypted) >= 1 AND octet_length(payload_encrypted) <= 16384),
    CONSTRAINT deletion_notifications_pkey PRIMARY KEY (id),
    CONSTRAINT deletion_notifications_recipient_role_check CHECK (recipient_role IN ('primary', 'backup')),
    CONSTRAINT deletion_notifications_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.deletion_requests(id) ON DELETE CASCADE,
    CONSTRAINT deletion_notifications_request_id_recipient_role_key UNIQUE (request_id, recipient_role),
    CONSTRAINT deletion_notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE INDEX idx_deletion_notifications_cleanup ON public.deletion_notifications (user_id, id) WHERE payload_encrypted IS NOT NULL;
CREATE INDEX idx_deletion_notifications_due ON public.deletion_notifications (next_attempt_at, id)
    WHERE accepted_at IS NULL AND failed_at IS NULL AND payload_encrypted IS NOT NULL;
-- No user FK: durable lifecycle delivery metadata survives account hard deletion.
CREATE TABLE public.event_outbox (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    subject VARCHAR(100) NOT NULL,
    payload TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    published_at TIMESTAMPTZ,
    attempts INTEGER DEFAULT 0 NOT NULL,
    last_error TEXT,
    admin_action BOOLEAN DEFAULT false NOT NULL,
    next_attempt_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    lifecycle_user_id UUID,
    lifecycle_revision BIGINT,
    CONSTRAINT event_outbox_lifecycle_metadata CHECK (lifecycle_user_id IS NULL AND lifecycle_revision IS NULL OR lifecycle_user_id IS NOT NULL AND lifecycle_revision IS NOT NULL AND lifecycle_user_id <> '00000000-0000-0000-0000-000000000000'::uuid AND lifecycle_revision > 0 AND NOT admin_action AND (subject IN ('identity.user.created', 'identity.user.updated', 'identity.user.suspended', 'identity.user.deleted'))),
    CONSTRAINT event_outbox_pkey PRIMARY KEY (id)
);
CREATE INDEX idx_event_outbox_admin_pending ON public.event_outbox (subject, next_attempt_at, created_at, id)
    WHERE admin_action AND published_at IS NULL;
CREATE INDEX idx_event_outbox_lifecycle_cleanup ON public.event_outbox (published_at, id)
    WHERE NOT admin_action AND published_at IS NOT NULL AND subject IN ('identity.user.created', 'identity.user.updated', 'identity.user.suspended', 'identity.user.deleted');
CREATE INDEX idx_event_outbox_lifecycle_head ON public.event_outbox (lifecycle_user_id, lifecycle_revision)
    WHERE NOT admin_action AND published_at IS NULL AND lifecycle_user_id IS NOT NULL;
CREATE INDEX idx_event_outbox_lifecycle_pending ON public.event_outbox (next_attempt_at, created_at, id)
    WHERE NOT admin_action AND published_at IS NULL AND subject IN ('identity.user.created', 'identity.user.updated', 'identity.user.suspended', 'identity.user.deleted');
CREATE UNIQUE INDEX idx_event_outbox_lifecycle_revision ON public.event_outbox (lifecycle_user_id, lifecycle_revision) WHERE lifecycle_user_id IS NOT NULL;
CREATE INDEX idx_event_outbox_unpublished ON public.event_outbox (created_at) WHERE published_at IS NULL;
CREATE TABLE public.admin_action_contexts (
    action_id UUID NOT NULL,
    account_ref UUID,
    details_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    CONSTRAINT admin_action_contexts_check CHECK (retain_until > created_at),
    CONSTRAINT admin_action_contexts_details_encrypted_check CHECK (octet_length(details_encrypted) > 0),
    CONSTRAINT admin_action_contexts_pkey PRIMARY KEY (action_id)
);
CREATE INDEX idx_admin_action_contexts_account ON public.admin_action_contexts (account_ref) WHERE account_ref IS NOT NULL;
CREATE INDEX idx_admin_action_contexts_retention ON public.admin_action_contexts (retain_until, action_id);

-- Canonical-v2 permanent chains retain event deduplication and two binary digests.
-- Payload erasure never removes a chain node. The RESTRICT FKs are intentional.
CREATE TABLE public.audit_log_chain (
    seq BIGINT DEFAULT nextval('public.audit_log_chain_seq'::regclass) NOT NULL,
    event_id UUID NOT NULL,
    leaf_hash BYTEA NOT NULL,
    chain_hash BYTEA NOT NULL,
    CONSTRAINT audit_log_chain_chain_hash_check CHECK (octet_length(chain_hash) = 32),
    CONSTRAINT audit_log_chain_event_id_key UNIQUE (event_id),
    CONSTRAINT audit_log_chain_leaf_hash_check CHECK (octet_length(leaf_hash) = 32),
    CONSTRAINT audit_log_chain_pkey PRIMARY KEY (seq)
);
ALTER SEQUENCE public.audit_log_chain_seq OWNED BY public.audit_log_chain.seq;
CREATE TABLE public.security_ledger_chain (
    seq BIGINT DEFAULT nextval('public.security_ledger_chain_seq'::regclass) NOT NULL,
    event_id UUID NOT NULL,
    leaf_hash BYTEA NOT NULL,
    chain_hash BYTEA NOT NULL,
    CONSTRAINT security_ledger_chain_chain_hash_check CHECK (octet_length(chain_hash) = 32),
    CONSTRAINT security_ledger_chain_event_id_key UNIQUE (event_id),
    CONSTRAINT security_ledger_chain_leaf_hash_check CHECK (octet_length(leaf_hash) = 32),
    CONSTRAINT security_ledger_chain_pkey PRIMARY KEY (seq)
);
ALTER SEQUENCE public.security_ledger_chain_seq OWNED BY public.security_ledger_chain.seq;
CREATE TABLE public.mvp_audit_logs (
    seq BIGINT NOT NULL,
    user_id UUID,
    actor_id UUID NOT NULL,
    actor_spiffe_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action_status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    payload TEXT NOT NULL,
    "timestamp" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT mvp_audit_logs_pkey PRIMARY KEY (seq),
    CONSTRAINT mvp_audit_logs_seq_fkey FOREIGN KEY (seq) REFERENCES public.audit_log_chain(seq) ON DELETE RESTRICT,
    CONSTRAINT mvp_audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL
);
CREATE INDEX idx_mvp_audit_logs_event_type ON public.mvp_audit_logs (event_type);
CREATE INDEX idx_mvp_audit_logs_timestamp ON public.mvp_audit_logs ("timestamp" DESC);
CREATE INDEX idx_mvp_audit_logs_user_id ON public.mvp_audit_logs (user_id) WHERE user_id IS NOT NULL;
-- No users FK: attribution survives hard deletion, bounded by retain_until.
CREATE TABLE public.security_event_ledger (
    seq BIGINT NOT NULL,
    account_ref UUID NOT NULL,
    identity_blind_index VARCHAR(64),
    blind_index_version SMALLINT NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    client_ip VARCHAR(50),
    ip_subnet VARCHAR(50),
    user_agent TEXT,
    device_fingerprint VARCHAR(128),
    client_id VARCHAR(100),
    scope TEXT,
    "timestamp" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL,
    CONSTRAINT security_event_ledger_blind_index_version_check CHECK (blind_index_version >= 0),
    CONSTRAINT security_event_ledger_pkey PRIMARY KEY (seq),
    CONSTRAINT security_event_ledger_seq_fkey FOREIGN KEY (seq) REFERENCES public.security_ledger_chain(seq) ON DELETE RESTRICT
);
CREATE INDEX idx_security_ledger_account_ref ON public.security_event_ledger (account_ref);
CREATE INDEX idx_security_ledger_blind_index ON public.security_event_ledger (identity_blind_index);
CREATE INDEX idx_security_ledger_event_type ON public.security_event_ledger (event_type);
CREATE INDEX idx_security_ledger_retention ON public.security_event_ledger (retain_until, seq);
-- Exact golden genesis values are constraints, not initialization or defaults.
CREATE TABLE public.audit_log_head (
    singleton BOOLEAN DEFAULT true NOT NULL,
    seq BIGINT NOT NULL,
    chain_hash BYTEA NOT NULL,
    CONSTRAINT audit_log_head_chain_hash_check CHECK (octet_length(chain_hash) = 32),
    CONSTRAINT audit_log_head_check CHECK (seq <> 0 OR chain_hash = '\x5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb'::bytea),
    CONSTRAINT audit_log_head_pkey PRIMARY KEY (singleton),
    CONSTRAINT audit_log_head_seq_check CHECK (seq >= 0),
    CONSTRAINT audit_log_head_singleton_check CHECK (singleton)
);
CREATE TABLE public.security_ledger_head (
    singleton BOOLEAN DEFAULT true NOT NULL,
    seq BIGINT NOT NULL,
    chain_hash BYTEA NOT NULL,
    CONSTRAINT security_ledger_head_chain_hash_check CHECK (octet_length(chain_hash) = 32),
    CONSTRAINT security_ledger_head_check CHECK (seq <> 0 OR chain_hash = '\x6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54'::bytea),
    CONSTRAINT security_ledger_head_pkey PRIMARY KEY (singleton),
    CONSTRAINT security_ledger_head_seq_check CHECK (seq >= 0),
    CONSTRAINT security_ledger_head_singleton_check CHECK (singleton)
);
-- Append-only erasure spans are evidence annotations, not v1 repair checkpoints.
CREATE TABLE public.security_ledger_erasures (
    first_seq BIGINT NOT NULL,
    last_seq BIGINT NOT NULL,
    operation_id UUID NOT NULL,
    erased_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT security_ledger_erasures_check CHECK (last_seq >= first_seq),
    CONSTRAINT security_ledger_erasures_first_seq_check CHECK (first_seq > 0),
    CONSTRAINT security_ledger_erasures_pkey PRIMARY KEY (first_seq, last_seq)
);
CREATE INDEX idx_security_ledger_erasures_operation ON public.security_ledger_erasures (operation_id);
CREATE TABLE public.security_ledger_retention_settings (
    singleton BOOLEAN DEFAULT true NOT NULL,
    audit_subject TEXT NOT NULL,
    CONSTRAINT security_ledger_retention_settings_audit_subject_check CHECK (octet_length(audit_subject) BETWEEN 1 AND 100 AND audit_subject ~ '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$'::text AND audit_subject <> 'identity.user.deleted'::text),
    CONSTRAINT security_ledger_retention_settings_pkey PRIMARY KEY (singleton),
    CONSTRAINT security_ledger_retention_settings_singleton_check CHECK (singleton)
);

-- Final encrypted legal holds. Metadata tombstones are legitimate only after
-- release and details purge; no plaintext expansion/backfill layout is installed.
CREATE TABLE public.legal_holds (
    id UUID DEFAULT public.uuid_generate_v4() NOT NULL,
    account_ref UUID NOT NULL,
    applied_by UUID NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    review_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    released_by UUID,
    request_kind TEXT DEFAULT 'legal_hold'::text NOT NULL,
    idempotency_key UUID,
    details_encrypted BYTEA,
    details_purged_at TIMESTAMPTZ,
    CONSTRAINT legal_holds_encrypted_or_purged CHECK (details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL OR details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL),
    CONSTRAINT legal_holds_pkey PRIMARY KEY (id),
    CONSTRAINT legal_holds_request_kind_check CHECK (request_kind = ANY (ARRAY['legal_hold'::text, 'preservation'::text]))
);
CREATE INDEX idx_legal_holds_active ON public.legal_holds (account_ref) WHERE is_active = true;
CREATE INDEX legal_holds_released_cleanup ON public.legal_holds (released_at, id) WHERE NOT is_active AND details_purged_at IS NULL;
CREATE UNIQUE INDEX legal_holds_request_identity ON public.legal_holds (account_ref, request_kind, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE TABLE public.legal_governance_policies (
    id UUID NOT NULL,
    artifact JSONB NOT NULL,
    installed_by UUID NOT NULL,
    operator_identity TEXT NOT NULL,
    action_id UUID NOT NULL,
    installed_environment TEXT NOT NULL,
    installed_at TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT legal_governance_policies_action_id_check CHECK (action_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT legal_governance_policies_action_id_key UNIQUE (action_id),
    CONSTRAINT legal_governance_policies_artifact_check CHECK (octet_length(artifact::text) <= 16384),
    CONSTRAINT legal_governance_policies_check CHECK (public.legal_policy_artifact_valid(artifact, id)),
    CONSTRAINT legal_governance_policies_check1 CHECK ((artifact ->> 'fixture'::text) = 'false'::text OR (installed_environment = ANY (ARRAY['development'::text, 'test'::text]))),
    CONSTRAINT legal_governance_policies_id_check CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT legal_governance_policies_installed_by_check CHECK (installed_by <> '00000000-0000-0000-0000-000000000000'::uuid),
    CONSTRAINT legal_governance_policies_installed_environment_check CHECK (length(installed_environment) >= 1 AND length(installed_environment) <= 100),
    CONSTRAINT legal_governance_policies_operator_identity_check CHECK (length(operator_identity) BETWEEN 10 AND 255 AND operator_identity LIKE 'spiffe://%'::text),
    CONSTRAINT legal_governance_policies_pkey PRIMARY KEY (id)
);
CREATE TABLE public.legal_governance_baseline (
    singleton BOOLEAN NOT NULL,
    policy_id UUID NOT NULL,
    bound_at TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT legal_governance_baseline_pkey PRIMARY KEY (singleton),
    CONSTRAINT legal_governance_baseline_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.legal_governance_policies(id),
    CONSTRAINT legal_governance_baseline_policy_id_key UNIQUE (policy_id),
    CONSTRAINT legal_governance_baseline_singleton_check CHECK (singleton)
);
-- Restricted workflow metadata deliberately has no users FK.
CREATE TABLE public.legal_cases (
    id UUID NOT NULL,
    status TEXT NOT NULL,
    version BIGINT NOT NULL,
    content_revision BIGINT DEFAULT 0 NOT NULL,
    proposal_revision BIGINT DEFAULT 0 NOT NULL,
    decision TEXT DEFAULT 'pending'::text NOT NULL,
    reviewed_revision BIGINT DEFAULT 0 NOT NULL,
    response_content_revision BIGINT DEFAULT 0 NOT NULL,
    approved_proposal_revision BIGINT DEFAULT 0 NOT NULL,
    policy_id UUID,
    received_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    next_review_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    content_event UUID,
    response_event UUID,
    preparer UUID,
    preparer_auth_version BIGINT,
    approver UUID,
    approver_auth_version BIGINT,
    CONSTRAINT legal_cases_check CHECK ((preparer IS NULL) = (preparer_auth_version IS NULL)),
    CONSTRAINT legal_cases_check1 CHECK ((approver IS NULL) = (approver_auth_version IS NULL)),
    CONSTRAINT legal_cases_check2 CHECK (approver IS NULL OR approver <> preparer),
    CONSTRAINT legal_cases_check3 CHECK (status = 'erased'::text OR policy_id IS NOT NULL AND received_at IS NOT NULL AND created_at IS NOT NULL AND expires_at IS NOT NULL),
    CONSTRAINT legal_cases_check4 CHECK (status <> 'erased'::text OR version = 0 AND content_revision = 0 AND proposal_revision = 0 AND policy_id IS NULL AND received_at IS NULL AND created_at IS NULL AND closed_at IS NULL AND next_review_at IS NULL AND expires_at IS NULL AND content_event IS NULL AND response_event IS NULL AND preparer IS NULL AND approver IS NULL),
    CONSTRAINT legal_cases_content_revision_check CHECK (content_revision >= 0),
    CONSTRAINT legal_cases_decision_check CHECK (decision = ANY (ARRAY['pending'::text, 'needs_information'::text, 'accepted'::text, 'rejected'::text])),
    CONSTRAINT legal_cases_pkey PRIMARY KEY (id),
    CONSTRAINT legal_cases_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.legal_governance_policies(id),
    CONSTRAINT legal_cases_proposal_revision_check CHECK (proposal_revision >= 0),
    CONSTRAINT legal_cases_status_check CHECK (status = ANY (ARRAY['open'::text, 'closed'::text, 'erased'::text])),
    CONSTRAINT legal_cases_version_check CHECK (version >= 0)
);
CREATE INDEX legal_cases_due ON public.legal_cases (next_review_at, id) WHERE status = 'open'::text;
CREATE INDEX legal_cases_expiry ON public.legal_cases (expires_at, id) WHERE status <> 'erased'::text;
CREATE TABLE public.legal_case_subjects (
    case_id UUID NOT NULL,
    account_ref UUID NOT NULL,
    current BOOLEAN NOT NULL,
    CONSTRAINT legal_case_subjects_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.legal_cases(id),
    CONSTRAINT legal_case_subjects_pkey PRIMARY KEY (case_id, account_ref)
);
CREATE TABLE public.legal_case_holds (
    case_id UUID NOT NULL,
    hold_id UUID NOT NULL,
    account_ref UUID NOT NULL,
    current BOOLEAN NOT NULL,
    CONSTRAINT legal_case_holds_case_id_account_ref_fkey FOREIGN KEY (case_id, account_ref) REFERENCES public.legal_case_subjects(case_id, account_ref),
    CONSTRAINT legal_case_holds_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.legal_cases(id),
    CONSTRAINT legal_case_holds_hold_id_fkey FOREIGN KEY (hold_id) REFERENCES public.legal_holds(id),
    CONSTRAINT legal_case_holds_pkey PRIMARY KEY (case_id, hold_id)
);
CREATE TABLE public.legal_workflow_events (
    id UUID NOT NULL,
    scope UUID NOT NULL,
    scope_kind TEXT NOT NULL,
    revision BIGINT NOT NULL,
    purpose TEXT NOT NULL,
    actor UUID NOT NULL,
    auth_version BIGINT NOT NULL,
    action_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    body_encrypted BYTEA NOT NULL,
    CONSTRAINT legal_workflow_events_body_encrypted_check CHECK (octet_length(body_encrypted) > 0),
    CONSTRAINT legal_workflow_events_pkey PRIMARY KEY (id),
    CONSTRAINT legal_workflow_events_purpose_check CHECK (purpose = ANY (ARRAY['create'::text, 'revise'::text, 'review'::text, 'prepare'::text, 'approve'::text, 'deliver'::text, 'close'::text, 'hold_review'::text])),
    CONSTRAINT legal_workflow_events_revision_check CHECK (revision > 0),
    CONSTRAINT legal_workflow_events_scope_kind_check CHECK (scope_kind = ANY (ARRAY['case'::text, 'hold'::text])),
    CONSTRAINT legal_workflow_events_scope_kind_scope_revision_key UNIQUE (scope_kind, scope, revision)
);
CREATE TABLE public.legal_hold_reviews (
    hold_id UUID NOT NULL,
    account_ref UUID NOT NULL,
    policy_id UUID NOT NULL,
    version BIGINT NOT NULL,
    next_review_at TIMESTAMPTZ,
    CONSTRAINT legal_hold_reviews_hold_id_fkey FOREIGN KEY (hold_id) REFERENCES public.legal_holds(id),
    CONSTRAINT legal_hold_reviews_pkey PRIMARY KEY (hold_id),
    CONSTRAINT legal_hold_reviews_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.legal_governance_policies(id),
    CONSTRAINT legal_hold_reviews_version_check CHECK (version > 0)
);
CREATE TABLE public.legal_workflow_replays (
    operation TEXT NOT NULL,
    scope UUID NOT NULL,
    idempotency_key UUID NOT NULL,
    result_id UUID NOT NULL,
    erased BOOLEAN DEFAULT false NOT NULL,
    event_id UUID,
    CONSTRAINT legal_workflow_replays_check CHECK (erased = (event_id IS NULL)),
    CONSTRAINT legal_workflow_replays_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.legal_workflow_events(id),
    CONSTRAINT legal_workflow_replays_operation_check CHECK (operation = ANY (ARRAY['create'::text, 'revise'::text, 'review'::text, 'prepare'::text, 'approve'::text, 'deliver'::text, 'close'::text, 'hold_review'::text])),
    CONSTRAINT legal_workflow_replays_pkey PRIMARY KEY (operation, scope, idempotency_key)
);
CREATE INDEX legal_workflow_replays_result ON public.legal_workflow_replays (result_id);

-- Case-free aggregate history and exact reviewed artifact bytes remain restricted.
CREATE TABLE public.legal_transparency_coverage (
    singleton BOOLEAN DEFAULT true NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT legal_transparency_coverage_pkey PRIMARY KEY (singleton),
    CONSTRAINT legal_transparency_coverage_singleton_check CHECK (singleton)
);
CREATE TABLE public.legal_transparency_years (
    year INTEGER NOT NULL,
    data_version BIGINT DEFAULT 0 NOT NULL,
    CONSTRAINT legal_transparency_years_data_version_check CHECK (data_version >= 0),
    CONSTRAINT legal_transparency_years_pkey PRIMARY KEY (year),
    CONSTRAINT legal_transparency_years_year_check CHECK (year >= 1 AND year <= 9999)
);
CREATE TABLE public.legal_transparency_months (
    month DATE NOT NULL,
    received BIGINT DEFAULT 0 NOT NULL,
    answered BIGINT DEFAULT 0 NOT NULL,
    full_disclosure BIGINT DEFAULT 0 NOT NULL,
    partial_disclosure BIGINT DEFAULT 0 NOT NULL,
    no_responsive_data BIGINT DEFAULT 0 NOT NULL,
    refusal BIGINT DEFAULT 0 NOT NULL,
    preservation_acknowledgement BIGINT DEFAULT 0 NOT NULL,
    CONSTRAINT legal_transparency_months_answered_check CHECK (answered >= 0),
    CONSTRAINT legal_transparency_months_check CHECK (answered = (full_disclosure + partial_disclosure + no_responsive_data + refusal + preservation_acknowledgement)),
    CONSTRAINT legal_transparency_months_full_disclosure_check CHECK (full_disclosure >= 0),
    CONSTRAINT legal_transparency_months_month_check CHECK (EXTRACT(day FROM month) = 1::numeric),
    CONSTRAINT legal_transparency_months_no_responsive_data_check CHECK (no_responsive_data >= 0),
    CONSTRAINT legal_transparency_months_partial_disclosure_check CHECK (partial_disclosure >= 0),
    CONSTRAINT legal_transparency_months_pkey PRIMARY KEY (month),
    CONSTRAINT legal_transparency_months_preservation_acknowledgement_check CHECK (preservation_acknowledgement >= 0),
    CONSTRAINT legal_transparency_months_received_check CHECK (received >= 0),
    CONSTRAINT legal_transparency_months_refusal_check CHECK (refusal >= 0)
);
CREATE TABLE public.legal_transparency_reports (
    id UUID NOT NULL,
    version BIGINT NOT NULL,
    year INTEGER NOT NULL,
    data_version BIGINT NOT NULL,
    schema_version INTEGER NOT NULL,
    policy_id UUID NOT NULL,
    payload BYTEA NOT NULL,
    digest TEXT NOT NULL,
    status TEXT NOT NULL,
    prepared_by UUID NOT NULL,
    prepared_auth_version BIGINT NOT NULL,
    prepared_at TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    approved_by UUID,
    approved_auth_version BIGINT,
    approved_at TIMESTAMPTZ,
    downloaded_at TIMESTAMPTZ,
    CONSTRAINT legal_transparency_reports_check CHECK (approved_by IS NULL OR approved_by <> prepared_by),
    CONSTRAINT legal_transparency_reports_check1 CHECK (status = 'prepared'::text AND approved_by IS NULL AND approved_auth_version IS NULL AND approved_at IS NULL AND downloaded_at IS NULL OR (status = ANY (ARRAY['approved'::text, 'downloaded'::text])) AND approved_by IS NOT NULL AND approved_auth_version >= 0 AND approved_at IS NOT NULL AND (status = 'approved'::text AND downloaded_at IS NULL OR status = 'downloaded'::text AND downloaded_at IS NOT NULL)),
    CONSTRAINT legal_transparency_reports_data_version_check CHECK (data_version >= 0),
    CONSTRAINT legal_transparency_reports_digest_check CHECK (digest ~ '^[0-9a-f]{64}$'::text),
    CONSTRAINT legal_transparency_reports_payload_check CHECK (octet_length(payload) >= 2 AND octet_length(payload) <= 8192),
    CONSTRAINT legal_transparency_reports_pkey PRIMARY KEY (id),
    CONSTRAINT legal_transparency_reports_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.legal_governance_policies(id),
    CONSTRAINT legal_transparency_reports_prepared_auth_version_check CHECK (prepared_auth_version >= 0),
    CONSTRAINT legal_transparency_reports_schema_version_check CHECK (schema_version = 1),
    CONSTRAINT legal_transparency_reports_status_check CHECK (status = ANY (ARRAY['prepared'::text, 'approved'::text, 'downloaded'::text])),
    CONSTRAINT legal_transparency_reports_version_check CHECK (version > 0),
    CONSTRAINT legal_transparency_reports_year_fkey FOREIGN KEY (year) REFERENCES public.legal_transparency_years(year)
);
CREATE INDEX legal_transparency_reports_year ON public.legal_transparency_reports (year, data_version);
CREATE TABLE public.legal_transparency_replays (
    operation TEXT NOT NULL,
    scope TEXT NOT NULL,
    idempotency_key UUID NOT NULL,
    input JSONB NOT NULL,
    result BYTEA NOT NULL,
    CONSTRAINT legal_transparency_replays_input_check CHECK (jsonb_typeof(input) = 'object'::text AND octet_length(input::text) <= 2048),
    CONSTRAINT legal_transparency_replays_operation_check CHECK (operation = ANY (ARRAY['prepare'::text, 'approve'::text, 'download'::text])),
    CONSTRAINT legal_transparency_replays_pkey PRIMARY KEY (operation, scope, idempotency_key),
    CONSTRAINT legal_transparency_replays_result_check CHECK (octet_length(result) BETWEEN 2 AND 16384 AND jsonb_typeof(convert_from(result, 'UTF8'::name)::jsonb) = 'object'::text),
    CONSTRAINT legal_transparency_replays_scope_check CHECK (length(scope) >= 1 AND length(scope) <= 36)
);

-- Final function bodies and individual security attributes. No v1 repair routines.
-- +goose StatementBegin
CREATE FUNCTION public.advance_account_auth_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.auth_version < OLD.auth_version THEN
        RAISE EXCEPTION 'account auth version cannot decrease';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR NEW.auth_version IS DISTINCT FROM OLD.auth_version THEN
        IF NEW.auth_version = OLD.auth_version THEN
            NEW.auth_version := OLD.auth_version + 1;
        END IF;
        NEW.auth_epoch := nextval('account_auth_epoch_seq');
    ELSE
        NEW.auth_epoch := OLD.auth_epoch;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Verify every new node, including exact terminal equality, before moving a head.
-- The audit coordination lock is 5200004, independent of the signer lock.
-- +goose StatementBegin
CREATE FUNCTION public.advance_chain_head(
    which text, expected_seq bigint, first_seq bigint, last_seq bigint, node_count bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' AS $$
DECLARE
    head_seq bigint;
    head_hash bytea;
    prefix bytea;
    item record;
    previous bytea;
    seen bigint := 0;
    terminal_seq bigint;
BEGIN
    IF which IS NULL OR which NOT IN ('audit', 'ledger') THEN
        RAISE EXCEPTION 'unknown chain' USING ERRCODE = '22023';
    END IF;
    IF expected_seq IS NULL OR first_seq IS NULL OR last_seq IS NULL OR node_count IS NULL
       OR expected_seq < 0 OR first_seq <= expected_seq OR last_seq < first_seq OR node_count <= 0
       OR node_count > last_seq - first_seq + 1 THEN
        RAISE EXCEPTION 'invalid head advancement span' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(CASE which WHEN 'audit' THEN 5200004 ELSE 5200002 END::bigint);
    IF which = 'audit' THEN
        SELECT h.seq, h.chain_hash INTO STRICT head_seq, head_hash
            FROM public.audit_log_head h WHERE h.singleton FOR UPDATE;
        prefix := convert_to('hatef.audit.chain.v2', 'UTF8') || '\x00'::bytea;
    ELSE
        SELECT h.seq, h.chain_hash INTO STRICT head_seq, head_hash
            FROM public.security_ledger_head h WHERE h.singleton FOR UPDATE;
        prefix := convert_to('hatef.ledger.chain.v2', 'UTF8') || '\x00'::bytea;
    END IF;
    IF head_seq <> expected_seq THEN
        RAISE EXCEPTION 'chain head expectation mismatch' USING ERRCODE = '23000';
    END IF;

    previous := head_hash;
    FOR item IN
        SELECT nodes.seq, nodes.leaf_hash, nodes.chain_hash FROM (
            SELECT c.seq, c.leaf_hash, c.chain_hash FROM public.audit_log_chain c
            WHERE which = 'audit' AND c.seq > head_seq
            UNION ALL
            SELECT c.seq, c.leaf_hash, c.chain_hash FROM public.security_ledger_chain c
            WHERE which = 'ledger' AND c.seq > head_seq
        ) nodes ORDER BY nodes.seq
    LOOP
        IF item.chain_hash <> sha256(prefix || previous || item.leaf_hash) THEN
            RAISE EXCEPTION 'chain linkage mismatch at seq %', item.seq USING ERRCODE = '23000';
        END IF;
        previous := item.chain_hash;
        seen := seen + 1;
        terminal_seq := item.seq;
        IF seen = 1 AND item.seq <> first_seq THEN
            RAISE EXCEPTION 'chain advancement does not start at the declared first seq' USING ERRCODE = '23000';
        END IF;
        IF item.seq > last_seq THEN
            RAISE EXCEPTION 'chain advancement exceeds the declared span' USING ERRCODE = '23000';
        END IF;
    END LOOP;
    IF seen <> node_count THEN
        RAISE EXCEPTION 'chain advancement node count mismatch' USING ERRCODE = '23000';
    END IF;
    IF terminal_seq IS DISTINCT FROM last_seq THEN
        RAISE EXCEPTION 'chain advancement terminal does not equal the declared last seq' USING ERRCODE = '23000';
    END IF;
    IF which = 'audit' THEN
        UPDATE public.audit_log_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    ELSE
        UPDATE public.security_ledger_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.chain_table_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'chain tables are append-only: % on % is not permitted', TG_OP, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.legal_governance_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legal governance records are immutable: % is not permitted', TG_OP;
END;
$$;
-- +goose StatementEnd

-- Aggregate functions are SECURITY INVOKER, never migration-owner authority.
-- +goose StatementBegin
CREATE FUNCTION public.legal_transparency_lock_year(p_year integer) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE result BIGINT;
BEGIN
    IF p_year < 1 OR p_year > 9999 OR p_year IS NULL THEN
        RAISE EXCEPTION 'invalid reporting year';
    END IF;
    INSERT INTO public.legal_transparency_years (year) VALUES (p_year) ON CONFLICT DO NOTHING;
    SELECT data_version INTO STRICT result FROM public.legal_transparency_years WHERE year=p_year FOR UPDATE;
    RETURN result;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.legal_transparency_count(p_at timestamptz, p_category text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE p_month DATE; p_year INTEGER;
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_at > clock_timestamp() OR p_category IS NULL OR
        p_category NOT IN ('received','full_disclosure','partial_disclosure','no_responsive_data','refusal','preservation_acknowledgement') THEN
        RAISE EXCEPTION 'invalid reporting counter';
    END IF;
    p_month := date_trunc('month',p_at AT TIME ZONE 'UTC')::DATE;
    p_year := EXTRACT(YEAR FROM p_month)::INTEGER;
    PERFORM public.legal_transparency_lock_year(p_year);
    INSERT INTO public.legal_transparency_coverage (started_at) VALUES (clock_timestamp()) ON CONFLICT DO NOTHING;
    UPDATE public.legal_transparency_years SET data_version=data_version+1 WHERE year=p_year;
    INSERT INTO public.legal_transparency_months AS m
        (month,received,answered,full_disclosure,partial_disclosure,no_responsive_data,refusal,preservation_acknowledgement)
    VALUES (p_month, (p_category='received')::INTEGER, (p_category<>'received')::INTEGER,
        (p_category='full_disclosure')::INTEGER, (p_category='partial_disclosure')::INTEGER,
        (p_category='no_responsive_data')::INTEGER, (p_category='refusal')::INTEGER,
        (p_category='preservation_acknowledgement')::INTEGER)
    ON CONFLICT (month) DO UPDATE SET received=m.received+EXCLUDED.received,
        answered=m.answered+EXCLUDED.answered, full_disclosure=m.full_disclosure+EXCLUDED.full_disclosure,
        partial_disclosure=m.partial_disclosure+EXCLUDED.partial_disclosure,
        no_responsive_data=m.no_responsive_data+EXCLUDED.no_responsive_data,
        refusal=m.refusal+EXCLUDED.refusal,
        preservation_acknowledgement=m.preservation_acknowledgement+EXCLUDED.preservation_acknowledgement;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.legal_transparency_report_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'report history is immutable'; END IF;
    IF ROW(NEW.id,NEW.year,NEW.data_version,NEW.schema_version,NEW.policy_id,NEW.payload,NEW.digest,
        NEW.prepared_by,NEW.prepared_auth_version,NEW.prepared_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.year,OLD.data_version,OLD.schema_version,OLD.policy_id,OLD.payload,OLD.digest,
        OLD.prepared_by,OLD.prepared_auth_version,OLD.prepared_at) THEN
        RAISE EXCEPTION 'report snapshot is immutable';
    END IF;
    IF NEW.version <> OLD.version+1 OR NOT (
        (OLD.status='prepared' AND NEW.status='approved' AND NEW.downloaded_at IS NULL) OR
        (OLD.status='approved' AND NEW.status='downloaded' AND
            ROW(NEW.approved_by,NEW.approved_auth_version,NEW.approved_at) IS NOT DISTINCT FROM
            ROW(OLD.approved_by,OLD.approved_auth_version,OLD.approved_at))) THEN
        RAISE EXCEPTION 'invalid report transition';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.legal_workflow_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'legal workflow history is immutable';
END;
$$;
-- +goose StatementEnd

-- The sole payload UPDATE exception is the users FK's ON DELETE SET NULL.
-- DELETE remains controlled by grants to separately provisioned retention roles.
-- +goose StatementBegin
CREATE FUNCTION public.mvp_audit_logs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.user_id IS NULL
       AND OLD.user_id IS NOT NULL
       AND to_jsonb(NEW) - 'user_id' = to_jsonb(OLD) - 'user_id' THEN
        RETURN NEW; -- FK ON DELETE SET NULL from the users hard-delete purge
    END IF;
    RAISE EXCEPTION 'mvp_audit_logs is immutable: % is not permitted', TG_OP
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.security_event_ledger_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'security_event_ledger is immutable: % is not permitted', TG_OP
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

-- Trigger event coverage is intentional: payload DELETE is privilege-controlled.
CREATE TRIGGER trg_audit_log_chain_append_only BEFORE DELETE OR UPDATE ON public.audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_audit_log_chain_no_truncate BEFORE TRUNCATE ON public.audit_log_chain
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER legal_governance_baseline_immutable BEFORE DELETE OR UPDATE ON public.legal_governance_baseline
    FOR EACH ROW EXECUTE FUNCTION public.legal_governance_immutable();
CREATE TRIGGER legal_governance_baseline_no_truncate BEFORE TRUNCATE ON public.legal_governance_baseline
    FOR EACH STATEMENT EXECUTE FUNCTION public.legal_governance_immutable();
CREATE TRIGGER legal_governance_policy_immutable BEFORE DELETE OR UPDATE ON public.legal_governance_policies
    FOR EACH ROW EXECUTE FUNCTION public.legal_governance_immutable();
CREATE TRIGGER legal_governance_policy_no_truncate BEFORE TRUNCATE ON public.legal_governance_policies
    FOR EACH STATEMENT EXECUTE FUNCTION public.legal_governance_immutable();
CREATE TRIGGER legal_transparency_report_immutable BEFORE DELETE OR UPDATE ON public.legal_transparency_reports
    FOR EACH ROW EXECUTE FUNCTION public.legal_transparency_report_immutable();
CREATE TRIGGER legal_workflow_events_immutable BEFORE UPDATE ON public.legal_workflow_events
    FOR EACH ROW EXECUTE FUNCTION public.legal_workflow_event_immutable();
CREATE TRIGGER trg_mvp_audit_logs_immutable BEFORE UPDATE ON public.mvp_audit_logs
    FOR EACH ROW EXECUTE FUNCTION public.mvp_audit_logs_guard();
CREATE TRIGGER trg_mvp_audit_logs_no_truncate BEFORE TRUNCATE ON public.mvp_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION public.mvp_audit_logs_guard();
CREATE TRIGGER trg_security_event_ledger_immutable BEFORE UPDATE ON public.security_event_ledger
    FOR EACH ROW EXECUTE FUNCTION public.security_event_ledger_guard();
CREATE TRIGGER trg_security_event_ledger_no_truncate BEFORE TRUNCATE ON public.security_event_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION public.security_event_ledger_guard();
CREATE TRIGGER trg_security_ledger_chain_append_only BEFORE DELETE OR UPDATE ON public.security_ledger_chain
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_chain_no_truncate BEFORE TRUNCATE ON public.security_ledger_chain
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_erasures_append_only BEFORE DELETE OR UPDATE ON public.security_ledger_erasures
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_erasures_no_truncate BEFORE TRUNCATE ON public.security_ledger_erasures
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER users_advance_auth_version BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.advance_account_auth_version();

-- Preserve individual PUBLIC revocations, not a blanket function ACL policy.
-- No database roles, ownership transfers, or operator-only grants are installed.
REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_log_chain, public.security_ledger_chain,
    public.security_ledger_erasures, public.mvp_audit_logs, public.security_event_ledger FROM PUBLIC;
REVOKE ALL ON public.admin_action_contexts, public.audit_log_head, public.security_ledger_head,
    public.security_ledger_retention_settings, public.legal_governance_policies, public.legal_governance_baseline,
    public.legal_cases, public.legal_case_subjects, public.legal_case_holds, public.legal_workflow_events,
    public.legal_hold_reviews, public.legal_workflow_replays, public.legal_transparency_coverage,
    public.legal_transparency_years, public.legal_transparency_months, public.legal_transparency_reports,
    public.legal_transparency_replays FROM PUBLIC;
REVOKE ALL ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.chain_table_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.legal_governance_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.legal_transparency_count(timestamptz, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.legal_transparency_lock_year(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.legal_workflow_event_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.mvp_audit_logs_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_event_ledger_guard() FROM PUBLIC;

-- Reference RBAC only: 4 roles, 13 permissions, and 15 assignments.
-- Support has no PII grant; super_admin verifies integrity but cannot read users.
-- No users, user-role assignments, policy bindings, heads, retention settings,
-- approvals, or runtime history are initialized by migration.
INSERT INTO public.roles (id, description) VALUES
    ('dpo', 'Data Protection Officer: read-only audit access, Legal Hold and lawful-inquiry handling.'),
    ('moderator', 'Trust & Safety / Content Moderator: account abuse prevention (suspend/ban).'),
    ('super_admin', 'System Administrator: infrastructure and role management. No access to individual user data.'),
    ('support', 'Support / Helpdesk: high-level account status only, no personal data.')
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.permissions (id, description) VALUES
    ('admin.audit_logs.read', 'Query the immutable audit log within a bounded time window.'),
    ('admin.audit_logs.verify', 'Recompute and verify either cryptographic hash chain.'),
    ('admin.users.read', 'List and view accounts without any PII (no email address).'),
    ('admin.users.read.pii', 'Adds the email address to account reads and enables POST exact-email lookup.'),
    ('admin.users.status.write', 'Change an account status between active, suspended, and banned.'),
    ('legal.cases.read', 'Read restricted legal case workflow metadata.'),
    ('legal.cases.write', 'Receive, review and attest legal case responses.'),
    ('legal.holds.read', 'List Legal Holds.'),
    ('legal.holds.write', 'Apply and release Legal Holds and record preservation requests.'),
    ('legal.inquiry.lookup', 'Blind-index attribution lookup against the security event ledger.'),
    ('legal.responses.approve', 'Approve an exact legal response prepared by a distinct DPO.'),
    ('legal.transparency.approve', 'Approve an exact aggregate transparency artifact prepared by a different DPO.'),
    ('legal.transparency.read', 'Read restricted aggregate statistics and prepare or download reviewed transparency artifacts.')
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.role_permissions (role_id, permission_id) VALUES
    ('dpo', 'admin.audit_logs.read'),
    ('dpo', 'admin.audit_logs.verify'),
    ('dpo', 'legal.cases.read'),
    ('dpo', 'legal.cases.write'),
    ('dpo', 'legal.holds.read'),
    ('dpo', 'legal.holds.write'),
    ('dpo', 'legal.inquiry.lookup'),
    ('dpo', 'legal.responses.approve'),
    ('dpo', 'legal.transparency.approve'),
    ('dpo', 'legal.transparency.read'),
    ('moderator', 'admin.users.read'),
    ('moderator', 'admin.users.read.pii'),
    ('moderator', 'admin.users.status.write'),
    ('super_admin', 'admin.audit_logs.verify'),
    ('support', 'admin.users.read')
ON CONFLICT DO NOTHING;

-- +goose Down
-- A development reset is a separate, explicitly scoped operation.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'identity schema baseline is forward-only; preserve durable state and use separately scoped fresh setup';
END $$;
-- +goose StatementEnd
