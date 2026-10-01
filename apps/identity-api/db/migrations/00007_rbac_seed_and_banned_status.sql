-- Task 5.3: prerequisites for the /api/v1/admin/* surface.
--
-- Two independent changes ship in one migration because both are hard
-- prerequisites for the same route group and neither is useful alone:
--
--   1a. `banned` becomes a legal users.status value. PATCH
--       /api/v1/admin/users/{user_id}/status is documented to accept
--       "Active, Suspended, Banned" (api-design.md §1.7) and banning is the
--       Trust & Safety role's core capability (architecture.md:101), but the
--       CHECK constraint installed by 00001_initial_schema.sql:31 allows only
--       active | suspended | pending_verification | pending_deletion.
--
--   1b. The capability model is seeded. RBAC here is permission-based, not
--       role-based: the Go guard evaluates UserHasPermission, so a capability
--       change is a role_permissions row rather than a code edit.
--
-- Managed by goose; sqlc parses this file as schema input. Apply with:
--   nx run identity-api:migrate-up   (or: go run ./cmd/migrate up)

-- +goose Up

-- 1a. Add 'banned' to the users.status domain.
--
-- Ban is deliberately *only* a status value here. The re-registration
-- fingerprint mentioned in architecture.md:102 is not implemented: it needs a
-- separate table and its own retention story, and a partial ban is strictly
-- better than no ban at all.
--
-- Note what is NOT added: no admin-settable pending_deletion. Manual admin
-- deletion is prohibited (architecture.md:114 "No Manual Deletion"), so
-- pending_deletion stays reachable only through the user's own
-- "Right to be Forgotten" flow. The constraint cannot express that -- the
-- handler enforces it -- but the intent is recorded here because this is where
-- a future reader will look.
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'suspended', 'pending_verification', 'pending_deletion', 'banned'));

-- 1b. Seed roles, permissions, and the grants between them.
--
-- Every statement is idempotent (ON CONFLICT DO NOTHING), matching the upsert
-- intent already documented at db/queries/rbac.sql:8: roles are provisioned by
-- bootstrap/IaC, so a re-run must be a no-op rather than a failure.
--
-- The four roles are exactly the ones architecture.md §RBAC defines.
INSERT INTO roles (id, description) VALUES
    ('super_admin', 'System Administrator: infrastructure and role management. No access to individual user data.'),
    ('moderator',   'Trust & Safety / Content Moderator: account abuse prevention (suspend/ban).'),
    ('support',     'Support / Helpdesk: high-level account status only, no personal data.'),
    ('dpo',         'Data Protection Officer: read-only audit access, Legal Hold and lawful-inquiry handling.')
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, description) VALUES
    ('admin.users.read',         'List and view accounts without any PII (no email address).'),
    ('admin.users.read.pii',     'Adds the email address to account reads and enables POST exact-email lookup.'),
    ('admin.users.status.write', 'Change an account status between active, suspended, and banned.'),
    ('admin.audit_logs.read',    'Query the immutable audit log within a bounded time window.'),
    ('admin.audit_logs.verify',  'Recompute and verify either cryptographic hash chain.'),
    ('legal.holds.read',         'List Legal Holds.'),
    ('legal.holds.write',        'Apply and release Legal Holds and record preservation requests.'),
    ('legal.inquiry.lookup',     'Blind-index attribution lookup against the security event ledger.')
ON CONFLICT (id) DO NOTHING;

-- Grants. Two splits in this table are load-bearing and must not be "tidied":
--
--   * support holds admin.users.read but NOT admin.users.read.pii. Support is
--     documented as having "No access to personal data" (architecture.md:111),
--     so the email address is a separate permission rather than part of the
--     base read.
--   * super_admin holds neither a user-data nor a legal permission.
--     architecture.md:97 states it "does NOT have access to read individual
--     user raw data or private telemetry", so granting it admin.users.read
--     here would contradict the role's own definition. It manages roles; it
--     does not read subjects.
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Trust & Safety: needs to identify the abusive account it is acting on,
    -- and needs the email because abuse reports arrive keyed by address.
    ('moderator',   'admin.users.read'),
    ('moderator',   'admin.users.read.pii'),
    ('moderator',   'admin.users.status.write'),

    -- Support: status triage only.
    ('support',     'admin.users.read'),

    -- Super Admin may verify integrity, never read individual audit records.
    ('super_admin', 'admin.audit_logs.verify'),

    -- DPO: compliance and audit, plus the whole lawful-request surface.
    ('dpo',         'admin.audit_logs.read'),
    ('dpo',         'admin.audit_logs.verify'),
    ('dpo',         'legal.holds.read'),
    ('dpo',         'legal.holds.write'),
    ('dpo',         'legal.inquiry.lookup')
ON CONFLICT DO NOTHING;

-- +goose Down

-- Guard first: fail loudly rather than silently rewriting a banned account.
--
-- This runs before any DELETE so the rollback is a no-op on the failure path
-- even if the transaction wrapper is ever removed. Goose wraps a migration in
-- a transaction by default, which would roll the DELETEs back anyway, but
-- ordering the check first means correctness does not depend on that.
--
-- Re-adding the old CHECK would abort on an existing 'banned' row regardless,
-- but with a raw constraint-violation message that says nothing about what to
-- do. An explicit RAISE names the problem and forces an operator decision,
-- because the obvious alternative -- UPDATE ... SET status = 'suspended' --
-- would quietly un-ban abusive accounts across the whole ecosystem as a side
-- effect of a schema rollback.
-- +goose StatementBegin
DO $$
DECLARE
    banned_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO banned_count FROM users WHERE status = 'banned';
    IF banned_count > 0 THEN
        RAISE EXCEPTION
            'cannot roll back 00007: % account(s) have status = ''banned''; '
            'decide their status explicitly (suspended or active) before down-migrating',
            banned_count;
    END IF;
END
$$;
-- +goose StatementEnd

-- Preserve definitions and assignments: ON CONFLICT seeds cannot distinguish
-- pre-existing operator-owned rows from rows created by this migration.

ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'suspended', 'pending_verification', 'pending_deletion'));
