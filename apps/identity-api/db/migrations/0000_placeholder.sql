-- PLACEHOLDER schema for Task 1.5 (sqlc pipeline wiring only).
--
-- This file exists so `sqlc generate` has a valid schema to compile against and
-- the codegen target is verifiable today. It is REPLACED by the real migrations
-- in Task 2.1 (users, roles, permissions, role_permissions, user_roles,
-- webauthn_credentials, recovery_codes, mvp_audit_logs). Do not build on it.
CREATE TABLE schema_bootstrap_check (
    id UUID PRIMARY KEY,
    note TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
