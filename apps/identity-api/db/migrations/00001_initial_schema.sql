-- Task 2.1: Initial schema for the Hatef Identity Platform (MVP).
--
-- Source of truth: docs/data-architecture.md §1.1 (PostgreSQL DDL). Covers:
--   users, roles, permissions, role_permissions, user_roles,
--   webauthn_credentials, recovery_codes, mvp_audit_logs.
--
-- Managed by goose (https://github.com/pressly/goose). sqlc parses this file
-- as its schema input and ignores the Down section. Apply with:
--   nx run identity-api:migrate-up   (or: go run ./cmd/migrate up)

-- +goose Up

-- Enable necessary extensions (docs specify uuid-ossp / uuid_generate_v4()).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users Table (Core Identity)
--
-- PII columns (backup email, phone, TOTP secret) hold AES-GCM-256
-- envelope-encrypted payloads (data-architecture.md §2); exact-match lookups
-- go through the SHA-256(PII + pepper) blind index columns instead.
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL, -- Global UNIQUE constraint removed to allow reuse after Soft Delete/Deactivation
    password_hash VARCHAR(255) NULL, -- NULL for passwordless WebAuthn-only accounts
    backup_email_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    backup_email_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Email + Pepper)
    phone_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    phone_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Phone + Pepper)
    mfa_totp_secret_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'pending_verification', 'pending_deletion')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL -- Support soft deletion for Right to be Forgotten retention windows (30-day Grace Period)
);

-- Partial Unique Index to enforce email uniqueness only for active accounts,
-- permitting reuse after soft-deletion.
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status);
CREATE UNIQUE INDEX idx_users_phone_blind ON users(phone_blind_index) WHERE deleted_at IS NULL AND phone_blind_index IS NOT NULL;
CREATE UNIQUE INDEX idx_users_backup_email_blind ON users(backup_email_blind_index) WHERE deleted_at IS NULL AND backup_email_blind_index IS NOT NULL;

-- 2. Roles & Permissions Tables (RBAC)
CREATE TABLE roles (
    id VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permissions (
    role_id VARCHAR(50) REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(50) REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- 3. WebAuthn Credentials Table
CREATE TABLE webauthn_credentials (
    id BYTEA PRIMARY KEY, -- Credential ID (raw binary)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL, -- Public Key in COSE format
    attestation_type VARCHAR(50) NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0, -- Signature counter to detect cloned devices
    user_present BOOLEAN NOT NULL DEFAULT TRUE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    aaguid UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE NULL
);

CREATE INDEX idx_webauthn_user_id ON webauthn_credentials(user_id);

-- 4. Recovery Codes (Backup Codes) Table
CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the recovery code
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE NULL
);

-- Index is critical to perform O(1) matching. It avoids sequential
-- password-like decryption loops (threat-modeling.md D1).
CREATE UNIQUE INDEX idx_recovery_codes_hash ON recovery_codes(code_hash) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

-- 5. MVP FALLBACK: Audit Logs Table
-- Used in place of ClickHouse during the MVP Phase to reduce memory
-- (architecture.md "Append-Only Log Management"). Each row's chain_hash links
-- to the previous row, forming a tamper-evident cryptographic ledger.
CREATE TABLE mvp_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_id UUID NOT NULL,
    actor_spiffe_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action_status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    payload TEXT NOT NULL, -- Serialized JSON representation (masked of PII)
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    chain_hash VARCHAR(64) NOT NULL -- Chained Cryptographic hash for auditing integrity
);

CREATE INDEX idx_mvp_audit_logs_event_type ON mvp_audit_logs(event_type);
CREATE INDEX idx_mvp_audit_logs_timestamp ON mvp_audit_logs(timestamp DESC);

-- Append-only enforcement (architecture.md: "administrative database roles do
-- not possess UPDATE or DELETE permissions on the audit logs table").
--
-- A trigger guards the ledger even for the table owner. The single permitted
-- mutation is the FK referential action (ON DELETE SET NULL) that nulls
-- user_id when a user row is hard-deleted by the GDPR purge worker (Task 5.1);
-- every other UPDATE, and all DELETE/TRUNCATE, breaks append-only semantics
-- and is rejected.
-- +goose StatementBegin
CREATE FUNCTION mvp_audit_logs_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.user_id IS NULL
       AND OLD.user_id IS NOT NULL
       AND to_jsonb(NEW) - 'user_id' = to_jsonb(OLD) - 'user_id' THEN
        RETURN NEW; -- FK ON DELETE SET NULL from the users hard-delete purge
    END IF;
    RAISE EXCEPTION 'mvp_audit_logs is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_mvp_audit_logs_append_only
    BEFORE UPDATE OR DELETE ON mvp_audit_logs
    FOR EACH ROW EXECUTE FUNCTION mvp_audit_logs_guard();

CREATE TRIGGER trg_mvp_audit_logs_no_truncate
    BEFORE TRUNCATE ON mvp_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION mvp_audit_logs_guard();

-- Defense-in-depth: strip UPDATE/DELETE/TRUNCATE from all non-owner roles so
-- production application/admin roles can never be granted mutation rights by
-- default (the trigger above covers the owner itself).
REVOKE UPDATE, DELETE, TRUNCATE ON mvp_audit_logs FROM PUBLIC;

-- +goose Down
DROP TABLE mvp_audit_logs;
DROP FUNCTION mvp_audit_logs_guard();
DROP TABLE recovery_codes;
DROP TABLE webauthn_credentials;
DROP TABLE user_roles;
DROP TABLE role_permissions;
DROP TABLE permissions;
DROP TABLE roles;
DROP TABLE users;
DROP EXTENSION IF EXISTS "uuid-ossp";
