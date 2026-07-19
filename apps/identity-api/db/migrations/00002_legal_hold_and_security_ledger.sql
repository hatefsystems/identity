-- Task 2.1 (extended): Legal Hold & persistent Security Event Ledger.
--
-- Source of truth: docs/compliance-and-data-governance.md (§2 Class B, §6 Legal
-- Hold, §7 Security Event Ledger) and docs/data-architecture.md §1.1 (tables 5-6).
--
-- Rationale (threat-modeling.md R2, "Deletion-to-Evade-Attribution"): a lawful
-- inquiry can arrive AFTER an account is hard-deleted (e.g. day 60 about an
-- action taken before a day-30 deletion). The standard mvp_audit_logs row is
-- rendered unattributable on hard-delete (user_id ON DELETE SET NULL, PII-masked
-- payload). This migration adds a minimal, non-PII ledger that is decoupled from
-- the account lifecycle, plus a Legal Hold that takes precedence over ALL
-- retention timers (holds > retention).
--
-- Managed by goose; sqlc parses this file as schema input. Apply with:
--   nx run identity-api:migrate-up   (or: go run ./cmd/migrate up)

-- +goose Up

-- 5. Security Event Ledger (Class B - Minimal, Persistent, Survives Account Deletion)
--
-- CRITICAL: intentionally NO foreign key to users(id). The stable account_ref
-- persists independently so an action remains attributable after the account row
-- is physically deleted - bounded strictly by retain_until. Only the identity
-- blind index is stored (SHA-256(PII + pepper), data-architecture.md §2.2); raw
-- PII stays in Class A (users) and is erased on hard-delete.
CREATE TABLE security_event_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,                       -- Stable identity reference; survives hard-delete (NO FK)
    identity_blind_index VARCHAR(64) NULL,           -- SHA-256(email/phone + pepper); attribution without raw PII
    event_type VARCHAR(100) NOT NULL,                -- e.g. 'auth.login', 'token.issued', 'security.rtr_breach'
    client_ip VARCHAR(50) NULL,
    ip_subnet VARCHAR(50) NULL,                      -- /24 (IPv4) or /48 (IPv6) grouping
    user_agent TEXT NULL,
    device_fingerprint VARCHAR(128) NULL,
    client_id VARCHAR(100) NULL,                     -- OAuth client that received an authorization, if any
    scope TEXT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retain_until TIMESTAMP WITH TIME ZONE NOT NULL,  -- Independent retention (e.g. NOW() + 6..18 months)
    chain_hash VARCHAR(64) NOT NULL                  -- Same cryptographic chaining as mvp_audit_logs
);

-- Attribution lookups by identity (authority supplies an identifier -> compute blind index).
CREATE INDEX idx_security_ledger_blind_index ON security_event_ledger(identity_blind_index);
CREATE INDEX idx_security_ledger_account_ref ON security_event_ledger(account_ref);
CREATE INDEX idx_security_ledger_retain_until ON security_event_ledger(retain_until);
CREATE INDEX idx_security_ledger_event_type ON security_event_ledger(event_type);

-- 6. Legal Holds (Precedence Lock over ALL retention timers)
--
-- An active hold overrides the 30-day grace window AND the ledger retention.
-- Holds > retention. A hold has no predefined duration; it stays until released.
CREATE TABLE legal_holds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,                        -- Subject reference (matches security_event_ledger.account_ref)
    reason TEXT NOT NULL,
    requesting_authority VARCHAR(255) NOT NULL,       -- Court / agency / case reference
    legal_basis VARCHAR(255) NOT NULL,                -- e.g. 'legal obligation', 'legal claims / investigation'
    applied_by UUID NOT NULL,                         -- Actor (DPO / Legal) who created the hold
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_at TIMESTAMP WITH TIME ZONE NULL,          -- Optional expected review date (advisory only)
    released_at TIMESTAMP WITH TIME ZONE NULL,
    released_by UUID NULL
);

-- The hard-delete Cron (Task 5.1) and the ledger purge job (Task 5.4) MUST
-- consult this index before purging any subject.
CREATE INDEX idx_legal_holds_active ON legal_holds(account_ref) WHERE is_active = TRUE;

-- Append-only enforcement for the ledger, mirroring mvp_audit_logs
-- (compliance-and-data-governance.md §2.3 / architecture.md "Append-Only Log
-- Management"). Unlike mvp_audit_logs there is NO FK-driven UPDATE to allow
-- here: the ledger is fully decoupled from users, so every UPDATE and all
-- DELETE/TRUNCATE break append-only semantics and are rejected. Physical purge
-- of expired rows is performed by a dedicated maintenance role/job (Task 5.4)
-- outside these guarded roles.
-- +goose StatementBegin
CREATE FUNCTION security_event_ledger_guard() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'security_event_ledger is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER trg_security_event_ledger_append_only
    BEFORE UPDATE OR DELETE ON security_event_ledger
    FOR EACH ROW EXECUTE FUNCTION security_event_ledger_guard();

CREATE TRIGGER trg_security_event_ledger_no_truncate
    BEFORE TRUNCATE ON security_event_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION security_event_ledger_guard();

-- Defense-in-depth: strip UPDATE/DELETE/TRUNCATE from all non-owner roles so
-- application/admin roles can never mutate the ledger. The retention purge job
-- (Task 5.4) runs under a dedicated maintenance role that is granted DELETE
-- explicitly and is exempt from the trigger by disabling it within its
-- transaction (documented operational procedure), or purges via a separate
-- superuser-run maintenance path.
REVOKE UPDATE, DELETE, TRUNCATE ON security_event_ledger FROM PUBLIC;

-- +goose Down
DROP TABLE legal_holds;
DROP TRIGGER IF EXISTS trg_security_event_ledger_no_truncate ON security_event_ledger;
DROP TRIGGER IF EXISTS trg_security_event_ledger_append_only ON security_event_ledger;
DROP TABLE security_event_ledger;
DROP FUNCTION IF EXISTS security_event_ledger_guard();
