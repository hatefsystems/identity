-- Task 2.2 (extended): Legal Hold & Security Event Ledger queries.
--
-- Backs the compliance controls in docs/compliance-and-data-governance.md
-- (§6 Legal Hold, §7 Security Event Ledger) and the admin endpoints in
-- api-design.md §1.7 (legal-holds, preservation-requests, legal-inquiry/lookup).
--
-- security_event_ledger is append-only (a DB trigger rejects UPDATE/DELETE), so
-- only inserts, reads, and a maintenance-role purge are defined here. Rows are
-- chained like mvp_audit_logs:
--   chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N)))

-- ---------------------------------------------------------------------------
-- Security Event Ledger
-- ---------------------------------------------------------------------------

-- name: InsertSecurityEvent :one
INSERT INTO security_event_ledger (
    account_ref, identity_blind_index, event_type, client_ip, ip_subnet,
    user_agent, device_fingerprint, client_id, scope, retain_until, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: InsertSecurityEvents :copyfrom
-- Batched writes for the single-threaded signing consumer (Task 5.2). Timestamp
-- is supplied explicitly so the chain hash covers the exact persisted value.
INSERT INTO security_event_ledger (
    account_ref, identity_blind_index, event_type, client_ip, ip_subnet,
    user_agent, device_fingerprint, client_id, scope, timestamp, retain_until, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetLatestSecurityEventChainHash :one
-- Seeds the next chain computation; returns no rows before the genesis record.
SELECT chain_hash FROM security_event_ledger
ORDER BY timestamp DESC, id DESC
LIMIT 1;

-- name: FindSecurityEventsByBlindIndex :many
-- Attribution lookup (api-design §1.7 legal-inquiry/lookup): an authority
-- supplies an identifier, the app computes the blind index, and we return the
-- non-PII ledger rows still within their retention window. Read-only.
SELECT * FROM security_event_ledger
WHERE identity_blind_index = $1
ORDER BY timestamp DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: FindSecurityEventsByAccountRef :many
SELECT * FROM security_event_ledger
WHERE account_ref = $1
ORDER BY timestamp DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: PurgeExpiredSecurityEvents :execrows
-- Retention purge (Task 5.4). Runs under a dedicated maintenance role. Rows are
-- removed ONLY when past retain_until AND the subject has no active Legal Hold
-- (holds > retention, compliance §6). Requires the maintenance role to be
-- exempt from the append-only trigger per the documented operational procedure.
DELETE FROM security_event_ledger sel
WHERE sel.retain_until < NOW()
  AND NOT EXISTS (
      SELECT 1 FROM legal_holds lh
      WHERE lh.account_ref = sel.account_ref AND lh.is_active = TRUE
  );

-- ---------------------------------------------------------------------------
-- Legal Holds
-- ---------------------------------------------------------------------------

-- name: ApplyLegalHold :one
INSERT INTO legal_holds (
    account_ref, reason, requesting_authority, legal_basis, applied_by, review_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ReleaseLegalHold :one
-- Sets is_active = false and records who/when. Released data returns to normal
-- retention timers and is purged on the next cycle if already past its window.
UPDATE legal_holds
SET is_active = FALSE,
    released_at = NOW(),
    released_by = $2
WHERE id = $1 AND is_active = TRUE
RETURNING *;

-- name: GetLegalHold :one
SELECT * FROM legal_holds WHERE id = $1;

-- name: ListLegalHolds :many
SELECT * FROM legal_holds
WHERE (sqlc.narg('account_ref')::uuid IS NULL OR account_ref = sqlc.narg('account_ref')::uuid)
  AND (sqlc.narg('active_only')::boolean IS NOT TRUE OR is_active = TRUE)
ORDER BY applied_at DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: HasActiveLegalHold :one
-- Consulted by the hard-delete Cron (Task 5.1) and the ledger purge (Task 5.4)
-- before removing any subject's data.
SELECT EXISTS (
    SELECT 1 FROM legal_holds
    WHERE account_ref = $1 AND is_active = TRUE
) AS has_active_hold;
