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
--
-- This is a SECOND, INDEPENDENT chain: it shares the formula with mvp_audit_logs
-- but not the sequence, and the two serializations carry distinct domain
-- prefixes so a record can never be replayed across ledgers. Chain position is
-- `seq` (migration 00006), never (timestamp, id).

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
--
-- `id` is the publisher-assigned event id from the JetStream message; the
-- consumer filters already-present ids (FilterExistingSecurityEventIDs) so an
-- at-least-once redelivery cannot append a permanent duplicate to a table whose
-- UPDATE/DELETE rights are revoked.
INSERT INTO security_event_ledger (
    id, account_ref, identity_blind_index, event_type, client_ip, ip_subnet,
    user_agent, device_fingerprint, client_id, scope, timestamp, retain_until, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: GetLatestSecurityEventChainHash :one
-- Seeds the next chain computation; returns no rows before the genesis record.
SELECT chain_hash FROM security_event_ledger
ORDER BY seq DESC
LIMIT 1;

-- name: FilterExistingSecurityEventIDs :many
-- Deduplication probe for the signing consumer (see InsertSecurityEvents).
SELECT id FROM security_event_ledger
WHERE id = ANY(sqlc.arg('ids')::uuid[]);

-- name: ListSecurityEventsForChainVerification :many
-- Ordered ascending scan for the ledger integrity audit (disaster-recovery
-- §3.2), mirroring ListAuditLogsForChainVerification. Keyset pagination over seq
-- keeps memory bounded; pass after_seq = 0 to start at genesis. See that query
-- for why the ::bigint cast matters.
SELECT * FROM security_event_ledger
WHERE seq > sqlc.arg('after_seq')::bigint
  AND seq <= sqlc.arg('through_seq')::bigint
ORDER BY seq
LIMIT sqlc.arg('page_limit');

-- name: GetSecurityEventHighWaterSeq :one
SELECT COALESCE(MAX(seq), 0)::bigint FROM security_event_ledger;

-- name: GetSecurityEventChainHashBySeq :one
-- Task 5.3: ledger counterpart of GetAuditLogChainHashBySeq, seeding a resumed
-- verification (GET /admin/ledger/verify with after_seq > 0). Matches seq
-- exactly for the same reason: gaps are legal, so "at or after" would return a
-- later row's digest and report a break in an intact chain.
SELECT chain_hash FROM security_event_ledger
WHERE seq = sqlc.arg('seq')::bigint;

-- name: FindSecurityEventsByBlindIndex :many
-- Legacy signer smoke probe. HTTP uses the bounded query below.
SELECT * FROM security_event_ledger
WHERE identity_blind_index = $1
ORDER BY timestamp DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: LookupLegalAttribution :many
-- Each page rechecks current retention/hold eligibility. A previous cursor
-- never grants access to expired evidence after release.
SELECT * FROM security_event_ledger sel
WHERE identity_blind_index = sqlc.arg('blind_index')::text
  AND timestamp >= sqlc.arg('start_time')::timestamptz
  AND timestamp <= sqlc.arg('end_time')::timestamptz
  AND seq > sqlc.arg('after_seq')::bigint
  AND seq <= sqlc.arg('through_seq')::bigint
  AND (retain_until >= sqlc.arg('as_of')::timestamptz OR EXISTS (
      SELECT 1 FROM legal_holds lh WHERE lh.account_ref = sel.account_ref AND lh.is_active
  ))
ORDER BY seq
LIMIT sqlc.arg('page_limit')::int;

-- name: LegalAttributionHighWater :one
SELECT COALESCE(MAX(seq), 0)::bigint AS through_seq FROM security_event_ledger;

-- name: ObserveLegalSubject :one
SELECT EXISTS (SELECT 1 FROM users WHERE id = sqlc.arg('account_ref')::uuid) AS account_present,
       EXISTS (SELECT 1 FROM security_event_ledger WHERE account_ref = sqlc.arg('account_ref')::uuid) AS ledger_evidence_present;

-- name: FindSecurityEventsByAccountRef :many
SELECT * FROM security_event_ledger
WHERE account_ref = $1
ORDER BY timestamp DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: PurgeExpiredSecurityEvents :execrows
-- Retention purge (Task 5.4). Runs under a dedicated maintenance role. Rows are
-- removed ONLY when past retain_until AND the subject has no active Legal Hold
-- (holds > retention, compliance §6). NOT safe as a live worker: before any
-- maintenance deletion, lock every selected account with pglock.LockAccount in
-- UUID order, then re-read in a NEW READ COMMITTED statement. API roles must not
-- bypass the append-only trigger. Task 5.4 owns the maintenance/checkpoint design.
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
-- Legacy migration/integration fixture only; runtime writes encrypted requests.
INSERT INTO legal_holds (
    account_ref, reason, requesting_authority, legal_basis, applied_by, review_at
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: CreateEncryptedLegalHold :one
INSERT INTO legal_holds (
    id, account_ref, applied_by, review_at, request_kind, idempotency_key, details_encrypted
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetLegalHoldByRequest :one
SELECT * FROM legal_holds
WHERE account_ref = $1 AND request_kind = $2 AND idempotency_key = $3;

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

-- name: ListLegalHolds :one
-- One statement guarantees count/page snapshot consistency, including offsets
-- beyond the last page, without a stale REPEATABLE READ snapshot after a lock.
WITH filtered AS (
    SELECT * FROM legal_holds
    WHERE (sqlc.narg('account_ref')::uuid IS NULL OR account_ref = sqlc.narg('account_ref')::uuid)
      AND (sqlc.arg('status')::text = 'all'
          OR (sqlc.arg('status')::text = 'active' AND is_active)
          OR (sqlc.arg('status')::text = 'released' AND NOT is_active))
), page AS (
    SELECT * FROM filtered ORDER BY applied_at DESC, id DESC
    LIMIT sqlc.arg('page_limit')::int OFFSET sqlc.arg('page_offset')::int
)
SELECT (SELECT COUNT(*) FROM filtered) AS total,
       COALESCE((SELECT jsonb_agg(to_jsonb(page) || jsonb_build_object('details_encrypted', encode(details_encrypted, 'base64'))
           ORDER BY applied_at DESC, id DESC) FROM page), '[]'::jsonb)::jsonb AS items;

-- name: CountUnencryptedLegalHolds :one
SELECT COUNT(*) FROM legal_holds
WHERE reason IS NOT NULL OR requesting_authority IS NOT NULL OR legal_basis IS NOT NULL
   OR (details_encrypted IS NULL AND details_purged_at IS NULL);

-- name: HasActiveLegalHold :one
-- Consulted by the hard-delete Cron (Task 5.1) and the ledger purge (Task 5.4)
-- before removing any subject's data.
SELECT EXISTS (
    SELECT 1 FROM legal_holds
    WHERE account_ref = $1 AND is_active = TRUE
) AS has_active_hold;
