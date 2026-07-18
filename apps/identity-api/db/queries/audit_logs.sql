-- Task 2.2: MVP audit ledger queries (insert/select only).
--
-- mvp_audit_logs is append-only — a DB trigger rejects UPDATE/DELETE/TRUNCATE
-- (architecture.md "Append-Only Log Management"), so no mutating queries are
-- defined here by design. Rows are chained via
--   chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N)))
-- computed by the single-threaded signing consumer (Task 5.2).

-- name: InsertAuditLog :one
INSERT INTO mvp_audit_logs (
    user_id, actor_id, actor_spiffe_id, event_type, action_status,
    client_ip, user_agent, payload, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: InsertAuditLogs :copyfrom
-- Batched writes for the signing consumer (e.g., every 5s or 1000 records,
-- data-architecture §4.2 MVP fallback). Timestamps are supplied explicitly so
-- the chain hash covers the exact persisted value.
INSERT INTO mvp_audit_logs (
    user_id, actor_id, actor_spiffe_id, event_type, action_status,
    client_ip, user_agent, payload, timestamp, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetLatestAuditLogChainHash :one
-- Seeds the next chain computation; returns no rows before the genesis record
-- (callers treat pgx.ErrNoRows as "start of chain").
SELECT chain_hash FROM mvp_audit_logs
ORDER BY timestamp DESC, id DESC
LIMIT 1;

-- name: ListAuditLogs :many
-- DPO/Admin query (api-design §1.7): start/end time bounds are mandatory to
-- prevent unbounded DoS scans; results include chain_hash for client-side
-- integrity validation.
SELECT * FROM mvp_audit_logs
WHERE timestamp >= sqlc.arg('start_time')
  AND timestamp <= sqlc.arg('end_time')
  AND (sqlc.narg('event_type')::varchar IS NULL OR event_type = sqlc.narg('event_type')::varchar)
ORDER BY timestamp DESC, id DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM mvp_audit_logs
WHERE timestamp >= sqlc.arg('start_time')
  AND timestamp <= sqlc.arg('end_time')
  AND (sqlc.narg('event_type')::varchar IS NULL OR event_type = sqlc.narg('event_type')::varchar);

-- name: ListAuditLogsForChainVerification :many
-- Ordered ascending scan (insertion order) for periodic ledger integrity
-- audits that recompute the chain from genesis (disaster-recovery §3.2).
-- Keyset pagination over (timestamp, id) keeps memory bounded.
SELECT * FROM mvp_audit_logs
WHERE (timestamp, id) > (sqlc.arg('after_timestamp'), sqlc.arg('after_id')::uuid)
ORDER BY timestamp, id
LIMIT sqlc.arg('page_limit');
