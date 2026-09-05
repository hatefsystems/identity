-- Task 2.2: MVP audit ledger queries (insert/select only).
--
-- mvp_audit_logs is append-only — a DB trigger rejects UPDATE/DELETE/TRUNCATE
-- (architecture.md "Append-Only Log Management"), so no mutating queries are
-- defined here by design. Rows are chained via
--   chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N)))
-- computed by the single-threaded signing consumer (Task 5.2).
--
-- Chain position is `seq` (migration 00006), never (timestamp, id): timestamp is
-- the event's occurrence time and is not monotonic in consumption order.
-- seq gaps are meaningless — rolled-back batches consume sequence values, and
-- removed rows are detected by the chain itself, not by gap analysis.

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
--
-- `id` is supplied explicitly too: it is the publisher-assigned event id carried
-- on the JetStream message (and its Nats-Msg-Id). Because JetStream is
-- at-least-once and these rows can never be updated or deleted, the consumer
-- filters ids that are already present (FilterExistingAuditLogIDs) before
-- copying, which makes a redelivery after commit-but-before-ack a no-op instead
-- of a permanent duplicate.
INSERT INTO mvp_audit_logs (
    id, user_id, actor_id, actor_spiffe_id, event_type, action_status,
    client_ip, user_agent, payload, timestamp, chain_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetLatestAuditLogChainHash :one
-- Seeds the next chain computation; returns no rows before the genesis record
-- (callers treat pgx.ErrNoRows as "start of chain").
SELECT chain_hash FROM mvp_audit_logs
ORDER BY seq DESC
LIMIT 1;

-- name: FilterExistingAuditLogIDs :many
-- Deduplication probe for the signing consumer: returns the subset of candidate
-- event ids already persisted, so a redelivered JetStream message is skipped
-- rather than appended a second time to an append-only table.
SELECT id FROM mvp_audit_logs
WHERE id = ANY(sqlc.arg('ids')::uuid[]);

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
-- Keyset pagination over seq keeps memory bounded. Pass after_seq = 0 to start
-- at genesis. The ::bigint cast is load-bearing: without it sqlc infers a
-- nullable parameter, and a NULL after_seq would silently return zero rows —
-- reporting an intact chain for a table it never read.
SELECT * FROM mvp_audit_logs
WHERE seq > sqlc.arg('after_seq')::bigint
ORDER BY seq
LIMIT sqlc.arg('page_limit');
