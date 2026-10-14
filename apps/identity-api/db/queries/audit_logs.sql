-- Task 2.2: MVP audit ledger queries (insert/select only).
--
-- Canonical format v2 (migration 00015) splits tamper-evidence from payload:
--
--   audit_log_chain   leaf_hash + chain_hash, append-only, never deleted
--   mvp_audit_logs    the record body, immutable but erasable
--
--   leaf_hash(N)  = SHA-256( leaf_prefix  || serialize(record(N)) )
--   chain_hash(N) = SHA-256( chain_prefix || chain_hash(N-1) || leaf_hash(N) )
--
-- Both digests are computed by the single-threaded signing consumer. The split
-- is what finally makes a Class C retention policy implementable: erasing a
-- body no longer breaks the chain.
--
-- Chain position is `seq`, allocated by the signer, never (timestamp, id):
-- timestamp is the event's occurrence time and is not monotonic in consumption
-- order. seq gaps are meaningless — rolled-back batches consume sequence values,
-- and removed nodes are detected by the chain itself, not by gap analysis.
--
-- The event UUID lives on the chain row. It is the pipeline's idempotency key,
-- and a key stored only on an erasable row would stop suppressing redeliveries
-- of events whose payload had since been erased.

-- name: InsertAuditLogWithChain :one
-- Fixture/bootstrap path: writes an audit chain node and its payload together.
-- See InsertSecurityEventWithChain for why the runtime signer does not use this.
WITH node AS (
    INSERT INTO audit_log_chain (event_id, leaf_hash, chain_hash)
    VALUES (sqlc.arg('event_id'), sqlc.arg('leaf_hash'), sqlc.arg('chain_hash'))
    RETURNING seq
)
INSERT INTO mvp_audit_logs (
    seq, user_id, actor_id, actor_spiffe_id, event_type, action_status,
    client_ip, user_agent, payload, timestamp
)
SELECT node.seq, sqlc.narg('user_id'), sqlc.arg('actor_id'),
       sqlc.arg('actor_spiffe_id'), sqlc.arg('event_type'), sqlc.arg('action_status'),
       sqlc.arg('client_ip'), sqlc.arg('user_agent'), sqlc.arg('payload'),
       sqlc.arg('timestamp')
FROM node
RETURNING seq;

-- name: GetAuditLogChainTip :one
-- Fixture helper: the highest chain node's digest, or no rows on an empty chain.
-- Runtime code reads the durable head instead (GetAuditLogHead), because an
-- empty table and an uninitialized chain are different states.
SELECT seq, chain_hash FROM audit_log_chain ORDER BY seq DESC LIMIT 1;

-- name: AllocateAuditLogSeqs :many
-- Reserves chain positions for one batch. See AllocateSecurityLedgerSeqs.
SELECT nextval('public.audit_log_chain_seq')::bigint AS seq
FROM generate_series(1, sqlc.arg('count')::int);

-- name: InsertAuditLogChain :copyfrom
-- Append-only chain nodes. Never deleted.
INSERT INTO audit_log_chain (seq, event_id, leaf_hash, chain_hash)
VALUES ($1, $2, $3, $4);

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
    seq, user_id, actor_id, actor_spiffe_id, event_type, action_status,
    client_ip, user_agent, payload, timestamp
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: FilterExistingAuditLogIDs :many
-- Deduplication probe for the signing consumer: returns the subset of candidate
-- event ids already persisted. It reads the chain table because those rows are
-- never deleted; probing the erasable payload table would stop suppressing a
-- redelivery once an event's body had been purged.
SELECT event_id FROM audit_log_chain
WHERE event_id = ANY(sqlc.arg('ids')::uuid[]);

-- name: LockAuditSubjects :many
-- Hold live subjects against deletion until COPY commits. Missing subjects are
-- intentionally absent from the result and must be inserted with a NULL user_id.
SELECT id FROM users
WHERE id = ANY(sqlc.arg('ids')::uuid[])
ORDER BY id
FOR KEY SHARE;

-- name: ListAuditLogs :many
-- DPO/Admin query (api-design §1.7): start/end time bounds are mandatory to
-- prevent unbounded DoS scans; results join the chain node so a client can
-- validate integrity itself.
SELECT l.*, c.event_id, c.leaf_hash, c.chain_hash FROM mvp_audit_logs l
JOIN public.audit_log_chain c ON c.seq = l.seq
WHERE l.timestamp >= sqlc.arg('start_time')
  AND l.timestamp <= sqlc.arg('end_time')
  AND (sqlc.narg('event_type')::varchar IS NULL OR l.event_type = sqlc.narg('event_type')::varchar)
ORDER BY l.seq DESC
LIMIT sqlc.arg('page_limit');

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM mvp_audit_logs
WHERE timestamp >= sqlc.arg('start_time')
  AND timestamp <= sqlc.arg('end_time')
  AND (sqlc.narg('event_type')::varchar IS NULL OR event_type = sqlc.narg('event_type')::varchar);

-- name: ListAuditLogChainForVerification :many
-- Ordered ascending scan over chain nodes for periodic integrity audits that
-- recompute the chain from genesis (disaster-recovery §3.2). Keyset pagination
-- over seq keeps memory bounded. Pass after_seq = 0 to start at genesis. The
-- ::bigint cast is load-bearing: without it sqlc infers a nullable parameter,
-- and a NULL after_seq would silently return zero rows — reporting an intact
-- chain for a table it never read.
--
-- A retained node returns its payload so the verifier can recompute the leaf;
-- an erased node returns a NULL payload. Class C has no purge worker yet, so
-- today payload_present is always true — the LEFT JOIN is what lets a future
-- Class C retention policy land without touching verification.
SELECT c.seq, c.event_id, c.leaf_hash, c.chain_hash,
       (l.seq IS NOT NULL)::boolean AS payload_present,
       l.user_id, l.actor_id, l.actor_spiffe_id, l.event_type, l.action_status,
       l.client_ip, l.user_agent, l.payload, l.timestamp
FROM public.audit_log_chain c
LEFT JOIN public.mvp_audit_logs l ON l.seq = c.seq
WHERE c.seq > sqlc.arg('after_seq')::bigint
  AND c.seq <= sqlc.arg('through_seq')::bigint
ORDER BY c.seq
LIMIT sqlc.arg('page_limit');

-- name: GetAuditLogHighWaterSeq :one
SELECT COALESCE(MAX(seq), 0)::bigint FROM public.audit_log_chain;

-- name: GetAuditLogChainHashBySeq :one
-- Task 5.3: seeds a *resumed* chain verification (GET /admin/audit-logs/verify
-- with after_seq > 0) by returning the predecessor digest at exactly that seq.
--
-- The equality match is load-bearing. seq gaps are legal and meaningless (see
-- the header comment): a rolled-back batch consumes sequence values without
-- leaving rows. Approximating this with "the first row at or after N" would, on
-- a gap, silently return a *later* row and hand verification the wrong
-- predecessor — reporting tampering across an intact chain. No rows means the
-- caller named a seq that does not exist, which is a bad request, not a break.
SELECT chain_hash FROM public.audit_log_chain
WHERE seq = sqlc.arg('seq')::bigint;

-- name: ListAuditLogsPage :one
-- Keyset pagination over seq, descending.
--
-- v1 used LIMIT/OFFSET plus an unrestricted COUNT(*) over the whole matching
-- set in one statement. The mandatory time bounds do not bound that: a DPO
-- legitimately asks for a year, so every page view re-counted and re-scanned
-- the full range. seq is the chain position and is monotonic in insertion
-- order, so it is a total order over the table and a correct keyset cursor —
-- unlike (timestamp, id), where occurrence time is not monotonic.
--
-- has_more replaces the exact total. A count over an append-only audit table
-- that grows without bound is not information worth an O(n) scan per page;
-- callers that need a magnitude can ask CountAuditLogs for a narrow range.
WITH page AS (
    SELECT l.*, c.event_id, c.leaf_hash, c.chain_hash
    FROM mvp_audit_logs l
    JOIN public.audit_log_chain c ON c.seq = l.seq
    WHERE l.timestamp >= sqlc.arg('start_time')
      AND l.timestamp <= sqlc.arg('end_time')
      AND (sqlc.narg('event_type')::varchar IS NULL OR l.event_type = sqlc.narg('event_type')::varchar)
      AND (sqlc.arg('before_seq')::bigint = 0 OR l.seq < sqlc.arg('before_seq')::bigint)
    ORDER BY l.seq DESC
    LIMIT sqlc.arg('page_limit')::int + 1
), bounded AS (
    SELECT * FROM page ORDER BY seq DESC LIMIT sqlc.arg('page_limit')::int
)
SELECT (SELECT COUNT(*) FROM page) > sqlc.arg('page_limit')::int AS has_more,
       COALESCE((SELECT MIN(seq) FROM bounded), 0)::bigint AS next_before_seq,
       COALESCE((SELECT jsonb_agg(jsonb_build_object(
           'id', event_id, 'user_id', user_id, 'actor_id', actor_id,
           'actor_spiffe_id', actor_spiffe_id, 'event_type', event_type,
           'action_status', action_status, 'client_ip', client_ip,
           'user_agent', user_agent, 'payload', payload, 'timestamp', timestamp,
           'sha256_leaf_hash', encode(leaf_hash, 'hex'),
           'sha256_chain_hash', encode(chain_hash, 'hex'), 'seq', seq
       ) ORDER BY seq DESC) FROM bounded), '[]'::jsonb)::jsonb AS items;
