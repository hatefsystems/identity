-- Task 2.2 (extended): Legal Hold & Security Event Ledger queries.
--
-- Backs the compliance controls in docs/compliance-and-data-governance.md
-- (§6 Legal Hold, §7 Security Event Ledger) and the admin endpoints in
-- api-design.md §1.7 (legal-holds, preservation-requests, legal-inquiry/lookup).
--
-- Canonical format v2 (migration 00015) splits tamper-evidence from payload:
--
--   security_ledger_chain    leaf_hash + chain_hash, append-only, never deleted
--   security_event_ledger    the record body, immutable but erasable
--
--   leaf_hash(N)  = SHA-256( leaf_prefix  || serialize(record(N)) )
--   chain_hash(N) = SHA-256( chain_prefix || chain_hash(N-1) || leaf_hash(N) )
--
-- So a retention purge or GDPR erasure drops a body and the chain stays
-- complete. This is a SECOND, INDEPENDENT chain from the audit log: it shares
-- the construction but not the sequence, and all four domain prefixes differ so
-- a record can never be replayed across chains or across stages.
--
-- Chain position is `seq`, allocated by the single-writer signer. The event
-- UUID lives on the chain row, not here: it is the idempotency key, and a key
-- stored only on an erasable row would stop suppressing redeliveries of events
-- whose payload has since been erased.

-- ---------------------------------------------------------------------------
-- Security Event Ledger
-- ---------------------------------------------------------------------------

-- name: InsertSecurityEventWithChain :one
-- Fixture/bootstrap path: writes a chain node and its payload together.
--
-- The runtime signer does not use this. It allocates a block of sequences and
-- COPYs both tables, because per-row inserts cannot sustain the ingest rate. But
-- a caller that needs one well-formed record — an integration fixture, or an
-- operator seeding a fresh genesis — must still write both halves atomically,
-- and the data-modifying CTE is what makes the payload reference the sequence the
-- chain node just received.
WITH node AS (
    INSERT INTO security_ledger_chain (event_id, leaf_hash, chain_hash)
    VALUES (sqlc.arg('event_id'), sqlc.arg('leaf_hash'), sqlc.arg('chain_hash'))
    RETURNING seq
)
INSERT INTO security_event_ledger (
    seq, account_ref, identity_blind_index, blind_index_version, event_type,
    client_ip, ip_subnet, user_agent, device_fingerprint, client_id, scope,
    timestamp, retain_until
)
SELECT node.seq, sqlc.arg('account_ref'), sqlc.arg('identity_blind_index'),
       sqlc.arg('blind_index_version'), sqlc.arg('event_type'),
       sqlc.arg('client_ip'), sqlc.arg('ip_subnet'), sqlc.arg('user_agent'),
       sqlc.arg('device_fingerprint'), sqlc.arg('client_id'), sqlc.arg('scope'),
       sqlc.arg('timestamp'), sqlc.arg('retain_until')
FROM node
RETURNING seq;

-- name: AllocateSecurityLedgerSeqs :many
-- Reserves chain positions for one batch.
--
-- The signer allocates explicitly rather than relying on a generated identity
-- because the :copyfrom writers cannot read back generated values, so payload
-- rows could not reference them. It is safe because the signer holds the
-- single-writer advisory lock; it also makes "seq order IS chain order" a
-- property of the writer rather than an emergent one.
SELECT nextval('public.security_ledger_chain_seq')::bigint AS seq
FROM generate_series(1, sqlc.arg('count')::int);

-- name: InsertSecurityLedgerChain :copyfrom
-- Append-only chain nodes. Never deleted, so event_id here is the permanent
-- idempotency key for the whole pipeline.
INSERT INTO security_ledger_chain (seq, event_id, leaf_hash, chain_hash)
VALUES ($1, $2, $3, $4);

-- name: InsertSecurityEvents :copyfrom
-- Batched payload writes. Timestamp is supplied explicitly so the leaf digest
-- covers the exact persisted value.
INSERT INTO security_event_ledger (
    seq, account_ref, identity_blind_index, blind_index_version, event_type,
    client_ip, ip_subnet, user_agent, device_fingerprint, client_id, scope,
    timestamp, retain_until
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);

-- name: FilterExistingSecurityEventIDs :many
-- Deduplication probe for the signing consumer. It reads the chain table, not
-- the payload table: payload rows are erasable, so probing them would stop
-- suppressing a redelivery once an event's body had been purged.
SELECT event_id FROM security_ledger_chain
WHERE event_id = ANY(sqlc.arg('ids')::uuid[]);

-- name: ListSecurityLedgerChainForVerification :many
-- Ordered ascending scan over chain nodes for the integrity audit
-- (disaster-recovery §3.2). Keyset pagination over seq keeps memory bounded;
-- pass after_seq = 0 to start at genesis. The ::bigint cast is load-bearing:
-- without it sqlc infers a nullable parameter, and a NULL after_seq would
-- silently return zero rows — reporting an intact chain for a table it never
-- read.
--
-- The LEFT JOIN is what makes erasure provable rather than merely tolerated.
-- A retained node returns its payload and the verifier recomputes the leaf; an
-- erased node returns a NULL payload plus the erasure record that authorizes it.
-- "Payload absent with no erasure record" is reported as tampering.
SELECT c.seq, c.event_id, c.leaf_hash, c.chain_hash,
       (l.seq IS NOT NULL)::boolean AS payload_present,
       l.account_ref, l.identity_blind_index, l.blind_index_version, l.event_type,
       l.client_ip, l.ip_subnet, l.user_agent, l.device_fingerprint,
       l.client_id, l.scope, l.timestamp, l.retain_until,
       e.operation_id AS erasure_operation_id
FROM public.security_ledger_chain c
LEFT JOIN public.security_event_ledger l ON l.seq = c.seq
LEFT JOIN public.security_ledger_erasures e
       ON c.seq BETWEEN e.first_seq AND e.last_seq
WHERE c.seq > sqlc.arg('after_seq')::bigint
  AND c.seq <= sqlc.arg('through_seq')::bigint
ORDER BY c.seq
LIMIT sqlc.arg('page_limit');

-- name: GetSecurityEventHighWaterSeq :one
SELECT COALESCE(MAX(seq), 0)::bigint FROM public.security_ledger_chain;

-- name: GetSecurityEventChainHashBySeq :one
-- Seeds a resumed verification (GET /admin/ledger/verify with after_seq > 0).
-- Matches seq exactly: gaps are legal, so "at or after" would return a later
-- node's digest and report a break in an intact chain.
SELECT chain_hash FROM public.security_ledger_chain
WHERE seq = sqlc.arg('seq')::bigint;

-- name: FindSecurityEventsByBlindIndex :many
-- Legacy signer smoke probe. HTTP uses the bounded query below.
SELECT l.*, c.event_id FROM security_event_ledger l
JOIN public.security_ledger_chain c ON c.seq = l.seq
WHERE l.identity_blind_index = $1
ORDER BY l.timestamp DESC, l.seq DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: LookupLegalAttribution :many
-- Each page rechecks current retention/hold eligibility. A previous cursor
-- never grants access to expired evidence after release.
SELECT sel.*, c.event_id FROM security_event_ledger sel
JOIN public.security_ledger_chain c ON c.seq = sel.seq
WHERE sel.identity_blind_index = sqlc.arg('blind_index')::text
  AND sel.timestamp >= sqlc.arg('start_time')::timestamptz
  AND sel.timestamp <= sqlc.arg('end_time')::timestamptz
  AND sel.seq > sqlc.arg('after_seq')::bigint
  AND sel.seq <= sqlc.arg('through_seq')::bigint
  AND (sel.retain_until >= sqlc.arg('as_of')::timestamptz OR EXISTS (
      SELECT 1 FROM legal_holds lh WHERE lh.account_ref = sel.account_ref AND lh.is_active
  ))
ORDER BY sel.seq
LIMIT sqlc.arg('page_limit')::int;

-- name: LegalAttributionHighWater :one
SELECT COALESCE(MAX(seq), 0)::bigint AS through_seq FROM public.security_ledger_chain;

-- name: ObserveLegalSubject :one
SELECT EXISTS (SELECT 1 FROM users WHERE id = sqlc.arg('account_ref')::uuid) AS account_present,
       EXISTS (SELECT 1 FROM security_event_ledger WHERE account_ref = sqlc.arg('account_ref')::uuid) AS ledger_evidence_present;

-- name: FindSecurityEventsByAccountRef :many
SELECT l.*, c.event_id FROM security_event_ledger l
JOIN public.security_ledger_chain c ON c.seq = l.seq
WHERE l.account_ref = $1
ORDER BY l.timestamp DESC, l.seq DESC
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

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
