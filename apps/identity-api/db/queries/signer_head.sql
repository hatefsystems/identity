-- name: GetSignerLedgerHead :one
-- Run after the ledger coordination lock, in a separate READ COMMITTED
-- statement. Missing initialization is deliberately not converted to genesis.
WITH live_tip AS (
    SELECT seq, chain_hash FROM public.security_event_ledger
    ORDER BY seq DESC LIMIT 1
), erased_tip AS (
    SELECT first_seq, last_seq, predecessor_seq, predecessor_hash,
           terminal_hash, erased_count
    FROM public.security_ledger_checkpoints
    ORDER BY last_seq DESC LIMIT 1
)
SELECT h.seq, h.chain_hash,
       (h.seq >= 0 AND h.chain_hash ~ '^[0-9a-f]{64}$'
        AND CASE WHEN h.seq = 0 THEN
            h.chain_hash = repeat('0', 64)
            AND NOT EXISTS (SELECT 1 FROM live_tip)
            AND NOT EXISTS (SELECT 1 FROM erased_tip)
        ELSE
            NOT EXISTS (SELECT 1 FROM live_tip WHERE seq > h.seq)
            AND NOT EXISTS (SELECT 1 FROM erased_tip WHERE last_seq > h.seq)
            AND (
                (EXISTS (SELECT 1 FROM live_tip WHERE seq = h.seq AND chain_hash = h.chain_hash)
                 AND NOT EXISTS (SELECT 1 FROM erased_tip WHERE last_seq >= h.seq))
                OR
                (EXISTS (SELECT 1 FROM erased_tip
                         WHERE last_seq = h.seq AND terminal_hash = h.chain_hash
                           AND first_seq > predecessor_seq AND predecessor_seq >= 0
                           AND last_seq >= first_seq AND erased_count > 0
                           AND erased_count <= last_seq - first_seq + 1
                           AND predecessor_hash ~ '^[0-9a-f]{64}$'
                           AND (predecessor_seq <> 0 OR predecessor_hash = repeat('0', 64)))
                 AND NOT EXISTS (SELECT 1 FROM live_tip, erased_tip WHERE seq >= first_seq))
            )
        END)::boolean AS state_valid
FROM public.security_ledger_head h
WHERE h.singleton = true;

-- name: AdvanceSecurityLedgerHead :exec
-- The restricted routine finds the actual terminal sequence from its UUID and
-- validates every new chain member. Never infer a sequence from COPY row counts.
SELECT public.advance_security_ledger_head(
    sqlc.arg('expected_seq')::bigint,
    sqlc.arg('terminal_id')::uuid
);
