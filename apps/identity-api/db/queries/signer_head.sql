-- Durable chain heads for both ledgers (canonical format v2).
--
-- The head is the independently readable logical tip. It exists so the signer
-- never infers "where the chain ends" from surviving payload rows: under v1 an
-- erased span could make the last *payload* row look like the tip, which is
-- precisely how a purge could have been turned into a silent chain fork.
--
-- In v2 the chain table is never deleted, so its own MAX(seq) is already
-- authoritative. The head is retained anyway because it is the one value an
-- operator can compare against an out-of-band record, and because the
-- advancement routine is where per-batch linkage is verified.

-- name: GetSecurityLedgerHead :one
-- Read after taking the coordination lock, in a separate READ COMMITTED
-- statement. Missing initialization is deliberately NOT converted to genesis:
-- an uninitialized head and a genuinely empty chain are different states, and
-- treating the first as the second is how a signer restarts at genesis over an
-- existing chain.
SELECT h.seq, h.chain_hash,
       (h.seq >= 0 AND octet_length(h.chain_hash) = 32
        AND NOT EXISTS (SELECT 1 FROM public.security_ledger_chain c WHERE c.seq > h.seq)
        AND CASE WHEN h.seq = 0
            THEN NOT EXISTS (SELECT 1 FROM public.security_ledger_chain)
            ELSE EXISTS (SELECT 1 FROM public.security_ledger_chain c
                         WHERE c.seq = h.seq AND c.chain_hash = h.chain_hash)
        END)::boolean AS state_valid
FROM public.security_ledger_head h
WHERE h.singleton = true;

-- name: GetAuditLogHead :one
SELECT h.seq, h.chain_hash,
       (h.seq >= 0 AND octet_length(h.chain_hash) = 32
        AND NOT EXISTS (SELECT 1 FROM public.audit_log_chain c WHERE c.seq > h.seq)
        AND CASE WHEN h.seq = 0
            THEN NOT EXISTS (SELECT 1 FROM public.audit_log_chain)
            ELSE EXISTS (SELECT 1 FROM public.audit_log_chain c
                         WHERE c.seq = h.seq AND c.chain_hash = h.chain_hash)
        END)::boolean AS state_valid
FROM public.audit_log_head h
WHERE h.singleton = true;

-- name: AdvanceChainHead :exec
-- Verifies linkage across the declared span and moves the head forward.
--
-- The span is passed explicitly instead of being inferred. v1 identified the
-- batch by comparing each row's xmin against the current transaction id as
-- text, which breaks silently the moment the COPY is wrapped in a savepoint or
-- a plpgsql EXCEPTION block, because a subtransaction's xid is not the
-- top-level one.
SELECT public.advance_chain_head(
    sqlc.arg('which')::text,
    sqlc.arg('expected_seq')::bigint,
    sqlc.arg('first_seq')::bigint,
    sqlc.arg('last_seq')::bigint,
    sqlc.arg('node_count')::bigint
);
