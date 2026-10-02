-- name: GetLedgerVerificationHead :one
-- Missing state is not genesis. Read this and every proof node in one bounded
-- READ ONLY REPEATABLE READ transaction, separate from the admin audit action.
SELECT h.seq, h.chain_hash,
       GREATEST(COALESCE((SELECT seq FROM public.security_event_ledger ORDER BY seq DESC LIMIT 1), 0),
                COALESCE((SELECT last_seq FROM public.security_ledger_checkpoints ORDER BY last_seq DESC LIMIT 1), 0))::bigint AS max_seq
FROM public.security_ledger_head h WHERE h.singleton = true;

-- name: ListLedgerVerificationNodes :many
-- Each branch is bounded before UNION, so checkpoints consume the same page
-- budget as live records. Boundary mode also returns covering spans: no digest
-- may be approximated at an interior position erased by checkpoint compaction.
WITH live AS (
    SELECT false AS erased, l.seq AS first_seq, l.seq AS last_seq,
           0::bigint AS predecessor_seq, ''::text AS predecessor_hash,
           l.chain_hash::text AS terminal_hash, 0::bigint AS erased_count
    FROM public.security_event_ledger l
    WHERE (sqlc.arg('boundary_only')::boolean AND l.seq = sqlc.arg('after_seq')::bigint)
       OR (NOT sqlc.arg('boundary_only')::boolean AND l.seq > sqlc.arg('after_seq')::bigint
           AND l.seq <= sqlc.arg('through_seq')::bigint)
    ORDER BY l.seq LIMIT sqlc.arg('node_limit')::int
), erased AS (
    SELECT true AS erased, c.first_seq, c.last_seq, c.predecessor_seq,
           c.predecessor_hash, c.terminal_hash, c.erased_count
    FROM public.security_ledger_checkpoints c
    WHERE (sqlc.arg('boundary_only')::boolean AND
           (c.predecessor_seq = sqlc.arg('after_seq')::bigint OR
            (c.first_seq <= sqlc.arg('after_seq')::bigint AND c.last_seq >= sqlc.arg('after_seq')::bigint)))
       OR (NOT sqlc.arg('boundary_only')::boolean AND c.last_seq > sqlc.arg('after_seq')::bigint
           AND c.first_seq <= sqlc.arg('through_seq')::bigint)
    ORDER BY c.first_seq LIMIT sqlc.arg('node_limit')::int
), nodes AS (
    SELECT * FROM live UNION ALL SELECT * FROM erased
), page AS (
    SELECT * FROM nodes ORDER BY first_seq, erased LIMIT sqlc.arg('node_limit')::int
)
SELECT p.erased, p.first_seq, p.last_seq, p.predecessor_seq,
       p.predecessor_hash, p.terminal_hash, p.erased_count,
       COALESCE(to_jsonb(l), 'null'::jsonb)::jsonb AS live_record,
       (EXISTS (SELECT 1 FROM public.security_ledger_checkpoints c
                WHERE c.first_seq <= p.last_seq AND c.last_seq >= p.first_seq
                  AND (NOT p.erased OR c.first_seq <> p.first_seq))
        OR (p.erased AND EXISTS (SELECT 1 FROM public.security_event_ledger x
                                WHERE x.seq >= p.first_seq AND x.seq <= p.last_seq)))::boolean AS overlaps,
       (NOT p.erased OR
        (p.predecessor_seq = COALESCE(prior.seq, 0) AND
         p.predecessor_hash = COALESCE(prior.chain_hash, repeat('0', 64))))::boolean AS predecessor_matches
FROM page p
LEFT JOIN public.security_event_ledger l ON NOT p.erased AND l.seq = p.first_seq
LEFT JOIN LATERAL (
    SELECT candidates.seq, candidates.chain_hash FROM (
        (SELECT x.seq, x.chain_hash::text AS chain_hash FROM public.security_event_ledger x
         WHERE p.erased AND x.seq < p.first_seq ORDER BY x.seq DESC LIMIT 1)
        UNION ALL
        (SELECT c.last_seq AS seq, c.terminal_hash AS chain_hash FROM public.security_ledger_checkpoints c
         WHERE p.erased AND c.last_seq < p.first_seq ORDER BY c.last_seq DESC LIMIT 1)
    ) candidates ORDER BY candidates.seq DESC LIMIT 1
) prior ON p.erased
ORDER BY p.first_seq, p.erased;
