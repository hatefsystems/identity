-- Ledger verification support (canonical format v2).
--
-- v1 needed ListLedgerVerificationNodes: a 55-line query that UNIONed live rows
-- with erased-span checkpoints, re-derived each span's predecessor through a
-- LATERAL subquery, and reported an `overlaps` flag, because an erased span left
-- a hole the verifier had to bridge using stored predecessor/terminal digests.
--
-- In v2 there are no holes. The chain table retains every node, so verification
-- is a straight keyset walk (ListSecurityLedgerChainForVerification in
-- legal.sql) and the only extra fact a verifier needs is whether a missing
-- payload was lawfully erased. That is one lookup.

-- name: GetLedgerVerificationHead :one
-- Read this and every node in one bounded READ ONLY REPEATABLE READ
-- transaction, separate from the admin audit action. Missing state is not
-- genesis.
SELECT h.seq, h.chain_hash,
       COALESCE((SELECT MAX(seq) FROM public.security_ledger_chain), 0)::bigint AS max_seq
FROM public.security_ledger_head h
WHERE h.singleton = true;

-- name: ListSecurityLedgerErasures :many
-- The erasure records covering a verification window, so the verifier can
-- authorize each absent payload. A node whose payload is gone and which no
-- record covers is reported as tampering, not tolerated as retention.
SELECT e.first_seq, e.last_seq, e.operation_id, e.erased_at
FROM public.security_ledger_erasures e
WHERE e.last_seq > sqlc.arg('after_seq')::bigint
  AND e.first_seq <= sqlc.arg('through_seq')::bigint
ORDER BY e.first_seq;

-- name: CountSecurityLedgerErasedNodes :one
-- Reconciliation gauge: chain nodes with no payload, and how many of those an
-- erasure record accounts for. A difference is an integrity incident.
SELECT COUNT(*)::bigint AS absent_payloads,
       COUNT(*) FILTER (WHERE EXISTS (
           SELECT 1 FROM public.security_ledger_erasures e
           WHERE c.seq BETWEEN e.first_seq AND e.last_seq))::bigint AS accounted_for
FROM public.security_ledger_chain c
WHERE NOT EXISTS (SELECT 1 FROM public.security_event_ledger l WHERE l.seq = c.seq);
