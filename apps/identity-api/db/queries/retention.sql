-- name: CaptureSecurityLedgerRetentionBoundary :one
SELECT statement_timestamp()::timestamptz AS cutoff, h.seq AS highwater
FROM public.security_ledger_head h WHERE h.singleton;

-- name: ListSecurityLedgerRetentionCandidates :many
-- Held accounts are prefiltered for fairness, then independently checked after
-- account locks by the maintenance function. No OFFSET over a shrinking table.
SELECT l.* FROM public.security_event_ledger l
WHERE l.retain_until < sqlc.arg('cutoff')::timestamptz
  AND l.seq <= sqlc.arg('highwater')::bigint
  AND (l.retain_until, l.seq) > (sqlc.arg('after_retain_until')::timestamptz, sqlc.arg('after_seq')::bigint)
  AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = l.account_ref AND h.is_active)
ORDER BY l.retain_until, l.seq
LIMIT LEAST(GREATEST(sqlc.arg('page_limit')::integer, 1), 5000);

-- name: PurgeExpiredSecurityEvents :one
-- The only production erasure surface: a bounded, independently validated
-- maintenance call. Transaction rollback is the full-fidelity dry-run path.
SELECT deleted_count::bigint, held_count::bigint
FROM public.purge_security_ledger_batch(
    sqlc.arg('cutoff')::timestamptz, sqlc.arg('highwater')::bigint,
    sqlc.arg('seqs')::bigint[], sqlc.arg('expected_hashes')::text[],
    sqlc.arg('canonical_bodies')::bytea[], sqlc.arg('operation_id')::uuid,
    sqlc.arg('audit_subject')::text);
