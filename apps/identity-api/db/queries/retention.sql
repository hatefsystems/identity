-- Security Event Ledger retention (Task 5.4) under canonical format v2.
--
-- v1 routed every erasure through purge_security_ledger_batch, a SECURITY
-- DEFINER routine that had to re-derive each row's canonical body in PL/pgSQL,
-- re-verify its digest, validate the digests of neighbouring erased spans, and
-- then compact those spans — all because removing a row removed a chain link.
--
-- v2 deletes a payload row and nothing else. The chain node, including its leaf
-- digest, stays. So this is an ordinary bounded DELETE executed by a dedicated
-- role that holds DELETE on the payload table and on nothing else, plus an
-- append-only erasure record and a chained receipt. No SECURITY DEFINER, no
-- trigger exemption, no second serializer.

-- name: CaptureSecurityLedgerRetentionBoundary :one
-- Freezes the cutoff and the high-water mark for one run, so a concurrently
-- appended event can never fall inside this run's eligible range.
SELECT statement_timestamp()::timestamptz AS cutoff,
       COALESCE((SELECT MAX(seq) FROM public.security_ledger_chain), 0)::bigint AS highwater;

-- name: ListSecurityLedgerRetentionCandidates :many
-- Held accounts are prefiltered for fairness, then independently rechecked
-- after the account locks are taken. Keyset paging over (retain_until, seq)
-- rather than OFFSET, because the table shrinks underneath the scan.
SELECT l.seq, l.account_ref, l.retain_until
FROM public.security_event_ledger l
WHERE l.retain_until < sqlc.arg('cutoff')::timestamptz
  AND l.seq <= sqlc.arg('highwater')::bigint
  AND (l.retain_until, l.seq) > (sqlc.arg('after_retain_until')::timestamptz, sqlc.arg('after_seq')::bigint)
  AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = l.account_ref AND h.is_active)
ORDER BY l.retain_until, l.seq
LIMIT LEAST(GREATEST(sqlc.arg('page_limit')::integer, 1), 5000);

-- name: RecheckSecurityLedgerPurgeCandidates :many
-- Re-reads eligibility after the account advisory locks are held. The candidate
-- listing above is not the concurrency guarantee: it runs before those locks, so
-- every decision it informed is rechecked here.
--
-- There is deliberately no FOR UPDATE. Every row-lock strength PostgreSQL offers
-- requires UPDATE privilege on the table, and granting UPDATE to the purge role
-- would hand it the one capability payload immutability exists to deny. The lock
-- is not needed either: DeleteExpiredSecurityEvents restates every predicate, so
-- eligibility is decided atomically at erasure time, and this read only has to be
-- fresh — which the preceding account locks guarantee.
SELECT l.seq, l.account_ref,
       (l.retain_until < sqlc.arg('cutoff')::timestamptz) AS expired,
       EXISTS (SELECT 1 FROM public.legal_holds h
               WHERE h.account_ref = l.account_ref AND h.is_active) AS held
FROM public.security_event_ledger l
WHERE l.seq = ANY(sqlc.arg('seqs')::bigint[])
ORDER BY l.seq;

-- name: DeleteExpiredSecurityEvents :execrows
-- The only erasure surface. Every predicate is restated here rather than
-- trusted from the listing: an active hold outranks every retention timer, so
-- "expired when we looked" must not be enough to delete.
DELETE FROM public.security_event_ledger l
WHERE l.seq = ANY(sqlc.arg('seqs')::bigint[])
  AND l.retain_until < sqlc.arg('cutoff')::timestamptz
  AND l.seq <= sqlc.arg('highwater')::bigint
  AND NOT EXISTS (SELECT 1 FROM public.legal_holds h
                  WHERE h.account_ref = l.account_ref AND h.is_active);

-- name: RecordSecurityLedgerErasure :exec
-- Append-only annotation making a lawful erasure distinguishable from a
-- deletion. Written in the same transaction as the DELETE; its authority comes
-- from the chained receipt carrying the same operation_id.
INSERT INTO public.security_ledger_erasures (first_seq, last_seq, operation_id, erased_at)
VALUES (sqlc.arg('first_seq'), sqlc.arg('last_seq'), sqlc.arg('operation_id'), sqlc.arg('erased_at'));

-- name: GetSecurityLedgerRetentionSubject :one
-- The receipt subject must be provisioned by an operator; an unprovisioned
-- subject fails the run rather than defaulting to something publishable.
SELECT s.audit_subject FROM public.security_ledger_retention_settings s
WHERE s.singleton;

-- name: CountUnerasedExpiredSecurityEvents :one
-- Backlog gauge for alerting: expired payloads still present and not held.
SELECT COUNT(*)::bigint AS pending,
       COALESCE(MIN(l.retain_until), sqlc.arg('cutoff')::timestamptz)::timestamptz AS oldest_retain_until
FROM public.security_event_ledger l
WHERE l.retain_until < sqlc.arg('cutoff')::timestamptz
  AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = l.account_ref AND h.is_active);
