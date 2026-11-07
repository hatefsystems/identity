-- Separately credentialed, read-only receipt assurance. Every result is bounded;
-- neither published_at nor a broker acknowledgment establishes Class C chaining.

-- name: ListLedgerReceiptOperations :many
WITH erasures AS (
    SELECT DISTINCT operation_id AS id FROM public.security_ledger_erasures
    WHERE operation_id > sqlc.arg('after_id')::uuid
    ORDER BY id LIMIT sqlc.arg('page_limit')::integer
), pending AS (
    SELECT id FROM public.event_outbox
    WHERE id > sqlc.arg('after_id')::uuid
      AND CASE WHEN octet_length(payload) <= 8192 THEN
          CASE WHEN payload IS JSON OBJECT THEN payload::jsonb->>'event_type' END END
          IN ('legal.ledger.purged', 'legal.ledger.purge_skipped')
    ORDER BY id LIMIT sqlc.arg('page_limit')::integer
), chained AS (
    SELECT c.event_id AS id FROM public.audit_log_chain c
    JOIN public.mvp_audit_logs l ON l.seq=c.seq
    WHERE c.event_id > sqlc.arg('after_id')::uuid
      AND l.event_type IN ('legal.ledger.purged', 'legal.ledger.purge_skipped')
    ORDER BY id LIMIT sqlc.arg('page_limit')::integer
)
SELECT id FROM (
    SELECT id FROM erasures UNION SELECT id FROM pending UNION SELECT id FROM chained
) operations ORDER BY id LIMIT sqlc.arg('page_limit')::integer;

-- name: GetLedgerReceiptOutbox :one
SELECT CASE WHEN octet_length(payload::text) <= 8192 THEN payload::text ELSE '' END::text AS envelope,
       admin_action FROM public.event_outbox WHERE id=sqlc.arg('id')::uuid;

-- name: GetLedgerChainedReceipt :one
SELECT c.seq,c.event_id,c.leaf_hash,c.chain_hash,
       (l.seq IS NOT NULL)::boolean AS payload_present,
       COALESCE(octet_length(l.payload) <= 4096 AND octet_length(l.user_agent) <= 4096,false)::boolean AS body_bounded,
       l.actor_id,l.actor_spiffe_id,l.event_type,l.action_status,
       l.client_ip,CASE WHEN octet_length(l.user_agent) <= 4096 THEN l.user_agent ELSE '' END::text AS user_agent,
       CASE WHEN octet_length(l.payload) <= 4096 THEN l.payload ELSE '' END::text AS payload,l.timestamp
FROM public.audit_log_chain c
LEFT JOIN public.mvp_audit_logs l ON l.seq=c.seq
WHERE c.event_id=sqlc.arg('id')::uuid;

-- name: ListLedgerReceiptSpans :many
SELECT first_seq,last_seq,erased_at FROM public.security_ledger_erasures
WHERE operation_id=sqlc.arg('id')::uuid
ORDER BY first_seq LIMIT 5001;

-- name: ListLedgerReceiptProofNodes :many
-- Receipt assurance checks Class C linkage, then only the correlated receipt
-- leaves. Do not read unrelated narrative bodies into this maintenance snapshot.
SELECT seq,leaf_hash,chain_hash FROM public.audit_log_chain
WHERE seq > sqlc.arg('after_seq')::bigint AND seq <= sqlc.arg('through_seq')::bigint
ORDER BY seq LIMIT sqlc.arg('page_limit')::integer;
