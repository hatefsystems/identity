-- name: InsertAdminActionOutbox :exec
INSERT INTO event_outbox (id, subject, payload, created_at, next_attempt_at, admin_action)
VALUES (sqlc.arg('id'), sqlc.arg('subject'), sqlc.arg('payload'),
        sqlc.arg('created_at'), sqlc.arg('created_at'), TRUE);

-- name: InsertAdminActionContext :exec
INSERT INTO admin_action_contexts (action_id, account_ref, details_encrypted, created_at, retain_until)
VALUES (sqlc.arg('action_id'), sqlc.narg('account_ref'), sqlc.arg('details_encrypted'),
        sqlc.arg('created_at'), sqlc.arg('retain_until'));

-- name: ClaimAdminActionOutbox :many
-- Keep the transaction/row locks until all synchronous JetStream acknowledgements
-- and delivery updates complete. Crash/rollback makes the rows claimable again.
SELECT id, payload, attempts
FROM event_outbox
WHERE subject = sqlc.arg('subject') AND admin_action AND published_at IS NULL
  AND next_attempt_at <= CURRENT_TIMESTAMP
ORDER BY next_attempt_at, created_at, id
LIMIT sqlc.arg('batch_size')
FOR UPDATE SKIP LOCKED;

-- name: MarkAdminActionPublished :execrows
UPDATE event_outbox
SET published_at = CURRENT_TIMESTAMP,
    attempts = LEAST(attempts::bigint + 1, 2147483647)::integer, last_error = NULL
WHERE id = sqlc.arg('id') AND subject = sqlc.arg('subject')
  AND admin_action AND published_at IS NULL;

-- name: RetryAdminActionOutbox :execrows
UPDATE event_outbox
SET attempts = LEAST(attempts::bigint + 1, 2147483647)::integer,
    next_attempt_at = sqlc.arg('next_attempt_at'), last_error = sqlc.arg('last_error')
WHERE id = sqlc.arg('id') AND subject = sqlc.arg('subject')
  AND admin_action AND published_at IS NULL;

-- name: AdminActionBacklog :one
SELECT COUNT(*)::bigint AS pending, MIN(created_at)::timestamptz AS oldest_at,
       COALESCE(SUM(attempts), 0)::bigint AS attempts
FROM event_outbox
WHERE subject = sqlc.arg('subject') AND admin_action AND published_at IS NULL;

-- name: ListExpiredAdminActionContexts :many
-- Candidate selection is not the concurrency guarantee. The cleanup worker takes
-- the shared account lock before a separate statement rechecks hold eligibility.
SELECT action_id, account_ref
FROM admin_action_contexts c
WHERE c.retain_until < sqlc.arg('as_of')::timestamptz
  AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.account_ref = c.account_ref AND h.is_active)
ORDER BY c.retain_until, c.action_id
LIMIT sqlc.arg('batch_size');

-- name: DeleteExpiredAdminActionContext :execrows
DELETE FROM admin_action_contexts c
WHERE c.action_id = sqlc.arg('action_id')
  AND c.retain_until < sqlc.arg('as_of')::timestamptz
  AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.account_ref = c.account_ref AND h.is_active);
