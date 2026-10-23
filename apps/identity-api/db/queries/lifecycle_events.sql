-- name: AdvanceUserLifecycleRevision :one
-- The caller holds the user row lock and commits intent in this transaction.
UPDATE users SET lifecycle_revision = lifecycle_revision + 1
WHERE id = $1 AND lifecycle_revision < 9223372036854775807
RETURNING lifecycle_revision;

-- name: InsertLifecycleEvent :exec
INSERT INTO event_outbox
    (id, subject, payload, created_at, next_attempt_at, lifecycle_user_id, lifecycle_revision)
VALUES (sqlc.arg('id'), sqlc.arg('subject'), sqlc.arg('payload'), sqlc.arg('created_at'),
        sqlc.arg('created_at'), sqlc.arg('lifecycle_user_id'), sqlc.arg('lifecycle_revision'));

-- name: ClaimLifecycleEvents :many
-- A delayed/locked/poisoned head still blocks later revisions of its account.
-- Keep row locks through acknowledgement and delivery bookkeeping commit.
SELECT o.* FROM event_outbox o
WHERE NOT o.admin_action AND o.published_at IS NULL
  AND o.subject IN ('identity.user.created', 'identity.user.updated',
                    'identity.user.suspended', 'identity.user.deleted')
  AND o.lifecycle_user_id IS NOT NULL
  AND o.next_attempt_at <= CURRENT_TIMESTAMP
  AND NOT EXISTS (
      SELECT 1 FROM event_outbox earlier
      WHERE earlier.lifecycle_user_id = o.lifecycle_user_id
        AND earlier.lifecycle_revision < o.lifecycle_revision
        AND earlier.published_at IS NULL AND NOT earlier.admin_action
  )
ORDER BY o.next_attempt_at, o.created_at, o.id
LIMIT sqlc.arg('batch_size')
FOR UPDATE OF o SKIP LOCKED;

-- name: ClaimLegacyLifecycleEvents :many
-- Legacy rows have no revision and are terminal deletions only. Invalid payloads
-- remain retryable; no casts of unvalidated JSON are performed in SQL.
SELECT * FROM event_outbox
WHERE NOT admin_action AND published_at IS NULL
  AND subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted')
  AND lifecycle_user_id IS NULL AND lifecycle_revision IS NULL
  AND next_attempt_at <= CURRENT_TIMESTAMP
ORDER BY next_attempt_at, created_at, id
LIMIT sqlc.arg('batch_size')
FOR UPDATE SKIP LOCKED;

-- name: MarkLifecyclePublished :execrows
UPDATE event_outbox
SET published_at = clock_timestamp(),
    attempts = LEAST(attempts::bigint + 1, 2147483647)::integer, last_error = NULL
WHERE id = $1 AND NOT admin_action AND published_at IS NULL
  AND subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted');

-- name: RetryLifecycleEvent :execrows
UPDATE event_outbox
SET attempts = LEAST(attempts::bigint + 1, 2147483647)::integer,
    next_attempt_at = sqlc.arg('next_attempt_at'), last_error = sqlc.arg('last_error')
WHERE id = sqlc.arg('id') AND NOT admin_action AND published_at IS NULL
  AND subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted');

-- name: LifecycleBacklog :one
SELECT COUNT(*)::bigint AS pending, MIN(created_at)::timestamptz AS oldest_at,
       COALESCE(SUM(attempts), 0)::bigint AS attempts,
       COUNT(*) FILTER (WHERE last_error = 'invalid_envelope')::bigint AS invalid
FROM event_outbox
WHERE NOT admin_action AND published_at IS NULL
  AND subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted');

-- name: ListExpiredLifecycleEvents :many
-- Exclude held candidates before LIMIT so they cannot monopolize every run.
-- The guarded JSON read supports legacy tombstones without casting invalid rows.
-- This is only a scheduling hint; deletion rechecks holds under the account lock.
SELECT o.* FROM event_outbox o
WHERE NOT o.admin_action AND o.published_at < sqlc.arg('cutoff')::timestamptz
  AND o.subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted')
  AND NOT EXISTS (
      SELECT 1 FROM legal_holds h
      WHERE h.is_active AND h.account_ref::text = COALESCE(
          o.lifecycle_user_id::text,
          CASE WHEN octet_length(o.payload) <= 16384 THEN
              CASE WHEN pg_input_is_valid(o.payload, 'jsonb') THEN o.payload::jsonb ->> 'user_id' END
          END
      )
  )
ORDER BY o.published_at, o.id
LIMIT sqlc.arg('batch_size');

-- name: GetExpiredLifecycleEventForUpdate :one
-- Caller first acquires the shared account advisory lock in a separate statement.
SELECT * FROM event_outbox
WHERE id = sqlc.arg('id') AND NOT admin_action
  AND published_at < sqlc.arg('cutoff')::timestamptz
  AND subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted')
FOR UPDATE;

-- name: DeleteExpiredLifecycleEvent :execrows
DELETE FROM event_outbox o
WHERE o.id = sqlc.arg('id') AND NOT o.admin_action
  AND o.published_at < sqlc.arg('cutoff')::timestamptz
  AND o.subject IN ('identity.user.created', 'identity.user.updated',
                  'identity.user.suspended', 'identity.user.deleted')
  AND NOT EXISTS (
      SELECT 1 FROM legal_holds h
      WHERE h.account_ref = sqlc.arg('account_ref') AND h.is_active
  );
