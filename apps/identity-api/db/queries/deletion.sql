-- Task 5.1: GDPR deletion-request (reclaim ceremony) and transactional outbox
-- queries.
--
-- Source of truth: docs/compliance-and-data-governance.md §4/§5,
-- docs/architecture.md ("Grace Period & Soft Deletes", "Account Reclamation"),
-- docs/api-design.md §1.4.
--
-- Conventions:
--   * A deletion request is "active" while consumed_at IS NULL AND expires_at >
--     NOW(). Every failure mode (unknown token, expired, consumed) is therefore a
--     single no-rows result, which is what lets the service collapse them into one
--     opaque error with no oracle.
--   * expires_at is always deleted_at + grace period, computed by the caller, so
--     the reclaim token and the purge cutoff can never disagree.
--   * This table holds only the token hash. The dedicated Class A notification
--     outbox holds envelope-encrypted per-recipient delivery material.

-- ---------------------------------------------------------------------------
-- Deletion Requests
-- ---------------------------------------------------------------------------

-- name: CreateDeletionRequest :one
INSERT INTO deletion_requests (user_id, token_hash, requested_ip, expires_at, requested_auth_version)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveDeletionRequestByTokenHashForUpdate :one
-- Preliminary lookup only. The final commit locks the user, then the exact
-- request by ID and validates it again after all lock waits.
SELECT * FROM deletion_requests
WHERE token_hash = $1
  AND consumed_at IS NULL
  AND expires_at > clock_timestamp()
FOR UPDATE;

-- name: GetDeletionRequestForUpdate :one
-- Always acquire the subject/user locks before this child lock.
SELECT * FROM deletion_requests WHERE id = $1 FOR UPDATE;

-- name: GetActiveDeletionRequestForUser :one
-- Concurrent admitted DELETEs coalesce without rotating the token or queue.
SELECT * FROM deletion_requests
WHERE user_id = $1
  AND consumed_at IS NULL
  AND expires_at > clock_timestamp()
ORDER BY created_at DESC, id
LIMIT 1;

-- name: RecordDeletionRequestFailure :one
-- Increment and retirement are indivisible. RETURNING is the only authoritative
-- attempt count for audit; never derive it from the pre-verification snapshot.
UPDATE deletion_requests
SET failed_attempts = failed_attempts + 1,
    consumed_at = CASE WHEN failed_attempts + 1 >= sqlc.arg('max_attempts')::integer
        THEN clock_timestamp() ELSE consumed_at END
WHERE id = sqlc.arg('id')
  AND user_id = sqlc.arg('user_id')
  AND token_hash = sqlc.arg('token_hash')
  AND consumed_at IS NULL
  AND expires_at > clock_timestamp()
  AND failed_attempts < sqlc.arg('max_attempts')::integer
RETURNING *;

-- name: MarkDeletionRequestNotified :execrows
-- Compatibility bookkeeping for legacy readers. Per-recipient acceptance is
-- authoritative in deletion_notifications; this is not proof of inbox delivery.
UPDATE deletion_requests
SET notified_at = NOW()
WHERE id = $1;

-- name: ConsumeDeletionRequest :execrows
-- Single-use retirement of one request: reclaim success, or the failed-attempt cap.
UPDATE deletion_requests
SET consumed_at = clock_timestamp()
WHERE id = $1
  AND consumed_at IS NULL;

-- name: ExpireDeletionRequestsForUser :execrows
-- Invalidates every outstanding request for the account. Used on reclaim success
-- (nothing may reclaim an already-reclaimed account) and before minting a
-- replacement token on resend (so only the newest token is ever live).
UPDATE deletion_requests
SET consumed_at = clock_timestamp()
WHERE user_id = $1
  AND consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- Transactional Outbox
-- ---------------------------------------------------------------------------

-- name: EnqueueOutboxEvent :one
-- Written in the SAME transaction as the hard DELETE. If the delete affects zero
-- rows the whole transaction rolls back, so an event can never describe a subject
-- that still exists, and a purged subject can never lack its event.
INSERT INTO event_outbox (subject, payload)
VALUES ($1, $2)
RETURNING *;
