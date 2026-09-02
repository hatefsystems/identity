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
--   * Only the SHA-256 hash of the reclaim token is ever stored.

-- ---------------------------------------------------------------------------
-- Deletion Requests
-- ---------------------------------------------------------------------------

-- name: CreateDeletionRequest :one
INSERT INTO deletion_requests (user_id, token_hash, requested_ip, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetActiveDeletionRequestByTokenHashForUpdate :one
-- Join-free lookup by token hash for the anonymous reclaim endpoint, row-locked so
-- the verify-then-consume sequence cannot be raced by two concurrent submissions
-- of the same token.
SELECT * FROM deletion_requests
WHERE token_hash = $1
  AND consumed_at IS NULL
  AND expires_at > NOW()
FOR UPDATE;

-- name: GetActiveDeletionRequestForUser :one
-- Feeds the idempotency and resend-cooldown decision on a repeated
-- DELETE /api/v1/users/me: an account already in pending_deletion must not be
-- soft-deleted twice, and its notice must not be re-sent inside the cooldown.
SELECT * FROM deletion_requests
WHERE user_id = $1
  AND consumed_at IS NULL
  AND expires_at > NOW()
ORDER BY created_at DESC, id
LIMIT 1;

-- name: IncrementDeletionRequestFailedAttempts :execrows
-- A wrong factor increments the counter but must NOT consume the token: consuming
-- it would destroy the account's only recovery path, the opposite trade-off from
-- the single-use recovery-code transaction. The attempt cap is what bounds abuse.
UPDATE deletion_requests
SET failed_attempts = failed_attempts + 1
WHERE id = $1
  AND consumed_at IS NULL;

-- name: MarkDeletionRequestNotified :execrows
-- Stamped only after the notifier accepted the message, so the resend cooldown
-- measures time since a *delivered* notice rather than since the request row.
UPDATE deletion_requests
SET notified_at = NOW()
WHERE id = $1;

-- name: ConsumeDeletionRequest :execrows
-- Single-use retirement of one request: reclaim success, or the failed-attempt cap.
UPDATE deletion_requests
SET consumed_at = NOW()
WHERE id = $1
  AND consumed_at IS NULL;

-- name: ExpireDeletionRequestsForUser :execrows
-- Invalidates every outstanding request for the account. Used on reclaim success
-- (nothing may reclaim an already-reclaimed account) and before minting a
-- replacement token on resend (so only the newest token is ever live).
UPDATE deletion_requests
SET consumed_at = NOW()
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
