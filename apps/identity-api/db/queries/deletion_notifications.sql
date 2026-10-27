-- Notification writes take the shared subject advisory lock, read one minimal
-- authority snapshot, then lock the delivery row. They never write user/request
-- authority and must not require UPDATE privileges on those tables.
-- No addresses, plaintext tokens, SMTP responses, or recovery URLs belong here.

-- name: GetDeletionNotificationState :one
SELECT u.id AS user_id, u.status AS user_status, u.auth_version AS user_auth_version,
       u.deleted_at AS user_deleted_at, r.id AS request_id, r.token_hash,
       r.expires_at, r.consumed_at, r.failed_attempts, r.requested_auth_version
FROM users u JOIN deletion_requests r ON r.user_id = u.id
WHERE u.id = sqlc.arg('user_id') AND r.id = sqlc.arg('request_id');

-- name: CreateDeletionNotification :execrows
INSERT INTO deletion_notifications (id, user_id, request_id, recipient_role, payload_encrypted, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (request_id, recipient_role) DO NOTHING;

-- name: ListDueDeletionNotifications :many
-- This is only a candidate list; the transaction rechecks the exact live request.
-- Invalid held payloads must not occupy the head of the delivery backlog.
SELECT n.id, n.user_id, n.request_id FROM deletion_notifications n
JOIN deletion_requests r ON r.id = n.request_id AND r.user_id = n.user_id
JOIN users u ON u.id = n.user_id
WHERE n.accepted_at IS NULL AND n.failed_at IS NULL AND n.payload_encrypted IS NOT NULL
  AND n.expires_at > clock_timestamp() AND n.expires_at = r.expires_at
  AND r.consumed_at IS NULL AND r.failed_attempts < sqlc.arg('max_attempts')::integer
  AND u.status = 'pending_deletion' AND u.deleted_at IS NOT NULL
  AND r.expires_at = u.deleted_at + sqlc.arg('grace_period')::interval
  AND (r.requested_auth_version IS NULL OR u.auth_version = r.requested_auth_version + 1)
  AND n.next_attempt_at <= clock_timestamp()
  AND (n.lease_until IS NULL OR n.lease_until <= clock_timestamp())
ORDER BY n.next_attempt_at, n.id
LIMIT sqlc.arg('batch_size');

-- name: ClaimDeletionNotification :one
UPDATE deletion_notifications
SET lease_token = sqlc.arg('lease_token'),
    lease_until = sqlc.arg('lease_until'),
    attempts = attempts + 1
WHERE id = sqlc.arg('id') AND request_id = sqlc.arg('request_id')
  AND accepted_at IS NULL AND failed_at IS NULL AND payload_encrypted IS NOT NULL
  AND expires_at > clock_timestamp()
  AND next_attempt_at <= clock_timestamp()
  AND (lease_until IS NULL OR lease_until <= clock_timestamp())
RETURNING *;

-- name: GetDeletionNotificationForUpdate :one
SELECT * FROM deletion_notifications WHERE id = $1 FOR UPDATE;

-- name: AcceptDeletionNotification :execrows
UPDATE deletion_notifications
SET accepted_at = clock_timestamp(), lease_token = NULL, lease_until = NULL, last_error_code = NULL
WHERE id = $1 AND request_id = $2 AND lease_token = $3
  AND lease_until > clock_timestamp()
  AND accepted_at IS NULL AND failed_at IS NULL AND expires_at > clock_timestamp();

-- name: RetryDeletionNotification :execrows
UPDATE deletion_notifications
SET next_attempt_at = $4, last_error_code = $5, lease_token = NULL, lease_until = NULL
WHERE id = $1 AND request_id = $2 AND lease_token = $3
  AND lease_until > clock_timestamp()
  AND accepted_at IS NULL AND failed_at IS NULL AND expires_at > clock_timestamp();

-- name: FailDeletionNotification :execrows
UPDATE deletion_notifications
SET failed_at = clock_timestamp(), last_error_code = $4, lease_token = NULL, lease_until = NULL
WHERE id = $1 AND request_id = $2 AND lease_token = $3
  AND lease_until > clock_timestamp()
  AND accepted_at IS NULL AND failed_at IS NULL;

-- name: ListDeletionNotificationsForCleanup :many
SELECT n.id, n.user_id, n.request_id
FROM deletion_notifications n
JOIN deletion_requests r ON r.id = n.request_id
JOIN users u ON u.id = n.user_id
WHERE n.payload_encrypted IS NOT NULL
  AND (n.accepted_at IS NOT NULL OR n.expires_at <= clock_timestamp()
       OR r.consumed_at IS NOT NULL OR r.expires_at <= clock_timestamp()
       OR r.failed_attempts >= sqlc.arg('max_attempts')::integer
       OR u.status <> 'pending_deletion' OR u.deleted_at IS NULL
       OR r.user_id <> n.user_id
       OR (r.requested_auth_version IS NOT NULL AND u.auth_version <> r.requested_auth_version + 1)
       OR n.expires_at <> r.expires_at
       OR r.expires_at <> u.deleted_at + sqlc.arg('grace_period')::interval)
-- Do not let held rows at the front starve the eligible cleanup backlog.
ORDER BY EXISTS (SELECT 1 FROM legal_holds h WHERE h.account_ref = n.user_id AND h.is_active),
         n.created_at, n.id
LIMIT sqlc.arg('batch_size');

-- name: ClearDeletionNotificationPayload :execrows
-- Caller has locked the subject and checked holds in a separate fresh statement.
-- Retire invalid work even if its ciphertext was held until this pass.
UPDATE deletion_notifications
SET payload_encrypted = NULL, lease_token = NULL, lease_until = NULL,
    failed_at = CASE WHEN accepted_at IS NULL THEN COALESCE(failed_at, clock_timestamp()) ELSE failed_at END,
    last_error_code = CASE WHEN accepted_at IS NULL THEN COALESCE(last_error_code, 'request_invalid') ELSE last_error_code END
WHERE id = $1 AND request_id = $2 AND payload_encrypted IS NOT NULL;
