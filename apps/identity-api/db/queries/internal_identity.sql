-- name: GetInternalUserInfo :one
SELECT id,
       status,
       (CASE WHEN status IN ('active', 'pending_verification') THEN email ELSE '' END)::text AS email
FROM users
WHERE id = $1
  AND deleted_at IS NULL
  AND status <> 'pending_deletion';
