-- name: GetInternalUserInfo :one
SELECT id,
       status,
       (CASE WHEN status IN ('active', 'pending_verification') THEN email ELSE '' END)::text AS email,
       (CASE WHEN status IN ('active', 'pending_verification') THEN display_name ELSE '' END)::text AS display_name,
       lifecycle_revision
FROM users
WHERE id = $1
  AND deleted_at IS NULL
  AND status <> 'pending_deletion';
