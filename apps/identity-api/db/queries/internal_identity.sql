-- name: GetInternalUserInfo :one
SELECT u.id,
       u.status,
       visible.email,
       (CASE WHEN u.status IN ('active', 'pending_verification') THEN u.display_name ELSE '' END)::text AS display_name,
       u.lifecycle_revision
FROM users u
LEFT JOIN users visible ON visible.id = u.id AND u.status IN ('active', 'pending_verification')
WHERE u.id = $1
  AND u.deleted_at IS NULL
  AND u.status <> 'pending_deletion';
