-- Minimal query surface for Task 2.1 so `sqlc generate`/`vet` compile against
-- the real schema in db/migrations/00001_initial_schema.sql.
--
-- The full transactional query set (recovery-code atomic lookup/deletion, RBAC,
-- WebAuthn credentials, audit log inserts, ...) is delivered in Task 2.2.

-- name: GetUserByID :one
SELECT id,
       email,
       password_hash,
       is_mfa_enabled,
       status,
       created_at,
       updated_at,
       deleted_at
FROM users
WHERE id = $1
  AND deleted_at IS NULL;
