-- name: RevokeUserCredentials :exec
-- A primary-database revocation barrier precedes best-effort Redis cleanup.
-- The auth-epoch trigger also fences already-running authentication ceremonies.
UPDATE users
SET auth_version = auth_version + 1,
    updated_at = NOW()
WHERE id = $1;
