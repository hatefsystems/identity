-- name: DeleteMfaTotpEnrollmentsForUser :execrows
DELETE FROM mfa_totp_enrollments
WHERE user_id = $1;

-- name: CreateMfaTotpEnrollment :one
INSERT INTO mfa_totp_enrollments (
    user_id, session_id, purpose, secret_encrypted, expires_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetMfaTotpEnrollmentForUpdate :one
SELECT * FROM mfa_totp_enrollments
WHERE id = $1
  AND user_id = $2
  AND session_id = $3
  AND purpose = $4
FOR UPDATE;

-- name: IncrementMfaTotpEnrollmentAttempts :execrows
UPDATE mfa_totp_enrollments
SET failed_attempts = failed_attempts + 1
WHERE id = $1;

-- name: DeleteMfaTotpEnrollment :execrows
DELETE FROM mfa_totp_enrollments
WHERE id = $1;

-- name: CompleteMfaTotpEnrollment :execrows
UPDATE users
SET mfa_totp_secret_encrypted = $2,
    is_mfa_enabled = TRUE,
    updated_at = NOW()
WHERE id = $1
  AND is_mfa_enabled = FALSE
  AND deleted_at IS NULL;
