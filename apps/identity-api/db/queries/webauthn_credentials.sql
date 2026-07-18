-- Task 2.2: WebAuthn/FIDO2 credential queries.
--
-- Backs registration/login verification and device management (api-design
-- §1.3, architecture.md "Phishing-Resistant WebAuthn / FIDO2"). Credential IDs
-- are raw binary (BYTEA); public keys are stored in COSE format.

-- name: CreateWebauthnCredential :one
INSERT INTO webauthn_credentials (
    id, user_id, public_key, attestation_type, sign_count,
    user_present, user_verified, backup_eligible, backup_state, aaguid
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetWebauthnCredential :one
SELECT * FROM webauthn_credentials
WHERE id = $1;

-- name: GetWebauthnCredentialForUpdate :one
-- Row-locked read during login assertion verification so the sign_count
-- check-then-update is race-free across concurrent logins.
SELECT * FROM webauthn_credentials
WHERE id = $1
FOR UPDATE;

-- name: ListWebauthnCredentialsByUser :many
-- Device management UI (GET /api/v1/auth/webauthn/keys).
SELECT * FROM webauthn_credentials
WHERE user_id = $1
ORDER BY created_at;

-- name: CountWebauthnCredentialsByUser :one
-- Guards flows like "don't allow removing the last passkey on a
-- passwordless-only account".
SELECT COUNT(*) FROM webauthn_credentials
WHERE user_id = $1;

-- name: UpdateWebauthnSignCount :execrows
-- Clone detection (architecture.md "Signature Counter Auditing"): the caller
-- verifies incoming SignCount > stored value under the FOR UPDATE lock, then
-- persists it and stamps last_used_at in the same transaction.
UPDATE webauthn_credentials
SET sign_count = $2,
    last_used_at = NOW()
WHERE id = $1;

-- name: DeleteWebauthnCredential :execrows
-- Step-up gated (DELETE /api/v1/auth/webauthn/keys/{id}). Scoped to user_id
-- so one user can never remove another user's authenticator.
DELETE FROM webauthn_credentials
WHERE id = $1
  AND user_id = $2;
