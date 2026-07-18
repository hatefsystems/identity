-- Task 2.2: Recovery (backup) code queries.
--
-- Lifecycle per docs/data-architecture.md §1.2: codes are high-entropy
-- (>=128-bit) values hashed with SHA-256 for O(1) indexed lookups (immune to
-- offline dictionary attacks, and no Argon2id CPU-DoS vector — threat-modeling
-- D1). Verification and physical deletion run inside one ACID transaction via
-- Queries.WithTx to neutralize race-condition replay attacks.

-- name: CreateRecoveryCodes :copyfrom
-- Batch insert (pgx CopyFrom) for the freshly generated code batch during
-- MFA/WebAuthn enrollment or regeneration.
INSERT INTO recovery_codes (user_id, code_hash)
VALUES ($1, $2);

-- name: GetActiveRecoveryCodeForUpdate :one
-- O(1) match via the partial unique index idx_recovery_codes_hash, row-locked
-- (FOR UPDATE) so the subsequent physical delete in the same transaction is
-- race-free. Scoped to the authenticating user_id.
SELECT id, user_id, code_hash
FROM recovery_codes
WHERE code_hash = $1
  AND user_id = $2
  AND used_at IS NULL
FOR UPDATE;

-- name: DeleteRecoveryCodePhysically :execrows
-- Atomic transactional destruction: executed in the same transaction as
-- GetActiveRecoveryCodeForUpdate, avoiding intermediate UPDATE round-trips.
DELETE FROM recovery_codes
WHERE id = $1;

-- name: DeleteAllRecoveryCodesForUser :execrows
-- Regeneration flow (POST /api/v1/auth/recovery-codes/generate): the old batch
-- is destroyed before inserting the replacement batch, in one transaction.
DELETE FROM recovery_codes
WHERE user_id = $1;

-- name: CountActiveRecoveryCodes :one
-- Status endpoint (GET /api/v1/auth/recovery-codes/status).
SELECT COUNT(*) FROM recovery_codes
WHERE user_id = $1
  AND used_at IS NULL;
