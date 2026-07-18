-- Task 2.2: User lifecycle, credentials, PII contact, and GDPR queries.
--
-- Source of truth: docs/data-architecture.md §1-2 and docs/api-design.md §1.
-- Conventions:
--   * All user-facing lookups filter `deleted_at IS NULL` (soft-delete aware).
--   * Admin lookups (…ForAdmin / ListUsers) intentionally include
--     `pending_deletion` accounts so moderators can inspect them.
--   * Encrypted PII columns hold AES-GCM-256 envelope payloads (Task 2.3);
--     exact-match search goes through the SHA-256 blind index columns only —
--     wildcard/substring queries on PII are prohibited (data-architecture §2.2).
--   * Every UPDATE bumps updated_at.

-- name: CreateUser :one
INSERT INTO users (email, password_hash, status)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
-- Uses the partial unique index idx_users_email (active accounts only).
SELECT * FROM users
WHERE email = $1
  AND deleted_at IS NULL;

-- name: GetUserByIDForAdmin :one
-- Admin/reclaim path: also returns soft-deleted (pending_deletion) accounts.
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByPhoneBlindIndex :one
-- O(1) exact-match lookup via idx_users_phone_blind (data-architecture §2.2).
SELECT * FROM users
WHERE phone_blind_index = $1
  AND deleted_at IS NULL;

-- name: GetUserByBackupEmailBlindIndex :one
-- O(1) exact-match lookup via idx_users_backup_email_blind.
SELECT * FROM users
WHERE backup_email_blind_index = $1
  AND deleted_at IS NULL;

-- name: UpdateUserPassword :execrows
-- Argon2id hash computed in the application layer (Task 2.4).
UPDATE users
SET password_hash = $2,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: UpdateUserStatus :execrows
-- Admin moderation (api-design §1.7) and email-verification activation.
UPDATE users
SET status = $2,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: SetMfaTotpSecret :execrows
-- Stores the envelope-encrypted TOTP secret prior to verification/enablement.
UPDATE users
SET mfa_totp_secret_encrypted = $2,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: EnableMfa :execrows
-- Guard: MFA can only be enabled once an encrypted TOTP secret is stored.
UPDATE users
SET is_mfa_enabled = TRUE,
    updated_at = NOW()
WHERE id = $1
  AND mfa_totp_secret_encrypted IS NOT NULL
  AND deleted_at IS NULL;

-- name: DisableMfa :execrows
-- Atomically clears the flag and wipes the encrypted secret (Step-up gated
-- endpoint, api-design §1.3).
UPDATE users
SET is_mfa_enabled = FALSE,
    mfa_totp_secret_encrypted = NULL,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: SetUserPhone :execrows
-- Writes the encrypted payload and its blind index together so they can never
-- drift apart (api-design §1.5, phone verification flow).
UPDATE users
SET phone_encrypted = $2,
    phone_blind_index = $3,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: RemoveUserPhone :execrows
UPDATE users
SET phone_encrypted = NULL,
    phone_blind_index = NULL,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: SetUserBackupEmail :execrows
UPDATE users
SET backup_email_encrypted = $2,
    backup_email_blind_index = $3,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: RemoveUserBackupEmail :execrows
UPDATE users
SET backup_email_encrypted = NULL,
    backup_email_blind_index = NULL,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: SoftDeleteUser :execrows
-- "Right to be Forgotten" entry point: flips the account to pending_deletion
-- and stamps deleted_at, opening the 30-day grace window (architecture.md
-- "Grace Period & Soft Deletes"). Session/token revocation happens in Redis.
UPDATE users
SET status = 'pending_deletion',
    deleted_at = NOW(),
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL;

-- name: ReclaimUser :execrows
-- Cancels a pending deletion within the 30-day grace window after the user
-- re-authenticates with MFA/WebAuthn + Step-up (architecture.md "Account
-- Reclamation"). The cutoff (NOW() - 30 days) is computed by the caller so
-- the retention policy lives in one place in Go config.
UPDATE users
SET status = 'active',
    deleted_at = NULL,
    updated_at = NOW()
WHERE id = $1
  AND status = 'pending_deletion'
  AND deleted_at >= $2;

-- name: ListUsersDueForHardDelete :many
-- Feeds the GDPR hard-delete cron worker (Task 5.1). cutoff is
-- NOW() - INTERVAL '30 days' computed by the worker; limit bounds each batch.
SELECT id FROM users
WHERE status = 'pending_deletion'
  AND deleted_at < $1
ORDER BY deleted_at
LIMIT $2;

-- name: HardDeleteUser :execrows
-- Physical purge after the grace window. FK cascades wipe webauthn
-- credentials, recovery codes, and role assignments; mvp_audit_logs rows are
-- retained with user_id nulled (ON DELETE SET NULL). The status/cutoff guards
-- make it impossible to hard-delete an active account.
DELETE FROM users
WHERE id = $1
  AND status = 'pending_deletion'
  AND deleted_at < $2;

-- name: ListUsers :many
-- Admin pagination (api-design §1.7). Includes pending_deletion accounts.
-- Optional exact status filter; NULL disables it.
SELECT * FROM users
WHERE (sqlc.narg('status')::varchar IS NULL OR status = sqlc.narg('status')::varchar)
ORDER BY created_at DESC, id
LIMIT sqlc.arg('page_limit') OFFSET sqlc.arg('page_offset');

-- name: CountUsers :one
SELECT COUNT(*) FROM users
WHERE (sqlc.narg('status')::varchar IS NULL OR status = sqlc.narg('status')::varchar);
