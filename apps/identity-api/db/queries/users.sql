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

-- name: SetWebauthnUserHandle :execrows
-- Task 4.2: Persists the CSPRNG-generated random 64-bit WebAuthn user handle
-- on first passkey registration (api-design.md §1.3). The handle is the stable
-- WebAuthn user.id (never the UUID PK) used to prevent identity correlation and
-- to map discoverable-credential logins (Task 4.3) back to the account. Only
-- sets it when currently NULL so the handle can never silently change.
UPDATE users
SET webauthn_user_handle = $2,
    updated_at = NOW()
WHERE id = $1
  AND webauthn_user_handle IS NULL
  AND deleted_at IS NULL;

-- name: GetUserByWebauthnUserHandle :one
-- Discoverable-credential login (Task 4.3) maps an authenticator's returned
-- userHandle back to the account via the unique idx_users_webauthn_handle.
SELECT * FROM users
WHERE webauthn_user_handle = $1
  AND deleted_at IS NULL;


-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1
  AND deleted_at IS NULL;

-- name: GetAccountAuthState :one
SELECT status, deleted_at, auth_version, auth_epoch FROM users WHERE id = $1;

-- name: GetAccountAuthStateForUpdate :one
SELECT status, deleted_at, auth_version, auth_epoch FROM users WHERE id = $1 FOR UPDATE;

-- name: NextAccountAuthEpoch :one
SELECT nextval('account_auth_epoch_seq')::bigint AS epoch;

-- name: ModerateUserStatus :one
-- Caller holds actor/target account locks and has checked live permission and
-- privileged-role protection. Every accepted action invalidates prior state.
UPDATE users SET status = $2, auth_version = auth_version + 1, updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL AND status IN ('active', 'suspended', 'banned')
RETURNING *;

-- name: GetUserByIDForUpdate :one
-- Stable per-account mutex for security-sensitive mutations that span child
-- tables. Permanent lock order is users first, then WebAuthn credentials ordered
-- by id, then recovery/enrollment rows. This serializes regeneration and
-- cross-factor teardown even when no child row exists yet.
SELECT * FROM users
WHERE id = $1
  AND deleted_at IS NULL
FOR UPDATE;

-- name: GetUserByEmail :one
-- Uses the partial unique index idx_users_email (active accounts only).
SELECT * FROM users
WHERE email = $1
  AND deleted_at IS NULL;

-- name: GetUserByIDForAdmin :one
-- Admin/reclaim path: also returns soft-deleted (pending_deletion) accounts.
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByEmailForAdmin :one
-- Task 5.3: exact-match account lookup for POST /api/v1/admin/users/lookup.
-- (api-design.md §1.7). Gated behind the admin.users.read.pii permission
-- because the caller must already know the address to use it.
--
-- Deliberately does NOT filter deleted_at, matching GetUserByIDForAdmin: an
-- account in its 30-day grace window is exactly the one a moderator or DPO
-- needs to find, and filtering it out would report "not found" for a row that
-- demonstrably exists.
--
-- Consequence: idx_users_email is partial (WHERE deleted_at IS NULL), so
-- uniqueness holds only across live accounts. Dropping the filter can therefore
-- match several rows — one live account plus any number of soft-deleted
-- predecessors that reused the address. That is legal by design
-- (partial_unique_index_on_soft_delete_email), so this query MUST NOT be left
-- to pick an arbitrary row: the ORDER BY makes it total. The live account wins;
-- among soft-deleted rows the most recent wins. LIMIT 1 is redundant given
-- :one/QueryRow but states the intent at the SQL layer.
SELECT * FROM users
WHERE email = $1
ORDER BY (deleted_at IS NULL) DESC, created_at DESC, id
LIMIT 1;

-- name: GetUserForUpdateIncludingDeleted :one
-- Task 5.1: the per-account mutex for the GDPR deletion lifecycle. Unlike
-- GetUserByIDForUpdate it does NOT filter deleted_at, because both callers
-- operate exclusively on soft-deleted rows: the reclaim ceremony (which clears
-- deleted_at) and the hard-delete purge worker (which removes the row). Using the
-- filtered variant there would find nothing and silently no-op.
--
-- Honours the documented lock order: users first, then children ordered by id.
SELECT * FROM users
WHERE id = $1
FOR UPDATE;

-- name: GetUserByPhoneBlindIndex :one
-- O(1) exact-match lookup via idx_users_phone_blind (data-architecture §2.2).
SELECT * FROM users
WHERE phone_blind_index = $1
  AND deleted_at IS NULL;-- name: GetUserByBackupEmailBlindIndex :one
-- O(1) exact-match lookup via idx_users_backup_email_blind.
SELECT * FROM users
WHERE backup_email_blind_index = $1
  AND deleted_at IS NULL;

-- name: GetUserEmailForBlindIndex :one
-- Task 5.2: the signing consumer resolves security_event_ledger.
-- identity_blind_index from account_ref by computing SHA-256(email + pepper)
-- itself, which keeps the pepper in one process and needs no call-site changes.
--
-- Deliberately does NOT filter deleted_at: a soft-deleted account is still
-- attributable throughout its 30-day grace window, and filtering it out would
-- silently drop the blind index for exactly the subjects a lawful inquiry is
-- most likely to ask about (threat-modeling.md R2).
--
-- Returns only the column needed. The email is Class A PII: it is hashed
-- immediately and MUST NOT be logged or persisted by the consumer.
SELECT email FROM users
WHERE id = $1;

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
    auth_version = auth_version + 1,
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
SELECT u.id FROM users u
WHERE u.status = 'pending_deletion'
  AND u.deleted_at < $1
ORDER BY EXISTS (SELECT 1 FROM legal_holds lh WHERE lh.account_ref = u.id AND lh.is_active),
         u.deleted_at, u.id
LIMIT $2;

-- name: HardDeleteUser :execrows
-- Physical purge after the grace window. FK cascades wipe webauthn
-- credentials, recovery codes, role assignments, pending TOTP enrollments, and
-- the deletion request itself; mvp_audit_logs rows are retained with user_id
-- nulled (ON DELETE SET NULL). The status/cutoff guards make it impossible to
-- hard-delete an active account.
--
-- Defense in depth only: callers must acquire the shared subject advisory lock
-- in a separate statement before eligibility reads, then the user row lock.
-- A NOT EXISTS predicate alone cannot serialize concurrent hold insertion.
DELETE FROM users u
WHERE u.id = $1
  AND u.status = 'pending_deletion'
  AND u.deleted_at < $2
  AND NOT EXISTS (
      SELECT 1 FROM legal_holds lh
      WHERE lh.account_ref = u.id AND lh.is_active = TRUE
  );

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

-- name: ListAdminUsersPage :one
-- A single statement gives the bounded safe projection and count one snapshot,
-- including requests whose offset is beyond the last result.
WITH matching AS MATERIALIZED (
    SELECT id, email, status, is_mfa_enabled, created_at, updated_at, deleted_at
    FROM users
    WHERE (sqlc.narg('status')::varchar IS NULL OR status = sqlc.narg('status')::varchar)
), page AS (
    SELECT * FROM matching ORDER BY created_at DESC, id
    LIMIT sqlc.arg('page_limit')::integer OFFSET sqlc.arg('page_offset')::integer
)
SELECT (SELECT COUNT(*) FROM matching)::bigint AS total,
       COALESCE((SELECT jsonb_agg(page ORDER BY created_at DESC, id) FROM page), '[]'::jsonb)::jsonb AS items;
