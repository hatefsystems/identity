-- Task 5.1: "Right to be Forgotten" reclaim ceremony + hard-delete outbox.
--
-- Source of truth: docs/compliance-and-data-governance.md §2/§4/§5/§6/§7,
-- docs/architecture.md ("Grace Period & Soft Deletes", "Hard Delete Cron Jobs"),
-- docs/api-design.md §1.4/§2, docs/threat-modeling.md A2/R2.
--
-- Managed by goose; sqlc parses this file as schema input. Apply with:
--   nx run identity-api:migrate-up   (or: go run ./cmd/migrate up)

-- +goose Up

-- 7. Deletion Requests (Class A - erased at hard-delete by the FK cascade)
--
-- One row per outstanding "Right to be Forgotten" request. It carries the
-- SHA-256 hash of the single-use reclaim token that is emailed to the subject at
-- soft-delete; the plaintext token exists only in the outbound notification, so a
-- database dump cannot be replayed against the reclaim endpoint.
--
-- This row is Class A data: the ON DELETE CASCADE below is precisely what erases
-- it when the purge worker hard-deletes the account, so no reclaim material for a
-- purged subject can outlive the subject.
CREATE TABLE deletion_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL,                       -- SHA-256(reclaim token), hex
    requested_ip VARCHAR(50) NULL,                         -- Source of the deletion request (audit context)
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,          -- Always deleted_at + grace period; never a separate policy
    consumed_at TIMESTAMP WITH TIME ZONE NULL,             -- Set on reclaim success, resend, or attempt-cap expiry
    notified_at TIMESTAMP WITH TIME ZONE NULL,             -- Last successful notification; drives the resend cooldown
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- O(1) lookup by token hash. The reclaim endpoint is anonymous and token-bearing,
-- so the hash is the only lookup key it has; a unique index also makes an
-- (astronomically unlikely) hash collision an insert failure rather than an
-- ambiguous read.
CREATE UNIQUE INDEX idx_deletion_requests_token ON deletion_requests(token_hash);

-- Supports the resend-cooldown check and the "invalidate everything outstanding"
-- sweep performed on reclaim success.
CREATE INDEX idx_deletion_requests_active ON deletion_requests(user_id) WHERE consumed_at IS NULL;

-- 8. Transactional Event Outbox
--
-- The purge worker cannot publish identity.user.deleted to NATS in the same
-- atomic unit as the DELETE, so it writes the event here instead, inside the
-- very same transaction. That makes "no event without a commit, no commit
-- without an event" a database guarantee rather than worker discipline. A later
-- task drains this table into NATS JetStream.
--
-- There is deliberately NO foreign key to users(id): the subject row is deleted
-- in the same transaction that inserts this event, so any FK would either block
-- the delete or cascade the event away. The payload carries only the user_id
-- (docs/api-design.md §3, subject identity.user.deleted) and never raw PII.
CREATE TABLE event_outbox (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject VARCHAR(100) NOT NULL,                         -- NATS subject, e.g. 'identity.user.deleted'
    payload TEXT NOT NULL,                                 -- Serialized JSON; PII-free by contract
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP WITH TIME ZONE NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NULL
);

-- Drives the publisher's "what is still unpublished" scan in creation order.
CREATE INDEX idx_event_outbox_unpublished ON event_outbox(created_at) WHERE published_at IS NULL;

-- 9. Reserve identifiers for the whole grace window
--
-- The original partial unique indexes only covered `deleted_at IS NULL`, which
-- freed an account's email, phone, and backup email the instant it entered
-- pending_deletion. Two consequences, both unacceptable:
--
--   * ReclaimUser sets deleted_at = NULL, which re-arms the index predicate. If a
--     third party claimed the identifier during the grace window, the reclaim
--     would fail with a unique violation (SQLSTATE 23505) and the subject would
--     be permanently unrecoverable. Widening the predicate is what makes reclaim
--     safe.
--   * The grace window is a recovery mechanism, so the identifier must stay
--     reserved for its owner until the account is actually purged.
--
-- IMPORTANT for whoever builds registration: GetUserByEmail (and both blind-index
-- lookups) filter `deleted_at IS NULL`, so they will NOT see a reserved
-- pending_deletion identifier. A registration attempt on a reserved identifier
-- therefore passes the application-level "is it taken?" check and then fails on
-- these indexes. That PostgreSQL 23505 must be mapped to a clean 409, not a 500.

-- 9a. Resolve pre-existing collisions before widening each predicate.
--
-- Until now the platform's contract was "soft-delete frees the identifier
-- immediately", so a live account may legitimately already share an email, phone,
-- or backup email with one or more pending_deletion rows. Widening the predicate
-- over that data fails outright (23505), and the collisions cannot be resolved by
-- keeping every claim: the entire point of the new index is that a reservation is
-- exclusive. So they are resolved here, deterministically.
--
-- One claim per identifier is kept and the rest are released:
--
--   * The live (deleted_at IS NULL) row always wins. The pre-existing narrow index
--     guaranteed at most one such row per identifier, so a live account's
--     identifier is never touched by this step.
--   * Among pending_deletion rows the most recently deleted wins: it is the one a
--     user is most plausibly about to reclaim.
--   * Losing rows have their identifier released. This forfeits nothing that was
--     not already forfeit: under the old contract those identifiers were free for
--     anyone to take, so those reclaims were already going to fail on the re-armed
--     index. Every losing row is queued for erasure regardless.
--
-- users.email is NOT NULL, so a losing row is rewritten to a deterministic
-- tombstone in the RFC 6761 reserved .invalid TLD, which can never be a real
-- address. The nullable PII columns are cleared together with their blind index,
-- matching RemoveUserPhone / RemoveUserBackupEmail, so an encrypted payload is
-- never left behind with nothing pointing at it.
--
-- This step is a data migration, not schema: the Down section restores the index
-- predicates but cannot restore released identifiers.
WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY email
               ORDER BY (deleted_at IS NULL) DESC, deleted_at DESC, created_at DESC, id
           ) AS rn
    FROM users
    WHERE deleted_at IS NULL OR status = 'pending_deletion'
)
UPDATE users u
SET email = 'deleted-' || u.id::text || '@invalid.local',
    updated_at = NOW()
FROM ranked r
WHERE u.id = r.id AND r.rn > 1;

WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY phone_blind_index
               ORDER BY (deleted_at IS NULL) DESC, deleted_at DESC, created_at DESC, id
           ) AS rn
    FROM users
    WHERE (deleted_at IS NULL OR status = 'pending_deletion')
      AND phone_blind_index IS NOT NULL
)
UPDATE users u
SET phone_encrypted = NULL,
    phone_blind_index = NULL,
    updated_at = NOW()
FROM ranked r
WHERE u.id = r.id AND r.rn > 1;

WITH ranked AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY backup_email_blind_index
               ORDER BY (deleted_at IS NULL) DESC, deleted_at DESC, created_at DESC, id
           ) AS rn
    FROM users
    WHERE (deleted_at IS NULL OR status = 'pending_deletion')
      AND backup_email_blind_index IS NOT NULL
)
UPDATE users u
SET backup_email_encrypted = NULL,
    backup_email_blind_index = NULL,
    updated_at = NOW()
FROM ranked r
WHERE u.id = r.id AND r.rn > 1;

-- 9b. Widen the predicates.
DROP INDEX idx_users_email;
CREATE UNIQUE INDEX idx_users_email ON users(email)
    WHERE deleted_at IS NULL OR status = 'pending_deletion';

DROP INDEX idx_users_phone_blind;
CREATE UNIQUE INDEX idx_users_phone_blind ON users(phone_blind_index)
    WHERE (deleted_at IS NULL OR status = 'pending_deletion') AND phone_blind_index IS NOT NULL;

DROP INDEX idx_users_backup_email_blind;
CREATE UNIQUE INDEX idx_users_backup_email_blind ON users(backup_email_blind_index)
    WHERE (deleted_at IS NULL OR status = 'pending_deletion') AND backup_email_blind_index IS NOT NULL;

-- +goose Down

-- Restore the original (narrower) index predicates from 00001. The identifier
-- releases performed by step 9a are data changes and are NOT reversed: the original
-- values are not recorded anywhere, and every row they touched was already queued
-- for erasure with an identifier that the pre-migration contract had freed.
DROP INDEX idx_users_backup_email_blind;
CREATE UNIQUE INDEX idx_users_backup_email_blind ON users(backup_email_blind_index)
    WHERE deleted_at IS NULL AND backup_email_blind_index IS NOT NULL;

DROP INDEX idx_users_phone_blind;
CREATE UNIQUE INDEX idx_users_phone_blind ON users(phone_blind_index)
    WHERE deleted_at IS NULL AND phone_blind_index IS NOT NULL;

DROP INDEX idx_users_email;
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;

DROP TABLE event_outbox;
DROP TABLE deletion_requests;
