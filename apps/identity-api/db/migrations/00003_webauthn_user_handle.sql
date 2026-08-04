-- Task 4.2: Add stable WebAuthn user handle for passwordless registration & login.
--
-- Per api-design.md §1.3 and the random 64-bit user ID challenge mapping
-- requirement, the WebAuthn user.id field must be a CSPRNG-generated random
-- 64-bit value (not the UUID primary key) to prevent user identity correlation.
-- For discoverable credentials (Task 4.3), the authenticator returns this
-- userHandle, which must be stable and persisted to map back to the user.
--
-- Generated on first passkey registration; NULL until then (not all accounts
-- will use WebAuthn). UNIQUE ensures no collisions.

-- +goose Up

ALTER TABLE users
ADD COLUMN webauthn_user_handle BYTEA UNIQUE NULL;

CREATE INDEX idx_users_webauthn_handle ON users(webauthn_user_handle)
WHERE webauthn_user_handle IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_users_webauthn_handle;
ALTER TABLE users DROP COLUMN IF EXISTS webauthn_user_handle;
