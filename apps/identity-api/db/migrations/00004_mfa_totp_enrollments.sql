-- +goose Up

-- Pending TOTP setup must be bound to the exact authenticated session that
-- consumed step-up authorization. Active secrets remain exclusively on users.
CREATE TABLE mfa_totp_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    purpose VARCHAR(32) NOT NULL CHECK (purpose IN ('maintenance')),
    secret_encrypted BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mfa_totp_enrollments_user ON mfa_totp_enrollments(user_id);
CREATE INDEX idx_mfa_totp_enrollments_expires ON mfa_totp_enrollments(expires_at);

-- Older builds stored unverified setup secrets directly on users. They were
-- not session-bound and must not survive the migration.
UPDATE users
SET mfa_totp_secret_encrypted = NULL,
    updated_at = NOW()
WHERE is_mfa_enabled = FALSE
  AND mfa_totp_secret_encrypted IS NOT NULL;

-- +goose Down
DROP TABLE mfa_totp_enrollments;
