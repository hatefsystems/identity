-- Class A retry material is separate from the metadata-only lifecycle outbox.
-- Legacy deletion requests retain their original hash/expiry; no delivery payload
-- can be reconstructed for them. Inventory those requests before enabling new work.
-- +goose Up
ALTER TABLE deletion_requests
    ADD COLUMN requested_auth_version BIGINT NULL
        CHECK (requested_auth_version >= 0 AND requested_auth_version < 9223372036854775807);

CREATE TABLE deletion_notifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES deletion_requests(id) ON DELETE CASCADE,
    recipient_role VARCHAR(10) NOT NULL CHECK (recipient_role IN ('primary', 'backup')),
    payload_encrypted BYTEA NULL CHECK (payload_encrypted IS NULL OR octet_length(payload_encrypted) BETWEEN 1 AND 16384),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_token UUID NULL,
    lease_until TIMESTAMP WITH TIME ZONE NULL,
    accepted_at TIMESTAMP WITH TIME ZONE NULL,
    failed_at TIMESTAMP WITH TIME ZONE NULL,
    last_error_code VARCHAR(32) NULL CHECK (last_error_code IN
        ('relay_temporary', 'relay_permanent', 'payload_unavailable', 'payload_invalid', 'request_invalid')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, recipient_role),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (accepted_at IS NULL OR failed_at IS NULL)
);

CREATE INDEX idx_deletion_notifications_due ON deletion_notifications(next_attempt_at, id)
    WHERE accepted_at IS NULL AND failed_at IS NULL AND payload_encrypted IS NOT NULL;
CREATE INDEX idx_deletion_notifications_cleanup ON deletion_notifications(user_id, id)
    WHERE payload_encrypted IS NOT NULL;

-- Ciphertext becomes eligible for removal after relay acceptance, request
-- invalidation, or expiry. Cleanup must take the shared account advisory lock,
-- read the minimal user/request snapshot, lock the delivery row, and fail closed
-- on active/unknown holds. Only the delivery table needs write privileges.
-- A hold preserves ciphertext, never token validity. Hard deletion cascades only
-- Class A rows; neither security ledgers nor lifecycle events reference this table.

-- +goose Down
-- Roll back feature enablement, not already accepted recovery/delivery state.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION '00018 is forward-only: pending deletion notifications must be preserved';
END $$;
-- +goose StatementEnd
