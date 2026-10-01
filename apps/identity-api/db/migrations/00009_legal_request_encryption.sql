-- Expand only: legacy plaintext is converted by the application backfill, never
-- by SQL placeholder encryption. Disable legal intake until backfill and key
-- readiness checks pass. New requests never populate the legacy columns.
-- +goose Up
ALTER TABLE legal_holds
    ALTER COLUMN reason DROP NOT NULL,
    ALTER COLUMN requesting_authority DROP NOT NULL,
    ALTER COLUMN legal_basis DROP NOT NULL,
    ADD COLUMN request_kind TEXT NOT NULL DEFAULT 'legal_hold'
        CHECK (request_kind IN ('legal_hold', 'preservation')),
    ADD COLUMN idempotency_key UUID,
    ADD COLUMN details_encrypted BYTEA,
    ADD COLUMN details_purged_at TIMESTAMPTZ,
    ADD CONSTRAINT legal_holds_details_exclusive CHECK (
        details_encrypted IS NULL OR
        (reason IS NULL AND requesting_authority IS NULL AND legal_basis IS NULL)
    ),
    ADD CONSTRAINT legal_holds_request_details CHECK (
        idempotency_key IS NULL OR details_encrypted IS NOT NULL OR
        (NOT is_active AND details_purged_at IS NOT NULL)
    );

CREATE UNIQUE INDEX legal_holds_request_identity
    ON legal_holds (account_ref, request_kind, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX legal_holds_released_cleanup
    ON legal_holds (released_at, id) WHERE NOT is_active AND details_purged_at IS NULL;
CREATE INDEX security_ledger_attribution_sequence
    ON security_event_ledger (identity_blind_index, seq);

-- Ciphertext and active holds must survive rollback. Downgrade is deliberately
-- refused once this migration has been used; disable routes instead.
-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM legal_holds WHERE details_encrypted IS NOT NULL
        OR idempotency_key IS NOT NULL OR details_purged_at IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot discard encrypted legal requests; disable routes instead';
    END IF;
END $$;
-- +goose StatementEnd
DROP INDEX security_ledger_attribution_sequence;
DROP INDEX legal_holds_released_cleanup;
DROP INDEX legal_holds_request_identity;
ALTER TABLE legal_holds
    DROP CONSTRAINT legal_holds_request_details,
    DROP CONSTRAINT legal_holds_details_exclusive,
    DROP COLUMN details_purged_at,
    DROP COLUMN details_encrypted,
    DROP COLUMN idempotency_key,
    DROP COLUMN request_kind,
    ALTER COLUMN reason SET NOT NULL,
    ALTER COLUMN requesting_authority SET NOT NULL,
    ALTER COLUMN legal_basis SET NOT NULL;
