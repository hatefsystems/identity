-- Apply 00019 first, stop intake/writers, run bounded application backfill and
-- verify keys/data inventory before applying this separate contraction.
-- +goose Up
LOCK TABLE public.legal_holds IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM public.legal_holds
        WHERE reason IS NOT NULL OR requesting_authority IS NOT NULL OR legal_basis IS NOT NULL
           OR NOT ((details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL)
               OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL))) THEN
        RAISE EXCEPTION 'legal hold contraction requires complete verified backfill or released/purged tombstones';
    END IF;
END $$;
-- +goose StatementEnd
-- Drop only known dependencies. Unexpected views/functions must stop migration,
-- not be removed recursively with CASCADE.
ALTER TABLE public.legal_holds
    DROP CONSTRAINT legal_holds_details_exclusive,
    DROP CONSTRAINT legal_holds_request_details,
    DROP COLUMN reason,
    DROP COLUMN requesting_authority,
    DROP COLUMN legal_basis,
    ADD CONSTRAINT legal_holds_encrypted_or_purged CHECK (
        (details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL)
        OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL)
    );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'legal hold plaintext contraction is forward-only';
END $$;
-- +goose StatementEnd
