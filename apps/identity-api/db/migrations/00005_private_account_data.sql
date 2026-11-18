-- +goose Up
-- One protected account child; no private attribute is a plaintext SQL column.
CREATE TABLE public.private_profile (
    account_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    details_encrypted BYTEA NOT NULL CHECK (octet_length(details_encrypted) BETWEEN 90 AND 16384),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'private account data migration is forward-only';
END $$;
-- +goose StatementEnd
