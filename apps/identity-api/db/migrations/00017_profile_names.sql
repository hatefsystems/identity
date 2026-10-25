-- +goose Up
-- Optional Class A names stay with their owning rows. Existing rows remain valid.
ALTER TABLE users
    ADD COLUMN display_name TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT users_display_name_length CHECK (char_length(display_name) <= 80);

ALTER TABLE webauthn_credentials
    ADD COLUMN name TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT webauthn_credentials_name_length CHECK (char_length(name) <= 80);

-- +goose Down
-- Rollback retains accepted names and requires v2-capable lifecycle readers.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION '00017 is forward-only: preserve profile names and lifecycle v2 compatibility';
END $$;
-- +goose StatementEnd
