-- +goose Up
LOCK TABLE public.private_profile IN ACCESS EXCLUSIVE MODE;

-- A prior payload has no authenticated write revision to backfill.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM public.private_profile) THEN
        RAISE EXCEPTION 'private profile revision migration requires an empty private_profile table';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE public.private_profile
    ADD COLUMN profile_revision BIGINT NOT NULL CHECK (profile_revision > 0);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'private profile revision migration is forward-only';
END $$;
-- +goose StatementEnd
