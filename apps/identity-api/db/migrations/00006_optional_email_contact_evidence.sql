-- +goose Up
-- Readers are typed for absence before this forward-only storage change.
ALTER TABLE public.users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE public.users ADD CONSTRAINT users_email_not_empty
    CHECK (email IS NULL OR length(btrim(email)) > 0);

CREATE TABLE public.contact_verification_evidence (
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'phone')),
    evidence_encrypted BYTEA NOT NULL CHECK (octet_length(evidence_encrypted) BETWEEN 90 AND 4096),
    PRIMARY KEY (user_id, channel)
);

-- Invalidation belongs at the storage boundary, not just an HTTP mutation path.
-- Compare the protected phone as well as its index to fail closed on replacement.
-- +goose StatementBegin
CREATE FUNCTION public.invalidate_contact_verification_evidence() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.email IS DISTINCT FROM OLD.email THEN
        DELETE FROM public.contact_verification_evidence WHERE user_id = OLD.id AND channel = 'email';
    END IF;
    IF NEW.phone_encrypted IS DISTINCT FROM OLD.phone_encrypted
       OR NEW.phone_blind_index IS DISTINCT FROM OLD.phone_blind_index THEN
        DELETE FROM public.contact_verification_evidence WHERE user_id = OLD.id AND channel = 'phone';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER users_invalidate_contact_verification_evidence
    AFTER UPDATE OF email, phone_encrypted, phone_blind_index ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.invalidate_contact_verification_evidence();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'optional email and contact evidence migration is forward-only';
END $$;
-- +goose StatementEnd
