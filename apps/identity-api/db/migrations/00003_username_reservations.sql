-- +goose Up
-- Refuse an unexpected legacy source instead of treating newly NULL fields as
-- evidence that the deployed target has never stored usernames. No values are
-- inspected or backfilled by this migration.
-- +goose StatementBegin
DO $$ BEGIN
    IF ARRAY(SELECT attname::text FROM pg_catalog.pg_attribute
        WHERE attrelid='public.users'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum)
        IS DISTINCT FROM ARRAY['id','email','password_hash','backup_email_encrypted','backup_email_blind_index',
            'phone_encrypted','phone_blind_index','mfa_totp_secret_encrypted','is_mfa_enabled','status',
            'created_at','updated_at','deleted_at','webauthn_user_handle','auth_version','auth_epoch',
            'lifecycle_revision','display_name'] THEN
        RAISE EXCEPTION 'unexpected users schema; reviewed username inventory required';
    END IF;
END $$;
-- +goose StatementEnd

CREATE TABLE public.username_policy_artifacts (
    policy_id UUID PRIMARY KEY CHECK (policy_id <> '00000000-0000-0000-0000-000000000000'),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    artifact BYTEA NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 16384),
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, fingerprint)
);
CREATE TABLE public.username_lookup_keys (
    key_id TEXT PRIMARY KEY CHECK (octet_length(key_id) BETWEEN 1 AND 128),
    key_verifier BYTEA NOT NULL CHECK (octet_length(key_verifier) = 32),
    UNIQUE (key_id, key_verifier)
);
CREATE TABLE public.username_active_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    -- Grant UPDATE on this invariant column only to permit SELECT FOR SHARE.
    -- It confers no authority to change admission or the policy binding.
    guard BOOLEAN NOT NULL DEFAULT TRUE CHECK (guard),
    policy_id UUID,
    fingerprint BYTEA,
    epoch BIGINT NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    key_id TEXT,
    key_verifier BYTEA,
    admission_state TEXT NOT NULL DEFAULT 'uninstalled' CHECK (admission_state IN ('uninstalled', 'closed', 'open')),
    CONSTRAINT username_active_tuple CHECK (
        (policy_id IS NULL AND fingerprint IS NULL AND key_id IS NULL AND key_verifier IS NULL
            AND epoch = 0 AND admission_state = 'uninstalled')
        OR (policy_id IS NOT NULL AND fingerprint IS NOT NULL AND key_id IS NOT NULL AND key_verifier IS NOT NULL
            AND epoch > 0 AND admission_state IN ('closed', 'open'))
    ),
    FOREIGN KEY (policy_id, fingerprint) REFERENCES public.username_policy_artifacts(policy_id, fingerprint),
    FOREIGN KEY (key_id, key_verifier) REFERENCES public.username_lookup_keys(key_id, key_verifier)
);
INSERT INTO public.username_active_policy(singleton) VALUES(TRUE);

ALTER TABLE public.users
    ADD COLUMN username_key BYTEA,
    ADD COLUMN username_details_encrypted BYTEA,
    ADD COLUMN username_policy_id UUID,
    ADD COLUMN username_policy_fingerprint BYTEA,
    ADD COLUMN username_policy_epoch BIGINT,
    ADD COLUMN username_lookup_key_id TEXT,
    ADD CONSTRAINT users_username_tuple CHECK (
        (username_key IS NULL AND username_details_encrypted IS NULL AND username_policy_id IS NULL
            AND username_policy_fingerprint IS NULL AND username_policy_epoch IS NULL AND username_lookup_key_id IS NULL)
        OR (username_key IS NOT NULL AND octet_length(username_key) = 32
            AND username_details_encrypted IS NOT NULL AND octet_length(username_details_encrypted) BETWEEN 90 AND 16384
            AND username_policy_id IS NOT NULL AND username_policy_fingerprint IS NOT NULL
            AND octet_length(username_policy_fingerprint) = 32 AND username_policy_epoch IS NOT NULL
            AND username_policy_epoch > 0 AND username_lookup_key_id IS NOT NULL)
    ),
    ADD CONSTRAINT users_username_key_unique UNIQUE(username_key),
    ADD FOREIGN KEY (username_policy_id, username_policy_fingerprint)
        REFERENCES public.username_policy_artifacts(policy_id, fingerprint),
    ADD FOREIGN KEY (username_lookup_key_id) REFERENCES public.username_lookup_keys(key_id);

-- +goose StatementBegin
CREATE FUNCTION public.username_registry_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    RAISE EXCEPTION 'username registry is immutable' USING ERRCODE = '23514';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER username_artifact_immutable BEFORE UPDATE OR DELETE ON public.username_policy_artifacts
    FOR EACH ROW EXECUTE FUNCTION public.username_registry_immutable();
CREATE TRIGGER username_artifact_no_truncate BEFORE TRUNCATE ON public.username_policy_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION public.username_registry_immutable();
CREATE TRIGGER username_key_immutable BEFORE UPDATE OR DELETE ON public.username_lookup_keys
    FOR EACH ROW EXECUTE FUNCTION public.username_registry_immutable();
CREATE TRIGGER username_key_no_truncate BEFORE TRUNCATE ON public.username_lookup_keys
    FOR EACH STATEMENT EXECUTE FUNCTION public.username_registry_immutable();
CREATE TRIGGER username_active_no_delete BEFORE DELETE ON public.username_active_policy
    FOR EACH ROW EXECUTE FUNCTION public.username_registry_immutable();
CREATE TRIGGER username_active_no_truncate BEFORE TRUNCATE ON public.username_active_policy
    FOR EACH STATEMENT EXECUTE FUNCTION public.username_registry_immutable();

-- There is deliberately NO maintenance role, role-name exception, session
-- setting, SECURITY DEFINER helper or executable reindex path in this migration.
-- +goose StatementBegin
CREATE FUNCTION public.username_ownership_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
    authority public.username_active_policy%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.username_key IS NOT NULL THEN
        IF ROW(NEW.id, NEW.username_key, NEW.username_details_encrypted, NEW.username_policy_id,
            NEW.username_policy_fingerprint, NEW.username_policy_epoch, NEW.username_lookup_key_id)
            IS DISTINCT FROM ROW(OLD.id, OLD.username_key, OLD.username_details_encrypted, OLD.username_policy_id,
            OLD.username_policy_fingerprint, OLD.username_policy_epoch, OLD.username_lookup_key_id) THEN
            RAISE EXCEPTION 'username assignment is immutable' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' AND OLD.username_key IS NULL THEN
        RETURN OLD;
    END IF;
    IF TG_OP <> 'DELETE' AND NEW.username_key IS NULL THEN
        RETURN NEW;
    END IF;
    -- Callers acquire this guard BEFORE account locks. This second check also
    -- fences direct ownership-changing SQL; it is not a substitute for ordering.
    SELECT * INTO STRICT authority FROM public.username_active_policy WHERE singleton FOR SHARE;
    IF TG_OP = 'DELETE' THEN
        IF authority.admission_state <> 'open' THEN
            RAISE EXCEPTION 'username ownership gate is closed' USING ERRCODE = '55000';
        END IF;
        RETURN OLD;
    END IF;
    IF authority.admission_state <> 'open' OR
        ROW(NEW.username_policy_id, NEW.username_policy_fingerprint, NEW.username_policy_epoch, NEW.username_lookup_key_id)
        IS DISTINCT FROM ROW(authority.policy_id, authority.fingerprint, authority.epoch, authority.key_id) THEN
        RAISE EXCEPTION 'username authority mismatch' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER users_username_immutable BEFORE INSERT OR UPDATE OF id, username_key, username_details_encrypted,
    username_policy_id, username_policy_fingerprint, username_policy_epoch, username_lookup_key_id OR DELETE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.username_ownership_guard();
-- TRUNCATE would bypass per-account release coordination. No ordinary path needs it.
CREATE TRIGGER users_username_no_truncate BEFORE TRUNCATE ON public.users
    FOR EACH STATEMENT EXECUTE FUNCTION public.username_registry_immutable();
REVOKE ALL ON public.username_policy_artifacts, public.username_lookup_keys, public.username_active_policy FROM PUBLIC;
REVOKE ALL ON FUNCTION public.username_registry_immutable(), public.username_ownership_guard() FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'username reservations are forward-only; restore an approved backup instead';
END $$;
-- +goose StatementEnd
