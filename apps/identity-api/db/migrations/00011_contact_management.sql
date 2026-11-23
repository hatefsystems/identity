-- +goose Up
CREATE TABLE public.contact_management_action_proofs (
    digest BYTEA PRIMARY KEY CHECK (octet_length(digest) = 32),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL CHECK (session_id ~ '^[!-~]{1,128}$'),
    dpop_jkt TEXT NOT NULL CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    auth_version BIGINT NOT NULL CHECK (auth_version >= 0),
    action TEXT NOT NULL CHECK (action IN ('contact_change', 'contact_remove')),
    target TEXT NOT NULL CHECK (target IN ('email', 'phone')),
    channel TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    contact_mac BYTEA NOT NULL CHECK (octet_length(contact_mac) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (isfinite(created_at) AND isfinite(expires_at)
        AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '5 minutes')
);
CREATE INDEX contact_management_action_proofs_expiry
    ON public.contact_management_action_proofs (expires_at, digest);
REVOKE ALL ON public.contact_management_action_proofs FROM PUBLIC;

CREATE TABLE public.contact_change_attempts (
    digest BYTEA PRIMARY KEY CHECK (octet_length(digest) = 32),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL CHECK (session_id ~ '^[!-~]{1,128}$'),
    dpop_jkt TEXT NOT NULL CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    auth_version BIGINT NOT NULL CHECK (auth_version >= 0),
    target TEXT NOT NULL CHECK (target IN ('email', 'phone')),
    authorization_method TEXT NOT NULL,
    authorization_expires_at TIMESTAMPTZ NOT NULL,
    channel TEXT,
    contact_mac BYTEA,
    original_state_digest BYTEA NOT NULL CHECK (octet_length(original_state_digest) = 32),
    destination_encrypted BYTEA NOT NULL CHECK (octet_length(destination_encrypted) BETWEEN 90 AND 4096),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT contact_change_attempts_current UNIQUE (user_id, target),
    CHECK (isfinite(created_at) AND isfinite(expires_at)
        AND isfinite(authorization_expires_at)
        AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '3 minutes'
        AND expires_at <= authorization_expires_at
        AND authorization_expires_at <= created_at + INTERVAL '5 minutes'),
    CHECK (
        (authorization_method IN ('webauthn_uv', 'totp')
            AND channel IS NULL AND contact_mac IS NULL)
        OR
        (authorization_method = 'password_contact'
            AND channel IS NOT NULL AND channel IN ('email', 'sms')
            AND contact_mac IS NOT NULL AND octet_length(contact_mac) = 32)
    )
);
CREATE INDEX contact_change_attempts_expiry
    ON public.contact_change_attempts (expires_at, digest);
REVOKE ALL ON public.contact_change_attempts FROM PUBLIC;

-- Runtime provisioning grants SELECT/INSERT/DELETE only. Replacing an attempt
-- is a freshly authorized DELETE + INSERT, never an UPDATE or renewed deadline.
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'Contact management migration is forward-only';
END $$;
-- +goose StatementEnd
