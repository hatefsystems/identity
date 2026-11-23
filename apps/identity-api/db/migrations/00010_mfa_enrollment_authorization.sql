-- +goose Up
CREATE TABLE public.mfa_enrollment_action_proofs (
    proof_digest BYTEA PRIMARY KEY CHECK (octet_length(proof_digest) = 32),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 128),
    jkt TEXT NOT NULL CHECK (length(jkt) = 43),
    auth_version BIGINT NOT NULL CHECK (auth_version >= 0),
    action TEXT NOT NULL CHECK (action = 'mfa_enrollment'),
    channel TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    contact_binding BYTEA NOT NULL CHECK (octet_length(contact_binding) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (isfinite(expires_at) AND expires_at > created_at
        AND expires_at <= created_at + INTERVAL '5 minutes')
);

CREATE INDEX mfa_enrollment_action_proofs_expiry
    ON public.mfa_enrollment_action_proofs (expires_at, proof_digest);

-- Provision only runtime SELECT/INSERT/DELETE; no UPDATE or TRUNCATE.
REVOKE ALL ON public.mfa_enrollment_action_proofs FROM PUBLIC;

ALTER TABLE public.mfa_totp_enrollments
    ADD COLUMN auth_version BIGINT,
    ADD COLUMN jkt TEXT,
    ADD COLUMN authorization_method TEXT,
    ADD COLUMN channel TEXT,
    ADD COLUMN contact_binding BYTEA,
    ADD CONSTRAINT mfa_totp_enrollments_authorization CHECK (
        (auth_version IS NULL AND jkt IS NULL AND authorization_method IS NULL
            AND channel IS NULL AND contact_binding IS NULL)
        OR
        (auth_version IS NOT NULL AND auth_version >= 0
            AND jkt IS NOT NULL AND length(jkt) = 43
            AND authorization_method IS NOT NULL
            AND isfinite(expires_at) AND expires_at > created_at
            AND expires_at <= created_at + INTERVAL '10 minutes'
            AND (
                (authorization_method = 'webauthn_uv'
                    AND channel IS NULL AND contact_binding IS NULL)
                OR
                (authorization_method = 'password_contact'
                    AND channel IS NOT NULL AND channel IN ('email', 'sms')
                    AND contact_binding IS NOT NULL AND octet_length(contact_binding) = 32)
            ))
    );

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'MFA enrollment authorization migration is forward-only';
END $$;
-- +goose StatementEnd
