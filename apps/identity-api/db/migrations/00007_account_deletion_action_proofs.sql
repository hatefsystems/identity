-- +goose Up
CREATE TABLE public.account_deletion_action_proofs (
    proof_digest BYTEA PRIMARY KEY CHECK (octet_length(proof_digest) = 32),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 128),
    jkt TEXT NOT NULL CHECK (length(jkt) = 43),
    auth_version BIGINT NOT NULL CHECK (auth_version >= 0),
    action TEXT NOT NULL CHECK (action = 'account_deletion'),
    channel TEXT NOT NULL CHECK (channel IN ('email', 'sms')),
    contact_binding BYTEA NOT NULL CHECK (octet_length(contact_binding) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes')
);

CREATE INDEX account_deletion_action_proofs_expiry
    ON public.account_deletion_action_proofs (expires_at, proof_digest);

-- Grants are explicit in deployment provisioning, never inherited from PUBLIC.
REVOKE ALL ON public.account_deletion_action_proofs FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'account deletion action proof migration is forward-only';
END $$;
-- +goose StatementEnd
