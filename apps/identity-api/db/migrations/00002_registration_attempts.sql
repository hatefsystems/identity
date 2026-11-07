-- +goose Up
CREATE TABLE public.registration_attempts (
    id UUID PRIMARY KEY,
    capability_hash BYTEA NOT NULL CHECK (octet_length(capability_hash) = 32),
    jkt TEXT NOT NULL CHECK (jkt ~ '^[A-Za-z0-9_-]{43}$'),
    details_encrypted BYTEA,
    email_token_hash BYTEA CHECK (email_token_hash IS NULL OR octet_length(email_token_hash) = 32),
    email_token_issued_at TIMESTAMPTZ,
    email_token_expires_at TIMESTAMPTZ,
    email_verified_at TIMESTAMPTZ,
    sms_verification_ref UUID,
    phone_verified_at TIMESTAMPTZ,
    challenge_revision BIGINT NOT NULL DEFAULT 0 CHECK (challenge_revision BETWEEN 0 AND 1000000),
    row_revision BIGINT NOT NULL DEFAULT 0 CHECK (row_revision BETWEEN 0 AND 1000000),
    passkey_created_at TIMESTAMPTZ,
    passkey_expires_at TIMESTAMPTZ,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    receipt_expires_at TIMESTAMPTZ,
    completion_fingerprint BYTEA CHECK (completion_fingerprint IS NULL OR octet_length(completion_fingerprint) = 32),
    result_user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT registration_attempt_times CHECK (
        isfinite(created_at) AND created_at >= '0001-01-01 UTC' AND created_at < '9999-12-31 UTC'
        AND expires_at = created_at + INTERVAL '15 minutes'
        AND (terminal_at IS NULL OR (isfinite(terminal_at) AND terminal_at >= created_at AND terminal_at < expires_at))
        AND (receipt_expires_at IS NULL OR receipt_expires_at = terminal_at + INTERVAL '1 hour')
    ),
    CONSTRAINT registration_email_times CHECK (
        (email_token_issued_at IS NULL) = (email_token_expires_at IS NULL)
        AND (email_token_issued_at IS NULL OR (
            isfinite(email_token_issued_at) AND email_token_issued_at >= created_at
            AND email_token_expires_at > email_token_issued_at
            AND email_token_expires_at <= email_token_issued_at + INTERVAL '10 minutes'
            AND email_token_expires_at <= expires_at))
        AND (email_verified_at IS NULL OR (isfinite(email_verified_at) AND email_verified_at >= created_at
            AND email_verified_at < expires_at))
        AND (state <> 'pending' OR email_verified_at IS NULL OR (
            email_token_issued_at IS NOT NULL AND email_verified_at >= email_token_issued_at
            AND email_verified_at < email_token_expires_at))
        AND (email_token_hash IS NULL OR (email_token_issued_at IS NOT NULL AND email_verified_at IS NULL))
    ),
    CONSTRAINT registration_phone_proof CHECK (
        (phone_verified_at IS NULL OR (email_verified_at IS NOT NULL AND isfinite(phone_verified_at)
            AND phone_verified_at >= email_verified_at AND phone_verified_at < expires_at))
        AND (state <> 'pending' OR phone_verified_at IS NULL OR sms_verification_ref IS NOT NULL)
        AND (sms_verification_ref IS NULL OR (sms_verification_ref <> '00000000-0000-0000-0000-000000000000'
            AND email_verified_at IS NOT NULL AND challenge_revision > 0))
    ),
    CONSTRAINT registration_passkey_times CHECK (
        (passkey_created_at IS NULL) = (passkey_expires_at IS NULL)
        AND (passkey_created_at IS NULL OR (isfinite(passkey_created_at)
            AND phone_verified_at IS NOT NULL AND passkey_created_at >= phone_verified_at
            AND passkey_expires_at > passkey_created_at
            AND passkey_expires_at <= passkey_created_at + INTERVAL '5 minutes'
            AND passkey_expires_at <= expires_at AND challenge_revision > 0))
    ),
    CONSTRAINT registration_state_material CHECK (
        (state = 'pending' AND details_encrypted IS NOT NULL
            AND octet_length(details_encrypted) BETWEEN 90 AND 32768
            AND terminal_at IS NULL AND receipt_expires_at IS NULL
            AND completion_fingerprint IS NULL AND result_user_id IS NULL)
        OR (state = 'completed' AND terminal_at IS NOT NULL AND receipt_expires_at IS NOT NULL
            AND completion_fingerprint IS NOT NULL AND result_user_id IS NOT NULL
            AND result_user_id <> '00000000-0000-0000-0000-000000000000'
            AND email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL
            AND email_verified_at <= terminal_at AND phone_verified_at <= terminal_at
            AND details_encrypted IS NULL AND email_token_hash IS NULL
            AND email_token_issued_at IS NULL AND email_token_expires_at IS NULL
            AND sms_verification_ref IS NULL AND passkey_created_at IS NULL AND passkey_expires_at IS NULL)
        OR (state = 'failed' AND terminal_at IS NOT NULL AND receipt_expires_at IS NOT NULL
            AND completion_fingerprint IS NULL AND result_user_id IS NULL
            AND details_encrypted IS NULL AND email_token_hash IS NULL
            AND email_token_issued_at IS NULL AND email_token_expires_at IS NULL
            AND sms_verification_ref IS NULL AND passkey_created_at IS NULL AND passkey_expires_at IS NULL)
    )
);

CREATE INDEX idx_registration_pending_expiry ON public.registration_attempts(expires_at, id) WHERE state = 'pending';
CREATE INDEX idx_registration_receipt_expiry ON public.registration_attempts(receipt_expires_at, id) WHERE state IN ('completed', 'failed');
CREATE INDEX idx_registration_result_user ON public.registration_attempts(result_user_id) WHERE result_user_id IS NOT NULL;
REVOKE ALL ON public.registration_attempts FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'registration attempts are forward-only; restore an approved backup instead';
END $$;
-- +goose StatementEnd
