-- name: ReadPrivateProfile :one
-- Caller holds the username policy guard, then the account advisory/row lock.
SELECT details_encrypted, profile_revision FROM public.private_profile WHERE account_id = $1;

-- name: SavePrivateProfile :execrows
-- Only real normalized edits reach this statement, in the revision/outbox tx.
INSERT INTO public.private_profile (account_id, details_encrypted, profile_revision) VALUES ($1, $2, $3)
ON CONFLICT (account_id) DO UPDATE
SET details_encrypted = EXCLUDED.details_encrypted,
    profile_revision = EXCLUDED.profile_revision,
    updated_at = now()
WHERE private_profile.profile_revision < EXCLUDED.profile_revision;
