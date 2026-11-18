-- name: ReadPrivateProfile :one
-- Caller holds the username policy guard, then the account advisory/row lock.
SELECT details_encrypted FROM public.private_profile WHERE account_id = $1;

-- name: SavePrivateProfile :execrows
-- Only real normalized edits reach this statement, in the revision/outbox tx.
INSERT INTO public.private_profile (account_id, details_encrypted) VALUES ($1, $2)
ON CONFLICT (account_id) DO UPDATE
SET details_encrypted = EXCLUDED.details_encrypted, updated_at = now();
