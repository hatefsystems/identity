-- Admission must acquire this transaction lock in a separate statement before
-- counting/inserting. Expired but uncleaned pending rows still consume capacity.
-- name: LockRegistrationAdmission :exec
SELECT pg_catalog.pg_advisory_xact_lock(551006, 2);

-- name: CreateRegistrationAttempt :one
INSERT INTO public.registration_attempts(id, capability_hash, jkt, details_encrypted, created_at, expires_at)
SELECT sqlc.arg('id'), sqlc.arg('capability_hash'), sqlc.arg('jkt'), sqlc.arg('details_encrypted'),
       sqlc.arg('created_at'), sqlc.arg('expires_at')
WHERE (SELECT count(*) FROM public.registration_attempts WHERE state = 'pending') < sqlc.arg('pending_capacity')::integer
RETURNING *;

-- name: GetRegistrationAttempt :one
SELECT * FROM public.registration_attempts WHERE id = $1;

-- name: LockRegistrationAttempt :one
SELECT * FROM public.registration_attempts WHERE id = $1 FOR UPDATE;

-- name: SaveRegistrationAttempt :one
UPDATE public.registration_attempts SET
    details_encrypted = sqlc.arg('details_encrypted'), email_token_hash = sqlc.narg('email_token_hash'),
    email_token_issued_at = sqlc.narg('email_token_issued_at'), email_token_expires_at = sqlc.narg('email_token_expires_at'),
    email_verified_at = sqlc.narg('email_verified_at'), sms_verification_ref = sqlc.narg('sms_verification_ref'),
    phone_verified_at = sqlc.narg('phone_verified_at'), challenge_revision = sqlc.arg('challenge_revision'),
    passkey_created_at = sqlc.narg('passkey_created_at'), passkey_expires_at = sqlc.narg('passkey_expires_at'),
    row_revision = row_revision + 1
WHERE id = sqlc.arg('id') AND state = 'pending' AND row_revision = sqlc.arg('row_revision')
    AND expires_at > sqlc.arg('now')
RETURNING *;

-- name: CompleteRegistrationAttempt :one
UPDATE public.registration_attempts SET state = 'completed', terminal_at = sqlc.arg('now'),
    receipt_expires_at = sqlc.arg('receipt_expires_at'), completion_fingerprint = sqlc.arg('completion_fingerprint'),
    result_user_id = sqlc.arg('result_user_id'), details_encrypted = NULL, email_token_hash = NULL,
    email_token_issued_at = NULL, email_token_expires_at = NULL, sms_verification_ref = NULL,
    passkey_created_at = NULL, passkey_expires_at = NULL, row_revision = row_revision + 1
WHERE id = sqlc.arg('id') AND state = 'pending' AND row_revision = sqlc.arg('row_revision')
    AND expires_at > sqlc.arg('now') AND email_verified_at IS NOT NULL AND phone_verified_at IS NOT NULL
    AND email_token_expires_at > sqlc.arg('now') AND passkey_expires_at > sqlc.arg('now')
RETURNING *;

-- name: FailRegistrationAttempt :one
UPDATE public.registration_attempts SET state = 'failed', terminal_at = sqlc.arg('now'),
    receipt_expires_at = sqlc.arg('receipt_expires_at'), details_encrypted = NULL, email_token_hash = NULL,
    email_token_issued_at = NULL, email_token_expires_at = NULL, sms_verification_ref = NULL,
    passkey_created_at = NULL, passkey_expires_at = NULL, row_revision = row_revision + 1
WHERE id = sqlc.arg('id') AND state = 'pending' AND row_revision = sqlc.arg('row_revision') AND expires_at > sqlc.arg('now')
RETURNING *;

-- name: ListExpiredRegistrationAttempts :many
-- Exclude already-held receipts from the candidate page to prevent a permanent
-- held prefix from starving unheld cleanup. The caller rechecks after its lock.
SELECT id, state, result_user_id FROM public.registration_attempts
WHERE (state = 'pending' AND expires_at <= sqlc.arg('cutoff'))
   OR (state = 'failed' AND receipt_expires_at <= sqlc.arg('cutoff'))
   OR (state = 'completed' AND receipt_expires_at <= sqlc.arg('cutoff')
       AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = result_user_id AND h.is_active))
ORDER BY COALESCE(receipt_expires_at, expires_at), id LIMIT sqlc.arg('batch_size');

-- DELETE acquires the tuple lock without requiring an UPDATE grant for SELECT
-- FOR UPDATE. The caller has acquired the subject lock for a completed receipt.
-- name: DeleteExpiredRegistrationAttempt :execrows
DELETE FROM public.registration_attempts a WHERE a.id = sqlc.arg('id')
AND ((a.state = 'pending' AND a.expires_at <= sqlc.arg('cutoff') AND a.result_user_id IS NULL)
  OR (a.state = 'failed' AND a.receipt_expires_at <= sqlc.arg('cutoff') AND a.result_user_id IS NULL)
  OR (a.state = 'completed' AND a.receipt_expires_at <= sqlc.arg('cutoff')
    AND a.result_user_id = sqlc.narg('result_user_id')
    AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = a.result_user_id AND h.is_active)));

-- name: RegistrationAttemptHeld :one
SELECT EXISTS (SELECT 1 FROM public.legal_holds WHERE account_ref = $1 AND is_active)::boolean;
