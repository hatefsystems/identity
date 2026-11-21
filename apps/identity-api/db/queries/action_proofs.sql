-- name: CreateAccountDeletionActionProof :execrows
-- The OTP's original deadline is never restamped. Expired issuance fails closed.
INSERT INTO public.account_deletion_action_proofs
    (proof_digest, user_id, session_id, jkt, auth_version, action, channel, contact_binding, expires_at)
SELECT sqlc.arg('proof_digest')::bytea, sqlc.arg('user_id')::uuid,
       sqlc.arg('session_id')::text, sqlc.arg('jkt')::text,
       sqlc.arg('auth_version')::bigint, 'account_deletion',
       sqlc.arg('channel')::text, sqlc.arg('contact_binding')::bytea,
       sqlc.arg('expires_at')::timestamptz
WHERE sqlc.arg('expires_at')::timestamptz > clock_timestamp()
  AND sqlc.arg('expires_at')::timestamptz <= clock_timestamp() + INTERVAL '5 minutes';

-- name: GetAccountDeletionActionProofBinding :one
-- Caller holds the account advisory and user row locks before reading a child.
SELECT channel, contact_binding FROM public.account_deletion_action_proofs
WHERE proof_digest = sqlc.arg('proof_digest')::bytea
  AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text
  AND jkt = sqlc.arg('jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = 'account_deletion'
  AND expires_at > clock_timestamp();

-- name: ConsumeAccountDeletionActionProof :execrows
-- Exactly one deleted row authorizes the action in this same caller transaction.
DELETE FROM public.account_deletion_action_proofs
WHERE proof_digest = sqlc.arg('proof_digest')::bytea
  AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text
  AND jkt = sqlc.arg('jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = 'account_deletion'
  AND channel = sqlc.arg('channel')::text
  AND contact_binding = sqlc.arg('contact_binding')::bytea
  AND expires_at > clock_timestamp();

-- name: CleanupExpiredAccountDeletionActionProofs :execrows
-- Bounded reclamation only; no scan API or UPDATE grant for row-lock syntax.
WITH expired AS (
    SELECT proof_digest FROM public.account_deletion_action_proofs
    WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at, proof_digest
    LIMIT sqlc.arg('batch_size')::integer
)
DELETE FROM public.account_deletion_action_proofs p
USING expired e WHERE p.proof_digest = e.proof_digest;

-- name: CreatePasswordChangeActionProof :execrows
INSERT INTO public.password_change_action_proofs
    (proof_digest, user_id, session_id, jkt, auth_version, action, channel, contact_binding, expires_at)
SELECT sqlc.arg('proof_digest')::bytea, sqlc.arg('user_id')::uuid,
       sqlc.arg('session_id')::text, sqlc.arg('jkt')::text,
       sqlc.arg('auth_version')::bigint, 'password_change',
       sqlc.arg('channel')::text, sqlc.arg('contact_binding')::bytea,
       sqlc.arg('expires_at')::timestamptz
WHERE sqlc.arg('expires_at')::timestamptz > clock_timestamp()
  AND sqlc.arg('expires_at')::timestamptz <= clock_timestamp() + INTERVAL '5 minutes';

-- name: GetPasswordChangeActionProofBinding :one
-- Non-consuming preflight; the consumer rechecks under account locks.
SELECT channel, contact_binding FROM public.password_change_action_proofs
WHERE proof_digest = sqlc.arg('proof_digest')::bytea
  AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text
  AND jkt = sqlc.arg('jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = 'password_change'
  AND expires_at > clock_timestamp();

-- name: ConsumePasswordChangeActionProof :execrows
-- Caller owns the READ COMMITTED transaction, including authorized no-ops.
DELETE FROM public.password_change_action_proofs
WHERE proof_digest = sqlc.arg('proof_digest')::bytea
  AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text
  AND jkt = sqlc.arg('jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = 'password_change'
  AND channel = sqlc.arg('channel')::text
  AND contact_binding = sqlc.arg('contact_binding')::bytea
  AND expires_at > clock_timestamp();

-- name: CleanupExpiredPasswordChangeActionProofs :execrows
WITH expired AS (
    SELECT proof_digest FROM public.password_change_action_proofs
    WHERE expires_at <= clock_timestamp()
    ORDER BY expires_at, proof_digest
    LIMIT sqlc.arg('batch_size')::integer
)
DELETE FROM public.password_change_action_proofs p
USING expired e WHERE p.proof_digest = e.proof_digest;
