-- name: GetCurrentPrimaryContacts :one
-- One MVCC snapshot; do not assemble contacts from separate READ COMMITTED reads.
SELECT u.id, u.email, u.phone_encrypted, u.phone_blind_index,
       u.status, u.deleted_at, u.auth_version,
       email.evidence_encrypted AS email_evidence,
       phone.evidence_encrypted AS phone_evidence
FROM public.users u
LEFT JOIN public.contact_verification_evidence email ON email.user_id = u.id AND email.channel = 'email'
LEFT JOIN public.contact_verification_evidence phone ON phone.user_id = u.id AND phone.channel = 'phone'
WHERE u.id = sqlc.arg('user_id')::uuid AND u.deleted_at IS NULL;

-- name: SetUserEmailIfAuthorized :execrows
-- Caller owns account and row locks; the existing trigger removes old evidence.
UPDATE public.users SET email = sqlc.arg('email')::text, updated_at = NOW()
WHERE id = sqlc.arg('user_id')::uuid AND status = 'active' AND deleted_at IS NULL
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND sqlc.arg('expires_at')::timestamptz > clock_timestamp();

-- name: SetManagedUserPhone :execrows
UPDATE public.users
SET phone_encrypted = sqlc.arg('phone_encrypted')::bytea,
    phone_blind_index = sqlc.arg('phone_blind_index')::text, updated_at = NOW()
WHERE id = sqlc.arg('user_id')::uuid AND status = 'active' AND deleted_at IS NULL
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND sqlc.arg('expires_at')::timestamptz > clock_timestamp();

-- name: RemoveUserEmailIfAuthorized :execrows
-- Operation-level email removal admission belongs to the service, not the schema.
UPDATE public.users SET email = NULL, updated_at = NOW()
WHERE id = sqlc.arg('user_id')::uuid AND status = 'active' AND deleted_at IS NULL
  AND auth_version = sqlc.arg('auth_version')::bigint AND email IS NOT NULL
  AND sqlc.arg('expires_at')::timestamptz > clock_timestamp();

-- name: RemoveManagedUserPhone :execrows
UPDATE public.users SET phone_encrypted = NULL, phone_blind_index = NULL, updated_at = NOW()
WHERE id = sqlc.arg('user_id')::uuid AND status = 'active' AND deleted_at IS NULL
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND (phone_encrypted IS NOT NULL OR phone_blind_index IS NOT NULL)
  AND sqlc.arg('expires_at')::timestamptz > clock_timestamp();

-- name: CreateContactManagementActionProof :execrows
INSERT INTO public.contact_management_action_proofs
    (digest,user_id,session_id,dpop_jkt,auth_version,action,target,channel,contact_mac,expires_at)
SELECT sqlc.arg('digest')::bytea, sqlc.arg('user_id')::uuid,
       sqlc.arg('session_id')::text, sqlc.arg('dpop_jkt')::text,
       sqlc.arg('auth_version')::bigint, sqlc.arg('action')::text,
       sqlc.arg('target')::text, sqlc.arg('channel')::text,
       sqlc.arg('contact_mac')::bytea, sqlc.arg('expires_at')::timestamptz
WHERE sqlc.arg('expires_at')::timestamptz > clock_timestamp()
  AND sqlc.arg('expires_at')::timestamptz <= clock_timestamp() + INTERVAL '5 minutes';

-- name: GetContactManagementActionProof :one
SELECT expires_at,channel,contact_mac FROM public.contact_management_action_proofs
WHERE digest = sqlc.arg('digest')::bytea AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text AND dpop_jkt = sqlc.arg('dpop_jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = sqlc.arg('action')::text AND target = sqlc.arg('target')::text
  AND expires_at > clock_timestamp();

-- name: ConsumeContactManagementActionProof :one
-- Deciding reads follow account locks. DELETE needs no generic UPDATE privilege.
DELETE FROM public.contact_management_action_proofs
WHERE digest = sqlc.arg('digest')::bytea AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text AND dpop_jkt = sqlc.arg('dpop_jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint
  AND action = sqlc.arg('action')::text AND target = sqlc.arg('target')::text
  AND channel = sqlc.arg('channel')::text AND contact_mac = sqlc.arg('contact_mac')::bytea
  AND expires_at > clock_timestamp()
RETURNING expires_at,channel,contact_mac;

-- name: CleanupExpiredContactManagementActionProofs :execrows
WITH expired AS (
    SELECT digest FROM public.contact_management_action_proofs
    WHERE expires_at <= clock_timestamp() ORDER BY expires_at,digest
    LIMIT sqlc.arg('batch_size')::integer
)
DELETE FROM public.contact_management_action_proofs p USING expired e WHERE p.digest = e.digest;

-- name: CreateContactChangeAttempt :execrows
INSERT INTO public.contact_change_attempts
    (digest,user_id,session_id,dpop_jkt,auth_version,target,authorization_method,
     authorization_expires_at,channel,contact_mac,original_state_digest,destination_encrypted,expires_at)
SELECT sqlc.arg('digest')::bytea, sqlc.arg('user_id')::uuid,
       sqlc.arg('session_id')::text, sqlc.arg('dpop_jkt')::text,
       sqlc.arg('auth_version')::bigint, sqlc.arg('target')::text,
       sqlc.arg('authorization_method')::text, sqlc.arg('authorization_expires_at')::timestamptz,
       sqlc.narg('channel')::text, sqlc.narg('contact_mac')::bytea,
       sqlc.arg('original_state_digest')::bytea, sqlc.arg('destination_encrypted')::bytea,
       sqlc.arg('expires_at')::timestamptz
WHERE sqlc.arg('expires_at')::timestamptz > clock_timestamp();

-- name: GetContactChangeAttempt :one
SELECT * FROM public.contact_change_attempts
WHERE digest = sqlc.arg('digest')::bytea AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text AND dpop_jkt = sqlc.arg('dpop_jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint AND target = sqlc.arg('target')::text
  AND expires_at > clock_timestamp();

-- name: DeleteCurrentContactChangeAttempt :execrows
-- Only a fresh authorized start/removal may cancel current pending work.
DELETE FROM public.contact_change_attempts
WHERE user_id = sqlc.arg('user_id')::uuid AND target = sqlc.arg('target')::text;

-- name: ConsumeContactChangeAttempt :execrows
DELETE FROM public.contact_change_attempts
WHERE digest = sqlc.arg('digest')::bytea AND user_id = sqlc.arg('user_id')::uuid
  AND session_id = sqlc.arg('session_id')::text AND dpop_jkt = sqlc.arg('dpop_jkt')::text
  AND auth_version = sqlc.arg('auth_version')::bigint AND target = sqlc.arg('target')::text
  AND expires_at > clock_timestamp();

-- name: CleanupExpiredContactChangeAttempts :execrows
WITH expired AS (
    SELECT digest FROM public.contact_change_attempts
    WHERE expires_at <= clock_timestamp() ORDER BY expires_at,digest
    LIMIT sqlc.arg('batch_size')::integer
)
DELETE FROM public.contact_change_attempts p USING expired e WHERE p.digest = e.digest;
