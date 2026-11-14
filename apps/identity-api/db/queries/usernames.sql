-- name: LockUsernamePolicy :one
SELECT * FROM public.username_active_policy WHERE singleton FOR SHARE;

-- name: GetUsernamePolicy :one
SELECT * FROM public.username_active_policy WHERE singleton;

-- name: GetUsernameArtifact :one
SELECT * FROM public.username_policy_artifacts WHERE policy_id = $1;

-- name: GetUsernameLookupKey :one
SELECT * FROM public.username_lookup_keys WHERE key_id = $1;

-- name: InstallUsernameArtifact :exec
INSERT INTO public.username_policy_artifacts(policy_id, fingerprint, artifact) VALUES($1,$2,$3)
ON CONFLICT (policy_id) DO NOTHING;

-- name: InstallUsernameLookupKey :exec
INSERT INTO public.username_lookup_keys(key_id, key_verifier) VALUES($1,$2)
ON CONFLICT (key_id) DO NOTHING;

-- name: UsernameReserved :one
SELECT EXISTS(SELECT 1 FROM public.users WHERE username_key = $1);

-- name: LookupUsername :one
SELECT id, username_key, username_details_encrypted, username_policy_id, username_policy_fingerprint,
    username_policy_epoch, username_lookup_key_id FROM public.users WHERE username_key = $1;

-- name: ReadUsername :one
SELECT id, username_key, username_details_encrypted, username_policy_id, username_policy_fingerprint,
    username_policy_epoch, username_lookup_key_id FROM public.users WHERE id = $1;

-- name: AssignUsername :execrows
UPDATE public.users SET username_key=$2, username_details_encrypted=$3, username_policy_id=$4,
    username_policy_fingerprint=$5, username_policy_epoch=$6, username_lookup_key_id=$7
WHERE id=$1 AND username_key IS NULL AND status='active' AND deleted_at IS NULL AND auth_version=$8;

-- name: ScanUsernameInventory :many
SELECT id, username_key, username_details_encrypted, username_policy_id, username_policy_fingerprint,
    username_policy_epoch, username_lookup_key_id FROM public.users
WHERE (sqlc.arg(first_page)::boolean OR id > sqlc.arg(after_id)::uuid)
ORDER BY id LIMIT sqlc.arg(page_size)::integer;

-- name: ListUsernameArtifacts :many
SELECT * FROM public.username_policy_artifacts ORDER BY policy_id LIMIT 1001;
