-- name: GeographyActiveRevision :one
SELECT active_revision FROM public.geography_catalog_state WHERE singleton;

-- name: GeographyLockState :one
SELECT active_revision FROM public.geography_catalog_state WHERE singleton FOR UPDATE;

-- name: GeographyCatalog :one
SELECT * FROM public.geography_catalogs WHERE revision = $1;

-- name: GeographyIdentity :one
SELECT * FROM public.geography_places WHERE id = $1;

-- name: GeographySnapshot :many
SELECT * FROM public.geography_place_versions WHERE revision = $1 ORDER BY id;

-- name: GeographyTypes :many
SELECT * FROM public.geography_types WHERE revision = $1 ORDER BY id;

-- name: GeographyIdentities :many
SELECT * FROM public.geography_places ORDER BY id;

-- name: GeographyInsertCatalog :exec
INSERT INTO public.geography_catalogs(revision,country,source_release,cities_sha256,types_sha256,
    cities_bytes,types_bytes,place_count,type_count,province_count,importer_version,normalization_version)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12);

-- name: GeographyInsertType :exec
INSERT INTO public.geography_types(revision,id,label) VALUES($1,$2,$3);

-- name: GeographyUpsertIdentity :batchexec
INSERT INTO public.geography_places(id,first_seen_revision,last_seen_revision) VALUES($1,$2,$2)
ON CONFLICT(id) DO UPDATE SET last_seen_revision=EXCLUDED.last_seen_revision;

-- name: GeographyInsertVersion :batchexec
INSERT INTO public.geography_place_versions(revision,id,label,type_id,parent_id,province_id,search_label)
VALUES($1,$2,$3,$4,$5,$6,$7);

-- name: GeographyActivate :exec
UPDATE public.geography_catalog_state SET active_revision = $1 WHERE singleton;

-- name: GeographyNextRevision :one
SELECT (COALESCE(max(revision),0) + 1)::bigint AS revision FROM public.geography_catalogs;
