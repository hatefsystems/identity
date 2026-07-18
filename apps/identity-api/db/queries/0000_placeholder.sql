-- PLACEHOLDER queries for Task 1.5 (sqlc pipeline wiring only).
--
-- Proves the sqlc -> Go pipeline generates compiling, type-safe code. REPLACED
-- by the real transactional queries in Task 2.2 (recovery-code lookup/deletion,
-- user CRUD, RBAC, audit log inserts). Do not build on this.

-- name: GetSchemaBootstrapCheck :one
SELECT id, note, created_at
FROM schema_bootstrap_check
WHERE id = $1;

-- name: CreateSchemaBootstrapCheck :exec
INSERT INTO schema_bootstrap_check (id, note)
VALUES ($1, $2);
