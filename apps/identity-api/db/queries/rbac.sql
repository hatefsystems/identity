-- Task 2.2: RBAC queries (roles, permissions, role_permissions, user_roles).
--
-- Backs the strict least-privilege RBAC model (architecture.md "Role-Based
-- Access Control"), the admin role-assignment API (api-design §1.7), and the
-- gRPC CheckPermission RPC (api-design §2.2 / Task 6.2).

-- name: CreateRole :one
-- Idempotent seed: roles are provisioned via IaC/bootstrap, so re-runs upsert
-- the description instead of failing.
INSERT INTO roles (id, description)
VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description
RETURNING *;

-- name: GetRole :one
SELECT * FROM roles
WHERE id = $1;

-- name: ListRoles :many
SELECT * FROM roles
ORDER BY id;

-- name: DeleteRole :execrows
-- FK cascades remove role_permissions and user_roles rows.
DELETE FROM roles
WHERE id = $1;

-- name: CreatePermission :one
INSERT INTO permissions (id, description)
VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description
RETURNING *;

-- name: ListPermissions :many
SELECT * FROM permissions
ORDER BY id;

-- name: AddPermissionToRole :exec
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemovePermissionFromRole :execrows
DELETE FROM role_permissions
WHERE role_id = $1
  AND permission_id = $2;

-- name: ListRolePermissions :many
SELECT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1
ORDER BY p.id;

-- name: AssignRoleToUser :exec
-- Super Admin only endpoint (api-design §1.7). Idempotent by design; every
-- assignment is additionally recorded in the immutable audit ledger.
INSERT INTO user_roles (user_id, role_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: RemoveRoleFromUser :execrows
DELETE FROM user_roles
WHERE user_id = $1
  AND role_id = $2;

-- name: ListUserRoles :many
SELECT r.* FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.id;

-- name: ListUserPermissions :many
-- Effective permission set: user -> roles -> role_permissions -> permissions.
SELECT DISTINCT p.* FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
JOIN user_roles ur ON ur.role_id = rp.role_id
WHERE ur.user_id = $1
ORDER BY p.id;

-- name: UserHasRole :one
SELECT EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_id = $1
      AND role_id = $2
) AS has_role;

-- name: UserHasPermission :one
-- Single-roundtrip RBAC evaluation for the gRPC CheckPermission RPC.
SELECT EXISTS (
    SELECT 1 FROM user_roles ur
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE ur.user_id = $1
      AND rp.permission_id = $2
) AS has_permission;
