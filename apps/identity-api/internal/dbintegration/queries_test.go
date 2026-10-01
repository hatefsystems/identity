//go:build integration

// Integration tests for the Task 2.2 sqlc-generated query layer.
//
// Requires a reachable PostgreSQL instance at DATABASE_URL. The mandatory Nx
// security-DB target treats missing or unreachable PostgreSQL as a failure.
//
// Coverage matrix:
//   - Users:           CreateUser, GetUserByEmail, GetUserByID, blind-index
//     lookups, PII contact set/remove, MFA enable/disable,
//     soft-delete, reclaim (grace-window cancel), hard-delete
//     GDPR cron path, admin list + pagination.
//   - RBAC:            role/permission CRUD, user-role assignment, UserHasPermission.
//   - WebAuthn:        credential create/get/list, sign-count update, delete.
//   - Recovery codes:  batch create, atomic FOR UPDATE + physical delete in tx,
//     count, full regeneration.
//   - Audit logs:      InsertAuditLog, GetLatestChainHash, ListAuditLogs bounds,
//     ListAuditLogsForChainVerification keyset page.
package dbintegration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	. "github.com/hatefsystems/identity/apps/identity-api/internal/db" //nolint:revive // This suite intentionally exercises the complete generated query surface.
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// ── helpers ──────────────────────────────────────────────────────────────────

const testTimeout = 2 * time.Minute

// openTestPool connects via pgx and fails when DATABASE_URL is absent/down.
// It first applies the embedded goose migrations so the sqlc-generated schema
// exists, then isolates fixtures in a transaction. Soft deletion deliberately
// retains email reservations, so it cannot serve as repeatable test cleanup.
func openTestPool(ctx context.Context, t *testing.T) pgx.Tx {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL is required for integration-tag query tests")
	}

	sqldb, err := migrate.Open(ctx, url)
	if err != nil {
		t.Fatalf("open query integration database: %v", err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	_ = sqldb.Close()

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect query integration database: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin query fixture transaction: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tx.Rollback(cleanup); err != nil && err != pgx.ErrTxClosed {
			t.Errorf("roll back query fixtures: %v", err)
		}
	})
	return tx
}

// ts wraps a time.Time as pgtype.Timestamptz (valid).
func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// ptr returns a pointer to s (string helper).
func ptr(s string) *string { return &s }

// ── Users ─────────────────────────────────────────────────────────────────────

func TestUsersQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn := openTestPool(ctx, t)
	q := New(conn)

	t.Run("CreateAndGetByEmail", testUsersCreateAndGetByEmail(ctx, q))

	t.Run("GetByID", testUsersGetByID(ctx, q))
	t.Run("BlindIndexLookups", testUsersBlindIndexLookups(ctx, q))
	t.Run("MFALifecycle", testUsersMFALifecycle(ctx, q))
	t.Run("SoftDeleteAndReclaim", testUsersSoftDeleteAndReclaim(ctx, q))
	t.Run("HardDeleteGDPRPath", testUsersHardDeleteGDPR(ctx, q))
	t.Run("AdminListPagination", testUsersAdminList(ctx, q))
}

func testUsersCreateAndGetByEmail(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "create@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.Email != "create@test.local" {
			t.Errorf("email mismatch: got %q", u.Email)
		}

		got, err := q.GetUserByEmail(ctx, "create@test.local")
		if err != nil {
			t.Fatalf("GetUserByEmail: %v", err)
		}
		if got.ID != u.ID {
			t.Errorf("ID mismatch: got %v, want %v", got.ID, u.ID)
		}

		// Soft-delete the user so it doesn't pollute subsequent tests.
		if _, err := q.SoftDeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("cleanup SoftDeleteUser: %v", err)
		}
		// After soft-delete, GetUserByEmail must return no rows.
		if _, err := q.GetUserByEmail(ctx, "create@test.local"); err == nil {
			t.Error("expected no-rows after soft-delete, got nil error")
		}
	}
}

func testUsersGetByID(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "getbyid@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		got, err := q.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if got.ID != u.ID {
			t.Errorf("ID mismatch")
		}

		// Admin variant returns pending_deletion accounts.
		_, _ = q.SoftDeleteUser(ctx, u.ID)
		if _, err := q.GetUserByIDForAdmin(ctx, u.ID); err != nil {
			t.Errorf("GetUserByIDForAdmin should find pending_deletion user: %v", err)
		}
		// Regular lookup should now miss it.
		if _, err := q.GetUserByID(ctx, u.ID); err == nil {
			t.Error("GetUserByID should return no-rows for soft-deleted user")
		}
	}
}

func testUsersBlindIndexLookups(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "blind@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		phoneBlind := "phoneblind0000000000000000000000000000000000000000000000000000000"[:64]
		emailBlind := "emailblind000000000000000000000000000000000000000000000000000000"[:64]

		if _, err := q.SetUserPhone(ctx, SetUserPhoneParams{
			ID:              u.ID,
			PhoneEncrypted:  []byte("ciphertext-phone"),
			PhoneBlindIndex: &phoneBlind,
		}); err != nil {
			t.Fatalf("SetUserPhone: %v", err)
		}
		if _, err := q.SetUserBackupEmail(ctx, SetUserBackupEmailParams{
			ID:                    u.ID,
			BackupEmailEncrypted:  []byte("ciphertext-email"),
			BackupEmailBlindIndex: &emailBlind,
		}); err != nil {
			t.Fatalf("SetUserBackupEmail: %v", err)
		}

		byPhone, err := q.GetUserByPhoneBlindIndex(ctx, &phoneBlind)
		if err != nil {
			t.Fatalf("GetUserByPhoneBlindIndex: %v", err)
		}
		if byPhone.ID != u.ID {
			t.Errorf("phone blind index lookup returned wrong user")
		}

		byEmail, err := q.GetUserByBackupEmailBlindIndex(ctx, &emailBlind)
		if err != nil {
			t.Fatalf("GetUserByBackupEmailBlindIndex: %v", err)
		}
		if byEmail.ID != u.ID {
			t.Errorf("backup email blind index lookup returned wrong user")
		}

		// Remove clears the columns.
		if _, err := q.RemoveUserPhone(ctx, u.ID); err != nil {
			t.Fatalf("RemoveUserPhone: %v", err)
		}
		if _, err := q.RemoveUserBackupEmail(ctx, u.ID); err != nil {
			t.Fatalf("RemoveUserBackupEmail: %v", err)
		}
		if _, err := q.GetUserByPhoneBlindIndex(ctx, &phoneBlind); err == nil {
			t.Error("expected no-rows after RemoveUserPhone")
		}
	}
}

func testUsersMFALifecycle(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "mfa@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		// EnableMfa must be a no-op before a secret is stored (guard condition).
		rows, err := q.EnableMfa(ctx, u.ID)
		if err != nil {
			t.Fatalf("EnableMfa (no secret): %v", err)
		}
		if rows != 0 {
			t.Error("EnableMfa should affect 0 rows when no TOTP secret is set")
		}

		if _, err := q.SetMfaTotpSecret(ctx, SetMfaTotpSecretParams{
			ID:                     u.ID,
			MfaTotpSecretEncrypted: []byte("encrypted-totp-secret"),
		}); err != nil {
			t.Fatalf("SetMfaTotpSecret: %v", err)
		}

		rows, err = q.EnableMfa(ctx, u.ID)
		if err != nil {
			t.Fatalf("EnableMfa: %v", err)
		}
		if rows != 1 {
			t.Errorf("EnableMfa expected 1 row, got %d", rows)
		}

		got, err := q.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after EnableMfa: %v", err)
		}
		if !got.IsMfaEnabled {
			t.Error("expected is_mfa_enabled=true")
		}

		if _, err := q.DisableMfa(ctx, u.ID); err != nil {
			t.Fatalf("DisableMfa: %v", err)
		}
		got, _ = q.GetUserByID(ctx, u.ID)
		if got.IsMfaEnabled {
			t.Error("expected is_mfa_enabled=false after DisableMfa")
		}
		if got.MfaTotpSecretEncrypted != nil {
			t.Error("expected mfa_totp_secret_encrypted=NULL after DisableMfa")
		}
	}
}

func testUsersSoftDeleteAndReclaim(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "reclaim@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		if _, err := q.SoftDeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("SoftDeleteUser: %v", err)
		}

		// GetUserByID must miss a soft-deleted user.
		if _, err := q.GetUserByID(ctx, u.ID); err == nil {
			t.Error("expected no-rows for soft-deleted user")
		}

		// Reclaim within the 30-day window (cutoff well in the past).
		cutoff := ts(time.Now().AddDate(0, 0, -31))
		rows, err := q.ReclaimUser(ctx, ReclaimUserParams{
			ID:        u.ID,
			DeletedAt: cutoff,
		})
		if err != nil {
			t.Fatalf("ReclaimUser: %v", err)
		}
		if rows != 1 {
			t.Errorf("ReclaimUser expected 1 row, got %d", rows)
		}

		got, err := q.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after reclaim: %v", err)
		}
		if got.Status != "active" {
			t.Errorf("expected status=active after reclaim, got %q", got.Status)
		}

		// Cleanup.
		_, _ = q.SoftDeleteUser(ctx, u.ID)
	}
}

func testUsersHardDeleteGDPR(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{
			Email:  "harddelete@test.local",
			Status: "active",
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		if _, err := q.SoftDeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("SoftDeleteUser: %v", err)
		}

		// Hard-delete must be a no-op if deleted_at is NOT past the cutoff.
		futureCutoff := ts(time.Now().AddDate(0, 0, -1)) // cutoff = yesterday; deleted_at = just now
		rows, err := q.HardDeleteUser(ctx, HardDeleteUserParams{
			ID:        u.ID,
			DeletedAt: futureCutoff,
		})
		if err != nil {
			t.Fatalf("HardDeleteUser (too early): %v", err)
		}
		if rows != 0 {
			t.Error("HardDeleteUser should be no-op when not past cutoff")
		}

		// After the 30-day window, hard-delete must succeed.
		pastCutoff := ts(time.Now().AddDate(0, 0, 1)) // cutoff = tomorrow; deleted_at is in the past
		rows, err = q.HardDeleteUser(ctx, HardDeleteUserParams{
			ID:        u.ID,
			DeletedAt: pastCutoff,
		})
		if err != nil {
			t.Fatalf("HardDeleteUser: %v", err)
		}
		if rows != 1 {
			t.Errorf("HardDeleteUser expected 1 row, got %d", rows)
		}

		// Row must be physically gone.
		if _, err := q.GetUserByIDForAdmin(ctx, u.ID); err == nil {
			t.Error("expected no-rows after HardDeleteUser")
		}
	}
}

func testUsersAdminList(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		// Create two users in distinct statuses.
		u1, err := q.CreateUser(ctx, CreateUserParams{Email: "list1@test.local", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser u1: %v", err)
		}
		u2, err := q.CreateUser(ctx, CreateUserParams{Email: "list2@test.local", Status: "suspended"})
		if err != nil {
			t.Fatalf("CreateUser u2: %v", err)
		}
		t.Cleanup(func() {
			_, _ = q.SoftDeleteUser(ctx, u1.ID)
			_, _ = q.SoftDeleteUser(ctx, u2.ID)
		})

		// Unfiltered: both should appear (plus existing DB rows).
		all, err := q.ListUsers(ctx, ListUsersParams{PageLimit: 100, PageOffset: 0})
		if err != nil {
			t.Fatalf("ListUsers (no filter): %v", err)
		}
		found := map[uuid.UUID]bool{}
		for _, u := range all {
			found[u.ID] = true
		}
		if !found[u1.ID] || !found[u2.ID] {
			t.Error("both users should appear in unfiltered ListUsers")
		}

		// Status filter: only suspended.
		suspended, err := q.ListUsers(ctx, ListUsersParams{
			Status:     ptr("suspended"),
			PageLimit:  100,
			PageOffset: 0,
		})
		if err != nil {
			t.Fatalf("ListUsers (suspended): %v", err)
		}
		for _, u := range suspended {
			if u.Status != "suspended" {
				t.Errorf("unexpected status %q in filtered result", u.Status)
			}
		}

		// CountUsers.
		cnt, err := q.CountUsers(ctx, ptr("suspended"))
		if err != nil {
			t.Fatalf("CountUsers: %v", err)
		}
		if cnt == 0 {
			t.Error("expected at least 1 suspended user")
		}
	}
}

// ── RBAC ──────────────────────────────────────────────────────────────────────

func TestRBACQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn := openTestPool(ctx, t)
	q := New(conn)

	t.Run("RoleCRUD", testRBACRoleCRUD(ctx, q))
	t.Run("UserHasPermission", testRBACUserHasPermission(ctx, q))
}

func testRBACRoleCRUD(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		role, err := q.CreateRole(ctx, CreateRoleParams{
			ID:          "test-moderator",
			Description: "Test moderator role",
		})
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		t.Cleanup(func() { _, _ = q.DeleteRole(ctx, role.ID) })

		perm, err := q.CreatePermission(ctx, CreatePermissionParams{
			ID:          "test-users.suspend",
			Description: "Suspend user accounts",
		})
		if err != nil {
			t.Fatalf("CreatePermission: %v", err)
		}

		if err := q.AddPermissionToRole(ctx, AddPermissionToRoleParams{
			RoleID:       role.ID,
			PermissionID: perm.ID,
		}); err != nil {
			t.Fatalf("AddPermissionToRole: %v", err)
		}

		perms, err := q.ListRolePermissions(ctx, role.ID)
		if err != nil {
			t.Fatalf("ListRolePermissions: %v", err)
		}
		if len(perms) != 1 || perms[0].ID != perm.ID {
			t.Errorf("expected permission %q in role, got %v", perm.ID, perms)
		}

		// Idempotent upsert: re-creating the role must not fail.
		if _, err := q.CreateRole(ctx, CreateRoleParams{
			ID:          "test-moderator",
			Description: "Updated description",
		}); err != nil {
			t.Errorf("CreateRole upsert: %v", err)
		}

		roles, err := q.ListRoles(ctx)
		if err != nil {
			t.Fatalf("ListRoles: %v", err)
		}
		found := false
		for _, r := range roles {
			if r.ID == role.ID {
				found = true
			}
		}
		if !found {
			t.Error("created role not found in ListRoles")
		}
	}
}

func testRBACUserHasPermission(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{Email: "rbac-perm@test.local", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		role, err := q.CreateRole(ctx, CreateRoleParams{
			ID:          "test-support",
			Description: "Support role",
		})
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		t.Cleanup(func() { _, _ = q.DeleteRole(ctx, role.ID) })

		perm, err := q.CreatePermission(ctx, CreatePermissionParams{
			ID:          "test-users.read",
			Description: "Read user accounts",
		})
		if err != nil {
			t.Fatalf("CreatePermission: %v", err)
		}

		if err := q.AddPermissionToRole(ctx, AddPermissionToRoleParams{
			RoleID: role.ID, PermissionID: perm.ID,
		}); err != nil {
			t.Fatalf("AddPermissionToRole: %v", err)
		}
		if err := q.AssignRoleToUser(ctx, AssignRoleToUserParams{
			UserID: u.ID, RoleID: role.ID,
		}); err != nil {
			t.Fatalf("AssignRoleToUser: %v", err)
		}

		// UserHasPermission should be true via the role chain.
		has, err := q.UserHasPermission(ctx, UserHasPermissionParams{
			UserID: u.ID, PermissionID: perm.ID,
		})
		if err != nil {
			t.Fatalf("UserHasPermission: %v", err)
		}
		if !has {
			t.Error("expected UserHasPermission=true")
		}

		// UserHasRole should also be true.
		hasRole, err := q.UserHasRole(ctx, UserHasRoleParams{UserID: u.ID, RoleID: role.ID})
		if err != nil {
			t.Fatalf("UserHasRole: %v", err)
		}
		if !hasRole {
			t.Error("expected UserHasRole=true")
		}

		// After removing the role, permission should be lost.
		if _, err := q.RemoveRoleFromUser(ctx, RemoveRoleFromUserParams{
			UserID: u.ID, RoleID: role.ID,
		}); err != nil {
			t.Fatalf("RemoveRoleFromUser: %v", err)
		}
		has, _ = q.UserHasPermission(ctx, UserHasPermissionParams{
			UserID: u.ID, PermissionID: perm.ID,
		})
		if has {
			t.Error("expected UserHasPermission=false after role removal")
		}
	}
}

// ── WebAuthn ──────────────────────────────────────────────────────────────────

func TestWebauthnQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn := openTestPool(ctx, t)
	q := New(conn)

	t.Run("CredentialLifecycle", testWebauthnCredentialLifecycle(ctx, q))
}

func testWebauthnCredentialLifecycle(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{Email: "webauthn@test.local", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		credID := []byte("test-credential-id-unique-bytes")
		aaguid := uuid.MustParse("00000000-0000-0000-0000-000000000001")

		cred, err := q.CreateWebauthnCredential(ctx, CreateWebauthnCredentialParams{
			ID:              credID,
			UserID:          u.ID,
			PublicKey:       []byte("cose-public-key-bytes"),
			AttestationType: "none",
			SignCount:       0,
			UserPresent:     true,
			UserVerified:    false,
			BackupEligible:  false,
			BackupState:     false,
			Aaguid:          aaguid,
		})
		if err != nil {
			t.Fatalf("CreateWebauthnCredential: %v", err)
		}
		if string(cred.ID) != string(credID) {
			t.Errorf("credential ID mismatch")
		}

		// GetWebauthnCredential.
		fetched, err := q.GetWebauthnCredential(ctx, credID)
		if err != nil {
			t.Fatalf("GetWebauthnCredential: %v", err)
		}
		if fetched.SignCount != 0 {
			t.Errorf("expected sign_count=0, got %d", fetched.SignCount)
		}

		// GetWebauthnCredentialForUpdate (row-lock path, outside tx for this test).
		locked, err := q.GetWebauthnCredentialForUpdate(ctx, credID)
		if err != nil {
			t.Fatalf("GetWebauthnCredentialForUpdate: %v", err)
		}
		if string(locked.ID) != string(credID) {
			t.Errorf("locked credential ID mismatch")
		}

		// UpdateWebauthnSignCount.
		if _, err := q.UpdateWebauthnSignCount(ctx, UpdateWebauthnSignCountParams{
			ID:        credID,
			SignCount: 5,
		}); err != nil {
			t.Fatalf("UpdateWebauthnSignCount: %v", err)
		}
		updated, err := q.GetWebauthnCredential(ctx, credID)
		if err != nil {
			t.Fatalf("GetWebauthnCredential after sign count update: %v", err)
		}
		if updated.SignCount != 5 {
			t.Errorf("expected sign_count=5, got %d", updated.SignCount)
		}
		if !updated.LastUsedAt.Valid {
			t.Error("expected last_used_at to be set after UpdateWebauthnSignCount")
		}

		// ListWebauthnCredentialsByUser.
		list, err := q.ListWebauthnCredentialsByUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("ListWebauthnCredentialsByUser: %v", err)
		}
		if len(list) != 1 {
			t.Errorf("expected 1 credential, got %d", len(list))
		}

		// CountWebauthnCredentialsByUser.
		cnt, err := q.CountWebauthnCredentialsByUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("CountWebauthnCredentialsByUser: %v", err)
		}
		if cnt != 1 {
			t.Errorf("expected count=1, got %d", cnt)
		}

		// DeleteWebauthnCredential (scoped to user_id).
		rows, err := q.DeleteWebauthnCredential(ctx, DeleteWebauthnCredentialParams{
			ID:     credID,
			UserID: u.ID,
		})
		if err != nil {
			t.Fatalf("DeleteWebauthnCredential: %v", err)
		}
		if rows != 1 {
			t.Errorf("expected 1 deleted row, got %d", rows)
		}
		if _, err := q.GetWebauthnCredential(ctx, credID); err == nil {
			t.Error("expected no-rows after DeleteWebauthnCredential")
		}
	}
}

// ── Recovery codes ────────────────────────────────────────────────────────────

func TestRecoveryCodesQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn := openTestPool(ctx, t)
	q := New(conn)

	t.Run("AtomicVerifyAndDelete", testRecoveryCodesAtomicVerifyDelete(ctx, conn, q))
	t.Run("BatchCreateAndCount", testRecoveryCodesBatchCreateCount(ctx, q))
}

func testRecoveryCodesAtomicVerifyDelete(ctx context.Context, conn pgx.Tx, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{Email: "codes-atomic@test.local", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		hash := strings.Repeat("c", 64)
		_, err = q.CreateRecoveryCodes(ctx, []CreateRecoveryCodesParams{
			{UserID: u.ID, CodeHash: hash},
		})
		if err != nil {
			t.Fatalf("CreateRecoveryCodes: %v", err)
		}

		// Atomic verify-and-delete inside a real transaction.
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin tx: %v", err)
		}
		qtx := q.WithTx(tx)

		row, err := qtx.GetActiveRecoveryCodeForUpdate(ctx, GetActiveRecoveryCodeForUpdateParams{
			CodeHash: hash,
			UserID:   u.ID,
		})
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("GetActiveRecoveryCodeForUpdate: %v", err)
		}
		if row.CodeHash != hash {
			_ = tx.Rollback(ctx)
			t.Fatalf("code hash mismatch")
		}

		if _, err := qtx.DeleteRecoveryCodePhysically(ctx, row.ID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("DeleteRecoveryCodePhysically: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		// Code must be physically gone now.
		if _, err := q.GetActiveRecoveryCodeForUpdate(ctx, GetActiveRecoveryCodeForUpdateParams{
			CodeHash: hash,
			UserID:   u.ID,
		}); err == nil {
			t.Error("expected no-rows after physical delete")
		}

		// A second attempt with the same hash must also miss (replay prevention).
		if _, err := q.GetActiveRecoveryCodeForUpdate(ctx, GetActiveRecoveryCodeForUpdateParams{
			CodeHash: hash,
			UserID:   u.ID,
		}); err == nil {
			t.Error("replay: second use of the same recovery code must be rejected")
		}
	}
}

func testRecoveryCodesBatchCreateCount(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		u, err := q.CreateUser(ctx, CreateUserParams{Email: "codes-batch@test.local", Status: "active"})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		t.Cleanup(func() { _, _ = q.SoftDeleteUser(ctx, u.ID) })

		// Batch-insert 10 codes.
		batch := make([]CreateRecoveryCodesParams, 10)
		for i := range batch {
			batch[i] = CreateRecoveryCodesParams{
				UserID:   u.ID,
				CodeHash: strings.Repeat(string(rune('a'+i)), 64),
			}
		}
		inserted, err := q.CreateRecoveryCodes(ctx, batch)
		if err != nil {
			t.Fatalf("CreateRecoveryCodes batch: %v", err)
		}
		if inserted != 10 {
			t.Errorf("expected 10 rows inserted, got %d", inserted)
		}

		cnt, err := q.CountActiveRecoveryCodes(ctx, u.ID)
		if err != nil {
			t.Fatalf("CountActiveRecoveryCodes: %v", err)
		}
		if cnt != 10 {
			t.Errorf("expected count=10, got %d", cnt)
		}

		// DeleteAllRecoveryCodesForUser (regeneration).
		deleted, err := q.DeleteAllRecoveryCodesForUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("DeleteAllRecoveryCodesForUser: %v", err)
		}
		if deleted != 10 {
			t.Errorf("expected 10 deleted, got %d", deleted)
		}

		cnt, _ = q.CountActiveRecoveryCodes(ctx, u.ID)
		if cnt != 0 {
			t.Errorf("expected count=0 after DeleteAll, got %d", cnt)
		}
	}
}

// ── Audit logs ────────────────────────────────────────────────────────────────

func TestAuditLogQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	conn := openTestPool(ctx, t)
	q := New(conn)

	t.Run("InsertAndChainHash", testAuditInsertChainHash(ctx, q))
	t.Run("BoundedList", testAuditBoundedList(ctx, q))
	t.Run("ChainVerificationPage", testAuditChainVerification(ctx, q))
}

// auditParams builds an InsertAuditLogParams with sane defaults.
func auditParams(eventType, chainHash string) InsertAuditLogParams {
	return InsertAuditLogParams{
		ActorID:       uuid.New(),
		ActorSpiffeID: "spiffe://hatef.ir/ns/identity/sa/idp-core",
		EventType:     eventType,
		ActionStatus:  "success",
		ClientIp:      "127.0.0.1",
		UserAgent:     "go-test",
		Payload:       "{}",
		ChainHash:     chainHash,
	}
}

func testAuditInsertChainHash(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		hash1 := strings.Repeat("1", 64)
		rec, err := q.InsertAuditLog(ctx, auditParams("test.chain.first", hash1))
		if err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}
		if rec.ChainHash != hash1 {
			t.Errorf("chain hash mismatch on insert")
		}

		// Latest chain hash must be the one just inserted.
		latest, err := q.GetLatestAuditLogChainHash(ctx)
		if err != nil {
			t.Fatalf("GetLatestAuditLogChainHash: %v", err)
		}
		if latest != hash1 {
			t.Errorf("expected latest chain hash %q, got %q", hash1, latest)
		}

		// Insert a second record; latest must advance.
		hash2 := strings.Repeat("2", 64)
		if _, err := q.InsertAuditLog(ctx, auditParams("test.chain.second", hash2)); err != nil {
			t.Fatalf("InsertAuditLog second: %v", err)
		}
		latest, err = q.GetLatestAuditLogChainHash(ctx)
		if err != nil {
			t.Fatalf("GetLatestAuditLogChainHash second: %v", err)
		}
		if latest != hash2 {
			t.Errorf("expected latest chain hash %q, got %q", hash2, latest)
		}
	}
}

func testAuditBoundedList(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		hash := strings.Repeat("3", 64)
		if _, err := q.InsertAuditLog(ctx, auditParams("test.bounded.list", hash)); err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}

		now := time.Now()
		logs, err := q.ListAuditLogs(ctx, ListAuditLogsParams{
			StartTime: ts(now.Add(-time.Hour)),
			EndTime:   ts(now.Add(time.Hour)),
			EventType: ptr("test.bounded.list"),
			PageLimit: 10,
		})
		if err != nil {
			t.Fatalf("ListAuditLogs: %v", err)
		}
		if len(logs) == 0 {
			t.Fatal("expected at least 1 audit log in the window")
		}
		for _, l := range logs {
			if l.EventType != "test.bounded.list" {
				t.Errorf("event_type filter leaked: %q", l.EventType)
			}
			if l.ChainHash == "" {
				t.Error("chain_hash must be included for client-side verification")
			}
		}

		// A window entirely in the past must return zero rows (bounds respected).
		empty, err := q.ListAuditLogs(ctx, ListAuditLogsParams{
			StartTime: ts(now.Add(-48 * time.Hour)),
			EndTime:   ts(now.Add(-24 * time.Hour)),
			EventType: ptr("test.bounded.list"),
			PageLimit: 10,
		})
		if err != nil {
			t.Fatalf("ListAuditLogs (past window): %v", err)
		}
		if len(empty) != 0 {
			t.Errorf("expected 0 logs outside the window, got %d", len(empty))
		}

		// CountAuditLogs agrees with the filter.
		cnt, err := q.CountAuditLogs(ctx, CountAuditLogsParams{
			StartTime: ts(now.Add(-time.Hour)),
			EndTime:   ts(now.Add(time.Hour)),
			EventType: ptr("test.bounded.list"),
		})
		if err != nil {
			t.Fatalf("CountAuditLogs: %v", err)
		}
		if cnt == 0 {
			t.Error("expected CountAuditLogs >= 1")
		}
	}
}

func testAuditChainVerification(ctx context.Context, q *Queries) func(*testing.T) {
	return func(t *testing.T) {
		// Insert two ordered records.
		hashA := strings.Repeat("4", 64)
		hashB := strings.Repeat("5", 64)
		if _, err := q.InsertAuditLog(ctx, auditParams("test.verify.a", hashA)); err != nil {
			t.Fatalf("InsertAuditLog a: %v", err)
		}
		if _, err := q.InsertAuditLog(ctx, auditParams("test.verify.b", hashB)); err != nil {
			t.Fatalf("InsertAuditLog b: %v", err)
		}

		// Ascending keyset scan from genesis must return records in insertion
		// order. Ordering is by seq, not (timestamp, id): timestamp is the event's
		// true occurrence time and is supplied by the publisher, so two events can
		// share one — or arrive out of order — without that being tampering. seq is
		// assigned by the database at insert and is the only total order the chain
		// can be verified against.
		head, err := q.GetAuditLogHighWaterSeq(ctx)
		if err != nil {
			t.Fatal(err)
		}
		page, err := q.ListAuditLogsForChainVerification(ctx, ListAuditLogsForChainVerificationParams{
			ThroughSeq: head,
			AfterSeq:   0,
			PageLimit:  1000,
		})
		if err != nil {
			t.Fatalf("ListAuditLogsForChainVerification: %v", err)
		}
		if len(page) < 2 {
			t.Fatalf("expected at least 2 records, got %d", len(page))
		}
		for i := 1; i < len(page); i++ {
			prev, cur := page[i-1], page[i]
			if cur.Seq <= prev.Seq {
				t.Errorf("records out of ascending seq order at index %d: %d then %d",
					i, prev.Seq, cur.Seq)
			}
		}

		// The keyset boundary is exclusive: resuming from the first page's last seq
		// must not repeat it. An off-by-one here would make a verifier hash one
		// record twice and report a break in an intact chain.
		firstOnly, err := q.ListAuditLogsForChainVerification(ctx, ListAuditLogsForChainVerificationParams{
			ThroughSeq: head,
			AfterSeq:   0,
			PageLimit:  1,
		})
		if err != nil {
			t.Fatalf("ListAuditLogsForChainVerification (page 1): %v", err)
		}
		if len(firstOnly) != 1 {
			t.Fatalf("expected exactly 1 record with PageLimit=1, got %d", len(firstOnly))
		}
		next, err := q.ListAuditLogsForChainVerification(ctx, ListAuditLogsForChainVerificationParams{
			ThroughSeq: head,
			AfterSeq:   firstOnly[0].Seq,
			PageLimit:  1,
		})
		if err != nil {
			t.Fatalf("ListAuditLogsForChainVerification (page 2): %v", err)
		}
		if len(next) != 1 {
			t.Fatalf("expected exactly 1 record on page 2, got %d", len(next))
		}
		if next[0].Seq <= firstOnly[0].Seq {
			t.Errorf("keyset is inclusive: page 2 seq %d must exceed page 1 seq %d",
				next[0].Seq, firstOnly[0].Seq)
		}

		// InsertAuditLogs (copyfrom batch used by the Task 5.2 signing consumer).
		//
		// id is supplied by the caller rather than defaulted by the database. That is
		// what makes the pipeline idempotent: the publisher mints the id, ships it as
		// the JetStream Nats-Msg-Id, and the signer filters ids that already exist
		// before this COPY. A server-generated id would make a redelivered message a
		// brand-new row, silently duplicating events inside the hash chain.
		now := time.Now().UTC()
		batchIDs := []uuid.UUID{uuid.New(), uuid.New()}
		batch := []InsertAuditLogsParams{
			{
				ID:            batchIDs[0],
				ActorID:       uuid.New(),
				ActorSpiffeID: "spiffe://hatef.ir/ns/identity/sa/idp-core",
				EventType:     "test.batch.insert",
				ActionStatus:  "success",
				ClientIp:      "127.0.0.1",
				UserAgent:     "go-test",
				Payload:       "{}",
				Timestamp:     ts(now),
				ChainHash:     strings.Repeat("6", 64),
			},
			{
				ID:            batchIDs[1],
				ActorID:       uuid.New(),
				ActorSpiffeID: "spiffe://hatef.ir/ns/identity/sa/idp-core",
				EventType:     "test.batch.insert",
				ActionStatus:  "success",
				ClientIp:      "127.0.0.1",
				UserAgent:     "go-test",
				Payload:       "{}",
				Timestamp:     ts(now.Add(time.Millisecond)),
				ChainHash:     strings.Repeat("7", 64),
			},
		}
		n, err := q.InsertAuditLogs(ctx, batch)
		if err != nil {
			t.Fatalf("InsertAuditLogs batch: %v", err)
		}
		if n != 2 {
			t.Errorf("expected 2 batch rows inserted, got %d", n)
		}

		// FilterExistingAuditLogIDs is the signer's pre-COPY duplicate guard. It must
		// report exactly the ids already stored, so a mixed set of one known and one
		// unknown id is the case that matters: returning both would drop a real event,
		// returning neither would duplicate one.
		unknown := uuid.New()
		existing, err := q.FilterExistingAuditLogIDs(ctx, []uuid.UUID{batchIDs[0], unknown})
		if err != nil {
			t.Fatalf("FilterExistingAuditLogIDs: %v", err)
		}
		if len(existing) != 1 || existing[0] != batchIDs[0] {
			t.Errorf("FilterExistingAuditLogIDs = %v, want exactly [%v]", existing, batchIDs[0])
		}

		// The chain tip must be the most recent row by seq, which is the value the
		// signer seeds its in-memory chain from on startup.
		tip, err := q.GetLatestAuditLogChainHash(ctx)
		if err != nil {
			t.Fatalf("GetLatestAuditLogChainHash: %v", err)
		}
		if tip != strings.Repeat("7", 64) {
			t.Errorf("GetLatestAuditLogChainHash = %q, want the last batch row's hash", tip)
		}
	}
}
