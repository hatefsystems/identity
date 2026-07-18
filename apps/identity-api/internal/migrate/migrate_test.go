// Integration tests for the Task 2.1 initial schema migration.
//
// These tests require a reachable PostgreSQL instance addressed by
// DATABASE_URL (see .env.example / docker-compose.dev.yml). When DATABASE_URL
// is unset or the database is unreachable, they skip cleanly so plain
// `go test ./...` stays green without Docker.
//
// Coverage:
//   - goose Up creates all 8 tables + the goose version table.
//   - Required indexes exist (partial unique indexes included).
//   - Soft-delete email reuse works (partial unique index semantics).
//   - users.status CHECK constraint rejects unknown values.
//   - recovery_codes hash uniqueness applies only to unused codes.
//   - mvp_audit_logs is append-only: UPDATE/DELETE/TRUNCATE are rejected,
//     while the FK ON DELETE SET NULL path (GDPR hard-delete) still works.
//   - goose Down (reset) rolls everything back cleanly.
package migrate

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// testTimeout bounds the whole migration lifecycle per test run.
const testTimeout = 2 * time.Minute

// openTestDB connects to DATABASE_URL, skipping the test when the variable is
// unset or the database is unreachable (no Docker in the environment).
func openTestDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping migration integration test")
	}
	sqldb, err := Open(ctx, url)
	if err != nil {
		t.Skipf("database unreachable; skipping migration integration test: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	return sqldb
}

// resetToClean rolls back all migrations so each test starts from an empty
// schema regardless of previous runs.
func resetToClean(t *testing.T, ctx context.Context, sqldb *sql.DB) {
	t.Helper()
	if err := Reset(ctx, sqldb); err != nil {
		t.Fatalf("reset to clean state: %v", err)
	}
}

func TestInitialSchemaMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	sqldb := openTestDB(t, ctx)
	resetToClean(t, ctx, sqldb)

	if err := Up(ctx, sqldb); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// Leave a clean database behind even when subtests fail.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if err := Reset(cleanupCtx, sqldb); err != nil {
			t.Errorf("cleanup reset: %v", err)
		}
	})

	t.Run("AllTablesCreated", func(t *testing.T) {
		tables := []string{
			"users", "roles", "permissions", "role_permissions", "user_roles",
			"webauthn_credentials", "recovery_codes", "mvp_audit_logs",
		}
		for _, table := range tables {
			var exists bool
			err := sqldb.QueryRowContext(ctx,
				`SELECT EXISTS (
					SELECT 1 FROM information_schema.tables
					WHERE table_schema = 'public' AND table_name = $1
				)`, table).Scan(&exists)
			if err != nil {
				t.Fatalf("check table %s: %v", table, err)
			}
			if !exists {
				t.Errorf("expected table %q to exist", table)
			}
		}
	})

	t.Run("RequiredIndexesCreated", func(t *testing.T) {
		indexes := []string{
			"idx_users_email", "idx_users_status",
			"idx_users_phone_blind", "idx_users_backup_email_blind",
			"idx_webauthn_user_id",
			"idx_recovery_codes_hash", "idx_recovery_codes_user_id",
			"idx_mvp_audit_logs_event_type", "idx_mvp_audit_logs_timestamp",
		}
		for _, index := range indexes {
			var exists bool
			err := sqldb.QueryRowContext(ctx,
				`SELECT EXISTS (
					SELECT 1 FROM pg_indexes
					WHERE schemaname = 'public' AND indexname = $1
				)`, index).Scan(&exists)
			if err != nil {
				t.Fatalf("check index %s: %v", index, err)
			}
			if !exists {
				t.Errorf("expected index %q to exist", index)
			}
		}
	})

	t.Run("EmailReusableAfterSoftDelete", func(t *testing.T) {
		const email = "reuse@test.local"
		// Active account claims the email.
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO users (email) VALUES ($1)`, email); err != nil {
			t.Fatalf("insert first user: %v", err)
		}
		// A second active account with the same email must be rejected.
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO users (email) VALUES ($1)`, email); err == nil {
			t.Fatal("expected duplicate active email to violate idx_users_email")
		}
		// Soft-delete the original; the email becomes reusable.
		if _, err := sqldb.ExecContext(ctx,
			`UPDATE users SET deleted_at = NOW() WHERE email = $1`, email); err != nil {
			t.Fatalf("soft-delete user: %v", err)
		}
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO users (email) VALUES ($1)`, email); err != nil {
			t.Errorf("expected email reuse after soft delete, got: %v", err)
		}
	})

	t.Run("UserStatusCheckConstraint", func(t *testing.T) {
		_, err := sqldb.ExecContext(ctx,
			`INSERT INTO users (email, status) VALUES ('badstatus@test.local', 'nonsense')`)
		if err == nil {
			t.Fatal("expected CHECK constraint to reject unknown status")
		}
	})

	t.Run("RecoveryCodeHashUniqueOnlyWhileUnused", func(t *testing.T) {
		var userID string
		if err := sqldb.QueryRowContext(ctx,
			`INSERT INTO users (email) VALUES ('codes@test.local') RETURNING id`).Scan(&userID); err != nil {
			t.Fatalf("insert user: %v", err)
		}
		hash := strings.Repeat("a", 64)
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash); err != nil {
			t.Fatalf("insert recovery code: %v", err)
		}
		// Duplicate unused hash must violate the partial unique index.
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash); err == nil {
			t.Fatal("expected duplicate unused code_hash to violate idx_recovery_codes_hash")
		}
		// Marking the original used frees the hash for a fresh code.
		if _, err := sqldb.ExecContext(ctx,
			`UPDATE recovery_codes SET used_at = NOW() WHERE code_hash = $1`, hash); err != nil {
			t.Fatalf("mark code used: %v", err)
		}
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash); err != nil {
			t.Errorf("expected reuse of hash after used_at set, got: %v", err)
		}
	})

	t.Run("AuditLogsAppendOnly", func(t *testing.T) {
		var userID string
		if err := sqldb.QueryRowContext(ctx,
			`INSERT INTO users (email) VALUES ('audit@test.local') RETURNING id`).Scan(&userID); err != nil {
			t.Fatalf("insert user: %v", err)
		}
		var logID string
		err := sqldb.QueryRowContext(ctx,
			`INSERT INTO mvp_audit_logs
				(user_id, actor_id, actor_spiffe_id, event_type, action_status,
				 client_ip, user_agent, payload, chain_hash)
			 VALUES ($1, $1, 'spiffe://hatef.ir/ns/identity/sa/idp-core',
				 'user.created', 'success', '127.0.0.1', 'go-test', '{}', $2)
			 RETURNING id`, userID, strings.Repeat("b", 64)).Scan(&logID)
		if err != nil {
			t.Fatalf("insert audit log: %v", err)
		}

		// Direct UPDATE must be rejected by the append-only trigger.
		if _, err := sqldb.ExecContext(ctx,
			`UPDATE mvp_audit_logs SET payload = 'tampered' WHERE id = $1`, logID); err == nil {
			t.Fatal("expected UPDATE on mvp_audit_logs to be rejected")
		}
		// Direct DELETE must be rejected.
		if _, err := sqldb.ExecContext(ctx,
			`DELETE FROM mvp_audit_logs WHERE id = $1`, logID); err == nil {
			t.Fatal("expected DELETE on mvp_audit_logs to be rejected")
		}
		// TRUNCATE must be rejected.
		if _, err := sqldb.ExecContext(ctx, `TRUNCATE mvp_audit_logs`); err == nil {
			t.Fatal("expected TRUNCATE on mvp_audit_logs to be rejected")
		}

		// The GDPR hard-delete purge path (FK ON DELETE SET NULL) must remain
		// possible: deleting the user nulls user_id but keeps the ledger row.
		if _, err := sqldb.ExecContext(ctx,
			`DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Fatalf("hard-delete user (expected to succeed): %v", err)
		}
		var gotUserID sql.NullString
		if err := sqldb.QueryRowContext(ctx,
			`SELECT user_id FROM mvp_audit_logs WHERE id = $1`, logID).Scan(&gotUserID); err != nil {
			t.Fatalf("re-read audit log: %v", err)
		}
		if gotUserID.Valid {
			t.Errorf("expected audit log user_id to be NULL after user hard delete, got %q", gotUserID.String)
		}
	})

	t.Run("DownLeavesCleanSchema", func(t *testing.T) {
		if err := Reset(ctx, sqldb); err != nil {
			t.Fatalf("roll back migrations: %v", err)
		}
		var count int
		err := sqldb.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.tables
			 WHERE table_schema = 'public'
			   AND table_name IN ('users', 'roles', 'permissions', 'role_permissions',
				 'user_roles', 'webauthn_credentials', 'recovery_codes', 'mvp_audit_logs')`).Scan(&count)
		if err != nil {
			t.Fatalf("count remaining tables: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 schema tables after down, found %d", count)
		}
		// Re-apply so the cleanup Reset in t.Cleanup has state to remove and
		// the database is usable for subsequent local runs.
		if err := Up(ctx, sqldb); err != nil {
			t.Fatalf("re-apply migrations: %v", err)
		}
	})
}
