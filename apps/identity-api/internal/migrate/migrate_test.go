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
//   - Forward-only retention migrations refuse reset without losing proof state.
package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

// testTimeout bounds the whole migration lifecycle per test run.
const testTimeout = 2 * time.Minute

// openTestDB connects to DATABASE_URL, skipping the test when the variable is
// unset or the database is unreachable (no Docker in the environment).
func openTestDB(ctx context.Context, t *testing.T) *sql.DB {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping migration integration test")
	}
	admin, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("configured migration database is unreachable: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := "migration_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create disposable migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop disposable migration database: %v", err)
		}
	})
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = name
	sqldb := stdlib.OpenDB(*cfg)
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	return sqldb
}

func TestInitialSchemaMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	sqldb := openTestDB(ctx, t)

	if err := Up(ctx, sqldb); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	t.Run("AllTablesCreated", func(t *testing.T) {
		tables := []string{
			"users", "roles", "permissions", "role_permissions", "user_roles",
			"webauthn_credentials", "recovery_codes", "mvp_audit_logs",
			"security_event_ledger", "security_ledger_head", "security_ledger_retention_settings",
			// Canonical format v2 (migration 00015): tamper-evidence lives in its
			// own append-only tables, and security_ledger_checkpoints is gone —
			// erasure no longer breaks a chain, so there is nothing to bridge.
			"audit_log_chain", "security_ledger_chain", "security_ledger_erasures", "audit_log_head",
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
			// Drives the retention worker's candidate scan, which pages by
			// (retain_until, seq). Replaced idx_security_ledger_retention_seq.
			"idx_security_ledger_retention",
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
		// Chain node first: the payload references it, and the FK is
		// ON DELETE RESTRICT so the ordering is enforced rather than conventional.
		var seq int64
		if err := sqldb.QueryRowContext(ctx,
			`INSERT INTO audit_log_chain (event_id, leaf_hash, chain_hash)
			 VALUES (gen_random_uuid(), sha256('leaf'), sha256('chain')) RETURNING seq`).Scan(&seq); err != nil {
			t.Fatalf("insert chain node: %v", err)
		}
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO mvp_audit_logs
				(seq, user_id, actor_id, actor_spiffe_id, event_type, action_status,
				 client_ip, user_agent, payload)
			 VALUES ($1, $2, $2, 'spiffe://hatef.ir/ns/identity/sa/idp-core',
				 'user.created', 'success', '127.0.0.1', 'go-test', '{}')`, seq, userID); err != nil {
			t.Fatalf("insert audit log: %v", err)
		}

		// The payload is immutable and un-truncatable for every role.
		if _, err := sqldb.ExecContext(ctx,
			`UPDATE mvp_audit_logs SET payload = 'tampered' WHERE seq = $1`, seq); err == nil {
			t.Fatal("expected UPDATE on mvp_audit_logs to be rejected")
		}
		if _, err := sqldb.ExecContext(ctx, `TRUNCATE mvp_audit_logs`); err == nil {
			t.Fatal("expected TRUNCATE on mvp_audit_logs to be rejected")
		}
		// The chain node is additionally undeletable: erasing a payload is a
		// retention operation, removing tamper-evidence never is.
		if _, err := sqldb.ExecContext(ctx,
			`UPDATE audit_log_chain SET chain_hash = sha256('x') WHERE seq = $1`, seq); err == nil {
			t.Fatal("expected UPDATE on audit_log_chain to be rejected")
		}
		if _, err := sqldb.ExecContext(ctx,
			`DELETE FROM audit_log_chain WHERE seq = $1`, seq); err == nil {
			t.Fatal("expected DELETE on audit_log_chain to be rejected")
		}

		// The GDPR hard-delete purge path (FK ON DELETE SET NULL) must remain
		// possible: deleting the user nulls user_id and keeps everything else
		// byte-identical, which is why user_id is excluded from the leaf digest.
		var leafBefore []byte
		if err := sqldb.QueryRowContext(ctx,
			`SELECT leaf_hash FROM audit_log_chain WHERE seq = $1`, seq).Scan(&leafBefore); err != nil {
			t.Fatalf("read leaf: %v", err)
		}
		if _, err := sqldb.ExecContext(ctx,
			`DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Fatalf("hard-delete user (expected to succeed): %v", err)
		}
		var gotUserID sql.NullString
		var leafAfter []byte
		if err := sqldb.QueryRowContext(ctx,
			`SELECT l.user_id, c.leaf_hash FROM mvp_audit_logs l
			 JOIN audit_log_chain c ON c.seq = l.seq WHERE l.seq = $1`, seq).
			Scan(&gotUserID, &leafAfter); err != nil {
			t.Fatalf("re-read audit log: %v", err)
		}
		if gotUserID.Valid {
			t.Errorf("expected audit log user_id to be NULL after user hard delete, got %q", gotUserID.String)
		}
		if !bytes.Equal(leafBefore, leafAfter) {
			t.Error("the GDPR purge altered the stored leaf digest")
		}
	})

	t.Run("ForwardOnlyRefusalPreservesState", func(t *testing.T) {
		// The genesis seed is derived, not 32 zero bytes, and the CHECK constraint
		// enforces it at seq 0 — so this insert doubles as a schema/code parity
		// assertion. See TestGenesisMatchesMigration.
		if _, err := sqldb.ExecContext(ctx,
			`INSERT INTO security_ledger_head(singleton,seq,chain_hash) VALUES(true,0,decode($1,'hex'))`,
			audit.GoldenLedgerGenesisHex); err != nil {
			t.Fatal(err)
		}
		if err := Reset(ctx, sqldb); err == nil || !strings.Contains(err.Error(), "forward-only") {
			t.Fatalf("expected forward-only reset refusal, got: %v", err)
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
		if count != 8 {
			t.Errorf("reset refusal lost schema tables: found %d", count)
		}
		var seq int64
		if err := sqldb.QueryRowContext(ctx, `SELECT seq FROM security_ledger_head WHERE singleton`).Scan(&seq); err != nil || seq != 0 {
			t.Fatalf("reset refusal lost initialized head: %d, %v", seq, err)
		}
		if err := Up(ctx, sqldb); err != nil {
			t.Fatalf("forward recovery after refused reset: %v", err)
		}
	})
}
