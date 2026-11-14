// Integration tests for the consolidated final schema baseline.
//
// These tests require a reachable PostgreSQL instance addressed by
// DATABASE_URL must identify test provisioning credentials with CREATEDB.
// Only uniquely named run-owned databases are created and removed. Unset DSNs
// skip local tests; a configured but unreachable database fails.
//
// Coverage:
//   - Guarded Up creates the final application schema and new lineage.
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
	t.Logf("run-owned migration database: %s", name)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0"); err != nil {
		t.Fatalf("create disposable migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP DATABASE "+quoted); err != nil {
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
			// Canonical format v2: tamper-evidence lives in its
			// own append-only tables, and security_ledger_checkpoints is gone;
			// erasure no longer breaks a chain, so there is nothing to bridge.
			"audit_log_chain", "security_ledger_chain", "security_ledger_erasures", "audit_log_head",
			"legal_holds", "mfa_totp_enrollments", "deletion_requests", "event_outbox", "admin_action_contexts",
			"legal_governance_policies", "legal_governance_baseline", "legal_cases", "legal_case_subjects", "legal_case_holds",
			"legal_workflow_events", "legal_hold_reviews", "legal_workflow_replays", "legal_transparency_coverage",
			"legal_transparency_years", "legal_transparency_months", "legal_transparency_reports", "legal_transparency_replays",
			"deletion_notifications", "registration_attempts",
			"username_policy_artifacts", "username_lookup_keys", "username_active_policy",
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
		var count int
		if err := sqldb.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'identity_schema_version'`).Scan(&count); err != nil || count != 38 {
			t.Fatalf("final application table count: %d, %v", count, err)
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
			"idx_registration_pending_expiry", "idx_registration_receipt_expiry", "idx_registration_result_user",
			"users_username_key_unique",
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

	t.Run("OnlyReferenceSeedsAndFinalObjects", func(t *testing.T) {
		for table, want := range map[string]int{"roles": 4, "permissions": 13, "role_permissions": 15,
			"users": 0, "user_roles": 0, "audit_log_head": 0, "security_ledger_head": 0,
			"audit_log_chain": 0, "security_ledger_chain": 0, "security_ledger_retention_settings": 0,
			"legal_governance_baseline": 0, "legal_governance_policies": 0, "event_outbox": 0, "registration_attempts": 0,
			"username_policy_artifacts": 0, "username_lookup_keys": 0, "username_active_policy": 1} {
			var count int
			if err := sqldb.QueryRowContext(ctx, "SELECT count(*) FROM public."+table).Scan(&count); err != nil || count != want {
				t.Fatalf("%s reference seed boundary: %d, want %d, %v", table, count, want, err)
			}
		}
		var functions, sequences int
		if err := sqldb.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
			WHERE n.nspname='public' AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')`).Scan(&functions); err != nil || functions != 13 {
			t.Fatalf("final function inventory: %d, %v", functions, err)
		}
		if err := sqldb.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname='public' AND c.relkind='S' AND c.relname<>'identity_schema_version_id_seq'`).Scan(&sequences); err != nil || sequences != 3 {
			t.Fatalf("final sequence inventory: %d, %v", sequences, err)
		}
		for _, table := range []string{"audit_log_chain", "security_ledger_chain"} {
			var owned, defaultNextval bool
			if err := sqldb.QueryRowContext(ctx, `SELECT pg_catalog.pg_get_serial_sequence($1,'seq')=$2,
				a.attidentity='' AND pg_catalog.pg_get_expr(d.adbin,d.adrelid) LIKE 'nextval(%'
				FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
				WHERE a.attrelid=$1::regclass AND a.attname='seq'`, "public."+table, "public."+table+"_seq").Scan(&owned, &defaultNextval); err != nil || !owned || !defaultNextval {
				t.Fatalf("%s owned sequence/default changed: %v, %v, %v", table, owned, defaultNextval, err)
			}
		}
		var independent, restricted bool
		if err := sqldb.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend WHERE classid='pg_catalog.pg_class'::regclass
			AND objid='public.account_auth_epoch_seq'::regclass AND deptype IN ('a','i'))`).Scan(&independent); err != nil || !independent {
			t.Fatalf("account epoch sequence lost independence: %v, %v", independent, err)
		}
		if err := sqldb.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT 1 FROM public.role_permissions WHERE
			(role_id='support' AND permission_id='admin.users.read.pii') OR (role_id='super_admin' AND permission_id='admin.users.read'))`).Scan(&restricted); err != nil || !restricted {
			t.Fatalf("RBAC seed widened private data access: %v, %v", restricted, err)
		}
	})

	t.Run("PendingDeletionReservesIdentifier", func(t *testing.T) {
		execFixture(ctx, t, sqldb, `INSERT INTO public.users(email,status,deleted_at) VALUES('pending@test.local','pending_deletion',now())`)
		if _, err := sqldb.ExecContext(ctx, `INSERT INTO public.users(email) VALUES('pending@test.local')`); err == nil {
			t.Fatal("pending deletion identifier became reusable")
		}
	})

	t.Run("MonotonicAuthenticationVersions", func(t *testing.T) {
		var id string
		var version, epoch int64
		if err := sqldb.QueryRowContext(ctx, `INSERT INTO public.users(email) VALUES('authversion@test.local') RETURNING id,auth_version,auth_epoch`).Scan(&id, &version, &epoch); err != nil || version != 0 || epoch != 0 {
			t.Fatalf("initial auth state: %d, %d, %v", version, epoch, err)
		}
		if err := sqldb.QueryRowContext(ctx, `UPDATE public.users SET status='suspended' WHERE id=$1 RETURNING auth_version,auth_epoch`, id).Scan(&version, &epoch); err != nil || version != 1 || epoch < 1 {
			t.Fatalf("auth transition: %d, %d, %v", version, epoch, err)
		}
		var afterVersion, afterEpoch int64
		if err := sqldb.QueryRowContext(ctx, `UPDATE public.users SET display_name='Fixture' WHERE id=$1 RETURNING auth_version,auth_epoch`, id).Scan(&afterVersion, &afterEpoch); err != nil || afterVersion != version || afterEpoch != epoch {
			t.Fatalf("profile update changed auth boundary: %d, %d, %v", afterVersion, afterEpoch, err)
		}
		if _, err := sqldb.ExecContext(ctx, `UPDATE public.users SET auth_version=0 WHERE id=$1`, id); err == nil {
			t.Fatal("auth version decrement accepted")
		}
		if err := sqldb.QueryRowContext(ctx, `UPDATE public.users SET auth_version=auth_version+2 WHERE id=$1 RETURNING auth_version,auth_epoch`, id).Scan(&afterVersion, &afterEpoch); err != nil || afterVersion != 3 || afterEpoch <= epoch {
			t.Fatalf("explicit revocation did not advance epoch: %d, %d, %v", afterVersion, afterEpoch, err)
		}
	})

	t.Run("EncryptedLegalHoldsAndReleasedTombstones", func(t *testing.T) {
		for _, query := range []string{
			`INSERT INTO public.legal_holds(account_ref,applied_by) VALUES(gen_random_uuid(),gen_random_uuid())`,
			`INSERT INTO public.legal_holds(account_ref,applied_by,details_encrypted) VALUES(gen_random_uuid(),gen_random_uuid(),'\x')`,
			`INSERT INTO public.legal_holds(account_ref,applied_by,details_purged_at) VALUES(gen_random_uuid(),gen_random_uuid(),now())`,
		} {
			if _, err := sqldb.ExecContext(ctx, query); err == nil {
				t.Fatal("unencrypted active hold accepted")
			}
		}
		execFixture(ctx, t, sqldb, `INSERT INTO public.legal_holds(account_ref,applied_by,details_encrypted) VALUES(gen_random_uuid(),gen_random_uuid(),'\x01')`)
		execFixture(ctx, t, sqldb, `UPDATE public.legal_holds SET is_active=false,released_at=now(),details_encrypted=NULL,details_purged_at=now()`)
		var legacyColumns int
		if err := sqldb.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid='public.legal_holds'::regclass
			AND NOT attisdropped AND attname IN ('reason','requesting_authority','legal_basis')`).Scan(&legacyColumns); err != nil || legacyColumns != 0 {
			t.Fatalf("plaintext legal columns survived: %d, %v", legacyColumns, err)
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
