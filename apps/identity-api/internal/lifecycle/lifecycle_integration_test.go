//go:build integration

package lifecycle_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	embedded "github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type lifecycleDatabase struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	provider *goose.Provider
}

func lifecycleDependency(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		if os.Getenv("REQUIRE_LIFECYCLE_INTEGRATION") == "1" {
			t.Fatalf("%s is required by mandatory lifecycle integration", key)
		}
		t.Skipf("%s is not configured", key)
	}
	return value
}

func newLifecycleDatabase(t *testing.T) lifecycleDatabase {
	t.Helper()
	dsn := lifecycleDependency(t, "DATABASE_URL")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL integration configuration")
	}
	t.Cleanup(admin.Close)
	ping, stop := context.WithTimeout(ctx, 5*time.Second)
	err = admin.Ping(ping)
	stop()
	if err != nil {
		t.Fatal("configured PostgreSQL integration dependency is unavailable")
	}
	schema := "lifecycle_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL integration configuration")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files := fstest.MapFS{}
	entries, err := fs.ReadDir(embedded.Migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		// Later audit migrations are deliberately public-specific. Never apply
		// them from this isolated fixture or touch another suite's tables.
		if entry.IsDir() || entry.Name() > "00010_account_auth_version.sql" && entry.Name() != "00016_user_lifecycle_events.sql" && entry.Name() != "00017_profile_names.sql" {
			continue
		}
		data, err := fs.ReadFile(embedded.Migrations, "migrations/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = &fstest.MapFile{Data: data}
	}
	sqlDB := stdlib.OpenDB(*cfg.ConnConfig)
	t.Cleanup(func() { _ = sqlDB.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	return lifecycleDatabase{ctx: ctx, pool: pool, provider: provider}
}

func lifecycleTx(t *testing.T, f lifecycleDatabase) pgx.Tx {
	t.Helper()
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	})
	return tx
}

func lifecycleExec(t *testing.T, f lifecycleDatabase, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func lifecycleCount(t *testing.T, f lifecycleDatabase, query string, args ...any) int64 {
	t.Helper()
	var count int64
	if err := f.pool.QueryRow(f.ctx, query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func lifecycleCreate(t *testing.T, f lifecycleDatabase) db.User {
	t.Helper()
	tx := lifecycleTx(t, f)
	user, err := lifecycle.CreateUser(f.ctx, tx, db.CreateUserParams{Email: uuid.NewString() + "@lifecycle.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return user
}

func lifecycleStatus(ctx context.Context, tx pgx.Tx, id uuid.UUID, after string) error {
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return err
	}
	q := db.New(tx)
	before, err := q.GetUserForUpdateIncludingDeleted(ctx, id)
	if err != nil {
		return err
	}
	if after == "pending_deletion" {
		count, err := q.SoftDeleteUser(ctx, id)
		if err != nil {
			return err
		}
		if count != 1 {
			return errors.New("expected exactly one soft delete")
		}
	} else if _, err := q.ModerateUserStatus(ctx, db.ModerateUserStatusParams{ID: id, Status: after}); err != nil {
		return err
	}
	return lifecycle.EnqueueStatusChange(ctx, q, id, before.Status, after)
}

func lifecycleChange(t *testing.T, f lifecycleDatabase, id uuid.UUID, after string) {
	t.Helper()
	tx := lifecycleTx(t, f)
	if err := lifecycleStatus(f.ctx, tx, id, after); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func lifecycleDelete(ctx context.Context, tx pgx.Tx, id uuid.UUID) (int64, error) {
	if err := pglock.LockAccount(ctx, tx, id); err != nil {
		return 0, err
	}
	q := db.New(tx)
	user, err := q.GetUserForUpdateIncludingDeleted(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count, err := q.HardDeleteUser(ctx, db.HardDeleteUserParams{ID: id, DeletedAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(-30 * 24 * time.Hour), Valid: true}})
	if err != nil || count != 1 {
		return count, err
	}
	return count, lifecycle.EnqueueDeletion(ctx, q, id, user.LifecycleRevision)
}

func TestLifecycleCreationTransactionIntegration(t *testing.T) {
	for _, mode := range []string{"commit", "rollback", "enqueue failure", "synthetic raw query"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifecycleDatabase(t)
			if mode == "enqueue failure" {
				lifecycleExec(t, f, `ALTER TABLE event_outbox ADD CONSTRAINT reject_created CHECK (subject <> 'identity.user.created')`)
			}
			tx := lifecycleTx(t, f)
			params := db.CreateUserParams{Email: uuid.NewString() + "@lifecycle.invalid", Status: "active"}
			var user db.User
			var err error
			if mode == "synthetic raw query" {
				user, err = db.New(tx).CreateUser(f.ctx, params)
			} else {
				user, err = lifecycle.CreateUser(f.ctx, tx, params)
			}
			if mode == "enqueue failure" {
				if !errors.Is(err, lifecycle.ErrEnqueue) {
					t.Fatalf("enqueue fault did not abort creation: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if count := lifecycleCount(t, f, "SELECT COUNT(*) FROM users"); count != 0 {
				t.Fatal("uncommitted creation visible outside business transaction")
			}
			if mode == "rollback" || mode == "enqueue failure" {
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal(err)
				}
				if lifecycleCount(t, f, "SELECT COUNT(*) FROM users") != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox") != 0 {
					t.Fatal("rollback left account or lifecycle intent")
				}
				return
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			stored, err := db.New(f.pool).GetUserByID(f.ctx, user.ID)
			if err != nil || stored.AuthVersion != 0 || stored.AuthEpoch != 0 {
				t.Fatalf("creation unexpectedly changed auth counters: %+v %v", stored, err)
			}
			if mode == "synthetic raw query" {
				if stored.LifecycleRevision != 0 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox") != 0 {
					t.Fatal("synthetic probe manufactured lifecycle intent")
				}
				return
			}
			if stored.LifecycleRevision != 1 || user.LifecycleRevision != 1 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND lifecycle_revision=1", user.ID) != 1 {
				t.Fatal("creation and revision-one intent did not commit atomically")
			}
		})
	}
}

func TestLifecycleStatusAndAuthCountersIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	user := lifecycleCreate(t, f)
	lifecycleChange(t, f, user.ID, "active")
	q := db.New(f.pool)
	noop, err := q.GetUserByID(f.ctx, user.ID)
	if err != nil || noop.LifecycleRevision != 1 || noop.AuthVersion != 1 || noop.AuthEpoch <= user.AuthEpoch || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox") != 1 {
		t.Fatalf("same-status moderation lost auth invalidation or emitted intent: %+v %v", noop, err)
	}
	lifecycleExec(t, f, `UPDATE users SET password_hash='test-only', phone_encrypted=$2, mfa_totp_secret_encrypted=$2, is_mfa_enabled=true WHERE id=$1`, user.ID, []byte("test-only-ciphertext"))
	credentials, err := q.GetUserByID(f.ctx, user.ID)
	if err != nil || credentials.LifecycleRevision != noop.LifecycleRevision || credentials.AuthVersion != noop.AuthVersion || credentials.AuthEpoch != noop.AuthEpoch || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox") != 1 {
		t.Fatalf("credential bookkeeping changed lifecycle/auth counters: %+v %v", credentials, err)
	}
	first := lifecycleTx(t, f)
	if err := lifecycleStatus(f.ctx, first, user.ID, "suspended"); err != nil {
		t.Fatal(err)
	}
	started, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			close(started)
			finished <- err
			return
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		close(started)
		if err = lifecycleStatus(f.ctx, tx, user.ID, "banned"); err == nil {
			err = tx.Commit(f.ctx)
		}
		finished <- err
	}()
	<-started
	if err := first.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-f.ctx.Done():
		t.Fatal("concurrent mutation did not finish")
	}
	final, err := q.GetUserByID(f.ctx, user.ID)
	if err != nil || final.LifecycleRevision != 3 || final.Status != "banned" || final.AuthVersion != 3 || final.AuthEpoch <= noop.AuthEpoch {
		t.Fatalf("concurrent status versions/counters invalid: %+v %v", final, err)
	}
	if lifecycleCount(t, f, `SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 AND ((lifecycle_revision=2 AND subject='identity.user.suspended') OR (lifecycle_revision=3 AND subject='identity.user.updated'))`, user.ID) != 2 {
		t.Fatal("concurrent changes did not allocate unique ordered revisions")
	}
}

func TestLifecyclePhysicalDeletionRollbackAndHoldIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	user := lifecycleCreate(t, f)
	lifecycleChange(t, f, user.ID, "pending_deletion")
	lifecycleExec(t, f, "UPDATE users SET deleted_at=now()-interval '31 days' WHERE id=$1", user.ID)
	lifecycleExec(t, f, "INSERT INTO legal_holds(account_ref,applied_by) VALUES ($1,$2)", user.ID, uuid.New())
	tx := lifecycleTx(t, f)
	if n, err := lifecycleDelete(f.ctx, tx, user.ID); err != nil || n != 0 {
		t.Fatalf("held account deleted: %d %v", n, err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	lifecycleExec(t, f, "UPDATE legal_holds SET is_active=false, released_at=now() WHERE account_ref=$1", user.ID)
	for _, fault := range []bool{false, true} {
		if fault {
			lifecycleExec(t, f, `ALTER TABLE event_outbox ADD CONSTRAINT reject_deleted CHECK (subject <> 'identity.user.deleted')`)
		}
		tx := lifecycleTx(t, f)
		n, err := lifecycleDelete(f.ctx, tx, user.ID)
		if n != 1 || fault && !errors.Is(err, lifecycle.ErrEnqueue) || !fault && err != nil {
			t.Fatalf("deletion fault=%v count=%d err=%v", fault, n, err)
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		if lifecycleCount(t, f, "SELECT COUNT(*) FROM users WHERE id=$1 AND lifecycle_revision=2", user.ID) != 1 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE subject=$1", lifecycle.SubjectDeleted) != 0 {
			t.Fatal("rollback lost account or retained a terminal event")
		}
	}
}

func TestLifecycleMigrationDownRefusesIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	user := lifecycleCreate(t, f)
	if _, err := f.provider.Down(f.ctx); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatalf("migration down accepted initialized lifecycle state: %v", err)
	}
	if lifecycleCount(t, f, "SELECT lifecycle_revision FROM users WHERE id=$1", user.ID) != 1 || lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1", user.ID) != 1 {
		t.Fatal("failed downgrade modified accepted lifecycle data")
	}
	// Retention cannot make a previously initialized revision safe to remove.
	lifecycleExec(t, f, "DELETE FROM event_outbox")
	if _, err := f.provider.Down(f.ctx); err == nil {
		t.Fatal("downgrade erased initialized revisions after outbox cleanup")
	}
}
