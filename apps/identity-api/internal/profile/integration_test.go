//go:build integration

package profile

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	embedded "github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type profileDatabase struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	provider *goose.Provider
	service  *Service
}

func newProfileDatabase(t *testing.T, version int64) profileDatabase {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("REQUIRE_PROFILE_INTEGRATION") == "1" || os.Getenv("REQUIRE_PORTAL_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required by mandatory profile integration")
		}
		t.Skip("DATABASE_URL is not configured")
	}
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
	schema := "profile_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
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
		// Later legal/retention migrations intentionally target public. Include
		// only the account and profile migrations in this owned schema.
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
	if _, err := provider.UpTo(ctx, version); err != nil {
		t.Fatal(err)
	}
	service, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return profileDatabase{ctx: ctx, pool: pool, provider: provider, service: service}
}

func profileExec(t *testing.T, f profileDatabase, sql string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

func profileUser(t *testing.T, f profileDatabase) db.User {
	t.Helper()
	u, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: uuid.NewString() + "@profile.invalid", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func loadProfileUser(t *testing.T, f profileDatabase, id uuid.UUID) db.User {
	t.Helper()
	u, err := db.New(f.pool).GetUserByID(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func profileIntentCount(t *testing.T, f profileDatabase, id uuid.UUID) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestProfileNamesExistingRowsMigrationIntegration(t *testing.T) {
	f := newProfileDatabase(t, 16)
	id, credential := uuid.New(), []byte("old-test-credential")
	profileExec(t, f, "INSERT INTO users(id,email,status) VALUES ($1,$2,'active')", id, uuid.NewString()+"@profile.invalid")
	profileExec(t, f, "INSERT INTO webauthn_credentials(id,user_id,public_key,attestation_type,aaguid) VALUES ($1,$2,$3,'none',$4)", credential, id, []byte("test-key"), uuid.Nil)
	if _, err := f.provider.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
	u := loadProfileUser(t, f, id)
	var credentialName string
	if err := f.pool.QueryRow(f.ctx, "SELECT name FROM webauthn_credentials WHERE id=$1", credential).Scan(&credentialName); err != nil || credentialName != "" || u.DisplayName != "" || u.LifecycleRevision != 0 {
		t.Fatal("additive migration did not preserve empty names/revisions")
	}
	if profileIntentCount(t, f, id) != 0 {
		t.Fatal("migration invented historical lifecycle intent")
	}
	name := strings.Repeat("\U0001f600", 80)
	profileExec(t, f, "UPDATE users SET display_name=$2 WHERE id=$1", id, name)
	profileExec(t, f, "UPDATE webauthn_credentials SET name=$2 WHERE id=$1", credential, name)
	for _, query := range []string{"UPDATE users SET display_name=$1", "UPDATE webauthn_credentials SET name=$1"} {
		if _, err := f.pool.Exec(f.ctx, query, name+"x"); err == nil {
			t.Fatal("database accepted more than 80 code points")
		}
	}
	other := profileUser(t, f)
	profileExec(t, f, "UPDATE users SET display_name=$2 WHERE id=$1", other.ID, name)
	if _, err := f.provider.Down(f.ctx); err == nil || !strings.Contains(err.Error(), "forward-only") {
		t.Fatal("unsafe name-schema downgrade accepted")
	}
	profileExec(t, f, "DELETE FROM users WHERE id=$1", id)
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM webauthn_credentials WHERE user_id=$1", id).Scan(&count); err != nil || count != 0 {
		t.Fatal("credential name survived owner deletion")
	}
}

func TestProfileUpdateNoopConflictAndRollbackIntegration(t *testing.T) {
	for _, failEnqueue := range []bool{false, true} {
		t.Run(strconv.FormatBool(failEnqueue), func(t *testing.T) {
			f := newProfileDatabase(t, 17)
			u := profileUser(t, f)
			profileExec(t, f, "UPDATE users SET updated_at='2000-01-01Z',lifecycle_revision=$2 WHERE id=$1", u.ID, int64(1<<53+1))
			before := loadProfileUser(t, f, u.ID)
			if failEnqueue {
				profileExec(t, f, "ALTER TABLE event_outbox ADD CONSTRAINT reject_profile CHECK (subject <> 'identity.user.updated')")
			}
			result, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, " \u00a0Private name ", "9007199254740993")
			after := loadProfileUser(t, f, u.ID)
			if failEnqueue {
				if !errors.Is(err, ErrUnavailable) || result != (UpdateResult{}) || after.DisplayName != before.DisplayName || after.LifecycleRevision != before.LifecycleRevision || !after.UpdatedAt.Time.Equal(before.UpdatedAt.Time) || profileIntentCount(t, f, u.ID) != 0 {
					t.Fatal("enqueue failure did not roll back name, timestamp and revision")
				}
				return
			}
			if err != nil || !result.Changed || result.Profile.DisplayName != "Private name" || result.Profile.LifecycleRevision != "9007199254740994" || after.AuthVersion != before.AuthVersion || after.AuthEpoch != before.AuthEpoch || after.UpdatedAt.Time.Equal(before.UpdatedAt.Time) {
				t.Fatalf("profile commit affected the wrong state: %v", err)
			}
			var payload string
			if err := f.pool.QueryRow(f.ctx, "SELECT payload FROM event_outbox WHERE lifecycle_user_id=$1", u.ID).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			event, err := lifecycle.UnmarshalEvent([]byte(payload))
			if err != nil || event.SchemaVersion != lifecycle.SchemaVersionV2 || event.GetRevision() != 1<<53+2 || strings.Contains(payload, "Private name") || strings.Contains(payload, u.Email) {
				t.Fatal("stored profile intent is not exact metadata-only v2")
			}
			noop, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, " Private name ", result.Profile.LifecycleRevision)
			if err != nil || noop.Changed || noop.Profile != result.Profile {
				t.Fatalf("no-op changed the profile: %v", err)
			}
			if _, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, "Private name", "9007199254740993"); !errors.Is(err, ErrConflict) {
				t.Fatal("stale no-op bypassed revision conflict")
			}
			unchanged := loadProfileUser(t, f, u.ID)
			if !unchanged.UpdatedAt.Time.Equal(after.UpdatedAt.Time) || unchanged.LifecycleRevision != after.LifecycleRevision || profileIntentCount(t, f, u.ID) != 1 {
				t.Fatal("no-op/conflict modified timestamps, revision or outbox")
			}
			cleared, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, "", result.Profile.LifecycleRevision)
			if err != nil || !cleared.Changed || cleared.Profile.DisplayName != "" || cleared.Profile.LifecycleRevision != "9007199254740995" {
				t.Fatal("empty name did not clear shared profile")
			}
		})
	}
}

func TestProfileConcurrentWritersIntegration(t *testing.T) {
	f := newProfileDatabase(t, 17)
	u := profileUser(t, f)
	start, results := make(chan struct{}), make(chan error, 2)
	for _, name := range []string{"First", "Second"} {
		go func() {
			<-start
			_, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, name, "0")
			results <- err
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent profile update failed: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || loadProfileUser(t, f, u.ID).LifecycleRevision != 1 || profileIntentCount(t, f, u.ID) != 1 {
		t.Fatal("concurrent profile writes did not have exactly one winner")
	}
}

func TestProfileModerationLockRechecksAuthorityIntegration(t *testing.T) {
	for _, status := range []string{"active", "suspended", "banned", "pending_deletion"} {
		t.Run(status, func(t *testing.T) {
			f := newProfileDatabase(t, 17)
			u := profileUser(t, f)
			tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(f.ctx) }()
			if err := pglock.LockAccount(f.ctx, tx, u.ID); err != nil {
				t.Fatal(err)
			}
			q := db.New(tx)
			if _, err := q.GetUserForUpdateIncludingDeleted(f.ctx, u.ID); err != nil {
				t.Fatal(err)
			}
			if status == "pending_deletion" {
				_, err = q.SoftDeleteUser(f.ctx, u.ID)
			} else {
				_, err = q.ModerateUserStatus(f.ctx, db.ModerateUserStatusParams{ID: u.ID, Status: status})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := lifecycle.EnqueueStatusChange(f.ctx, q, u.ID, "active", status); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := f.service.Update(f.ctx, u.ID, u.AuthVersion, "Must not persist", "0")
				result <- err
			}()
			select {
			case err := <-result:
				t.Fatalf("profile did not wait for the account lock: %v", err)
			case <-time.After(25 * time.Millisecond):
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("stale captured authority wrote after moderation: %v", err)
			}
			var name string
			if err := f.pool.QueryRow(f.ctx, "SELECT display_name FROM users WHERE id=$1", u.ID).Scan(&name); err != nil || name != "" {
				t.Fatal("moderation/profile race persisted a stale edit")
			}
		})
	}
}
