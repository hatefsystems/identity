//go:build integration

package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func TestPersistentAccountCutoffIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for account cutoff integration tests")
	}
	sqlDB, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqlDB.Close() }()
	if err := migrate.Up(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := db.New(pool)
	newUser := func(t *testing.T) db.User {
		t.Helper()
		u, err := q.CreateUser(ctx, db.CreateUserParams{Email: uuid.NewString() + "@auth-cutoff.invalid", Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", u.ID) })
		return u
	}
	update := func(t *testing.T, id uuid.UUID, status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, "UPDATE users SET status=$2 WHERE id=$1", id, status); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("two instances and monotonic epoch", func(t *testing.T) {
		u := newUser(t)
		var managers []*session.Manager
		var cookies []*http.Cookie
		for range 2 {
			codec, err := session.NewCookieCodec(session.CookieConfig{Name: "session", TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			manager, err := session.NewManager(session.NewMemoryStore(), codec, session.ManagerConfig{
				AbsoluteTTL: time.Hour, IdleTTL: time.Hour, AccountState: session.NewDBAccountState(pool),
			})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			if _, err := manager.IssueContext(ctx, w, session.IssueParams{UserID: u.ID.String(), AuthVersion: u.AuthVersion, AuthVersionSet: true}); err != nil {
				t.Fatal(err)
			}
			managers, cookies = append(managers, manager), append(cookies, w.Result().Cookies()[0])
		}
		accounts := session.NewDBAccountState(pool)
		before, err := accounts.Epoch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []string{"banned", "active"} {
			update(t, u.ID, status)
			for i, manager := range managers {
				r := httptest.NewRequest(http.MethodGet, "https://identity.test", nil).WithContext(ctx)
				r.AddCookie(cookies[i])
				if _, err := manager.Authenticate(r); !errors.Is(err, session.ErrAccountIneligible) {
					t.Fatalf("instance %d status %s revived session: %v", i, status, err)
				}
			}
		}
		current, err := q.GetAccountAuthState(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		after, err := accounts.Epoch(ctx)
		if err != nil || current.AuthVersion != u.AuthVersion+2 || current.AuthEpoch <= before || after <= current.AuthEpoch {
			t.Fatalf("cutoff order before=%d current=%+v after=%d err=%v", before, current, after, err)
		}
		if err := accounts.Validate(ctx, u.ID.String(), current.AuthVersion); err != nil {
			t.Fatalf("fresh authentication rejected: %v", err)
		}
	})

	t.Run("restriction wins before issuance", func(t *testing.T) {
		u := newUser(t)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		for _, status := range []string{"banned", "active"} {
			if _, err := tx.Exec(ctx, "UPDATE users SET status=$2 WHERE id=$1", u.ID, status); err != nil {
				t.Fatal(err)
			}
		}
		var issued atomic.Bool
		result := make(chan error, 1)
		go func() {
			result <- session.NewDBAccountState(pool).WithActive(ctx, u.ID.String(), u.AuthVersion, func() error { issued.Store(true); return nil })
		}()
		waitForAccountLockWaiter(ctx, t, pool, tx.Conn().PgConn().PID())
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, session.ErrAccountIneligible) || issued.Load() {
			t.Fatalf("old authentication issued after waiting: issued=%v err=%v", issued.Load(), err)
		}
	})

	t.Run("issuance holds account lock", func(t *testing.T) {
		u := newUser(t)
		accounts := session.NewDBAccountState(pool)
		err := accounts.WithActive(ctx, u.ID.String(), u.AuthVersion, func() error {
			blocked, stop := context.WithTimeout(ctx, 200*time.Millisecond)
			defer stop()
			_, err := pool.Exec(blocked, "UPDATE users SET status='banned' WHERE id=$1", u.ID)
			if !errors.Is(err, context.DeadlineExceeded) {
				return errors.New("moderation did not wait for the issuance account lock")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		update(t, u.ID, "banned")
		update(t, u.ID, "active")
		if err := accounts.Validate(ctx, u.ID.String(), u.AuthVersion); !errors.Is(err, session.ErrAccountIneligible) {
			t.Fatalf("issued credential survived a later restriction: %v", err)
		}
	})

	t.Run("mutation rechecks live permission after waiting", func(t *testing.T) {
		u := newUser(t)
		if err := q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: u.ID, RoleID: "moderator"}); err != nil {
			t.Fatal(err)
		}
		permission := db.UserHasPermissionParams{UserID: u.ID, PermissionID: "admin.users.status.write"}
		if allowed, err := q.UserHasPermission(ctx, permission); err != nil || !allowed {
			t.Fatalf("entry permission: %v %v", allowed, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := pglock.LockAccount(ctx, tx, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.New(tx).GetUserForUpdateIncludingDeleted(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.New(tx).RemoveRoleFromUser(ctx, db.RemoveRoleFromUserParams{UserID: u.ID, RoleID: "moderator"}); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			mutation, err := pool.Begin(ctx)
			if err != nil {
				result <- err
				return
			}
			defer func() { _ = mutation.Rollback(context.Background()) }()
			result <- rbac.LockAuthorized(ctx, mutation, u.ID, []uuid.UUID{u.ID, uuid.New()}, permission.PermissionID, u.AuthVersion)
		}()
		waitForAccountLockWaiter(ctx, t, pool, tx.Conn().PgConn().PID())
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, rbac.ErrForbidden) {
			t.Fatalf("entry permission was reused after revocation: %v", err)
		}
	})
}

func waitForAccountLockWaiter(ctx context.Context, t *testing.T, pool *pgxpool.Pool, holder uint32) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))", int64(holder)).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
