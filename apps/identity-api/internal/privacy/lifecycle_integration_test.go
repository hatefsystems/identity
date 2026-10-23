//go:build integration

package privacy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
)

type rejectLifecycleBeginner struct{ pool *pgxpool.Pool }

func (b rejectLifecycleBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return rejectLifecycleTx{tx}, nil
}

type rejectLifecycleTx struct{ pgx.Tx }

func (tx rejectLifecycleTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "-- name: InsertLifecycleEvent") {
		return pgconn.CommandTag{}, errors.New("injected lifecycle persistence failure")
	}
	return tx.Tx.Exec(ctx, query, args...)
}

func TestPrivacyLifecycleIntentFailureRollsBackIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	user := createTestUser(ctx, t, pool, "lifecycle-rollback@privacy.test")
	env.svc.tx = rejectLifecycleBeginner{pool}
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); !errors.Is(err, lifecycle.ErrEnqueue) {
		t.Fatalf("missing soft-delete intent was accepted: %v", err)
	}
	stored, err := env.queries.GetUserByIDForAdmin(ctx, user.ID)
	if err != nil || stored.Status != "active" || stored.DeletedAt.Valid || stored.LifecycleRevision != 0 || stored.AuthVersion != user.AuthVersion {
		t.Fatalf("soft-delete state escaped rollback: %v", err)
	}
	if env.notifier.count() != 0 || countRows(ctx, t, pool, "SELECT COUNT(*) FROM deletion_requests WHERE user_id=$1", user.ID) != 0 {
		t.Fatal("failed soft deletion created a notification or recovery request")
	}
	env.svc.tx = pool
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatal(err)
	}
	notice, _ := env.notifier.last()
	env.svc.tx = rejectLifecycleBeginner{pool}
	if err := env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, lifecycle.ErrEnqueue) {
		t.Fatalf("missing reclaim intent was accepted: %v", err)
	}
	stored, err = env.queries.GetUserByIDForAdmin(ctx, user.ID)
	if err != nil || stored.Status != "pending_deletion" || !stored.DeletedAt.Valid || stored.LifecycleRevision != 1 {
		t.Fatalf("reclaim state escaped rollback: %v", err)
	}
	if countRows(ctx, t, pool, "SELECT COUNT(*) FROM deletion_requests WHERE user_id=$1 AND consumed_at IS NULL", user.ID) != 1 ||
		countRows(ctx, t, pool, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1", user.ID) != 1 {
		t.Fatal("failed reclaim retired the token or persisted another intent")
	}
}
