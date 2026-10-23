//go:build integration

package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func TestLifecycleCleanupPublishedOnlyAndHoldsIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	first, second := lifecycleCreate(t, f), lifecycleCreate(t, f)
	held, fresh := lifecycleCreate(t, f), lifecycleCreate(t, f)
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10), 4)
	lifecycleExec(t, f, "UPDATE event_outbox SET published_at=now()-interval '2 hours' WHERE lifecycle_user_id<>$1", fresh.ID)
	pending := lifecycleCreate(t, f)
	lifecycleExec(t, f, "UPDATE event_outbox SET next_attempt_at=now()-interval '2 hours' WHERE lifecycle_user_id=$1", pending.ID)
	lifecycleExec(t, f, "INSERT INTO legal_holds(account_ref,applied_by) VALUES ($1,$2)", held.ID, uuid.New())
	legacyID, malformedID, auditID, otherID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	lifecycleExec(t, f, `INSERT INTO event_outbox(id,subject,payload,published_at,admin_action) VALUES
		($1,$5,$6,now()-interval '2 hours',false),
		($2,$5,'{}',now()-interval '2 hours',false),
		($3,$5,$6,now()-interval '2 hours',true),
		($4,'audit.security',$6,now()-interval '2 hours',false)`,
		legacyID, malformedID, auditID, otherID, lifecycle.SubjectDeleted, fmt.Sprintf(`{"user_id":%q}`, uuid.New()))
	if n, err := lifecycle.CleanupPublished(f.ctx, f.pool, time.Hour, 20); n != 3 || !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatalf("cleanup did not delete only valid expired acknowledged rows: %d %v", n, err)
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id IN ($1,$2) OR id=$3", first.ID, second.ID, legacyID) != 0 {
		t.Fatal("eligible published rows were not cleaned")
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id IN ($1,$2,$3) OR id IN ($4,$5,$6)", held.ID, fresh.ID, pending.ID, malformedID, auditID, otherID) != 6 {
		t.Fatal("cleanup deleted held, fresh, pending, malformed or isolated audit data")
	}
	if lifecycleMessages(f.ctx, t, b.stream) != 4 {
		t.Fatal("DB cleanup modified broker replay history")
	}
	lifecycleExec(t, f, "UPDATE legal_holds SET is_active=false,released_at=now() WHERE account_ref=$1", held.ID)
	if n, err := lifecycle.CleanupPublished(f.ctx, f.pool, time.Hour, 20); n != 1 || !errors.Is(err, lifecycle.ErrInvalidEvent) {
		t.Fatalf("released hold remained ineligible or malformed row was removed: %d %v", n, err)
	}
}

func TestLifecycleHeldHistoryCannotMonopolizeCleanupBatchIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	held, eligible := lifecycleCreate(t, f), lifecycleCreate(t, f)
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 10), 2)
	lifecycleExec(t, f, "UPDATE event_outbox SET published_at=now()-interval '2 hours'")
	lifecycleExec(t, f, "UPDATE event_outbox SET published_at=now()-interval '3 hours' WHERE lifecycle_user_id=$1", held.ID)
	legacyUser, legacyEvent := uuid.New(), uuid.New()
	lifecycleExec(t, f, "INSERT INTO event_outbox(id,subject,payload,published_at) VALUES ($1,$2,$3,now()-interval '4 hours')",
		legacyEvent, lifecycle.SubjectDeleted, fmt.Sprintf(`{"user_id":%q}`, legacyUser))
	lifecycleExec(t, f, "INSERT INTO legal_holds(account_ref,applied_by) VALUES ($1,$3),($2,$3)", held.ID, legacyUser, uuid.New())
	if n, err := lifecycle.CleanupPublished(f.ctx, f.pool, time.Hour, 1); err != nil || n != 1 {
		t.Fatalf("held rows monopolized the bounded cleanup batch: %d %v", n, err)
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1", eligible.ID) != 0 ||
		lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1 OR id=$2", held.ID, legacyEvent) != 2 {
		t.Fatal("cleanup lost protected history or failed to reach eligible history")
	}
}

func TestLifecycleRetentionStartsAtPublicationNotTransactionStartIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	user := lifecycleCreate(t, f)
	tx := lifecycleTx(t, f)
	var id uuid.UUID
	if err := tx.QueryRow(f.ctx, "SELECT id FROM event_outbox WHERE lifecycle_user_id=$1", user.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	var acknowledgedAt, publishedAt time.Time
	if err := tx.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&acknowledgedAt); err != nil {
		t.Fatal(err)
	}
	if n, err := db.New(tx).MarkLifecyclePublished(f.ctx, id); err != nil || n != 1 {
		t.Fatalf("mark acknowledged event: %d %v", n, err)
	}
	if err := tx.QueryRow(f.ctx, "SELECT published_at FROM event_outbox WHERE id=$1", id).Scan(&publishedAt); err != nil || publishedAt.Before(acknowledgedAt) {
		t.Fatalf("retention counted time before publication: %v", err)
	}
}

type lifecycleLockObserver struct {
	lifecycle.Beginner
	entered chan struct{}
	once    sync.Once
}

type lifecycleObservedTx struct {
	pgx.Tx
	observer *lifecycleLockObserver
}

func (b *lifecycleLockObserver) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.Beginner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return lifecycleObservedTx{Tx: tx, observer: b}, nil
}

func (tx lifecycleObservedTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "pg_advisory_xact_lock") {
		tx.observer.once.Do(func() { close(tx.observer.entered) })
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func TestLifecycleCleanupRechecksHoldAfterAccountLockIntegration(t *testing.T) {
	f := newLifecycleDatabase(t)
	b := newLifecycleBroker(f.ctx, t, 1024*1024)
	user := lifecycleCreate(t, f)
	lifecycleRun(f.ctx, t, lifecyclePublisher(t, f.pool, b.js, b.opts.Name, 1), 1)
	lifecycleExec(t, f, "UPDATE event_outbox SET published_at=now()-interval '2 hours'")
	holdTx := lifecycleTx(t, f)
	if err := pglock.LockAccount(f.ctx, holdTx, user.ID); err != nil {
		t.Fatal(err)
	}
	observer := &lifecycleLockObserver{Beginner: f.pool, entered: make(chan struct{})}
	type result struct {
		n   int64
		err error
	}
	finished := make(chan result, 1)
	go func() {
		n, err := lifecycle.CleanupPublished(f.ctx, observer, time.Hour, 1)
		finished <- result{n, err}
	}()
	select {
	case <-observer.entered:
	case <-f.ctx.Done():
		t.Fatal("cleanup did not request account advisory lock")
	}
	if _, err := holdTx.Exec(f.ctx, "INSERT INTO legal_holds(account_ref,applied_by) VALUES ($1,$2)", user.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := holdTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-finished:
		if result.err != nil || result.n != 0 {
			t.Fatalf("cleanup used a pre-lock hold snapshot: %+v", result)
		}
	case <-f.ctx.Done():
		t.Fatal("cleanup did not return after hold transaction committed")
	}
	if lifecycleCount(t, f, "SELECT COUNT(*) FROM event_outbox WHERE lifecycle_user_id=$1", user.ID) != 1 {
		t.Fatal("new legal hold did not preserve published lifecycle metadata")
	}
}
