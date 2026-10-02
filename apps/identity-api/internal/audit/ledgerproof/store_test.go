package ledgerproof

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type snapshotPool struct {
	tx       *snapshotTx
	options  pgx.TxOptions
	beginErr error
	deadline time.Time
}

func (p *snapshotPool) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	p.options = options
	p.deadline, _ = ctx.Deadline()
	return p.tx, p.beginErr
}

type snapshotTx struct {
	pgx.Tx
	execSQL           string
	execErr, queryErr error
	rollback          bool
	cleanupErr        error
	cleanupDeadline   time.Time
	cancel            context.CancelFunc
}

func (tx *snapshotTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.execSQL = sql
	return pgconn.CommandTag{}, tx.execErr
}
func (tx *snapshotTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	if tx.cancel != nil {
		tx.cancel()
	}
	return snapshotRow{err: tx.queryErr}
}
func (tx *snapshotTx) Rollback(ctx context.Context) error {
	tx.rollback, tx.cleanupErr = true, ctx.Err()
	tx.cleanupDeadline, _ = ctx.Deadline()
	return nil
}

type snapshotRow struct{ err error }

func (r snapshotRow) Scan(...any) error { return r.err }

func TestSnapshotReadOnlyRepeatableReadSeparateAndBounded(t *testing.T) {
	tx := &snapshotTx{queryErr: pgx.ErrNoRows}
	pool := &snapshotPool{tx: tx}
	start := time.Now()
	r, err := VerifySnapshot(context.Background(), pool, Params{Limit: 10})
	if err != nil || r.Verified || r.FailureReason == nil || *r.FailureReason != "missing_head" {
		t.Fatalf("%+v %v", r, err)
	}
	if pool.options.IsoLevel != pgx.RepeatableRead || pool.options.AccessMode != pgx.ReadOnly {
		t.Fatalf("options %+v", pool.options)
	}
	if pool.deadline.IsZero() || pool.deadline.After(start.Add(16*time.Second)) || !tx.rollback || tx.cleanupErr != nil || tx.cleanupDeadline.IsZero() {
		t.Fatal("snapshot/cleanup not bounded")
	}
	if !strings.Contains(tx.execSQL, "statement_timeout") || !strings.Contains(tx.execSQL, "lock_timeout") || strings.Contains(tx.execSQL, "advisory") {
		t.Fatalf("unsafe setup %q", tx.execSQL)
	}
}

func TestSnapshotFailureAndCancelledCleanup(t *testing.T) {
	failure := errors.New("unavailable")
	for _, phase := range []string{"begin", "setup", "query"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tx := &snapshotTx{queryErr: failure, cancel: cancel}
			pool := &snapshotPool{tx: tx}
			if phase == "begin" {
				pool.beginErr = failure
			}
			if phase == "setup" {
				tx.execErr = failure
			}
			_, err := VerifySnapshot(ctx, pool, Params{Limit: 1})
			if !errors.Is(err, failure) {
				t.Fatal(err)
			}
			if phase != "begin" && (!tx.rollback || tx.cleanupErr != nil || tx.cleanupDeadline.IsZero()) {
				t.Fatal("cancelled/leaked cleanup")
			}
		})
	}
}
