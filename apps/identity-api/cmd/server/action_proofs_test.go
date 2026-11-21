package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

type cancelProofCleanup struct {
	t     *testing.T
	calls int
	stop  context.CancelFunc
}

func (c *cancelProofCleanup) CleanupExpired(ctx context.Context, batch int32) (int64, error) {
	c.t.Helper()
	c.calls++
	if batch != 1000 {
		c.t.Fatal("cleanup batch is not bounded")
	}
	if _, ok := ctx.Deadline(); !ok {
		c.t.Fatal("cleanup dependency has no timeout")
	}
	c.stop()
	return 0, errors.New("private proof and destination must not enter diagnostics")
}

func TestAccountDeletionProofMaintenanceIsBoundedAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := &cancelProofCleanup{t: t, stop: cancel}
	maintainAccountDeletionProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	if cleanup.calls != 1 {
		t.Fatal("cleanup retried or did not execute one bounded batch")
	}
	maintainAccountDeletionProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	if cleanup.calls != 1 {
		t.Fatal("canceled maintenance started another operation")
	}
}
