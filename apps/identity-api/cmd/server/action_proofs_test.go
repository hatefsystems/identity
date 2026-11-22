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

func (c *cancelProofCleanup) CleanupExpiredPasswordChange(ctx context.Context, batch int32) (int64, error) {
	return c.CleanupExpired(ctx, batch)
}

func TestPasswordChangeProofMaintenanceIsBoundedAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := &cancelProofCleanup{t: t, stop: cancel}
	maintainPasswordChangeProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	maintainPasswordChangeProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	if cleanup.calls != 1 {
		t.Fatal("password-change maintenance retried after cancellation")
	}
}

func TestPasswordChangeProofBuilderDefaultOff(t *testing.T) {
	for _, key := range []string{"PASSWORD_CHANGE_PROOFS_ENABLED", "PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "PASSWORD_CHANGE_PROOFS_SMS_ENABLED"} {
		t.Setenv(key, "")
	}
	if svc, err := buildPasswordChangeProofs("production", nil, nil, nil, nil); err != nil || svc != nil {
		t.Fatal("disabled builder required dependencies or acquired authority")
	}
	if sender, err := buildPasswordChangeSMSSender("production"); err != nil || sender != nil {
		t.Fatal("disabled builder required provider or enabled SMS")
	}
}

func (c *cancelProofCleanup) CleanupExpiredFirstPasskey(ctx context.Context, batch int32) (int64, error) {
	return c.CleanupExpired(ctx, batch)
}

func TestFirstPasskeyProofMaintenanceAndDefaultOffBuilder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := &cancelProofCleanup{t: t, stop: cancel}
	maintainFirstPasskeyProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	maintainFirstPasskeyProofs(ctx, cleanup, slog.New(slog.DiscardHandler))
	if cleanup.calls != 1 {
		t.Fatal("first-passkey cleanup retried after cancellation")
	}
	for _, key := range []string{"FIRST_PASSKEY_PROOFS_ENABLED", "FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "FIRST_PASSKEY_PROOFS_SMS_ENABLED"} {
		t.Setenv(key, "")
	}
	if proofs, err := buildFirstPasskeyProofs("production", nil, nil, nil, nil); err != nil || proofs != nil {
		t.Fatal("disabled first-passkey builder acquired authority/dependencies")
	}
	if sender, err := buildFirstPasskeySMSSender("production"); err != nil || sender != nil {
		t.Fatal("disabled first-passkey builder activated provider")
	}
}
