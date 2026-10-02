package signer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type recordingTx struct {
	pgx.Tx
	commands  []string
	arguments [][]any
	execErr   error
	rollback  func(context.Context) error
}

func (t *recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	t.commands = append(t.commands, sql)
	t.arguments = append(t.arguments, args)
	return pgconn.CommandTag{}, t.execErr
}

func (t *recordingTx) Rollback(ctx context.Context) error { return t.rollback(ctx) }

type recordingTransacter struct {
	tx      *recordingTx
	options pgx.TxOptions
}

func (t *recordingTransacter) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	t.options = options
	return t.tx, nil
}

func TestPgBatchLocksLedgerBeforeOrderedAccounts(t *testing.T) {
	tx := &recordingTx{}
	db := &recordingTransacter{tx: tx}
	opener, err := NewPgBatchTxOpener(db)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := opener.BeginBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if db.options.IsoLevel != pgx.ReadCommitted {
		t.Fatal("connection isolation default was not overridden")
	}
	if len(tx.commands) != 2 || !strings.Contains(tx.commands[0], "lock_timeout = '2s'") || !strings.Contains(tx.commands[0], "statement_timeout = '30s'") || tx.arguments[1][0] != pglock.LedgerCoordinationKey {
		t.Fatalf("timeouts and ledger lock order: %v %v", tx.commands, tx.arguments)
	}
	first := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	last := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	if err := batch.LockAccounts(context.Background(), []uuid.UUID{last, first, last, first}); err != nil {
		t.Fatal(err)
	}
	if len(tx.commands) != 4 {
		t.Fatalf("account locks not deduplicated: %v", tx.commands)
	}
	for i, id := range []uuid.UUID{first, last} {
		sum := sha256.Sum256(append([]byte("identity:account-lock:v1:"), id[:]...))
		want := -int64(binary.BigEndian.Uint64(sum[:8])&0x7fffffffffffffff) - 1
		if tx.arguments[i+2][0] != want {
			t.Fatalf("account locks not in UUID order: %v", tx.arguments)
		}
	}
}

func TestPgBatchRollbackIndependentAndBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	tx := &recordingTx{rollback: func(cleanup context.Context) error {
		called = true
		deadline, ok := cleanup.Deadline()
		if cleanup.Err() != nil || !ok || time.Until(deadline) <= 0 || time.Until(deadline) > rollbackTimeout {
			t.Fatal("rollback inherited cancellation or has no finite deadline")
		}
		return pgx.ErrTxClosed
	}}
	if err := (&pgBatchTx{tx: tx}).Rollback(ctx); err != nil || !called {
		t.Fatalf("rollback: %v called=%v", err, called)
	}
}

func TestPgBatchInitializationFailureRollsBack(t *testing.T) {
	rolledBack := false
	tx := &recordingTx{execErr: errors.New("timeout setup failed"), rollback: func(ctx context.Context) error {
		rolledBack = ctx.Err() == nil
		return nil
	}}
	opener, err := NewPgBatchTxOpener(&recordingTransacter{tx: tx})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opener.BeginBatch(context.Background()); err == nil || !rolledBack {
		t.Fatalf("setup failure leaked transaction: %v", err)
	}
}
