package pglock

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReservedWorkerKeysArePositiveAndDistinct(t *testing.T) {
	seen := make(map[int64]bool)
	for _, key := range []int64{PurgeKey, AuditSignerKey, LedgerCoordinationKey, SecurityLedgerPurgeKey} {
		if key <= 0 || seen[key] {
			t.Fatalf("nonpositive or reused worker key: %d", key)
		}
		seen[key] = true
	}
	if err := LockLedger(context.Background(), nil); err == nil {
		t.Fatal("ledger lock accepted nil transaction")
	}
}

func TestNewPgAdvisoryLockerRequiresPool(t *testing.T) {
	t.Parallel()

	_, err := NewPgAdvisoryLocker(nil, AuditSignerKey)
	if err == nil {
		t.Fatal("expected error when pool is nil")
	}
}

func TestPgAdvisoryLockerMutualExclusion(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL is not set; skipping live PostgreSQL advisory lock test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		t.Skipf("cannot ping database at %s: %v; skipping", dsn, err)
	}

	key := int64(9999001) // unique test key
	locker1, err := NewPgAdvisoryLocker(pool, key)
	if err != nil {
		t.Fatalf("NewPgAdvisoryLocker 1: %v", err)
	}
	locker2, err := NewPgAdvisoryLocker(pool, key)
	if err != nil {
		t.Fatalf("NewPgAdvisoryLocker 2: %v", err)
	}

	acq1, rel1, err := locker1.TryLock(ctx)
	if err != nil {
		t.Fatalf("locker1.TryLock: %v", err)
	}
	if !acq1 {
		t.Fatal("expected locker1 to acquire lock")
	}
	defer rel1()

	// Second locker with the same key should fail to acquire (mutual exclusion)
	acq2, rel2, err := locker2.TryLock(ctx)
	if err != nil {
		t.Fatalf("locker2.TryLock: %v", err)
	}
	if acq2 {
		rel2()
		t.Fatal("locker2 acquired lock, expected false due to contention")
	}

	// Release first lock (idempotent, calling twice should not panic)
	rel1()
	rel1()

	// Now locker2 should be able to acquire
	acq2After, rel2After, err := locker2.TryLock(ctx)
	if err != nil {
		t.Fatalf("locker2.TryLock after release: %v", err)
	}
	if !acq2After {
		t.Fatal("expected locker2 to acquire lock after locker1 released")
	}
	rel2After()
}
