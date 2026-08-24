// Integration tests for Task 4.6, exercising the recovery-code service against
// real PostgreSQL.
//
// The unit tests in service_test.go run without a Transacter, so every atomicity
// claim the design rests on — the FOR UPDATE row lock, the physical delete inside
// the same transaction as the match, the all-or-nothing regeneration — is
// unverified there. These tests close that gap by driving the service with a real
// pgxpool and a migrated schema.
//
// They require a reachable PostgreSQL instance addressed by DATABASE_URL (see
// .env.example / docker-compose.dev.yml). When DATABASE_URL is unset or the
// database is unreachable they skip cleanly, so plain `go test ./...` stays green
// without Docker — mirroring internal/migrate and internal/db.
//
// With DATABASE_URL set, run the DB-backed packages serially:
//
//	go test -p 1 ./...
//
// `go test` runs packages in parallel, and internal/migrate, internal/db, and
// this package all drive goose against the one shared schema (internal/migrate
// additionally Resets it), so a parallel run has them tearing down each other's
// tables. This is a pre-existing property of the shared-database suites, not
// something specific to these tests.
//
// Coverage:
//   - Verify consumes exactly one row and the row is physically deleted, not
//     used_at-stamped.
//   - Several concurrent submissions of one code: exactly one succeeds.
//   - Regeneration destroys the whole previous batch atomically.
//   - A code belonging to another account is refused.
//   - A non-active account is refused against the real users.status CHECK.
package recovery

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// testTimeout bounds the whole lifecycle per test run.
const testTimeout = 2 * time.Minute

// openTestPool applies the embedded migrations and returns a connection pool,
// skipping the test when DATABASE_URL is unset or the database is unreachable.
//
// MinConns/MaxConns are raised because the concurrency test needs several
// simultaneous transactions: with a single connection the racing Verify calls
// would serialize behind each other at the pool rather than at the row lock, and
// the test would pass without ever exercising FOR UPDATE.
func openTestPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping recovery integration test")
	}

	sqldb, err := migrate.Open(ctx, url)
	if err != nil {
		t.Skipf("database unreachable; skipping recovery integration test: %v", err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	_ = sqldb.Close()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	cfg.MinConns = 2
	if cfg.MaxConns < 8 {
		cfg.MaxConns = 8
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Skipf("database unreachable; skipping recovery integration test: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("database unreachable; skipping recovery integration test: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// newIntegrationService builds the real service over the pool: queries through
// the sqlc layer and transactions opened on the pool itself, which is the exact
// wiring cmd/server uses.
func newIntegrationService(t *testing.T, pool *pgxpool.Pool) *Service {
	t.Helper()

	svc, err := New(Config{}, db.New(pool), WithTransacter(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

// createTestUser inserts an active account and registers a physical cleanup. The
// recovery_codes FK is ON DELETE CASCADE, so removing the user removes its codes
// and leaves no residue for the next run's unique index to collide with.
func createTestUser(ctx context.Context, t *testing.T, pool *pgxpool.Pool, email string) uuid.UUID {
	t.Helper()

	q := db.New(pool)
	// A previous aborted run may have left this fixture behind; the email is
	// unique among non-deleted rows, so clear it first.
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email); err != nil {
		t.Fatalf("clear stale fixture %s: %v", email, err)
	}

	user, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", email, err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, user.ID); err != nil {
			t.Errorf("cleanup user %s: %v", email, err)
		}
	})
	return user.ID
}

// countRows reports the raw number of recovery_codes rows for a user, ignoring
// used_at. CountActiveRecoveryCodes filters on `used_at IS NULL`, so it alone
// cannot distinguish a physically deleted row from one merely stamped as used;
// this does.
func countRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) int {
	t.Helper()

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count recovery_codes rows: %v", err)
	}
	return n
}

func TestIntegrationVerifyPhysicallyDeletesOneRow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	svc := newIntegrationService(t, pool)
	q := db.New(pool)
	userID := createTestUser(ctx, t, pool, "recovery-consume@test.local")

	batch, err := svc.Generate(ctx, userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := countRows(ctx, t, pool, userID); got != batch.Count {
		t.Fatalf("rows after Generate = %d, want %d", got, batch.Count)
	}

	if err := svc.Verify(ctx, userID, batch.Codes[0], ""); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	active, err := q.CountActiveRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("CountActiveRecoveryCodes: %v", err)
	}
	if want := int64(batch.Count - 1); active != want {
		t.Errorf("active codes = %d, want %d", active, want)
	}
	// The decisive assertion: the raw row count dropped too. A used_at stamp
	// would leave the row present and this would still read batch.Count.
	if got := countRows(ctx, t, pool, userID); got != batch.Count-1 {
		t.Errorf("raw rows = %d, want %d; the consumed code was not physically deleted", got, batch.Count-1)
	}

	// Replay against the real schema: the row is gone, so the indexed lookup
	// misses.
	if err := svc.Verify(ctx, userID, batch.Codes[0], ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("replayed Verify = %v, want ErrInvalidCode", err)
	}
	// Sibling codes are unaffected.
	if err := svc.Verify(ctx, userID, batch.Codes[1], ""); err != nil {
		t.Errorf("Verify of a sibling code = %v, want nil", err)
	}
}

// TestIntegrationConcurrentVerifyAllowsOneWinner is the test the whole atomicity
// design exists for: several clients submit the identical code at the same
// instant. The FOR UPDATE lock plus the delete-in-the-same-transaction mean the
// losers block on the lock, then find the row gone under READ COMMITTED
// re-evaluation and fail. Exactly one must win, and exactly one row must
// disappear.
func TestIntegrationConcurrentVerifyAllowsOneWinner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	svc := newIntegrationService(t, pool)
	userID := createTestUser(ctx, t, pool, "recovery-race@test.local")

	batch, err := svc.Generate(ctx, userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	code := batch.Codes[0]

	const racers = 8
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(racers)

	results := make([]error, racers)
	for i := 0; i < racers; i++ {
		go func(idx int) {
			defer done.Done()
			// Release every goroutine from the same barrier so the transactions
			// genuinely overlap and actually contend for the row lock.
			start.Wait()
			results[idx] = svc.Verify(ctx, userID, code, "")
		}(i)
	}
	start.Done()
	done.Wait()

	winners, losers := 0, 0
	for i, err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrInvalidCode):
			losers++
		default:
			t.Errorf("racer %d returned an unexpected error: %v", i, err)
		}
	}
	if winners != 1 {
		t.Errorf("%d concurrent verifications succeeded, want exactly 1 (double-spend)", winners)
	}
	if losers != racers-1 {
		t.Errorf("%d concurrent verifications were refused with ErrInvalidCode, want %d", losers, racers-1)
	}

	// A single code was spent, no matter how the two transactions interleaved.
	if got := countRows(ctx, t, pool, userID); got != batch.Count-1 {
		t.Errorf("raw rows = %d, want %d; the race consumed the wrong number of codes", got, batch.Count-1)
	}
}

// TestIntegrationRegenerateInvalidatesPreviousBatch proves a regeneration is
// all-or-nothing against the real database: every code from the old batch is
// gone, exactly one batch survives, and the new codes work.
func TestIntegrationRegenerateInvalidatesPreviousBatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	svc := newIntegrationService(t, pool)
	userID := createTestUser(ctx, t, pool, "recovery-regen@test.local")

	first, err := svc.Generate(ctx, userID, "")
	if err != nil {
		t.Fatalf("Generate first batch: %v", err)
	}
	second, err := svc.Generate(ctx, userID, "")
	if err != nil {
		t.Fatalf("Generate second batch: %v", err)
	}

	// Never a union of the two batches.
	if got := countRows(ctx, t, pool, userID); got != second.Count {
		t.Errorf("rows after regeneration = %d, want %d", got, second.Count)
	}

	for i, code := range first.Codes {
		if err := svc.Verify(ctx, userID, code, ""); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("old-batch code %d verified with %v, want ErrInvalidCode", i, err)
		}
	}
	if err := svc.Verify(ctx, userID, second.Codes[0], ""); err != nil {
		t.Errorf("new-batch code = %v, want nil", err)
	}
}

// TestIntegrationCrossUserCodeRefused confirms the user_id predicate on the
// lookup, not just the hash match: idx_recovery_codes_hash is globally unique
// rather than per-user, so without that predicate a stolen code would verify
// under whichever session presented it.
func TestIntegrationCrossUserCodeRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	svc := newIntegrationService(t, pool)
	victimID := createTestUser(ctx, t, pool, "recovery-victim@test.local")
	attackerID := createTestUser(ctx, t, pool, "recovery-attacker@test.local")

	victimBatch, err := svc.Generate(ctx, victimID, "")
	if err != nil {
		t.Fatalf("Generate for the victim: %v", err)
	}
	if _, err := svc.Generate(ctx, attackerID, ""); err != nil {
		t.Fatalf("Generate for the attacker: %v", err)
	}

	// The attacker holds a valid session for their own account and submits the
	// victim's code.
	if err := svc.Verify(ctx, attackerID, victimBatch.Codes[0], ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("cross-user Verify = %v, want ErrInvalidCode", err)
	}
	if got := countRows(ctx, t, pool, victimID); got != victimBatch.Count {
		t.Errorf("victim rows = %d, want %d; a cross-user attempt consumed a code", got, victimBatch.Count)
	}
	// And the code still works for its rightful owner.
	if err := svc.Verify(ctx, victimID, victimBatch.Codes[0], ""); err != nil {
		t.Errorf("victim's own Verify after the attempt = %v, want nil", err)
	}
}

// TestIntegrationNonActiveAccountRefused exercises the account-status gate
// against the real users.status CHECK constraint, so the gate is proven against
// the states the database actually allows rather than a fake's string field.
func TestIntegrationNonActiveAccountRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	svc := newIntegrationService(t, pool)
	q := db.New(pool)
	userID := createTestUser(ctx, t, pool, "recovery-suspended@test.local")

	batch, err := svc.Generate(ctx, userID, "")
	if err != nil {
		t.Fatalf("Generate while active: %v", err)
	}

	for _, status := range []string{"suspended", "pending_verification", "pending_deletion"} {
		if _, err := q.UpdateUserStatus(ctx, db.UpdateUserStatusParams{ID: userID, Status: status}); err != nil {
			t.Fatalf("UpdateUserStatus %s: %v", status, err)
		}

		if _, err := svc.Generate(ctx, userID, ""); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Generate for a %s account = %v, want ErrAccountNotActive", status, err)
		}
		if _, err := svc.Status(ctx, userID); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Status for a %s account = %v, want ErrAccountNotActive", status, err)
		}
		if err := svc.Verify(ctx, userID, batch.Codes[0], ""); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Verify for a %s account = %v, want ErrAccountNotActive", status, err)
		}
		if got := countRows(ctx, t, pool, userID); got != batch.Count {
			t.Fatalf("a refused %s account lost codes: rows = %d, want %d", status, got, batch.Count)
		}
	}

	// Reinstatement restores access to the untouched batch.
	if _, err := q.UpdateUserStatus(ctx, db.UpdateUserStatusParams{ID: userID, Status: "active"}); err != nil {
		t.Fatalf("UpdateUserStatus active: %v", err)
	}
	if err := svc.Verify(ctx, userID, batch.Codes[0], ""); err != nil {
		t.Errorf("Verify after reinstatement = %v, want nil", err)
	}
}
