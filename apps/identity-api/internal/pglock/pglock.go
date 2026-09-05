// Package pglock provides PostgreSQL session-scoped advisory locks, the
// platform's cross-process mutex for background workers.
//
// It exists so the single-writer guarantee is implemented once. Two workers now
// need it for different reasons, and those reasons demand opposite failure
// handling, so the *policy* deliberately stays with each caller:
//
//   - The GDPR purge worker (Task 5.1) treats contention as success: an
//     overlapping CronJob tick is normal operation, and paging somebody for it
//     would be noise.
//   - The audit signing worker (Task 5.2) treats contention as fatal: a second
//     signer would race the hash-chain tip and fork the chain, so it must exit
//     non-zero rather than continue.
//
// This package only answers "did I get the lock"; it never decides what that
// means.
package pglock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Reserved advisory-lock keys.
//
// The values are arbitrary but must be stable and unique across every advisory
// lock this platform takes. They are written as decimal literals rather than
// hashes of a name so they are greppable and can be read directly out of
// pg_locks.objid during an incident.
//
// Reserve a new literal here for each future worker; never reuse one. Sharing a
// key silently serialises two unrelated workers against each other, which
// presents as one of them mysteriously never running.
const (
	// PurgeKey guards one run of the GDPR hard-delete worker (cmd/purge-worker).
	PurgeKey int64 = 5100001
	// AuditSignerKey guards the audit signing worker (cmd/audit-signer). Unlike
	// PurgeKey this is a correctness lock, not a de-duplication convenience: the
	// holder is the sole writer of both hash chains.
	AuditSignerKey int64 = 5200001
)

// AdvisoryLocker serialises worker runs across processes.
type AdvisoryLocker interface {
	// TryLock reports whether the lock was acquired without waiting. When it
	// returns true the caller must invoke release exactly once. When it returns
	// false the caller decides what contention means — see the package doc; this
	// method deliberately does not treat it as an error.
	TryLock(ctx context.Context) (acquired bool, release func(), err error)
}

// PgAdvisoryLocker holds pg_try_advisory_lock on a dedicated pooled connection for
// the whole run.
//
// The connection is dedicated because a session-scoped advisory lock lives on the
// connection that took it: taking it on a pooled connection that is then returned
// and handed to another query would release the lock (or, worse, leak it onto an
// unrelated caller). Holding one connection out of the pool for the run's duration
// is the cost of that guarantee.
type PgAdvisoryLocker struct {
	pool *pgxpool.Pool
	key  int64
}

// NewPgAdvisoryLocker constructs an AdvisoryLocker over a pgx pool.
func NewPgAdvisoryLocker(pool *pgxpool.Pool, key int64) (*PgAdvisoryLocker, error) {
	if pool == nil {
		return nil, errors.New("pglock: pool is required for the advisory lock")
	}
	return &PgAdvisoryLocker{pool: pool, key: key}, nil
}

// TryLock implements AdvisoryLocker with pg_try_advisory_lock, which returns
// immediately rather than queueing behind the holder.
func (l *PgAdvisoryLocker) TryLock(ctx context.Context) (bool, func(), error) {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("pglock: acquire advisory lock connection: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", l.key).Scan(&acquired); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("pglock: pg_try_advisory_lock: %w", err)
	}
	if !acquired {
		conn.Release()
		return false, nil, nil
	}

	release := func() {
		// Unlock explicitly rather than relying on the connection closing: the
		// connection goes back to the pool, where a session-scoped lock would
		// otherwise persist. A background context is used so a cancelled run
		// (SIGTERM) still releases.
		unlockCtx, cancel := context.WithTimeout(context.Background(), advisoryUnlockTimeout)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", l.key); err != nil {
			// Losing the connection also drops the lock, so this is reportable but
			// not corrupting.
			slog.Default().Error("pglock: release advisory lock",
				slog.Int64("lock_key", l.key),
				slog.String("error", err.Error()))
		}
		conn.Release()
	}
	return true, release, nil
}

// advisoryUnlockTimeout bounds the explicit unlock so a wedged connection cannot
// hang process shutdown.
const advisoryUnlockTimeout = 5 * time.Second
