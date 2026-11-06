package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ErrV1History requires a separate preservation/conversion procedure, never a
// genesis reset or automatic v1 rehash. Outbox/broker v1 envelopes must also be
// inventoried and quarantined separately before restarting compatible writers.
var ErrV1History = errors.New("migrate: v1 history or initialized proof state requires preservation before 00015")

const migrationLockTimeout = 10 * time.Second

var migrationKeys = []int64{pglock.MigrationKey, pglock.PurgeKey, pglock.AuditSignerKey,
	pglock.SecurityLedgerPurgeKey, pglock.LedgerCoordinationKey, pglock.AuditCoordinationKey}

type migrationLocker struct {
	target  int64
	one, up bool
}

func (l migrationLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	bounded, cancel := context.WithTimeout(ctx, migrationLockTimeout)
	defer cancel()
	acquired := 0
	for _, key := range migrationKeys {
		for {
			var locked bool
			if err := conn.QueryRowContext(bounded, "SELECT pg_catalog.pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
				releaseErr := unlockMigration(conn, acquired)
				// Cancellation may hide a successful acquisition. Discard this
				// session even when all previously observed locks unlocked cleanly.
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				return errors.Join(fmt.Errorf("migrate: exclusion unavailable: %w", err), releaseErr)
			}
			if locked {
				acquired++
				break
			}
			timer := time.NewTimer(25 * time.Millisecond)
			select {
			case <-bounded.Done():
				timer.Stop()
				return errors.Join(fmt.Errorf("migrate: exclusion timeout: %w", bounded.Err()), unlockMigration(conn, acquired))
			case <-timer.C:
			}
		}
	}
	if l.up {
		if err := l.preflight(bounded, conn); err != nil {
			return errors.Join(err, unlockMigration(conn, acquired))
		}
	}
	return nil
}

func (migrationLocker) SessionUnlock(_ context.Context, conn *sql.Conn) error {
	return unlockMigration(conn, len(migrationKeys))
}

func unlockMigration(conn *sql.Conn, count int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result error
	for i := count - 1; i >= 0; i-- {
		var unlocked bool
		err := conn.QueryRowContext(ctx, "SELECT pg_catalog.pg_advisory_unlock($1)", migrationKeys[i]).Scan(&unlocked)
		if err != nil || !unlocked {
			result = errors.Join(result, fmt.Errorf("migrate: exclusion release failed: %v", err))
		}
	}
	if result != nil {
		// Never put a session with a possibly leaked lock back into database/sql.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	return result
}

func (l migrationLocker) preflight(ctx context.Context, conn *sql.Conn) error {
	var versionTable bool
	if err := conn.QueryRowContext(ctx, "SELECT to_regclass('public.goose_db_version') IS NOT NULL").Scan(&versionTable); err != nil {
		return fmt.Errorf("migrate: version inventory: %w", err)
	}
	var current int64
	var applied bool
	if versionTable {
		if err := conn.QueryRowContext(ctx, `SELECT COALESCE(MAX(version_id),0),
			COALESCE(bool_or(version_id=15),false) FROM public.goose_db_version WHERE is_applied`).Scan(&current, &applied); err != nil {
			return fmt.Errorf("migrate: version inventory: %w", err)
		}
	}
	if applied || l.target < 15 || (l.one && current < 14) {
		return nil
	}
	for _, table := range []string{"mvp_audit_logs", "security_event_ledger", "security_ledger_head",
		"security_ledger_checkpoints", "security_ledger_retention_settings", "audit_log_head",
		"audit_log_chain", "security_ledger_chain", "security_ledger_erasures"} {
		var exists bool
		if err := conn.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", "public."+table).Scan(&exists); err != nil {
			return fmt.Errorf("migrate: history inventory: %w", err)
		}
		if !exists {
			if (current >= 1 && table == "mvp_audit_logs") || (current >= 2 && table == "security_event_ledger") ||
				(current >= 11 && (table == "security_ledger_head" || table == "security_ledger_checkpoints" || table == "security_ledger_retention_settings")) {
				return fmt.Errorf("migrate: required history inventory table missing")
			}
			continue
		}
		var populated bool
		// Table names are a fixed allowlist, not caller-controlled SQL.
		if err := conn.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM public."+table+")").Scan(&populated); err != nil {
			return fmt.Errorf("migrate: history inventory: %w", err)
		}
		if populated {
			return ErrV1History
		}
	}
	return nil
}
