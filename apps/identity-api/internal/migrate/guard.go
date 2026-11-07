package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ErrLineage rejects adoption of legacy, untracked, or contradictory state.
var ErrLineage = errors.New("migrate: invalid schema lineage; use separately scoped fresh setup, never automatic adoption or deletion")

// ErrForwardOnly protects the baseline before any future rollback can run.
var ErrForwardOnly = errors.New("migrate: baseline is forward-only; reset requires separately scoped fresh setup")

const versionTable = "public.identity_schema_version"

const migrationLockTimeout = 10 * time.Second

var migrationKeys = []int64{pglock.MigrationKey, pglock.PurgeKey, pglock.AuditSignerKey,
	pglock.SecurityLedgerPurgeKey, pglock.LedgerCoordinationKey, pglock.AuditCoordinationKey}

type migrationLocker struct {
	sources []*goose.Source
	exactUp int64
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
	state, err := inventory(bounded, conn, l.sources)
	if err == nil && l.exactUp > 1 {
		if _, baseline := state.applied[1]; !baseline {
			err = fmt.Errorf("%w: exact future application requires installed baseline 1", ErrLineage)
		}
	}
	if err != nil {
		return errors.Join(err, unlockMigration(conn, acquired))
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

type lineage struct {
	applied map[int64]time.Time
	version int64
}

// inventory uses only the supplied connection. Its read-only snapshot is closed
// before Goose starts a transaction, including with a one-connection pool.
func inventory(ctx context.Context, conn *sql.Conn, sources []*goose.Source) (lineage, error) {
	state := lineage{applied: make(map[int64]time.Time)}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return state, fmt.Errorf("migrate: lineage inventory: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var legacy bool
	var table sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT pg_catalog.to_regclass('public.goose_db_version') IS NOT NULL,
		pg_catalog.to_regclass('public.identity_schema_version')::oid`).Scan(&legacy, &table); err != nil {
		return state, fmt.Errorf("migrate: lineage inventory: %w", err)
	}
	if legacy {
		return state, fmt.Errorf("%w: legacy public.goose_db_version exists", ErrLineage)
	}
	if table.Valid {
		var valid bool
		if err := tx.QueryRowContext(ctx, `SELECT c.relkind='r' AND c.relpersistence='p'
			AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
			AND (SELECT count(*) FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped)=4
			AND (SELECT count(*) FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
				WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull AND a.attgenerated=''
				AND ((a.attnum=1 AND a.attname='id' AND a.atttypid='pg_catalog.int4'::regtype AND a.attidentity='d' AND d.oid IS NULL)
				OR (a.attnum=2 AND a.attname='version_id' AND a.atttypid='pg_catalog.int8'::regtype AND a.attidentity='' AND d.oid IS NULL)
				OR (a.attnum=3 AND a.attname='is_applied' AND a.atttypid='pg_catalog.bool'::regtype AND a.attidentity='' AND d.oid IS NULL)
				OR (a.attnum=4 AND a.attname='tstamp' AND a.atttypid='pg_catalog.timestamp'::regtype AND a.attidentity='' AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='now()')))=4
			AND EXISTS(SELECT 1 FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid AND i.indisprimary AND i.indisunique AND i.indisvalid AND i.indkey::text='1')
			AND (SELECT count(*) FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid)=1
			AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p' AND k.conkey=ARRAY[1]::smallint[] AND k.convalidated AND NOT k.condeferrable)
			AND (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid)=1
			AND (SELECT count(*) FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class s ON s.oid=d.objid JOIN pg_catalog.pg_sequence q ON q.seqrelid=s.oid
				WHERE d.classid='pg_catalog.pg_class'::regclass AND d.refclassid='pg_catalog.pg_class'::regclass
				AND d.refobjid=c.oid AND d.refobjsubid=1 AND d.deptype='i' AND s.relkind='S' AND s.relpersistence='p' AND s.relnamespace=c.relnamespace
				AND q.seqtypid='pg_catalog.int4'::regtype AND q.seqstart=1 AND q.seqincrement=1 AND q.seqmin=1 AND q.seqmax=2147483647 AND q.seqcache=1 AND NOT q.seqcycle)=1
			AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid)
			AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=c.oid)
			AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h WHERE h.inhrelid=c.oid OR h.inhparent=c.oid)
			FROM pg_catalog.pg_class c WHERE c.oid=$1`, table.Int64).Scan(&valid); err != nil {
			return state, fmt.Errorf("migrate: metadata shape inventory: %w", err)
		}
		if !valid {
			return state, fmt.Errorf("%w: malformed %s relation/column shape", ErrLineage, versionTable)
		}
		known := map[int64]bool{0: true}
		for _, source := range sources {
			known[source.Version] = true
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,version_id,is_applied,tstamp FROM public.identity_schema_version ORDER BY id`)
		if err != nil {
			return state, fmt.Errorf("migrate: complete history inventory: %w", err)
		}
		for rows.Next() {
			var id, version int64
			var applied bool
			var timestamp time.Time
			if err := rows.Scan(&id, &version, &applied, &timestamp); err != nil {
				_ = rows.Close()
				return state, fmt.Errorf("migrate: complete history inventory: %w", err)
			}
			_, duplicate := state.applied[version]
			_, zero := state.applied[0]
			_, baseline := state.applied[1]
			if id < 1 || !known[version] || !applied || duplicate || (version != 0 && !zero) || (version > 1 && !baseline) {
				_ = rows.Close()
				return state, fmt.Errorf("%w: contradictory or unknown history version %d", ErrLineage, version)
			}
			state.applied[version] = timestamp
			if version > state.version {
				state.version = version
			}
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return state, fmt.Errorf("migrate: complete history inventory: %w", err)
		}
		if _, zero := state.applied[0]; !zero {
			return state, fmt.Errorf("%w: missing applied version 0", ErrLineage)
		}
	}
	if state.version == 0 {
		// Only extension members and the legitimate tracking table's primary
		// index/owned identity sequence may exist before the baseline. Names alone
		// cannot make an arbitrary leftover index or sequence legitimate.
		var nonempty bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname='public' AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.deptype='e')
			AND c.oid<>COALESCE($1::oid,0)
			AND NOT (c.relkind='i' AND EXISTS(SELECT 1 FROM pg_catalog.pg_index i WHERE i.indexrelid=c.oid AND i.indrelid=$1 AND i.indisprimary))
			AND NOT (c.relkind='S' AND EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.refclassid='pg_catalog.pg_class'::regclass AND d.refobjid=$1 AND d.refobjsubid=1 AND d.deptype='i'))
			UNION ALL
			SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
			AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')
			UNION ALL
			SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typrelid=0 AND t.typelem=0
			AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_catalog.pg_type'::regclass AND d.objid=t.oid AND d.deptype='e')
		)`, table).Scan(&nonempty); err != nil {
			return state, fmt.Errorf("migrate: schema inventory: %w", err)
		}
		if nonempty {
			return state, fmt.Errorf("%w: untracked nonempty public schema", ErrLineage)
		}
	}
	return state, nil
}
