package retention

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

const batchTimeout = 15 * time.Second

// PgStore never owns tables or writes outbox rows directly.
type PgStore struct {
	pool    *pgxpool.Pool
	subject string
}

// NewPgStore binds maintenance receipts to the configured audit subject.
func NewPgStore(pool *pgxpool.Pool, subject string) (*PgStore, error) {
	if pool == nil || subject == "" {
		return nil, ErrPrivilege
	}
	return &PgStore{pool: pool, subject: subject}, nil
}

// Probe rejects privileged/shared credentials and incomplete operator provisioning.
func (s *PgStore) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		return ErrDatabase
	}
	var valid bool
	err := s.pool.QueryRow(ctx, `
SELECT current_user = session_user AND current_user = 'identity_ledger_purge'
 AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND r.rolcanlogin AND NOT r.rolinherit
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member IN (r.oid, o.oid))
 AND NOT (o.rolsuper OR o.rolcanlogin OR o.rolcreaterole OR o.rolcreatedb OR o.rolreplication OR o.rolbypassrls OR o.rolinherit)
 AND p.proowner = o.oid AND p.prosecdef
 AND EXISTS (SELECT 1 FROM unnest(p.proconfig) setting WHERE setting IN ('search_path=pg_catalog','search_path=pg_catalog, pg_temp'))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl, pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee NOT IN (r.oid,o.oid) AND a.privilege_type='EXECUTE')
 AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')
 AND NOT pg_catalog.has_function_privilege(r.oid,'public.advance_security_ledger_head(bigint,uuid)','EXECUTE')
 AND NOT pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
 AND NOT pg_catalog.has_database_privilege(o.oid,current_database(),'CREATE')
 AND NOT pg_catalog.has_parameter_privilege(r.oid,'session_replication_role','SET')
 AND NOT pg_catalog.has_parameter_privilege(o.oid,'session_replication_role','SET')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND
   (pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE') OR pg_catalog.has_schema_privilege(o.oid,n.oid,'CREATE')))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f') AND c.relowner IN (r.oid,o.oid))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','v','f') AND
   (pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES')
    OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))
 AND EXISTS (SELECT 1 FROM public.security_ledger_retention_settings WHERE singleton AND audit_subject=$1)
 AND (SELECT count(*)=2 FROM pg_catalog.pg_trigger WHERE tgrelid='public.security_event_ledger'::regclass
   AND tgname IN ('trg_security_event_ledger_append_only','trg_security_event_ledger_no_truncate') AND tgenabled IN ('O','A'))
FROM pg_catalog.pg_roles r, pg_catalog.pg_roles o, pg_catalog.pg_proc p
WHERE r.rolname=current_user AND o.rolname='identity_ledger_maintenance_owner'
 AND p.oid='public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text)'::regprocedure`, s.subject).Scan(&valid)
	if err != nil || !valid {
		return ErrPrivilege
	}
	_, err = s.Capture(ctx)
	return err
}

// Capture reads one statement snapshot; UTC normalization is independent of session timezone.
func (s *PgStore) Capture(ctx context.Context) (Boundary, error) {
	var b Boundary
	var hash string
	var valid bool
	err := s.pool.QueryRow(ctx, `
SELECT statement_timestamp(), h.seq, h.chain_hash,
 CASE WHEN h.seq=0 THEN h.chain_hash=repeat('0',64) AND NOT EXISTS(SELECT 1 FROM public.security_event_ledger)
   AND NOT EXISTS(SELECT 1 FROM public.security_ledger_checkpoints)
 ELSE h.seq=(SELECT max(seq) FROM (
   (SELECT seq FROM public.security_event_ledger ORDER BY seq DESC LIMIT 1)
   UNION ALL (SELECT last_seq FROM public.security_ledger_checkpoints ORDER BY last_seq DESC LIMIT 1)) terminal)
 AND (SELECT count(*)=1 AND bool_and(terminal.chain_hash=h.chain_hash) FROM (
   SELECT chain_hash FROM public.security_event_ledger WHERE seq=h.seq
   UNION ALL SELECT terminal_hash FROM public.security_ledger_checkpoints WHERE last_seq=h.seq) terminal)
 END
FROM public.security_ledger_head h WHERE singleton`).Scan(&b.Cutoff, &b.ThroughSeq, &hash, &valid)
	if err != nil || !valid || b.ThroughSeq < 0 {
		return Boundary{}, ErrIntegrity
	}
	if _, err := audit.DecodeChainHash(hash); err != nil {
		return Boundary{}, ErrIntegrity
	}
	b.Cutoff = audit.NormalizeChainTime(b.Cutoff)
	return b, nil
}

// Candidates keysets by persisted expiration, excluding active holds for fairness.
func (s *PgStore) Candidates(ctx context.Context, b Boundary, cursor Candidate, limit int) ([]Candidate, error) {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT l.seq,l.account_ref,l.retain_until
FROM public.security_event_ledger l
WHERE l.retain_until<$1 AND l.seq<=$2 AND (l.retain_until,l.seq)>($3,$4)
AND NOT EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref=l.account_ref AND h.is_active)
ORDER BY l.retain_until,l.seq LIMIT $5`, b.Cutoff, b.ThroughSeq, cursor.RetainUntil, cursor.Seq, limit)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()
	var candidates []Candidate
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.Seq, &c.AccountRef, &c.RetainUntil); err != nil {
			return nil, ErrDatabase
		}
		candidates = append(candidates, c)
	}
	return candidates, classify(rows.Err())
}

// Purge verifies in Go before asking the independently enforcing SQL boundary to erase.
func (s *PgStore) Purge(ctx context.Context, b Boundary, candidates []Candidate, dryRun bool) (BatchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return BatchResult{}, classify(err)
	}
	defer func() { _ = rollback(ctx, tx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='15s'"); err != nil {
		return BatchResult{}, classify(err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_catalog.pg_advisory_xact_lock($1)", pglock.LedgerCoordinationKey); err != nil {
		return BatchResult{}, classify(err)
	}
	accounts := make([]uuid.UUID, len(candidates))
	seqs := make([]int64, len(candidates))
	for i, c := range candidates {
		accounts[i], seqs[i] = c.AccountRef, c.Seq
	}
	slices.SortFunc(accounts, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range slices.Compact(accounts) {
		if err := pglock.LockAccount(ctx, tx, id); err != nil {
			return BatchResult{}, classify(err)
		}
	}
	// This read is deliberately separate from all lock statements for fresh hold snapshots.
	rows, err := tx.Query(ctx, `SELECT seq,id,account_ref,identity_blind_index,event_type,
client_ip,ip_subnet,user_agent,device_fingerprint,client_id,scope,timestamp,retain_until,chain_hash
FROM public.security_event_ledger WHERE seq=ANY($1::bigint[]) ORDER BY seq`, seqs)
	if err != nil {
		return BatchResult{}, classify(err)
	}
	var liveSeqs []int64
	var hashes []string
	var bodies [][]byte
	for rows.Next() {
		var rec audit.LedgerRecord
		var seq int64
		var id, account uuid.UUID
		var hash string
		if err := rows.Scan(&seq, &id, &account, &rec.IdentityBlindIndex, &rec.EventType, &rec.ClientIP,
			&rec.IPSubnet, &rec.UserAgent, &rec.DeviceFingerprint, &rec.ClientID, &rec.Scope, &rec.Timestamp, &rec.RetainUntil, &hash); err != nil {
			rows.Close()
			return BatchResult{}, ErrDatabase
		}
		rec.ID, rec.AccountRef = id.String(), account.String()
		liveSeqs = append(liveSeqs, seq)
		hashes = append(hashes, hash)
		bodies = append(bodies, audit.SerializeLedger(rec))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return BatchResult{}, classify(err)
	}
	if len(liveSeqs) == 0 {
		return BatchResult{}, nil
	}
	for i, seq := range liveSeqs {
		var previous string
		err := tx.QueryRow(ctx, `SELECT chain_hash FROM (
 (SELECT seq,chain_hash FROM public.security_event_ledger WHERE seq<$1 ORDER BY seq DESC LIMIT 1)
 UNION ALL (SELECT last_seq,terminal_hash FROM public.security_ledger_checkpoints WHERE last_seq<$1 ORDER BY last_seq DESC LIMIT 1)
) p ORDER BY seq DESC LIMIT 1`, seq).Scan(&previous)
		prev := audit.GenesisChainHash
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return BatchResult{}, classify(err)
		}
		if err == nil {
			prev, err = audit.DecodeChainHash(previous)
			if err != nil {
				return BatchResult{}, ErrIntegrity
			}
		}
		if audit.ChainHash(prev, bodies[i]) != hashes[i] {
			return BatchResult{}, ErrIntegrity
		}
	}
	outcome, err := db.New(tx).PurgeExpiredSecurityEvents(ctx, db.PurgeExpiredSecurityEventsParams{
		Cutoff: pgtype.Timestamptz{Time: b.Cutoff, Valid: true}, Highwater: b.ThroughSeq,
		Seqs: liveSeqs, ExpectedHashes: hashes, CanonicalBodies: bodies, OperationID: uuid.New(), AuditSubject: s.subject,
	})
	if err != nil {
		return BatchResult{}, classify(err)
	}
	if outcome.DeletedCount < 0 || outcome.HeldCount < 0 || outcome.DeletedCount+outcome.HeldCount > int64(len(liveSeqs)) {
		return BatchResult{}, ErrIntegrity
	}
	result := BatchResult{Deleted: int(outcome.DeletedCount), Held: int(outcome.HeldCount)}
	if dryRun {
		if err := rollback(ctx, tx); err != nil {
			return BatchResult{}, ErrDatabase
		}
		return result, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return BatchResult{}, commitFailure(err)
	}
	return result, nil
}

// Backlog caps the number of eligible expirations inspected and reports a lower bound.
func (s *PgStore) Backlog(ctx context.Context, b Boundary, limit int) (Backlog, error) {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	var result Backlog
	var oldest *time.Time
	err := s.pool.QueryRow(ctx, `SELECT count(*),min(retain_until) FROM (
SELECT l.retain_until FROM public.security_event_ledger l WHERE retain_until<$1 AND seq<=$2
AND NOT EXISTS(SELECT 1 FROM public.legal_holds h WHERE h.account_ref=l.account_ref AND h.is_active)
ORDER BY retain_until,seq LIMIT $3) eligible`, b.Cutoff, b.ThroughSeq, limit+1).Scan(&result.Count, &oldest)
	if err != nil {
		return Backlog{}, classify(err)
	}
	result.Capped = result.Count > limit
	if result.Capped {
		result.Count = limit
	}
	if oldest != nil {
		result.Oldest = *oldest
	}
	return result, nil
}

func rollback(ctx context.Context, tx pgx.Tx) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Rollback(cleanup)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "55P03", "57014", "40P01":
			return ErrDeferred
		case "42501", "42883", "42P01", "25001":
			return ErrPrivilege
		case "P0001", "P0002", "23000", "23514", "23P01", "22023":
			return ErrIntegrity
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrDeferred
	}
	return ErrDatabase
}

func commitFailure(err error) error {
	// Only an explicit ERROR response (or ROLLBACK command tag) establishes a
	// failed commit. FATAL/PANIC connection termination can follow a durable commit.
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrTxCommitRollback) || (errors.As(err, &pgErr) && pgErr.Severity == "ERROR") {
		return classify(err)
	}
	return ErrUncertain
}
