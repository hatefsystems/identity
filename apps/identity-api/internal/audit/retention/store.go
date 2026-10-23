package retention

import (
	"context"
	"encoding/json"
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
	// v2 has no SECURITY DEFINER purge routine, so there is no function owner to
	// vet and no EXECUTE grant to confirm. The erasure surface is now an ordinary
	// DELETE, which means the authority question becomes a plain privilege
	// question: this role must hold DELETE on the payload table and INSERT on the
	// erasure/outbox tables, and must hold nothing else anywhere.
	//
	// The checks that remain are the ones that still carry weight: a dedicated,
	// non-inheriting, unprivileged login that cannot reach the chain tables, cannot
	// disable triggers, and cannot create objects.
	err := s.pool.QueryRow(ctx, `
SELECT current_user = session_user AND current_user = 'identity_ledger_purge'
 AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND r.rolcanlogin AND NOT r.rolinherit
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid)
 AND NOT pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
 AND NOT pg_catalog.has_parameter_privilege(r.oid,'session_replication_role','SET')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname !~ '^pg_' AND
   pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))
 -- Exactly the privileges the erasure path needs, and no others on any table.
 AND pg_catalog.has_table_privilege(r.oid,'public.security_event_ledger','DELETE')
 AND pg_catalog.has_table_privilege(r.oid,'public.security_ledger_erasures','INSERT')
 AND pg_catalog.has_table_privilege(r.oid,'public.event_outbox','INSERT')
 -- The chain is what makes erasure safe; this role must never be able to touch it.
 AND NOT pg_catalog.has_table_privilege(r.oid,'public.security_ledger_chain','INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT pg_catalog.has_table_privilege(r.oid,'public.audit_log_chain','INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT pg_catalog.has_table_privilege(r.oid,'public.security_event_ledger','UPDATE,TRUNCATE,TRIGGER')
 AND NOT pg_catalog.has_table_privilege(r.oid,'public.security_ledger_erasures','UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT pg_catalog.has_table_privilege(r.oid,'public.security_ledger_head','UPDATE,DELETE,TRUNCATE')
 AND NOT pg_catalog.has_function_privilege(r.oid,'public.advance_chain_head(text,bigint,bigint,bigint,bigint)','EXECUTE')
 AND EXISTS (SELECT 1 FROM public.security_ledger_retention_settings WHERE singleton AND audit_subject=$1)
 -- The immutability guards must be armed, or erasure is unbounded.
 AND (SELECT count(*)=2 FROM pg_catalog.pg_trigger WHERE tgrelid='public.security_event_ledger'::regclass
   AND tgname IN ('trg_security_event_ledger_immutable','trg_security_event_ledger_no_truncate') AND tgenabled IN ('O','A'))
 AND (SELECT count(*)=2 FROM pg_catalog.pg_trigger WHERE tgrelid='public.security_ledger_chain'::regclass
   AND tgname IN ('trg_security_ledger_chain_append_only','trg_security_ledger_chain_no_truncate') AND tgenabled IN ('O','A'))
FROM pg_catalog.pg_roles r
WHERE r.rolname=current_user`, s.subject).Scan(&valid)
	if err != nil || !valid {
		return ErrPrivilege
	}
	_, err = s.Capture(ctx)
	return err
}

// Capture reads one statement snapshot; UTC normalization is independent of session timezone.
//
// The high-water mark comes from the chain table, which is never deleted, so it is
// a true ceiling. In v1 it had to be reconciled against the surviving payload tip
// and the checkpoint tip, because an erased span could otherwise make the head look
// ahead of the table.
func (s *PgStore) Capture(ctx context.Context) (Boundary, error) {
	var b Boundary
	var hash []byte
	var valid bool
	err := s.pool.QueryRow(ctx, `
SELECT statement_timestamp(), h.seq, h.chain_hash,
 h.seq >= 0 AND octet_length(h.chain_hash) = 32
 AND NOT EXISTS (SELECT 1 FROM public.security_ledger_chain c WHERE c.seq > h.seq)
 AND CASE WHEN h.seq = 0
   THEN NOT EXISTS (SELECT 1 FROM public.security_ledger_chain)
   ELSE EXISTS (SELECT 1 FROM public.security_ledger_chain c
                WHERE c.seq = h.seq AND c.chain_hash = h.chain_hash)
 END
FROM public.security_ledger_head h WHERE singleton`).Scan(&b.Cutoff, &b.ThroughSeq, &hash, &valid)
	if err != nil || !valid || b.ThroughSeq < 0 {
		return Boundary{}, ErrIntegrity
	}
	if _, err := audit.DecodeDigest(hash); err != nil {
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

// Purge erases expired payloads and records what it erased.
//
// v2 removes an entire class of work. v1 had to re-derive every candidate's
// canonical body, recompute its digest against the predecessor it found by
// searching live rows and checkpoints, validate the digests of any neighbouring
// erased spans, and then hand all of it to a SECURITY DEFINER routine that
// repeated the checks and compacted the spans — because deleting a row deleted a
// chain link.
//
// Here the chain node stays. So the sequence is: lock the accounts, re-read
// eligibility under those locks, delete, record the erasure, and enqueue the
// chained receipt. All five steps are one transaction, which is what makes a
// rollback a full-fidelity dry run.
func (s *PgStore) Purge(ctx context.Context, b Boundary, candidates []Candidate, dryRun bool) (BatchResult, error) {
	if len(candidates) == 0 {
		return BatchResult{}, nil
	}
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
	// Account locks precede every eligibility read, in UUID order, matching every
	// other pglock caller so a hold application and a purge cannot deadlock.
	slices.SortFunc(accounts, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, id := range slices.Compact(accounts) {
		if err := pglock.LockAccount(ctx, tx, id); err != nil {
			return BatchResult{}, classify(err)
		}
	}

	queries := db.New(tx)
	// Deliberately a separate statement from every lock above, so it sees a fresh
	// hold snapshot rather than the pre-wait one.
	locked, err := queries.RecheckSecurityLedgerPurgeCandidates(ctx, db.RecheckSecurityLedgerPurgeCandidatesParams{
		Seqs:   seqs,
		Cutoff: pgtype.Timestamptz{Time: b.Cutoff, Valid: true},
	})
	if err != nil {
		return BatchResult{}, classify(err)
	}

	eligible := make([]int64, 0, len(locked))
	held := 0
	for _, row := range locked {
		switch {
		case row.Held:
			// An active hold outranks every retention timer, unconditionally.
			held++
		case row.Expired:
			eligible = append(eligible, row.Seq)
		}
	}
	if len(eligible) == 0 {
		return BatchResult{Held: held}, nil
	}

	deleted, err := queries.DeleteExpiredSecurityEvents(ctx, db.DeleteExpiredSecurityEventsParams{
		Seqs:      eligible,
		Cutoff:    pgtype.Timestamptz{Time: b.Cutoff, Valid: true},
		Highwater: b.ThroughSeq,
	})
	if err != nil {
		return BatchResult{}, classify(err)
	}
	if deleted != int64(len(eligible)) {
		// The DELETE restates every predicate, so a shortfall means eligibility
		// changed between the recheck and the erasure despite the account locks.
		// Refuse rather than record an erasure span that does not describe what was
		// actually removed: a wrong span would make a retained payload look
		// lawfully erased.
		return BatchResult{}, ErrIntegrity
	}

	operationID := uuid.New()
	erasedAt := audit.NormalizeChainTime(b.Cutoff)
	// One record per contiguous run, so the common case (a long expired prefix) is
	// a single row rather than one per seq.
	for _, span := range contiguousSpans(eligible) {
		if err := queries.RecordSecurityLedgerErasure(ctx, db.RecordSecurityLedgerErasureParams{
			FirstSeq:    span[0],
			LastSeq:     span[1],
			OperationID: operationID,
			ErasedAt:    pgtype.Timestamptz{Time: erasedAt, Valid: true},
		}); err != nil {
			return BatchResult{}, classify(err)
		}
	}

	if err := s.enqueueReceipt(ctx, tx, operationID, b, len(eligible), held, dryRun); err != nil {
		return BatchResult{}, err
	}

	result := BatchResult{Deleted: int(deleted), Held: held}
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

// contiguousSpans collapses a sorted seq list into [first, last] runs.
func contiguousSpans(seqs []int64) [][2]int64 {
	if len(seqs) == 0 {
		return nil
	}
	spans := make([][2]int64, 0, len(seqs))
	start, prev := seqs[0], seqs[0]
	for _, seq := range seqs[1:] {
		if seq == prev+1 {
			prev = seq
			continue
		}
		spans = append(spans, [2]int64{start, prev})
		start, prev = seq, seq
	}
	return append(spans, [2]int64{start, prev})
}

// enqueueReceipt writes the Class C erasure receipt into the transactional outbox,
// in the same transaction as the DELETE.
//
// This is what makes an erasure provable rather than merely recorded: the
// erasure index says a span was erased, and the chained receipt — signed into the
// audit chain once the publisher drains it — says who erased it, under what cutoff,
// and with which operation id. A verifier that finds an absent payload with an
// erasure record but no corresponding receipt is looking at an unexplained
// deletion.
func (s *PgStore) enqueueReceipt(ctx context.Context, tx pgx.Tx, operationID uuid.UUID, b Boundary, deleted, held int, dryRun bool) error {
	outcome := "ineligible"
	switch {
	case deleted > 0:
		outcome = "purged"
	case held > 0:
		outcome = "held"
	}
	eventType := audit.EventLegalLedgerPurgeSkipped
	if deleted > 0 {
		eventType = audit.EventLegalLedgerPurged
	}
	payload := map[string]any{
		"operation_id":  operationID.String(),
		"cutoff":        audit.FormatChainTime(b.Cutoff),
		"deleted_count": deleted,
		"held_count":    held,
		"dry_run":       dryRun,
		"outcome":       outcome,
		"highwater_seq": b.ThroughSeq,
	}
	envelope, err := audit.NewEnvelope(audit.Event{
		EventType:     eventType,
		ActionStatus:  audit.StatusSuccess,
		ActorSPIFFEID: audit.LedgerRetentionActorSPIFFEID,
		Payload:       payload,
	}, operationID, b.Cutoff)
	if err != nil {
		return ErrIntegrity
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return ErrIntegrity
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.event_outbox
(id, subject, payload, created_at, next_attempt_at, admin_action)
VALUES ($1, $2, $3, $4, $4, true)`,
		operationID, s.subject, string(encoded),
		pgtype.Timestamptz{Time: b.Cutoff, Valid: true}); err != nil {
		return classify(err)
	}
	return nil
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
