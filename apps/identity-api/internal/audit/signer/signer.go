package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// ErrLockUnavailable reports that another signer holds the advisory lock.
//
// The caller must exit non-zero. Unlike the purge worker — where an overlapping run
// is a harmless schedule artefact — a second signer would read the same chain tip and
// fork both chains into two branches claiming the same predecessor. Because UPDATE
// and DELETE are revoked on both tables, that damage is permanent. Failing closed is
// the only safe response.
var ErrLockUnavailable = errors.New("signer: another audit signer holds the advisory lock")

// ErrChainTipsUnknown is fatal: no further batch may use uncertain cached tips.
var ErrChainTipsUnknown = errors.New("signer: chain tips unknown after commit failure")

// ErrLedgerStateInvalid prevents appends to an uninitialized or inconsistent ledger.
var ErrLedgerStateInvalid = errors.New("signer: invalid durable ledger state")

// quarantineNamespace derives the event id of a synthesized
// audit.pipeline.undecodable record from the offending message's stream position.
//
// It must be deterministic. If the batch containing a quarantine record fails to
// commit, the original message is redelivered and the record is synthesized again;
// a random id would append a second copy of the same incident to an append-only
// table on every retry. A derived id makes the existing-id filter suppress it.
var quarantineNamespace = uuid.NewSHA1(uuid.Nil, []byte("hatef.audit.quarantine.v1"))

// Fetcher is the pull-consumer surface the signer uses. jetstream.Consumer satisfies
// it; a unit test supplies a fake so the whole batch state machine is exercisable
// without a NATS server.
type Fetcher interface {
	Fetch(batch int, opts ...jetstream.FetchOpt) (jetstream.MessageBatch, error)
}

// BlindIndexer derives the ledger's identity_blind_index and reports which
// pepper generation produced it. *blindindex.Indexer satisfies it.
//
// Version is part of the interface because the digest alone is not enough: the
// generation is hashed into the signed ledger body, so a row written without it
// could never be re-derived after a pepper rotation.
type BlindIndexer interface {
	Compute(pii string) string
	Version() int16
}

// Config carries the signer's batching and retention policy.
type Config struct {
	// BatchSize bounds how many messages one batch pulls and COPYs.
	BatchSize int
	// FlushInterval bounds how long a partially filled batch waits before being
	// written, so a low-traffic system still persists events promptly.
	FlushInterval time.Duration
	// LedgerRetention sets security_event_ledger.retain_until relative to the
	// event's occurrence time. It is independent of the audit table's retention:
	// the ledger's legal-evidence window outlives the operational log.
	LedgerRetention time.Duration
}

// BatchTimeout bounds one batch's database work. It is generous relative to a COPY
// of BatchSize rows because exceeding it means Nak and redelivery, not loss — but it
// must stay well under the consumer's AckWait so the server does not redeliver a
// batch that is still committing.
//
// It is exported so the configuration loader can enforce that relationship against a
// real number rather than a copied literal: AckWait has to cover the time a batch
// spends filling *plus* the time it spends committing.
const BatchTimeout = 30 * time.Second

// commitFailureBackoff is how long the signer waits after a failed commit before
// fetching again. Without it, a database outage would spin the fetch loop at full
// speed while every batch fails.
const commitFailureBackoff = 2 * time.Second

// Signer drains the audit stream and writes both hash chains. Construct it with
// New; the zero value is not usable.
type Signer struct {
	cfg      Config
	store    Store
	opener   BatchTxOpener
	consumer Fetcher
	locker   pglock.AdvisoryLocker
	indexer  BlindIndexer
	logger   *slog.Logger
	now      func() time.Time

	// Both tips and their head sequences are re-read from the durable head rows
	// at the start of every batch, under the coordination lock. Caching them
	// across batches would make a failed commit's uncertainty unrecoverable.
	auditTip    audit.Digest
	ledgerTip   audit.Digest
	auditSeq    int64
	ledgerSeq   int64
	tipsUnknown bool
}

// Option configures optional behaviour on a Signer.
type Option func(*Signer)

// WithLogger overrides the worker logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Signer) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock overrides the time source so retain_until arithmetic is deterministic
// in tests.
func WithClock(now func() time.Time) Option {
	return func(s *Signer) {
		if now != nil {
			s.now = now
		}
	}
}

// WithBlindIndexer attaches the blind-index derivation.
//
// It is optional so the worker still runs — and still chains correctly — when the
// pepper is unavailable. identity_blind_index is nullable by design, so the cost of
// its absence is a degraded lookup path, whereas refusing to sign would stop the
// ledger entirely. The absence is logged once per batch that needed it.
func WithBlindIndexer(i BlindIndexer) Option {
	return func(s *Signer) {
		if i != nil {
			s.indexer = i
		}
	}
}

// WithAdvisoryLocker attaches the single-writer lock. It is an Option only so unit
// tests can omit it; production wiring must always supply it.
func WithAdvisoryLocker(l pglock.AdvisoryLocker) Option {
	return func(s *Signer) { s.locker = l }
}

// New constructs a Signer.
func New(cfg Config, store Store, opener BatchTxOpener, consumer Fetcher, opts ...Option) (*Signer, error) {
	if store == nil || opener == nil || consumer == nil {
		return nil, errors.New("signer: store, batch opener and consumer are required")
	}
	if cfg.BatchSize <= 0 {
		return nil, fmt.Errorf("signer: batch size must be positive, got %d", cfg.BatchSize)
	}
	if cfg.FlushInterval <= 0 {
		return nil, fmt.Errorf("signer: flush interval must be positive, got %s", cfg.FlushInterval)
	}
	if cfg.LedgerRetention <= 0 {
		return nil, fmt.Errorf("signer: ledger retention must be positive, got %s", cfg.LedgerRetention)
	}
	s := &Signer{
		cfg:      cfg,
		store:    store,
		opener:   opener,
		consumer: consumer,
		logger:   slog.Default(),
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// RunUntilDone signs batches until ctx is cancelled.
//
// A cancelled context is a normal, successful shutdown: the in-flight batch is
// allowed to finish (its database work runs on a context detached from ctx) and then
// the loop exits. Killing a batch mid-commit would only produce a redelivery.
func (s *Signer) RunUntilDone(ctx context.Context) error {
	if s.locker == nil {
		return errors.New("signer: advisory locker is required; refusing to run without the single-writer guarantee")
	}

	acquired, release, err := s.locker.TryLock(ctx)
	if err != nil {
		return fmt.Errorf("signer: acquire advisory lock: %w", err)
	}
	if !acquired {
		return ErrLockUnavailable
	}
	defer release()

	if err := s.seedChainTips(ctx); err != nil {
		return err
	}

	s.logger.Info("signer: started",
		slog.Int("batch_size", s.cfg.BatchSize),
		slog.String("flush_interval", s.cfg.FlushInterval.String()),
		slog.String("ledger_retention", s.cfg.LedgerRetention.String()))

	for {
		if err := ctx.Err(); err != nil {
			s.logger.Info("signer: shutdown requested; stopping after the in-flight batch")
			return nil
		}

		batch, err := s.consumer.Fetch(s.cfg.BatchSize, jetstream.FetchMaxWait(s.cfg.FlushInterval))
		if err != nil {
			// A fetch error is a transport condition, not a data condition: nothing has
			// been consumed, so backing off and retrying is safe.
			s.logger.Error("signer: fetch batch", slog.String("error", err.Error()))
			if !sleepCtx(ctx, commitFailureBackoff) {
				return nil
			}
			continue
		}

		msgs := drain(batch)
		if err := batch.Error(); err != nil {
			// Report and still process what arrived: the messages already in hand are
			// un-acked, so discarding them would only force a redelivery.
			s.logger.Error("signer: batch delivery incomplete",
				slog.Int("messages_received", len(msgs)),
				slog.String("error", err.Error()))
		}
		if len(msgs) == 0 {
			continue
		}

		if err := s.processBatch(ctx, msgs); err != nil {
			if errors.Is(err, ErrChainTipsUnknown) || errors.Is(err, ErrLedgerStateInvalid) {
				return err
			}
			s.logger.Error("signer: batch failed; messages will be redelivered",
				slog.Int("messages", len(msgs)),
				slog.String("error", err.Error()))
			if !sleepCtx(ctx, commitFailureBackoff) {
				return nil
			}
		}
	}
}

// seedChainTips reads both durable heads and verifies the ledger chain before the
// signer appends to it.
func (s *Signer) seedChainTips(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	tx, err := s.opener.BeginBatch(ctx)
	if err != nil {
		return err
	}
	defer s.rollbackBatch(ctx, tx)
	auditSeq, auditTip, err := readAuditHead(ctx, tx.Store())
	if err != nil {
		return fmt.Errorf("signer: read audit chain head: %w", err)
	}
	ledgerSeq, ledgerTip, err := readLedgerHead(ctx, tx.Store())
	if err != nil {
		return fmt.Errorf("signer: read ledger chain head: %w", err)
	}
	if err := tx.ValidateLedgerState(ctx, ledgerSeq); err != nil {
		return fmt.Errorf("signer: verify ledger state: %w", err)
	}
	s.auditSeq, s.auditTip = auditSeq, auditTip
	s.ledgerSeq, s.ledgerTip = ledgerSeq, ledgerTip
	s.tipsUnknown = false
	return nil
}

// readAuditHead reads the audit chain's durable head.
//
// A missing or inconsistent head is fatal rather than being treated as genesis.
// Both chains now get the same treatment: under v1 the audit tip was read with
// ORDER BY seq DESC LIMIT 1 and an empty table was accepted as genesis, which was
// only safe while audit rows were un-purgeable. The split makes a Class C
// retention policy possible, so "the table looks empty" must stop meaning "this
// chain has never been written".
func readAuditHead(ctx context.Context, store Store) (int64, audit.Digest, error) {
	head, err := store.GetAuditLogHead(ctx)
	if err != nil {
		return 0, audit.Digest{}, fmt.Errorf("%w: read audit head: %w", ErrLedgerStateInvalid, err)
	}
	tip, err := audit.DecodeDigest(head.ChainHash)
	if err != nil || !head.StateValid || head.Seq < 0 || (head.Seq == 0 && tip != audit.AuditGenesis()) {
		return 0, audit.Digest{}, ErrLedgerStateInvalid
	}
	return head.Seq, tip, nil
}

func readLedgerHead(ctx context.Context, store Store) (int64, audit.Digest, error) {
	head, err := store.GetSecurityLedgerHead(ctx)
	if err != nil {
		return 0, audit.Digest{}, fmt.Errorf("%w: read head: %w", ErrLedgerStateInvalid, err)
	}
	tip, err := audit.DecodeDigest(head.ChainHash)
	if err != nil || !head.StateValid || head.Seq < 0 || (head.Seq == 0 && tip != audit.LedgerGenesis()) {
		return 0, audit.Digest{}, ErrLedgerStateInvalid
	}
	return head.Seq, tip, nil
}

func (s *Signer) rollbackBatch(ctx context.Context, tx BatchTx) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := tx.Rollback(cleanupCtx); err != nil {
		s.logger.Error("signer: rollback batch transaction", slog.String("error", err.Error()))
	}
}

// batchStats is the per-batch observability record. It is one log line rather than
// Prometheus counters because this repo has no metrics endpoint yet (Task 5.2 D6);
// log-based alerting keys off these fields until it does.
type batchStats struct {
	messages          int
	eventsWritten     int
	ledgerRowsWritten int
	duplicatesSkipped int
	quarantined       int
	// ledgerUnattributable counts Class B events that could NOT be written to the
	// ledger because their attribution was unusable. It deliberately does not
	// count ordinary audit-only events.
	//
	// v1 reported `ledger_rows_skipped = kept - ledgerRows`, which is large in
	// normal operation because most audit events are not Class B at all. That made
	// the number useless for alerting and hid the condition that actually matters:
	// an event declared as a ledger type whose account_ref cannot be resolved, so
	// attribution evidence is silently lost.
	ledgerUnattributable int
	streamPending        uint64
}

// processBatch decodes, chains, and persists one batch, then acknowledges it.
//
// The order is load-bearing: acknowledge only after commit. Acking first would let a
// crash between ack and commit destroy the batch permanently, because JetStream has
// already dropped it and both tables refuse the retro-active insert an operator would
// need to repair the chain.
func (s *Signer) processBatch(ctx context.Context, msgs []jetstream.Msg) error {
	if s.tipsUnknown {
		s.nakAll(msgs)
		return ErrChainTipsUnknown
	}
	started := s.now()
	stats := batchStats{messages: len(msgs)}

	// Detached from ctx on purpose: a SIGTERM received mid-batch must not abort the
	// database work. Finishing costs one BatchTimeout at shutdown; aborting costs a
	// redelivery and a wasted chain computation.
	batchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), BatchTimeout)
	defer cancel()

	outcomes := s.decode(msgs)

	decoded, quarantined := split(outcomes)
	stats.quarantined = len(quarantined)
	stats.streamPending = pendingFromLast(msgs)

	tx, err := s.opener.BeginBatch(batchCtx)
	if err != nil {
		s.nakAll(msgs)
		return err
	}
	defer s.rollbackBatch(batchCtx, tx)

	store := tx.Store()

	// BeginBatch holds the ledger lock before any account/subject lock. Both heads
	// are re-read here rather than trusted from the previous batch: a separate
	// READ COMMITTED statement sees the latest committed head after a lock wait.
	auditSeq, auditTip, err := readAuditHead(batchCtx, store)
	if err != nil {
		s.nakAll(msgs)
		return err
	}
	ledgerSeq, ledgerTip, err := readLedgerHead(batchCtx, store)
	if err != nil {
		s.nakAll(msgs)
		return err
	}

	// Quarantine records are chained first, and before the real events, so the
	// incident is ordered ahead of everything that followed it in the same batch.
	pending := make([]pendingRecord, 0, len(decoded)+len(quarantined))
	pending = append(pending, quarantined...)
	pending = append(pending, decoded...)

	kept, skipped, err := s.filterDuplicates(batchCtx, store, pending)
	if err != nil {
		s.nakAll(msgs)
		return err
	}
	stats.duplicatesSkipped = skipped
	if len(kept) == 0 {
		// Nothing new survived deduplication. Commit so the (empty) transaction
		// releases its locks, then settle the messages: they are already durable.
		if err := tx.Commit(batchCtx); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: commit empty batch: %w", err)
		}
		s.acknowledge(outcomes)
		s.logBatch(stats, s.now().Sub(started))
		return nil
	}

	subjectIDs := make([]uuid.UUID, 0, len(kept))
	accountIDs := make([]uuid.UUID, 0, 2*len(kept))
	for _, rec := range kept {
		if id, err := uuid.Parse(rec.envelope.SubjectID); err == nil && id != uuid.Nil {
			subjectIDs = append(subjectIDs, id)
			accountIDs = append(accountIDs, id)
		}
		if security := rec.envelope.Security; security != nil {
			if id, err := uuid.Parse(security.AccountRef); err == nil && id != uuid.Nil {
				accountIDs = append(accountIDs, id)
			}
		}
	}
	if err := tx.LockAccounts(batchCtx, accountIDs); err != nil {
		s.nakAll(msgs)
		return fmt.Errorf("signer: lock accounts: %w", err)
	}
	liveSubjects := make(map[uuid.UUID]bool, len(subjectIDs))
	if len(subjectIDs) > 0 {
		ids, err := store.LockAuditSubjects(batchCtx, subjectIDs)
		if err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: lock audit subjects: %w", err)
		}
		for _, id := range ids {
			liveSubjects[id] = true
		}
	}

	// Resolve ledger attribution before allocating sequences, because only the
	// subset that produces a ledger row consumes a ledger position. Allocating
	// per-record and discarding the unused values would leave gaps that are
	// harmless but make an operator's "is my chain contiguous?" check useless.
	type ledgerPending struct {
		record     audit.LedgerRecord
		blindIndex *string
		version    int16
	}
	ledgerQueue := make([]ledgerPending, 0, len(kept))
	blindIndexes := make(map[uuid.UUID]*string, len(kept))
	ledgerContexts := make([]*ledgerContext, len(kept))
	for i, rec := range kept {
		lc, ok, resolveErr := s.resolveLedgerContext(rec.envelope)
		if resolveErr != nil {
			stats.ledgerUnattributable++
		}
		if !ok {
			continue
		}
		ctxCopy := lc
		ledgerContexts[i] = &ctxCopy
	}

	auditSeqs, err := store.AllocateAuditLogSeqs(batchCtx, int32(len(kept))) //nolint:gosec // G115: bounded by BatchSize.
	if err != nil {
		s.nakAll(msgs)
		return fmt.Errorf("signer: allocate audit chain positions: %w", err)
	}
	if len(auditSeqs) != len(kept) {
		s.nakAll(msgs)
		return fmt.Errorf("signer: allocated %d audit positions for %d records", len(auditSeqs), len(kept))
	}

	auditChain := make([]db.InsertAuditLogChainParams, 0, len(kept))
	auditRows := make([]db.InsertAuditLogsParams, 0, len(kept))

	for i, rec := range kept {
		env := rec.envelope
		// Covers old queued envelopes and synthetic events as well as new producers.
		env.OccurredAt = audit.NormalizeChainTime(env.OccurredAt)

		leafHash, err := audit.LeafAudit(env.AuditRecord())
		if err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: serialize audit record: %w", err)
		}
		auditTip = audit.ChainAudit(auditTip, leafHash)
		seq := auditSeqs[i]
		auditChain = append(auditChain, db.InsertAuditLogChainParams{
			Seq:       seq,
			EventID:   env.EventID,
			LeafHash:  leafHash.Bytes(),
			ChainHash: auditTip.Bytes(),
		})
		row := buildAuditRow(env, seq)
		if !liveSubjects[row.UserID.UUID] {
			row.UserID = uuid.NullUUID{}
		}
		auditRows = append(auditRows, row)

		lc := ledgerContexts[i]
		if lc == nil {
			continue
		}
		blindIndex := lc.identityBlindIndex
		version := lc.blindIndexVersion
		if blindIndex == nil {
			blindIndex, err = s.blindIndexFor(batchCtx, store, blindIndexes, lc.accountRef)
			if err != nil {
				s.nakAll(msgs)
				return err
			}
			if blindIndex != nil && s.indexer != nil {
				version = s.indexer.Version()
			}
		}
		ledgerQueue = append(ledgerQueue, ledgerPending{
			record:     s.buildLedgerRecord(env, *lc, blindIndex, version),
			blindIndex: blindIndex,
			version:    version,
		})
	}

	ledgerChain := make([]db.InsertSecurityLedgerChainParams, 0, len(ledgerQueue))
	ledgerRows := make([]db.InsertSecurityEventsParams, 0, len(ledgerQueue))
	if len(ledgerQueue) > 0 {
		ledgerSeqs, err := store.AllocateSecurityLedgerSeqs(batchCtx, int32(len(ledgerQueue))) //nolint:gosec // G115: bounded by BatchSize.
		if err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: allocate ledger chain positions: %w", err)
		}
		if len(ledgerSeqs) != len(ledgerQueue) {
			s.nakAll(msgs)
			return fmt.Errorf("signer: allocated %d ledger positions for %d records", len(ledgerSeqs), len(ledgerQueue))
		}
		for i, item := range ledgerQueue {
			leafHash, err := audit.LeafLedger(item.record)
			if err != nil {
				s.nakAll(msgs)
				return fmt.Errorf("signer: serialize ledger record: %w", err)
			}
			ledgerTip = audit.ChainLedger(ledgerTip, leafHash)
			eventID, parseErr := uuid.Parse(item.record.ID)
			if parseErr != nil {
				s.nakAll(msgs)
				return fmt.Errorf("signer: ledger record id %q: %w", item.record.ID, parseErr)
			}
			ledgerChain = append(ledgerChain, db.InsertSecurityLedgerChainParams{
				Seq:       ledgerSeqs[i],
				EventID:   eventID,
				LeafHash:  leafHash.Bytes(),
				ChainHash: ledgerTip.Bytes(),
			})
			ledgerRows = append(ledgerRows, buildLedgerRow(item.record, ledgerSeqs[i]))
		}
	}

	// Chain nodes first: the payload rows reference them.
	if len(auditChain) > 0 {
		if _, err := store.InsertAuditLogChain(batchCtx, auditChain); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy audit chain nodes: %w", err)
		}
		if _, err := store.InsertAuditLogs(batchCtx, auditRows); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy audit rows: %w", err)
		}
		if err := store.AdvanceChainHead(batchCtx, db.AdvanceChainHeadParams{
			Which:       "audit",
			ExpectedSeq: auditSeq,
			FirstSeq:    auditChain[0].Seq,
			LastSeq:     auditChain[len(auditChain)-1].Seq,
			NodeCount:   int64(len(auditChain)),
		}); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: advance audit head: %w", err)
		}
	}
	if len(ledgerChain) > 0 {
		if _, err := store.InsertSecurityLedgerChain(batchCtx, ledgerChain); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy ledger chain nodes: %w", err)
		}
		if _, err := store.InsertSecurityEvents(batchCtx, ledgerRows); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy ledger rows: %w", err)
		}
		if err := store.AdvanceChainHead(batchCtx, db.AdvanceChainHeadParams{
			Which:       "ledger",
			ExpectedSeq: ledgerSeq,
			FirstSeq:    ledgerChain[0].Seq,
			LastSeq:     ledgerChain[len(ledgerChain)-1].Seq,
			NodeCount:   int64(len(ledgerChain)),
		}); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: advance ledger head: %w", err)
		}
	}

	if err := tx.Commit(batchCtx); err != nil {
		// The transaction's outcome is unknown from here, so the cached tips can no
		// longer be trusted: re-read them from the database before the redelivered
		// batch is chained again.
		s.nakAll(msgs)
		s.tipsUnknown = true
		// End the uncertain transaction before taking a fresh coordination lock.
		s.rollbackBatch(batchCtx, tx)
		recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), BatchTimeout)
		defer recoveryCancel()
		if seedErr := s.seedChainTips(recoveryCtx); seedErr != nil {
			return fmt.Errorf("%w: commit: %v; reseed: %v", ErrChainTipsUnknown, err, seedErr)
		}
		return fmt.Errorf("signer: commit batch: %w", err)
	}

	s.auditTip, s.ledgerTip = auditTip, ledgerTip
	if len(auditChain) > 0 {
		s.auditSeq = auditChain[len(auditChain)-1].Seq
	}
	if len(ledgerChain) > 0 {
		s.ledgerSeq = ledgerChain[len(ledgerChain)-1].Seq
	}
	stats.eventsWritten = len(auditRows)
	stats.ledgerRowsWritten = len(ledgerRows)

	s.acknowledge(outcomes)
	s.logBatch(stats, s.now().Sub(started))
	return nil
}

// messageOutcome pairs one fetched message with the record it produced and how it
// must be settled. Keeping the pairing explicit means the ack disposition is decided
// once, at decode time, instead of being re-derived later from the payload.
type messageOutcome struct {
	msg         jetstream.Msg
	record      pendingRecord
	undecodable bool
}

// split separates decoded records from synthesized quarantine records, preserving
// fetch order within each group.
func split(outcomes []messageOutcome) (decoded, quarantined []pendingRecord) {
	decoded = make([]pendingRecord, 0, len(outcomes))
	for _, o := range outcomes {
		if o.undecodable {
			quarantined = append(quarantined, o.record)
			continue
		}
		decoded = append(decoded, o.record)
	}
	return decoded, quarantined
}

// pendingRecord carries one record awaiting chaining. Quarantine records reach this
// stage identically to published ones — they are chained by the same code path, which
// is the point: a record about a lost event is as tamper-evident as any other.
type pendingRecord struct {
	envelope audit.Envelope
}

// decode turns messages into envelopes, synthesizing a quarantine record for any
// message that cannot be decoded.
//
// An undecodable message is never simply dropped. A gap in the ledger is
// indistinguishable from a deletion, so the loss itself is recorded — with the
// stream sequence and a digest of the raw bytes, which is enough to locate the
// original in the NATS store and to prove what was discarded.
func (s *Signer) decode(msgs []jetstream.Msg) []messageOutcome {
	outcomes := make([]messageOutcome, 0, len(msgs))
	for _, msg := range msgs {
		var env audit.Envelope
		err := json.Unmarshal(msg.Data(), &env)
		if err == nil && env.SchemaVersion != audit.EnvelopeSchemaVersion {
			// Forward compatibility is a decode failure on purpose: guessing at an
			// unknown layout would write a record whose hashed bytes do not describe
			// the event that actually happened.
			err = fmt.Errorf("unsupported envelope schema version %d (this signer speaks %d)",
				env.SchemaVersion, audit.EnvelopeSchemaVersion)
		}
		if err == nil && env.EventID == uuid.Nil {
			// Without an id there is no deduplication key, so an at-least-once
			// redelivery would silently append a duplicate.
			err = errors.New("envelope carries no event id")
		}
		if err != nil {
			outcomes = append(outcomes, messageOutcome{
				msg:         msg,
				record:      s.quarantineRecord(msg, err),
				undecodable: true,
			})
			continue
		}
		outcomes = append(outcomes, messageOutcome{msg: msg, record: pendingRecord{envelope: env}})
	}
	return outcomes
}

// quarantineRecord synthesizes the audit record that stands in for a message the
// signer could not decode.
func (s *Signer) quarantineRecord(msg jetstream.Msg, cause error) pendingRecord {
	raw := msg.Data()
	digest := sha256.Sum256(raw)
	rawDigest := hex.EncodeToString(digest[:])

	streamName := ""
	var streamSeq uint64
	if md, err := msg.Metadata(); err == nil {
		streamName = md.Stream
		streamSeq = md.Sequence.Stream
	}

	// Derive the id from the stream position when it is known, and from the payload
	// digest otherwise, so a redelivery maps to the same row. See
	// quarantineNamespace.
	name := rawDigest
	if streamName != "" {
		name = fmt.Sprintf("%s/%d", streamName, streamSeq)
	}
	eventID := uuid.NewSHA1(quarantineNamespace, []byte(name))

	s.logger.Error("signer: undecodable audit message quarantined",
		slog.String("marker", audit.AuditTransportFailureMarker),
		slog.String("event_id", eventID.String()),
		slog.String("stream", streamName),
		slog.Uint64("stream_sequence", streamSeq),
		slog.Int("raw_bytes", len(raw)),
		slog.String("raw_sha256", rawDigest),
		slog.String("error", cause.Error()))

	env := audit.Envelope{
		EventID:       eventID,
		SchemaVersion: audit.EnvelopeSchemaVersion,
		OccurredAt:    audit.NormalizeChainTime(s.now()),
		EventType:     audit.EventPipelineUndecodable,
		ActionStatus:  audit.StatusFailure,
		ActorID:       uuid.Nil.String(),
		ActorSPIFFEID: audit.SignerActorSPIFFEID,
		Payload: marshalPayload(map[string]any{
			"stream":          streamName,
			"stream_sequence": streamSeq,
			"raw_bytes":       len(raw),
			"raw_sha256":      rawDigest,
			"reason":          cause.Error(),
		}),
	}
	return pendingRecord{envelope: env}
}

// filterDuplicates removes records whose event id is already persisted in either
// table.
//
// This is what makes at-least-once delivery safe. JetStream redelivers after a
// crash between commit and ack, and both tables have UPDATE and DELETE revoked, so a
// duplicate row would be permanent and uncorrectable. The check runs inside the
// batch transaction so it sees the same snapshot the COPY will write into.
func (s *Signer) filterDuplicates(ctx context.Context, store Store, records []pendingRecord) ([]pendingRecord, int, error) {
	if len(records) == 0 {
		return records, 0, nil
	}

	ids := make([]uuid.UUID, 0, len(records))
	for _, rec := range records {
		ids = append(ids, rec.envelope.EventID)
	}

	existing := make(map[uuid.UUID]struct{}, len(ids))
	auditIDs, err := store.FilterExistingAuditLogIDs(ctx, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("signer: filter existing audit ids: %w", err)
	}
	for _, id := range auditIDs {
		existing[id] = struct{}{}
	}
	ledgerIDs, err := store.FilterExistingSecurityEventIDs(ctx, ids)
	if err != nil {
		return nil, 0, fmt.Errorf("signer: filter existing ledger ids: %w", err)
	}
	for _, id := range ledgerIDs {
		existing[id] = struct{}{}
	}

	// Also guard against a duplicate id appearing twice within one batch, which the
	// database cannot reject mid-COPY.
	seen := make(map[uuid.UUID]struct{}, len(records))
	kept := make([]pendingRecord, 0, len(records))
	skipped := 0
	for _, rec := range records {
		id := rec.envelope.EventID
		_, alreadyStored := existing[id]
		_, alreadySeen := seen[id]
		if alreadyStored || alreadySeen {
			skipped++
			s.logger.Warn("signer: skipping already-persisted audit event",
				slog.String("event_id", id.String()),
				slog.String("event_type", rec.envelope.EventType))
			continue
		}
		seen[id] = struct{}{}
		kept = append(kept, rec)
	}
	return kept, skipped, nil
}

// ledgerContext is the resolved ledger attribution for one envelope.
type ledgerContext struct {
	accountRef         uuid.UUID
	clientID           string
	scope              string
	deviceFingerprint  string
	identityBlindIndex *string
	blindIndexVersion  int16
}

// resolveLedgerContext decides whether an envelope produces a ledger row.
//
// It returns (context, produceRow, attributionErr). The third value is what the
// batch counts as ledger_unattributable: a declared Class B event whose evidence
// could not be recorded. An ordinary audit-only event returns (zero, false, nil)
// and is not an error at all — conflating the two is what made v1's skip counter
// unusable.
func (s *Signer) resolveLedgerContext(env audit.Envelope) (ledgerContext, bool, error) {
	// The type allowlist, not producer-controlled Security, defines Class B.
	if !audit.IsLedgerEventType(env.EventType) {
		return ledgerContext{}, false, nil
	}

	if env.Security == nil {
		// Declared as a ledger event type but published without SecurityContext,
		// which means a call site forgot the declaration. Fall back to the audit
		// subject so the evidence is not lost outright.
		//
		// v1 re-tested IsLedgerEventType here, inside a branch the outer guard had
		// already made unreachable. The dead check implied this path handled
		// audit-only events; it never could.
		accountRef, err := uuid.Parse(env.SubjectID)
		if err != nil || accountRef == uuid.Nil {
			s.logger.Error("signer: ledger event type has neither security context nor a usable subject; no ledger row written",
				slog.String("event_id", env.EventID.String()),
				slog.String("event_type", env.EventType))
			return ledgerContext{}, false, errUnattributableLedgerEvent
		}
		s.logger.Error("signer: ledger event type published without a security context; falling back to the audit subject",
			slog.String("event_id", env.EventID.String()),
			slog.String("event_type", env.EventType),
			slog.String("account_ref", accountRef.String()))
		return ledgerContext{accountRef: accountRef}, true, errUnattributableLedgerEvent
	}

	accountRef, err := uuid.Parse(env.Security.AccountRef)
	if err != nil || accountRef == uuid.Nil {
		// account_ref is NOT NULL and must be a real users.id; inventing one would
		// fabricate attribution evidence. The audit row is still written.
		s.logger.Error("signer: security context has no usable account_ref; audit row written without a ledger row",
			slog.String("event_id", env.EventID.String()),
			slog.String("event_type", env.EventType))
		return ledgerContext{}, false, errUnattributableLedgerEvent
	}

	return ledgerContext{
		accountRef:         accountRef,
		clientID:           env.Security.ClientID,
		scope:              env.Security.Scope,
		deviceFingerprint:  env.Security.DeviceFingerprint,
		identityBlindIndex: env.Security.IdentityBlindIndex,
		blindIndexVersion:  env.Security.BlindIndexVersion,
	}, true, nil
}

// errUnattributableLedgerEvent marks a Class B event whose attribution could not
// be fully resolved. It is counted, never returned to the caller: the audit row is
// still written, and failing the batch would lose more evidence than it preserves.
var errUnattributableLedgerEvent = errors.New("signer: ledger event attribution incomplete")

// blindIndexFor resolves and caches identity_blind_index for one account.
//
// This is the fallback for legacy queued envelopes or failed producer capture.
// The email is read, hashed, and discarded; it is never logged.
//
// A purged subject yields NULL, which is the column's designed state for
// "attribution material no longer exists".
func (s *Signer) blindIndexFor(ctx context.Context, store Store, cache map[uuid.UUID]*string, accountRef uuid.UUID) (*string, error) {
	if cached, ok := cache[accountRef]; ok {
		return cached, nil
	}
	if s.indexer == nil {
		s.logger.Warn("signer: no blind indexer configured; ledger rows will have a NULL identity_blind_index",
			slog.String("account_ref", accountRef.String()))
		cache[accountRef] = nil
		return nil, nil
	}

	email, err := store.GetUserEmailForBlindIndex(ctx, accountRef)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The subject was hard-deleted between the event and its signing. The ledger
		// row still gets written — surviving deletion is the point — just without a
		// blind index to look it up by.
		cache[accountRef] = nil
		s.logger.Warn("signer: attribution unavailable; ledger index missing",
			slog.String("marker", "audit_index_missing"))
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("signer: resolve email for blind index: %w", err)
	}

	digest := s.indexer.Compute(email)
	cache[accountRef] = &digest
	return &digest, nil
}

// buildLedgerRecord assembles the chained ledger fields for one envelope.
func (s *Signer) buildLedgerRecord(env audit.Envelope, lc ledgerContext, blindIndex *string, version int16) audit.LedgerRecord {
	rec := audit.LedgerRecord{
		ID:                 env.EventID.String(),
		AccountRef:         lc.accountRef.String(),
		IdentityBlindIndex: blindIndex,
		BlindIndexVersion:  version,
		EventType:          env.EventType,
		ClientIP:           optional(env.ClientIP),
		UserAgent:          optional(env.UserAgent),
		DeviceFingerprint:  optional(lc.deviceFingerprint),
		ClientID:           optional(lc.clientID),
		Scope:              optional(lc.scope),
		Timestamp:          audit.NormalizeChainTime(env.OccurredAt),
		RetainUntil:        audit.NormalizeChainTime(env.OccurredAt.Add(s.cfg.LedgerRetention)),
	}
	if env.ClientIP != "" {
		subnet := ratelimit.Subnet(env.ClientIP)
		rec.IPSubnet = &subnet
	}
	return rec
}

// acknowledge settles every message in the batch after a successful commit.
//
// Undecodable messages are Term'ed, not Ack'ed: Term tells the server never to
// redeliver regardless of MaxDeliver, which is correct because the message cannot be
// decoded and further attempts cannot succeed. Its replacement quarantine record is
// already committed, so refusing it loses nothing.
func (s *Signer) acknowledge(outcomes []messageOutcome) {
	for _, o := range outcomes {
		var err error
		if o.undecodable {
			err = o.msg.TermWithReason("undecodable audit envelope; quarantine record committed")
		} else {
			err = o.msg.Ack()
		}
		if err != nil {
			// The batch is already durable, so a failed ack costs a redelivery that the
			// duplicate filter will absorb — not a lost event.
			s.logger.Warn("signer: acknowledge message after commit",
				slog.String("error", err.Error()))
		}
	}
}

// nakAll requests redelivery for the whole batch after a failure.
//
// NakWithDelay rather than Nak: an instant redelivery would hammer a database that is
// failing over, and the consumer's BackOff schedule does not apply to explicit naks.
func (s *Signer) nakAll(msgs []jetstream.Msg) {
	for _, msg := range msgs {
		if err := msg.NakWithDelay(commitFailureBackoff); err != nil {
			s.logger.Warn("signer: nak message after batch failure",
				slog.String("error", err.Error()))
		}
	}
}

// logBatch emits the single per-batch observability line.
func (s *Signer) logBatch(stats batchStats, elapsed time.Duration) {
	s.logger.Info("signer: batch committed",
		slog.Int("messages", stats.messages),
		slog.Int("events_written", stats.eventsWritten),
		slog.Int("ledger_rows_written", stats.ledgerRowsWritten),
		slog.Int("duplicates_skipped", stats.duplicatesSkipped),
		slog.Int("quarantined", stats.quarantined),
		// Any non-zero value here is a producer bug with compliance consequences:
		// a declared Class B event whose attribution could not be resolved.
		slog.Int("ledger_unattributable", stats.ledgerUnattributable),
		slog.Uint64("stream_pending", stats.streamPending),
		slog.String("batch_duration", elapsed.String()))
}

// buildAuditRow converts an envelope into payload COPY parameters.
//
// SubjectID becomes user_id here even though it is excluded from the hash: the column
// is the operational join for "show me this user's activity", while the hash must stay
// stable across the ON DELETE SET NULL that a GDPR purge triggers. See
// audit.AuditRecord.
//
// The event UUID is not written here. It belongs to the chain node, which is never
// deleted, because it is the pipeline's idempotency key.
func buildAuditRow(env audit.Envelope, seq int64) db.InsertAuditLogsParams {
	row := db.InsertAuditLogsParams{
		Seq:           seq,
		ActorSpiffeID: env.ActorSPIFFEID,
		EventType:     env.EventType,
		ActionStatus:  env.ActionStatus,
		ClientIp:      env.ClientIP,
		UserAgent:     env.UserAgent,
		Payload:       env.Payload,
		Timestamp:     timestamptz(env.OccurredAt),
	}
	if actorID, err := uuid.Parse(env.ActorID); err == nil {
		row.ActorID = actorID
	}
	if subjectID, err := uuid.Parse(env.SubjectID); err == nil && subjectID != uuid.Nil {
		row.UserID = uuid.NullUUID{UUID: subjectID, Valid: true}
	}
	return row
}

// buildLedgerRow converts a ledger record into payload COPY parameters.
func buildLedgerRow(rec audit.LedgerRecord, seq int64) db.InsertSecurityEventsParams {
	row := db.InsertSecurityEventsParams{
		Seq:                seq,
		IdentityBlindIndex: rec.IdentityBlindIndex,
		BlindIndexVersion:  rec.BlindIndexVersion,
		EventType:          rec.EventType,
		ClientIp:           rec.ClientIP,
		IpSubnet:           rec.IPSubnet,
		UserAgent:          rec.UserAgent,
		DeviceFingerprint:  rec.DeviceFingerprint,
		ClientID:           rec.ClientID,
		Scope:              rec.Scope,
		Timestamp:          timestamptz(rec.Timestamp),
		RetainUntil:        timestamptz(rec.RetainUntil),
	}
	// AccountRef was rendered from a real UUID by buildLedgerRecord, so this parse
	// cannot fail; ignoring the error keeps the happy path readable.
	row.AccountRef, _ = uuid.Parse(rec.AccountRef)
	return row
}
