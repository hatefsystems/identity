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

// BlindIndexer derives the ledger's identity_blind_index.
// *blindindex.Indexer satisfies it.
type BlindIndexer interface {
	Compute(pii string) string
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

	// auditTip and ledgerTip are the raw predecessor digests for the next record in
	// each chain. They are a cache of the database: any commit failure invalidates
	// them and they are re-read before the retry.
	auditTip    [sha256.Size]byte
	ledgerTip   [sha256.Size]byte
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
			if errors.Is(err, ErrChainTipsUnknown) {
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

// seedChainTips reads both chain tips from the database.
func (s *Signer) seedChainTips(ctx context.Context) error {
	auditTip, err := s.readTip(ctx, s.store.GetLatestAuditLogChainHash)
	if err != nil {
		return fmt.Errorf("signer: read audit chain tip: %w", err)
	}
	ledgerTip, err := s.readTip(ctx, s.store.GetLatestSecurityEventChainHash)
	if err != nil {
		return fmt.Errorf("signer: read ledger chain tip: %w", err)
	}
	s.auditTip = auditTip
	s.ledgerTip = ledgerTip
	s.tipsUnknown = false
	return nil
}

// readTip fetches one chain tip, treating an empty table as genesis.
func (s *Signer) readTip(ctx context.Context, get func(context.Context) (string, error)) ([sha256.Size]byte, error) {
	stored, err := get(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return audit.GenesisChainHash, nil
	}
	if err != nil {
		return audit.GenesisChainHash, err
	}
	return audit.DecodeChainHash(stored)
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
	ledgerSkipped     int
	streamPending     uint64
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
	defer func() {
		if rbErr := tx.Rollback(batchCtx); rbErr != nil {
			s.logger.Error("signer: rollback batch transaction", slog.String("error", rbErr.Error()))
		}
	}()

	store := tx.Store()

	// Both chains advance from the in-memory tips. They are only committed back to
	// the Signer once the transaction commits, so a rollback leaves the cached tips
	// exactly where the database still is.
	auditTip := s.auditTip
	ledgerTip := s.ledgerTip

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

	subjectIDs := make([]uuid.UUID, 0, len(kept))
	for _, rec := range kept {
		if id, err := uuid.Parse(rec.envelope.SubjectID); err == nil && id != uuid.Nil {
			subjectIDs = append(subjectIDs, id)
		}
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

	auditRows := make([]db.InsertAuditLogsParams, 0, len(kept))
	ledgerRows := make([]db.InsertSecurityEventsParams, 0, len(kept))
	blindIndexes := make(map[uuid.UUID]*string, len(kept))

	for _, rec := range kept {
		env := rec.envelope
		// Covers old queued envelopes and synthetic events as well as new producers.
		env.OccurredAt = audit.NormalizeChainTime(env.OccurredAt)

		auditRec := env.AuditRecord()
		auditHash := audit.ChainHash(auditTip, audit.SerializeAudit(auditRec))
		nextAuditTip, err := audit.DecodeChainHash(auditHash)
		if err != nil {
			// Unreachable: ChainHash always returns 64 hex characters. Handled rather
			// than ignored so a future change cannot silently corrupt the chain.
			s.nakAll(msgs)
			return fmt.Errorf("signer: decode computed audit chain hash: %w", err)
		}
		auditTip = nextAuditTip
		row := buildAuditRow(env, auditHash)
		if !liveSubjects[row.UserID.UUID] {
			row.UserID = uuid.NullUUID{}
		}
		auditRows = append(auditRows, row)

		ledgerCtx, ok := s.resolveLedgerContext(env)
		if !ok {
			continue
		}

		blindIndex := ledgerCtx.identityBlindIndex
		if blindIndex == nil {
			blindIndex, err = s.blindIndexFor(batchCtx, store, blindIndexes, ledgerCtx.accountRef)
			if err != nil {
				s.nakAll(msgs)
				return err
			}
		}

		ledgerRec := s.buildLedgerRecord(env, ledgerCtx, blindIndex)
		ledgerHash := audit.ChainHash(ledgerTip, audit.SerializeLedger(ledgerRec))
		nextLedgerTip, err := audit.DecodeChainHash(ledgerHash)
		if err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: decode computed ledger chain hash: %w", err)
		}
		ledgerTip = nextLedgerTip
		ledgerRows = append(ledgerRows, buildLedgerRow(ledgerRec, ledgerHash))
	}
	stats.ledgerSkipped = len(kept) - len(ledgerRows)

	if len(auditRows) > 0 {
		if _, err := store.InsertAuditLogs(batchCtx, auditRows); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy audit rows: %w", err)
		}
	}
	if len(ledgerRows) > 0 {
		if _, err := store.InsertSecurityEvents(batchCtx, ledgerRows); err != nil {
			s.nakAll(msgs)
			return fmt.Errorf("signer: copy ledger rows: %w", err)
		}
	}

	if err := tx.Commit(batchCtx); err != nil {
		// The transaction's outcome is unknown from here, so the cached tips can no
		// longer be trusted: re-read them from the database before the redelivered
		// batch is chained again.
		s.nakAll(msgs)
		s.tipsUnknown = true
		if seedErr := s.seedChainTips(batchCtx); seedErr != nil {
			return fmt.Errorf("%w: commit: %v; reseed: %v", ErrChainTipsUnknown, err, seedErr)
		}
		return fmt.Errorf("signer: commit batch: %w", err)
	}

	s.auditTip = auditTip
	s.ledgerTip = ledgerTip
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
}

// resolveLedgerContext decides whether an envelope produces a ledger row.
//
// Both mismatch directions are reported rather than silently accepted, because both
// are bugs with compliance consequences: a declared ledger event with no usable
// account loses attribution evidence, and a ledger event type published without
// SecurityContext means a call site forgot the declaration.
func (s *Signer) resolveLedgerContext(env audit.Envelope) (ledgerContext, bool) {
	// The type allowlist, not producer-controlled Security, defines Class B.
	if !audit.IsLedgerEventType(env.EventType) {
		return ledgerContext{}, false
	}
	if env.Security == nil {
		if !audit.IsLedgerEventType(env.EventType) {
			// Audit-only event: nothing to resolve.
			return ledgerContext{}, false
		}
		// Declared as a ledger event type but published without SecurityContext. Fall
		// back to the audit subject so the evidence is not lost outright.
		accountRef, err := uuid.Parse(env.SubjectID)
		if err != nil || accountRef == uuid.Nil {
			s.logger.Error("signer: ledger event type has neither security context nor a usable subject; no ledger row written",
				slog.String("event_id", env.EventID.String()),
				slog.String("event_type", env.EventType))
			return ledgerContext{}, false
		}
		s.logger.Error("signer: ledger event type published without a security context; falling back to the audit subject",
			slog.String("event_id", env.EventID.String()),
			slog.String("event_type", env.EventType),
			slog.String("account_ref", accountRef.String()))
		return ledgerContext{accountRef: accountRef}, true
	}

	accountRef, err := uuid.Parse(env.Security.AccountRef)
	if err != nil || accountRef == uuid.Nil {
		// account_ref is NOT NULL and must be a real users.id; inventing one would
		// fabricate attribution evidence. The audit row is still written.
		s.logger.Error("signer: security context has no usable account_ref; audit row written without a ledger row",
			slog.String("event_id", env.EventID.String()),
			slog.String("event_type", env.EventType))
		return ledgerContext{}, false
	}

	return ledgerContext{
		accountRef:         accountRef,
		clientID:           env.Security.ClientID,
		scope:              env.Security.Scope,
		deviceFingerprint:  env.Security.DeviceFingerprint,
		identityBlindIndex: env.Security.IdentityBlindIndex,
	}, true
}

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
func (s *Signer) buildLedgerRecord(env audit.Envelope, lc ledgerContext, blindIndex *string) audit.LedgerRecord {
	rec := audit.LedgerRecord{
		ID:                 env.EventID.String(),
		AccountRef:         lc.accountRef.String(),
		IdentityBlindIndex: blindIndex,
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
		slog.Int("ledger_rows_skipped", stats.ledgerSkipped),
		slog.Uint64("stream_pending", stats.streamPending),
		slog.String("batch_duration", elapsed.String()))
}

// buildAuditRow converts a chained envelope into COPY parameters.
//
// SubjectID becomes user_id here even though it is excluded from the hash: the column
// is the operational join for "show me this user's activity", while the hash must stay
// stable across the ON DELETE SET NULL that a GDPR purge triggers. See
// audit.AuditRecord.
func buildAuditRow(env audit.Envelope, chainHash string) db.InsertAuditLogsParams {
	row := db.InsertAuditLogsParams{
		ID:            env.EventID,
		ActorSpiffeID: env.ActorSPIFFEID,
		EventType:     env.EventType,
		ActionStatus:  env.ActionStatus,
		ClientIp:      env.ClientIP,
		UserAgent:     env.UserAgent,
		Payload:       env.Payload,
		Timestamp:     timestamptz(env.OccurredAt),
		ChainHash:     chainHash,
	}
	if actorID, err := uuid.Parse(env.ActorID); err == nil {
		row.ActorID = actorID
	}
	if subjectID, err := uuid.Parse(env.SubjectID); err == nil && subjectID != uuid.Nil {
		row.UserID = uuid.NullUUID{UUID: subjectID, Valid: true}
	}
	return row
}

// buildLedgerRow converts a chained ledger record into COPY parameters.
func buildLedgerRow(rec audit.LedgerRecord, chainHash string) db.InsertSecurityEventsParams {
	row := db.InsertSecurityEventsParams{
		IdentityBlindIndex: rec.IdentityBlindIndex,
		EventType:          rec.EventType,
		ClientIp:           rec.ClientIP,
		IpSubnet:           rec.IPSubnet,
		UserAgent:          rec.UserAgent,
		DeviceFingerprint:  rec.DeviceFingerprint,
		ClientID:           rec.ClientID,
		Scope:              rec.Scope,
		Timestamp:          timestamptz(rec.Timestamp),
		RetainUntil:        timestamptz(rec.RetainUntil),
		ChainHash:          chainHash,
	}
	// Both ids were rendered from real UUIDs by buildLedgerRecord, so these parses
	// cannot fail; ignoring the error keeps the happy path readable.
	row.ID, _ = uuid.Parse(rec.ID)
	row.AccountRef, _ = uuid.Parse(rec.AccountRef)
	return row
}
