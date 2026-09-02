package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// SubjectDeletedEvent is the NATS subject the outbox row carries
// (docs/api-design.md §3). Downstream services consume it to scrub their local
// copies of the subject's PII.
const SubjectDeletedEvent = "identity.user.deleted"

// PurgeAdvisoryLockKey is the PostgreSQL advisory-lock key the purge worker holds
// for the duration of a run, so two overlapping CronJob invocations (a slow run
// plus the next schedule tick, or a manual run alongside the schedule) cannot both
// walk the same batch.
//
// The value is arbitrary but must be stable and unique across every advisory lock
// this platform takes; it is written as a decimal literal rather than a hash so it
// is greppable and can be inspected directly in pg_locks (objid). Reserve a new
// literal for each future worker instead of reusing this one.
const PurgeAdvisoryLockKey int64 = 5100001

// PurgeStore is the database query subset the purge worker needs. It is satisfied
// by *db.Queries, both pool-bound (for the batch listing) and transaction-bound
// (for the per-subject work).
type PurgeStore interface {
	ListUsersDueForHardDelete(ctx context.Context, arg db.ListUsersDueForHardDeleteParams) ([]uuid.UUID, error)
	GetUserForUpdateIncludingDeleted(ctx context.Context, id uuid.UUID) (db.User, error)
	HasActiveLegalHold(ctx context.Context, accountRef uuid.UUID) (bool, error)
	HardDeleteUser(ctx context.Context, arg db.HardDeleteUserParams) (int64, error)
	EnqueueOutboxEvent(ctx context.Context, arg db.EnqueueOutboxEventParams) (db.EventOutbox, error)
}

// SubjectTx is one per-subject transaction: a transaction-bound query set plus its
// commit/rollback control.
//
// It is an interface rather than a closure so a unit test can assert *that* a
// subject was rolled back rather than committed — which is the whole point of the
// fail-closed legal-hold behaviour and of dry-run mode, and is otherwise
// unobservable without a live database.
type SubjectTx interface {
	// Store returns the transaction-bound query set.
	Store() PurgeStore
	// Commit makes the subject's delete and its outbox event durable together.
	Commit(ctx context.Context) error
	// Rollback discards both. It must be safe to call after Commit.
	Rollback(ctx context.Context) error
}

// SubjectTxOpener opens one transaction per subject. The purge worker never shares
// a transaction across subjects: one poisoned subject must not roll back or block
// the rest of the batch.
type SubjectTxOpener interface {
	BeginSubject(ctx context.Context) (SubjectTx, error)
}

// AdvisoryLocker serialises worker runs across processes.
type AdvisoryLocker interface {
	// TryLock reports whether the lock was acquired without waiting. When it
	// returns true the caller must invoke release exactly once. When it returns
	// false the caller must exit successfully: another run holds the lock, and
	// treating contention as an error would make a normal schedule overlap page
	// somebody.
	TryLock(ctx context.Context) (acquired bool, release func(), err error)
}

// PurgeStats summarises one run. Considered is the batch size actually examined,
// so Considered == BatchSize is the signal that more subjects are waiting and the
// worker should be run again (or its schedule tightened).
type PurgeStats struct {
	Considered       int
	Purged           int
	SkippedLegalHold int
	Failed           int
}

// PurgeConfig carries the worker's policy.
type PurgeConfig struct {
	// GracePeriod is the recovery window; the cutoff is now - GracePeriod. It must
	// match the value the reclaim tokens were minted against, which is why both
	// come from the same config.PrivacyConfig.
	GracePeriod time.Duration
	// BatchSize bounds how many subjects one run considers.
	BatchSize int
	// DryRun performs every read and decision, logs the intended outcome, and
	// rolls back without deleting or enqueuing.
	DryRun bool
}

// Purger is the one-shot GDPR hard-delete worker. Construct it with NewPurger; the
// zero value is not usable.
type Purger struct {
	store    PurgeStore
	opener   SubjectTxOpener
	locker   AdvisoryLocker
	recorder audit.Recorder
	logger   *slog.Logger

	gracePeriod time.Duration
	batchSize   int
	dryRun      bool

	now func() time.Time
}

// PurgeOption configures optional behavior on a Purger.
type PurgeOption func(*Purger)

// WithAdvisoryLocker attaches the cross-process run lock. Without it, concurrent
// runs are possible; every individual subject is still safe (the per-subject
// users-row lock and the query guards make double-deletion impossible), but the
// runs would duplicate work and interleave their logs.
func WithAdvisoryLocker(l AdvisoryLocker) PurgeOption {
	return func(p *Purger) { p.locker = l }
}

// WithPurgeLogger overrides the worker logger.
func WithPurgeLogger(l *slog.Logger) PurgeOption {
	return func(p *Purger) {
		if l != nil {
			p.logger = l
		}
	}
}

// WithPurgeClock overrides the worker time source so cutoff arithmetic is
// deterministic in tests.
func WithPurgeClock(now func() time.Time) PurgeOption {
	return func(p *Purger) {
		if now != nil {
			p.now = now
		}
	}
}

// NewPurger constructs a Purger.
func NewPurger(cfg PurgeConfig, store PurgeStore, opener SubjectTxOpener, recorder audit.Recorder, opts ...PurgeOption) (*Purger, error) {
	if store == nil {
		return nil, errors.New("privacy: purge store is required")
	}
	if opener == nil {
		return nil, errors.New("privacy: subject transaction opener is required")
	}
	if recorder == nil {
		return nil, errors.New("privacy: audit recorder is required")
	}

	p := &Purger{
		store:       store,
		opener:      opener,
		recorder:    recorder,
		logger:      slog.Default(),
		gracePeriod: cfg.GracePeriod,
		batchSize:   cfg.BatchSize,
		dryRun:      cfg.DryRun,
		now:         time.Now,
	}
	if p.gracePeriod <= 0 {
		p.gracePeriod = defaultGracePeriod
	}
	if p.batchSize <= 0 {
		p.batchSize = defaultPurgeBatchSize
	}

	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// defaultPurgeBatchSize mirrors config.LoadPrivacy's default so a Purger built
// without a loaded config behaves like production.
const defaultPurgeBatchSize = 100

// RunOnce performs one bounded purge pass and returns its statistics.
//
// The contract, in order of importance:
//
//   - It never purges when the legal-hold answer is uncertain. A hold-check error
//     skips the subject, records privacy.deletion.purge_failed, and continues.
//     Holds outrank every retention timer, so "we could not tell" must resolve to
//     "do not delete".
//   - Every subject runs in its own transaction. One failure never rolls back or
//     blocks the batch.
//   - No event without a commit, no commit without an event. The DELETE and the
//     outbox insert share one transaction, and a DELETE affecting anything other
//     than exactly one row rolls both back.
//   - The security_event_ledger is never touched. That is enforced by the schema
//     (it has no foreign key to users), not by discipline here.
//
// An error return means the run could not proceed at all (the batch listing
// failed). Per-subject problems are counted in PurgeStats.Failed, not returned:
// exiting non-zero for one bad subject would make a CronJob alert on a condition
// the next run may well clear by itself.
func (p *Purger) RunOnce(ctx context.Context) (PurgeStats, error) {
	var stats PurgeStats

	if p.locker != nil {
		acquired, release, err := p.locker.TryLock(ctx)
		if err != nil {
			return stats, fmt.Errorf("privacy: acquire purge advisory lock: %w", err)
		}
		if !acquired {
			p.logger.Info("privacy: purge run skipped; another run holds the advisory lock")
			return stats, nil
		}
		defer release()
	}

	cutoff := p.now().Add(-p.gracePeriod)
	due, err := p.store.ListUsersDueForHardDelete(ctx, db.ListUsersDueForHardDeleteParams{
		DeletedAt: pgtype.Timestamptz{Time: cutoff, Valid: true},
		Limit:     int32(p.batchSize), //nolint:gosec // G115: batchSize is a validated positive int from config.
	})
	if err != nil {
		return stats, fmt.Errorf("privacy: list subjects due for hard delete: %w", err)
	}
	stats.Considered = len(due)

	for _, userID := range due {
		// The batch is bounded, but a cancelled context (SIGTERM) must stop the
		// walk rather than have every remaining subject fail its transaction.
		if ctx.Err() != nil {
			break
		}
		switch p.purgeSubject(ctx, userID, cutoff) {
		case outcomePurged:
			stats.Purged++
		case outcomeSkippedLegalHold:
			stats.SkippedLegalHold++
		case outcomeFailed:
			stats.Failed++
		}
	}

	p.logger.Info("privacy: purge run complete",
		slog.Time("cutoff", cutoff.UTC()),
		slog.Bool("dry_run", p.dryRun),
		slog.Int("considered", stats.Considered),
		slog.Int("purged", stats.Purged),
		slog.Int("skipped_legal_hold", stats.SkippedLegalHold),
		slog.Int("failed", stats.Failed),
	)
	return stats, nil
}

// subjectOutcome classifies what happened to one subject.
type subjectOutcome int

const (
	// outcomePurged means the delete and its outbox event committed (or, in
	// dry-run, would have).
	outcomePurged subjectOutcome = iota
	// outcomeSkippedLegalHold means an active hold blocked the purge.
	outcomeSkippedLegalHold
	// outcomeFailed means the subject could not be decided or committed. It
	// includes the fail-closed hold-check error.
	outcomeFailed
	// outcomeNoop means the subject needed no action: it had already been purged
	// or had been reclaimed since the batch was listed. The batch listing is not
	// transactional, so this is an expected race, not an error — counting it as a
	// failure would make a normal reclaim look like a broken run.
	outcomeNoop
)

// purgeSubject runs one subject's transaction. It never returns an error: the
// outcome is the return value, and every failure path has already rolled back,
// audited, and logged by the time it returns.
func (p *Purger) purgeSubject(ctx context.Context, userID uuid.UUID, cutoff time.Time) subjectOutcome {
	tx, err := p.opener.BeginSubject(ctx)
	if err != nil {
		p.failSubject(ctx, userID, "begin_transaction", err)
		return outcomeFailed
	}
	committed := false
	defer func() {
		if !committed {
			// Rollback on every non-commit path, including dry-run.
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				p.logger.Error("privacy: rollback purge subject",
					slog.String("user_id", userID.String()), slog.String("error", rbErr.Error()))
			}
		}
	}()
	store := tx.Store()

	// Lock order: users first, then children. The soft-delete-blind variant is
	// mandatory here — the filtered lock cannot see a pending_deletion row.
	user, err := store.GetUserForUpdateIncludingDeleted(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Already gone: a concurrent run purged it, or a reclaim removed it
			// from the batch between the listing and now. Not a failure.
			p.logger.Info("privacy: purge subject no longer present",
				slog.String("user_id", userID.String()))
			return outcomeNoop
		}
		p.failSubject(ctx, userID, "lock_user", err)
		return outcomeFailed
	}
	if user.Status != statusPendingDeletion || !user.DeletedAt.Valid || !user.DeletedAt.Time.Before(cutoff) {
		// The listing is not transactional, so the row may have been reclaimed
		// since. Refuse rather than trust the stale batch.
		p.logger.Info("privacy: purge subject no longer eligible",
			slog.String("user_id", userID.String()), slog.String("status", user.Status))
		return outcomeNoop
	}

	// Fail closed: an error here is "we could not tell whether a hold exists", and
	// a hold outranks the retention timer.
	held, err := store.HasActiveLegalHold(ctx, user.ID)
	if err != nil {
		p.failSubject(ctx, userID, "legal_hold_check", err)
		return outcomeFailed
	}
	if held {
		p.record(ctx, audit.Event{
			EventType:     audit.EventDeletionSkippedLegalHold,
			ActionStatus:  audit.StatusSuccess,
			ActorSPIFFEID: audit.SystemActorSPIFFEID,
			SubjectID:     &user.ID,
			Payload: map[string]any{
				"reason":  "active legal hold outranks the retention timer",
				"dry_run": p.dryRun,
			},
		})
		p.logger.Info("privacy: purge skipped for active legal hold",
			slog.String("user_id", userID.String()))
		return outcomeSkippedLegalHold
	}

	if p.dryRun {
		p.logger.Info("privacy: dry run would hard-delete subject",
			slog.String("user_id", userID.String()),
			slog.Time("deleted_at", user.DeletedAt.Time.UTC()))
		return outcomePurged
	}

	affected, err := store.HardDeleteUser(ctx, db.HardDeleteUserParams{
		ID:        user.ID,
		DeletedAt: pgtype.Timestamptz{Time: cutoff, Valid: true},
	})
	if err != nil {
		p.failSubject(ctx, userID, "hard_delete", err)
		return outcomeFailed
	}
	if affected != 1 {
		// Either a reclaim won the row, or the query's own NOT EXISTS legal-hold
		// predicate caught a hold applied since the check above (the TOCTOU this
		// predicate exists to close). Roll back without enqueuing an event: an
		// identity.user.deleted for a subject that still exists would have
		// downstream services scrub live data.
		p.record(ctx, audit.Event{
			EventType:     audit.EventDeletionPurgeFailed,
			ActionStatus:  audit.StatusFailure,
			ActorSPIFFEID: audit.SystemActorSPIFFEID,
			SubjectID:     &user.ID,
			Payload: map[string]any{
				"stage":         "hard_delete",
				"rows_affected": affected,
				"reason":        "subject was reclaimed or a legal hold was applied concurrently",
			},
		})
		p.logger.Warn("privacy: hard delete affected no rows; rolling back",
			slog.String("user_id", userID.String()), slog.Int64("rows", affected))
		return outcomeFailed
	}

	payload, err := json.Marshal(map[string]string{"user_id": user.ID.String()})
	if err != nil {
		p.failSubject(ctx, userID, "marshal_event", err)
		return outcomeFailed
	}
	if _, err := store.EnqueueOutboxEvent(ctx, db.EnqueueOutboxEventParams{
		Subject: SubjectDeletedEvent,
		Payload: string(payload),
	}); err != nil {
		p.failSubject(ctx, userID, "enqueue_event", err)
		return outcomeFailed
	}

	if err := tx.Commit(ctx); err != nil {
		p.failSubject(ctx, userID, "commit", err)
		return outcomeFailed
	}
	committed = true

	p.record(ctx, audit.Event{
		EventType:     audit.EventDeletionPurged,
		ActionStatus:  audit.StatusSuccess,
		ActorSPIFFEID: audit.SystemActorSPIFFEID,
		SubjectID:     &user.ID,
		Payload: map[string]any{
			"subject_event": SubjectDeletedEvent,
			"cutoff":        cutoff.UTC().Format(time.RFC3339),
		},
	})
	return outcomePurged
}

// failSubject records and logs a per-subject failure. The transaction is rolled
// back by purgeSubject's deferred cleanup, so nothing here needs to undo work.
func (p *Purger) failSubject(ctx context.Context, userID uuid.UUID, stage string, cause error) {
	subject := userID
	p.record(ctx, audit.Event{
		EventType:     audit.EventDeletionPurgeFailed,
		ActionStatus:  audit.StatusFailure,
		ActorSPIFFEID: audit.SystemActorSPIFFEID,
		SubjectID:     &subject,
		Payload: map[string]any{
			"stage":  stage,
			"reason": cause.Error(),
		},
	})
	p.logger.Error("privacy: purge subject failed; skipping without deleting",
		slog.String("user_id", userID.String()),
		slog.String("stage", stage),
		slog.String("error", cause.Error()))
}

// record persists an audit event, logging rather than propagating a transport
// failure. The worker's decisions are already reflected in its own log line, so an
// audit outage must not turn a correct skip into a failed run.
func (p *Purger) record(ctx context.Context, e audit.Event) {
	if err := p.recorder.Record(ctx, e); err != nil {
		p.logger.Error("privacy: record purge audit event",
			slog.String("event_type", e.EventType), slog.String("error", err.Error()))
	}
}

// ---------------------------------------------------------------------------
// PostgreSQL adapters
// ---------------------------------------------------------------------------

// PgSubjectTxOpener opens one pgx transaction per subject over a Transacter.
type PgSubjectTxOpener struct {
	tx Transacter
}

// NewPgSubjectTxOpener constructs a SubjectTxOpener over a pgx pool.
func NewPgSubjectTxOpener(tx Transacter) (*PgSubjectTxOpener, error) {
	if tx == nil {
		return nil, errors.New("privacy: transacter is required")
	}
	return &PgSubjectTxOpener{tx: tx}, nil
}

// BeginSubject implements SubjectTxOpener.
func (o *PgSubjectTxOpener) BeginSubject(ctx context.Context) (SubjectTx, error) {
	tx, err := o.tx.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("privacy: begin subject transaction: %w", err)
	}
	return &pgSubjectTx{tx: tx, store: db.New(tx)}, nil
}

// pgSubjectTx is the pgx-backed SubjectTx.
type pgSubjectTx struct {
	tx    pgx.Tx
	store PurgeStore
}

func (t *pgSubjectTx) Store() PurgeStore                { return t.store }
func (t *pgSubjectTx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

// Rollback discards the transaction. pgx.ErrTxClosed is swallowed so the deferred
// rollback after a successful commit is a no-op rather than a spurious error.
func (t *pgSubjectTx) Rollback(ctx context.Context) error {
	if err := t.tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
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
		return nil, errors.New("privacy: pool is required for the advisory lock")
	}
	return &PgAdvisoryLocker{pool: pool, key: key}, nil
}

// TryLock implements AdvisoryLocker with pg_try_advisory_lock, which returns
// immediately rather than queueing behind the holder.
func (l *PgAdvisoryLocker) TryLock(ctx context.Context) (bool, func(), error) {
	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("privacy: acquire advisory lock connection: %w", err)
	}

	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", l.key).Scan(&acquired); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("privacy: pg_try_advisory_lock: %w", err)
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
			slog.Default().Error("privacy: release purge advisory lock",
				slog.String("error", err.Error()))
		}
		conn.Release()
	}
	return true, release, nil
}

// advisoryUnlockTimeout bounds the explicit unlock so a wedged connection cannot
// hang process shutdown.
const advisoryUnlockTimeout = 5 * time.Second
