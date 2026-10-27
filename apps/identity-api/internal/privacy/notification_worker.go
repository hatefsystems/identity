package privacy

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// NotificationStore is satisfied by pool- and transaction-bound *db.Queries.
type NotificationStore interface {
	ListDueDeletionNotifications(context.Context, db.ListDueDeletionNotificationsParams) ([]db.ListDueDeletionNotificationsRow, error)
	GetDeletionNotificationState(context.Context, db.GetDeletionNotificationStateParams) (db.GetDeletionNotificationStateRow, error)
	ClaimDeletionNotification(context.Context, db.ClaimDeletionNotificationParams) (db.DeletionNotification, error)
	GetDeletionNotificationForUpdate(context.Context, uuid.UUID) (db.DeletionNotification, error)
	AcceptDeletionNotification(context.Context, db.AcceptDeletionNotificationParams) (int64, error)
	RetryDeletionNotification(context.Context, db.RetryDeletionNotificationParams) (int64, error)
	FailDeletionNotification(context.Context, db.FailDeletionNotificationParams) (int64, error)
	ListDeletionNotificationsForCleanup(context.Context, db.ListDeletionNotificationsForCleanupParams) ([]db.ListDeletionNotificationsForCleanupRow, error)
	ClearDeletionNotificationPayload(context.Context, db.ClearDeletionNotificationPayloadParams) (int64, error)
	HasActiveLegalHold(context.Context, uuid.UUID) (bool, error)
}

// NotificationConfig bounds each pass, lease, and network attempt. GracePeriod
// and ReclaimMaxAttempts must match the privacy service; expiry is never renewed.
type NotificationConfig struct {
	BatchSize          int
	Concurrency        int
	LeaseDuration      time.Duration
	SendTimeout        time.Duration
	RetryBase          time.Duration
	RetryMax           time.Duration
	GracePeriod        time.Duration
	ReclaimMaxAttempts int
}

// NotificationStats distinguishes durable relay acceptance from delivery attempts.
type NotificationStats struct {
	Considered       int
	Claimed          int
	Accepted         int
	Retried          int
	Failed           int
	Cleaned          int
	SkippedLegalHold int
}

// NotificationWorker processes one bounded batch with per-recipient leases.
// SMTP runs outside every database transaction. Delivery is at least once: a
// crash after acceptance but before bookkeeping may repeat the same Message-ID.
type NotificationWorker struct {
	cfg      NotificationConfig
	store    NotificationStore
	tx       Transacter
	cipher   Cipher
	notifier Notifier
	recorder audit.Recorder
	logger   *slog.Logger
	now      func() time.Time
	withTx   func(context.Context, uuid.UUID, func(NotificationStore) error) error
}

// NotificationOption configures a worker's logger or clock.
type NotificationOption func(*NotificationWorker)

// WithNotificationLogger supplies the worker's metadata-only logger.
func WithNotificationLogger(logger *slog.Logger) NotificationOption {
	return func(w *NotificationWorker) {
		if logger != nil {
			w.logger = logger
		}
	}
}

// WithNotificationClock supplies a clock for deterministic expiry tests.
func WithNotificationClock(now func() time.Time) NotificationOption {
	return func(w *NotificationWorker) {
		if now != nil {
			w.now = now
		}
	}
}

// NewNotificationWorker validates the dependencies and bounded delivery policy.
func NewNotificationWorker(cfg NotificationConfig, store NotificationStore, tx Transacter, cipher Cipher, notifier Notifier, recorder audit.Recorder, opts ...NotificationOption) (*NotificationWorker, error) {
	if store == nil || tx == nil || cipher == nil || notifier == nil || recorder == nil {
		return nil, errors.New("privacy: notification store, transactions, cipher, notifier, and audit recorder are required")
	}
	if notifier.IsDevelopmentOnly() {
		return nil, errors.New("privacy: notification worker requires a delivering notifier")
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 50
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 4
	}
	if cfg.LeaseDuration == 0 {
		cfg.LeaseDuration = time.Minute
	}
	if cfg.SendTimeout == 0 {
		cfg.SendTimeout = 15 * time.Second
	}
	if cfg.RetryBase == 0 {
		cfg.RetryBase = 30 * time.Second
	}
	if cfg.RetryMax == 0 {
		cfg.RetryMax = time.Hour
	}
	if cfg.GracePeriod == 0 {
		cfg.GracePeriod = defaultGracePeriod
	}
	if cfg.ReclaimMaxAttempts == 0 {
		cfg.ReclaimMaxAttempts = defaultReclaimMaxAttempts
	}
	if cfg.BatchSize < 1 || cfg.BatchSize > 200 || cfg.Concurrency < 1 || cfg.Concurrency > 16 ||
		cfg.SendTimeout <= 0 || cfg.SendTimeout > time.Minute || cfg.LeaseDuration < cfg.SendTimeout+5*time.Second ||
		cfg.LeaseDuration > 5*time.Minute || cfg.RetryBase <= 0 || cfg.RetryMax < cfg.RetryBase || cfg.RetryMax > 24*time.Hour ||
		cfg.GracePeriod <= 0 || cfg.ReclaimMaxAttempts < 1 || cfg.ReclaimMaxAttempts > math.MaxInt32 {
		return nil, errors.New("privacy: invalid notification worker limits")
	}
	w := &NotificationWorker{cfg: cfg, store: store, tx: tx, cipher: cipher, notifier: notifier,
		recorder: recorder, logger: slog.Default(), now: time.Now}
	w.withTx = w.transaction
	for _, opt := range opts {
		opt(w)
	}
	return w, nil
}

// RunOnce delivers one bounded batch and cleans eligible delivery ciphertext.
func (w *NotificationWorker) RunOnce(ctx context.Context) (NotificationStats, error) {
	var stats NotificationStats
	due, err := w.store.ListDueDeletionNotifications(ctx, db.ListDueDeletionNotificationsParams{
		BatchSize: int32(w.cfg.BatchSize), MaxAttempts: int32(w.cfg.ReclaimMaxAttempts), //nolint:gosec // Constructor bounds both.
		GracePeriod: pgtype.Interval{Microseconds: w.cfg.GracePeriod.Microseconds(), Valid: true},
	})
	if err != nil {
		return stats, errors.New("privacy: list due notifications unavailable")
	}
	stats.Considered = len(due)
	jobs := make(chan db.ListDueDeletionNotificationsRow)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range w.cfg.Concurrency {
		wg.Go(func() {
			for candidate := range jobs {
				one := w.deliver(ctx, candidate)
				mu.Lock()
				stats.Claimed += one.Claimed
				stats.Accepted += one.Accepted
				stats.Retried += one.Retried
				stats.Failed += one.Failed
				mu.Unlock()
			}
		})
	}
schedule:
	for _, candidate := range due {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break schedule
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return stats, ctx.Err()
	}
	if err := w.cleanup(ctx, &stats); err != nil {
		return stats, err
	}
	w.logger.Info("privacy: notification pass complete",
		slog.Int("considered", stats.Considered), slog.Int("claimed", stats.Claimed),
		slog.Int("relay_accepted", stats.Accepted), slog.Int("retried", stats.Retried),
		slog.Int("failed", stats.Failed), slog.Int("payloads_cleaned", stats.Cleaned),
		slog.Int("skipped_legal_hold", stats.SkippedLegalHold))
	return stats, nil
}

func (w *NotificationWorker) deliver(ctx context.Context, candidate db.ListDueDeletionNotificationsRow) NotificationStats {
	var stats NotificationStats
	if ctx.Err() != nil {
		return stats
	}
	var row db.DeletionNotification
	var request db.DeletionRequest
	err := w.withTx(ctx, candidate.UserID, func(store NotificationStore) error {
		user, current, err := notificationState(ctx, store, candidate.UserID, candidate.RequestID)
		if err != nil {
			return err
		}
		request = current
		now := w.now()
		if !liveDeletionRequest(user, request, now, w.cfg.GracePeriod, w.cfg.ReclaimMaxAttempts) {
			return pgx.ErrNoRows
		}
		leaseUntil := now.Add(w.cfg.LeaseDuration)
		if request.ExpiresAt.Time.Before(leaseUntil) {
			leaseUntil = request.ExpiresAt.Time
		}
		row, err = store.ClaimDeletionNotification(ctx, db.ClaimDeletionNotificationParams{
			ID: candidate.ID, RequestID: request.ID,
			LeaseToken: uuid.NullUUID{UUID: uuid.New(), Valid: true},
			LeaseUntil: pgtype.Timestamptz{Time: leaseUntil, Valid: true},
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return stats
	}
	if err != nil {
		stats.Failed++
		w.logger.Error("privacy: notification claim unavailable", slog.String("delivery_id", candidate.ID.String()))
		return stats
	}
	stats.Claimed++
	w.logger.Info("privacy: notification claimed", slog.String("delivery_id", row.ID.String()),
		slog.Int("attempt", int(row.Attempts)), slog.Duration("queued_age", w.now().Sub(row.CreatedAt.Time)))

	// Bound decryption as well as the network operation by the current lease.
	attemptCtx, cancel := context.WithTimeout(ctx, max(time.Duration(0), row.LeaseUntil.Time.Sub(w.now())))
	defer cancel()
	plaintext, err := w.cipher.Decrypt(attemptCtx, row.PayloadEncrypted)
	if err != nil {
		return w.finish(ctx, row, request, "payload_unavailable", false, stats)
	}
	notice, err := decodeNotificationPayload(plaintext, row, request)
	clear(plaintext)
	if err != nil {
		return w.finish(ctx, row, request, "payload_invalid", true, stats)
	}
	// KMS/network preparation can be slow. Recheck immediately before sending,
	// including cancellation/retirement since the claim. Never hold these locks
	// across SMTP; already in-flight mail cannot be recalled after this point.
	err = w.withTx(attemptCtx, row.UserID, func(store NotificationStore) error {
		_, err := w.liveLease(attemptCtx, store, row, request)
		return err
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			stats.Failed++
		}
		return stats
	}
	sendCtx, sendCancel := context.WithTimeout(attemptCtx, w.cfg.SendTimeout)
	err = w.notifier.NotifyDeletionRequested(sendCtx, notice)
	sendCancel()
	if err == nil {
		return w.finish(ctx, row, request, "", false, stats)
	}
	var permanent interface{ Permanent() bool }
	if errors.As(err, &permanent) && permanent.Permanent() {
		return w.finish(ctx, row, request, "relay_permanent", true, stats)
	}
	return w.finish(ctx, row, request, "relay_temporary", false, stats)
}

// The shared subject lock serializes lifecycle/hold changes; the authority read
// is one statement and the delivery row locks fence competing acknowledgements.
func (w *NotificationWorker) liveLease(ctx context.Context, store NotificationStore, claimed db.DeletionNotification, original db.DeletionRequest) (db.DeletionNotification, error) {
	user, request, err := notificationState(ctx, store, claimed.UserID, claimed.RequestID)
	if err != nil {
		return db.DeletionNotification{}, err
	}
	row, err := store.GetDeletionNotificationForUpdate(ctx, claimed.ID)
	if err != nil {
		return db.DeletionNotification{}, err
	}
	now := w.now()
	if !liveDeletionRequest(user, request, now, w.cfg.GracePeriod, w.cfg.ReclaimMaxAttempts) ||
		request.ID != original.ID || request.TokenHash != original.TokenHash || !request.ExpiresAt.Time.Equal(original.ExpiresAt.Time) ||
		row.RequestID != request.ID || row.UserID != user.ID || row.RecipientRole != claimed.RecipientRole ||
		!row.ExpiresAt.Valid || !row.ExpiresAt.Time.Equal(request.ExpiresAt.Time) ||
		!row.LeaseToken.Valid || row.LeaseToken != claimed.LeaseToken || !row.LeaseUntil.Valid || !row.LeaseUntil.Time.After(now) ||
		row.AcceptedAt.Valid || row.FailedAt.Valid || len(row.PayloadEncrypted) == 0 {
		return db.DeletionNotification{}, pgx.ErrNoRows
	}
	return row, nil
}

func notificationState(ctx context.Context, store NotificationStore, userID, requestID uuid.UUID) (db.User, db.DeletionRequest, error) {
	state, err := store.GetDeletionNotificationState(ctx, db.GetDeletionNotificationStateParams{UserID: userID, RequestID: requestID})
	if err != nil {
		return db.User{}, db.DeletionRequest{}, err
	}
	return db.User{ID: state.UserID, Status: state.UserStatus, AuthVersion: state.UserAuthVersion, DeletedAt: state.UserDeletedAt},
		db.DeletionRequest{ID: state.RequestID, UserID: state.UserID, TokenHash: state.TokenHash,
			ExpiresAt: state.ExpiresAt, ConsumedAt: state.ConsumedAt, FailedAttempts: state.FailedAttempts,
			RequestedAuthVersion: state.RequestedAuthVersion}, nil
}

func (w *NotificationWorker) finish(ctx context.Context, row db.DeletionNotification, request db.DeletionRequest, code string, permanent bool, stats NotificationStats) NotificationStats {
	// A completed SMTP transaction must get a bounded bookkeeping attempt even
	// if the worker was asked to shut down while waiting for its acknowledgement.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var affected int64
	err := w.withTx(ctx, row.UserID, func(store NotificationStore) error {
		if _, err := w.liveLease(ctx, store, row, request); err != nil {
			return err
		}
		var err error
		switch {
		case code == "":
			affected, err = store.AcceptDeletionNotification(ctx, db.AcceptDeletionNotificationParams{
				ID: row.ID, RequestID: row.RequestID, LeaseToken: row.LeaseToken,
			})
		case permanent:
			affected, err = store.FailDeletionNotification(ctx, db.FailDeletionNotificationParams{
				ID: row.ID, RequestID: row.RequestID, LeaseToken: row.LeaseToken, LastErrorCode: &code,
			})
		default:
			next := w.now().Add(w.retryDelay(row.Attempts))
			if request.ExpiresAt.Time.Before(next) {
				next = request.ExpiresAt.Time
			}
			affected, err = store.RetryDeletionNotification(ctx, db.RetryDeletionNotificationParams{
				ID: row.ID, RequestID: row.RequestID, LeaseToken: row.LeaseToken, LastErrorCode: &code,
				NextAttemptAt: pgtype.Timestamptz{Time: next, Valid: true},
			})
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && affected == 0) {
		return stats
	}
	if err != nil {
		stats.Failed++
		w.logger.Error("privacy: notification result unavailable", slog.String("delivery_id", row.ID.String()))
		return stats
	}
	status := audit.StatusFailure
	result := code
	switch {
	case code == "":
		stats.Accepted++
		status = audit.StatusSuccess
		result = "relay_accepted"
	case permanent:
		stats.Failed++
	default:
		stats.Retried++
	}
	w.record(ctx, audit.Event{
		EventType: audit.EventDeletionRequested, ActionStatus: status,
		ActorSPIFFEID: audit.SystemActorSPIFFEID, SubjectID: &row.UserID,
		Payload: map[string]any{"stage": "notification", "delivery_id": row.ID.String(),
			"request_id": row.RequestID.String(), "recipient_role": row.RecipientRole,
			"attempt": int(row.Attempts), "result": result},
	})
	// Never log err.Error(): even an SMTP 550 may echo a recipient or message.
	w.logger.Info("privacy: notification result", slog.String("delivery_id", row.ID.String()),
		slog.String("result", result), slog.Int("attempt", int(row.Attempts)))
	return stats
}

func (w *NotificationWorker) retryDelay(attempts int32) time.Duration {
	delay := w.cfg.RetryBase
	for i := int32(1); i < attempts && delay < w.cfg.RetryMax; i++ {
		if delay > w.cfg.RetryMax/2 {
			delay = w.cfg.RetryMax
			break
		}
		delay *= 2
	}
	delay = min(delay, w.cfg.RetryMax)
	// Equal jitter keeps a nonzero floor without synchronized retry waves. This
	// randomness is scheduling only; tokens and lease IDs use crypto/rand.
	return max(time.Nanosecond, delay/2+time.Duration(rand.Int64N(max(int64(1), int64(delay-delay/2))))) //nolint:gosec // Non-security jitter.
}

func (w *NotificationWorker) cleanup(ctx context.Context, stats *NotificationStats) error {
	rows, err := w.store.ListDeletionNotificationsForCleanup(ctx, db.ListDeletionNotificationsForCleanupParams{
		BatchSize: int32(w.cfg.BatchSize), MaxAttempts: int32(w.cfg.ReclaimMaxAttempts), //nolint:gosec // Constructor bounds both.
		GracePeriod: pgtype.Interval{Microseconds: w.cfg.GracePeriod.Microseconds(), Valid: true},
	})
	if err != nil {
		return errors.New("privacy: list notification cleanup unavailable")
	}
	for _, candidate := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var affected int64
		var held bool
		err := w.withTx(ctx, candidate.UserID, func(store NotificationStore) error {
			user, request, err := notificationState(ctx, store, candidate.UserID, candidate.RequestID)
			if err != nil {
				return err
			}
			row, err := store.GetDeletionNotificationForUpdate(ctx, candidate.ID)
			if err != nil {
				return err
			}
			if row.UserID != candidate.UserID || row.RequestID != request.ID || len(row.PayloadEncrypted) == 0 {
				return pgx.ErrNoRows
			}
			if !row.AcceptedAt.Valid && row.ExpiresAt.Valid && row.ExpiresAt.Time.Equal(request.ExpiresAt.Time) &&
				liveDeletionRequest(user, request, w.now(), w.cfg.GracePeriod, w.cfg.ReclaimMaxAttempts) {
				return nil
			}
			held, err = store.HasActiveLegalHold(ctx, user.ID)
			if err != nil || held {
				return err
			}
			affected, err = store.ClearDeletionNotificationPayload(ctx, db.ClearDeletionNotificationPayloadParams{ID: row.ID, RequestID: row.RequestID})
			return err
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			continue
		case err != nil:
			stats.Failed++
			w.logger.Error("privacy: notification cleanup unavailable; payload retained", slog.String("delivery_id", candidate.ID.String()))
		case held:
			stats.SkippedLegalHold++
			w.record(ctx, audit.Event{EventType: audit.EventDeletionSkippedLegalHold, ActionStatus: audit.StatusSuccess,
				ActorSPIFFEID: audit.SystemActorSPIFFEID, SubjectID: &candidate.UserID,
				Payload: map[string]any{"stage": "notification_cleanup", "delivery_id": candidate.ID.String()}})
		case affected == 1:
			stats.Cleaned++
		}
	}
	return nil
}

func (w *NotificationWorker) transaction(ctx context.Context, userID uuid.UUID, fn func(NotificationStore) error) error {
	tx, err := w.tx.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
		return err
	}
	if err := pglock.LockAccount(ctx, tx, userID); err != nil {
		return err
	}
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *NotificationWorker) record(ctx context.Context, event audit.Event) {
	if err := w.recorder.Record(ctx, event); err != nil {
		w.logger.Error("privacy: notification audit unavailable")
	}
}
