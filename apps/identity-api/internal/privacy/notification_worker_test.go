package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type notificationFake struct {
	*fakeStore
	txMu    sync.Mutex
	inTx    atomic.Bool
	held    map[uuid.UUID]bool
	holdErr error
	listErr error
	ackErr  error
}

func (f *notificationFake) GetDeletionNotificationState(ctx context.Context, arg db.GetDeletionNotificationStateParams) (db.GetDeletionNotificationStateRow, error) {
	user, err := f.GetUserByIDForAdmin(ctx, arg.UserID)
	if err != nil {
		return db.GetDeletionNotificationStateRow{}, err
	}
	request, err := f.GetDeletionRequestForUpdate(ctx, arg.RequestID)
	if err != nil {
		return db.GetDeletionNotificationStateRow{}, err
	}
	if request.UserID != user.ID {
		return db.GetDeletionNotificationStateRow{}, pgx.ErrNoRows
	}
	return db.GetDeletionNotificationStateRow{
		UserID: user.ID, UserStatus: user.Status, UserAuthVersion: user.AuthVersion, UserDeletedAt: user.DeletedAt,
		RequestID: request.ID, TokenHash: request.TokenHash, ExpiresAt: request.ExpiresAt,
		ConsumedAt: request.ConsumedAt, FailedAttempts: request.FailedAttempts, RequestedAuthVersion: request.RequestedAuthVersion,
	}, nil
}

func (f *notificationFake) ListDueDeletionNotifications(_ context.Context, arg db.ListDueDeletionNotificationsParams) ([]db.ListDueDeletionNotificationsRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var rows []db.ListDueDeletionNotificationsRow
	for _, id := range f.notificationIDs {
		r := f.notifications[id]
		var request db.DeletionRequest
		for _, candidate := range f.requests {
			if candidate.ID == r.RequestID {
				request = candidate
				break
			}
		}
		if !r.AcceptedAt.Valid && !r.FailedAt.Valid && len(r.PayloadEncrypted) > 0 && r.ExpiresAt.Time.After(f.now()) &&
			r.ExpiresAt.Time.Equal(request.ExpiresAt.Time) && liveDeletionRequest(f.users[r.UserID], request, f.now(), time.Duration(arg.GracePeriod.Microseconds)*time.Microsecond, int(arg.MaxAttempts)) &&
			!r.NextAttemptAt.Time.After(f.now()) && (!r.LeaseUntil.Valid || !r.LeaseUntil.Time.After(f.now())) {
			rows = append(rows, db.ListDueDeletionNotificationsRow{ID: r.ID, UserID: r.UserID, RequestID: r.RequestID})
		}
		if len(rows) == int(arg.BatchSize) {
			break
		}
	}
	return rows, nil
}

func (f *notificationFake) ClaimDeletionNotification(_ context.Context, arg db.ClaimDeletionNotificationParams) (db.DeletionNotification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.notifications[arg.ID]
	if !ok || r.RequestID != arg.RequestID || r.AcceptedAt.Valid || r.FailedAt.Valid || len(r.PayloadEncrypted) == 0 ||
		!r.ExpiresAt.Time.After(f.now()) || r.NextAttemptAt.Time.After(f.now()) || (r.LeaseUntil.Valid && r.LeaseUntil.Time.After(f.now())) {
		return db.DeletionNotification{}, pgx.ErrNoRows
	}
	r.LeaseToken, r.LeaseUntil = arg.LeaseToken, arg.LeaseUntil
	r.Attempts++
	f.notifications[r.ID] = r
	return r, nil
}

func (f *notificationFake) GetDeletionNotificationForUpdate(_ context.Context, id uuid.UUID) (db.DeletionNotification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.notifications[id]
	if !ok {
		return db.DeletionNotification{}, pgx.ErrNoRows
	}
	return r, nil
}

func (f *notificationFake) finishableLocked(id, requestID uuid.UUID, lease uuid.NullUUID) (db.DeletionNotification, bool) {
	r, ok := f.notifications[id]
	return r, ok && r.RequestID == requestID && lease.Valid && r.LeaseToken == lease && r.LeaseUntil.Time.After(f.now()) &&
		!r.AcceptedAt.Valid && !r.FailedAt.Valid && r.ExpiresAt.Time.After(f.now())
}

func (f *notificationFake) AcceptDeletionNotification(_ context.Context, arg db.AcceptDeletionNotificationParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ackErr != nil {
		return 0, f.ackErr
	}
	r, ok := f.finishableLocked(arg.ID, arg.RequestID, arg.LeaseToken)
	if !ok {
		return 0, nil
	}
	r.AcceptedAt, r.LeaseUntil, r.LeaseToken = ts(f.now()), pgtype.Timestamptz{}, uuid.NullUUID{}
	f.notifications[r.ID] = r
	return 1, nil
}

func (f *notificationFake) RetryDeletionNotification(_ context.Context, arg db.RetryDeletionNotificationParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.finishableLocked(arg.ID, arg.RequestID, arg.LeaseToken)
	if !ok {
		return 0, nil
	}
	r.NextAttemptAt, r.LastErrorCode = arg.NextAttemptAt, arg.LastErrorCode
	r.LeaseUntil, r.LeaseToken = pgtype.Timestamptz{}, uuid.NullUUID{}
	f.notifications[r.ID] = r
	return 1, nil
}

func (f *notificationFake) FailDeletionNotification(_ context.Context, arg db.FailDeletionNotificationParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.finishableLocked(arg.ID, arg.RequestID, arg.LeaseToken)
	if !ok {
		return 0, nil
	}
	r.FailedAt, r.LastErrorCode = ts(f.now()), arg.LastErrorCode
	r.LeaseUntil, r.LeaseToken = pgtype.Timestamptz{}, uuid.NullUUID{}
	f.notifications[r.ID] = r
	return 1, nil
}

func (f *notificationFake) ListDeletionNotificationsForCleanup(_ context.Context, arg db.ListDeletionNotificationsForCleanupParams) ([]db.ListDeletionNotificationsForCleanupRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var rows []db.ListDeletionNotificationsForCleanupRow
	for _, id := range f.notificationIDs {
		r := f.notifications[id]
		if len(r.PayloadEncrypted) == 0 {
			continue
		}
		var request db.DeletionRequest
		for _, candidate := range f.requests {
			if candidate.ID == r.RequestID {
				request = candidate
				break
			}
		}
		if r.AcceptedAt.Valid || !r.ExpiresAt.Time.Equal(request.ExpiresAt.Time) ||
			!liveDeletionRequest(f.users[r.UserID], request, f.now(), time.Duration(arg.GracePeriod.Microseconds)*time.Microsecond, int(arg.MaxAttempts)) {
			rows = append(rows, db.ListDeletionNotificationsForCleanupRow{ID: r.ID, UserID: r.UserID, RequestID: r.RequestID})
		}
		if len(rows) == int(arg.BatchSize) {
			break
		}
	}
	return rows, nil
}

func (f *notificationFake) ClearDeletionNotificationPayload(_ context.Context, arg db.ClearDeletionNotificationPayloadParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.notifications[arg.ID]
	if !ok || r.RequestID != arg.RequestID || len(r.PayloadEncrypted) == 0 {
		return 0, nil
	}
	r.PayloadEncrypted, r.LeaseToken, r.LeaseUntil = nil, uuid.NullUUID{}, pgtype.Timestamptz{}
	if !r.AcceptedAt.Valid {
		r.FailedAt = ts(f.now())
	}
	f.notifications[r.ID] = r
	return 1, nil
}

func (f *notificationFake) HasActiveLegalHold(_ context.Context, id uuid.UUID) (bool, error) {
	return f.held[id], f.holdErr
}

type unusedNotificationTransacter struct{}

func (unusedNotificationTransacter) Begin(context.Context) (pgx.Tx, error) {
	panic("unit worker must use its fake transaction")
}

type notifierFunc func(context.Context, DeletionNotice) error

func (f notifierFunc) NotifyDeletionRequested(ctx context.Context, notice DeletionNotice) error {
	return f(ctx, notice)
}
func (notifierFunc) IsDevelopmentOnly() bool { return false }

type permanentNotificationError struct{}

func (permanentNotificationError) Error() string   { return "relay refused recipient" }
func (permanentNotificationError) Permanent() bool { return true }

func newTestWorker(t *testing.T, h *harness, cfg NotificationConfig) (*NotificationWorker, *notificationFake) {
	t.Helper()
	store := &notificationFake{fakeStore: h.store, held: make(map[uuid.UUID]bool)}
	w, err := NewNotificationWorker(cfg, store, unusedNotificationTransacter{}, h.cipher, h.notifier, h.recorder,
		WithNotificationClock(h.clock.now), WithNotificationLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	w.withTx = func(ctx context.Context, _ uuid.UUID, fn func(NotificationStore) error) error {
		store.txMu.Lock()
		defer store.txMu.Unlock()
		store.inTx.Store(true)
		defer store.inTx.Store(false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fn(store)
	}
	return w, store
}

func TestNotificationWorkerLimits(t *testing.T) {
	h := newHarness(t, Config{})
	store := &notificationFake{fakeStore: h.store}
	if _, err := NewNotificationWorker(NotificationConfig{}, store, nil, h.cipher, h.notifier, h.recorder); err == nil {
		t.Fatal("worker accepted missing transactions")
	}
	if _, err := NewNotificationWorker(NotificationConfig{}, store, unusedNotificationTransacter{}, h.cipher, NewLogNotifier(nil), h.recorder); err == nil {
		t.Fatal("worker accepted a non-delivering log notifier")
	}
	for _, cfg := range []NotificationConfig{{BatchSize: 201}, {Concurrency: 17}, {LeaseDuration: time.Second}, {RetryBase: time.Hour, RetryMax: time.Minute}} {
		if _, err := NewNotificationWorker(cfg, store, unusedNotificationTransacter{}, h.cipher, h.notifier, h.recorder); err == nil {
			t.Fatal("invalid worker limits accepted")
		}
	}
}

func TestNotificationRecipientsRetryIndependently(t *testing.T) {
	h := newHarness(t, Config{})
	u := h.store.addActiveUser("primary@example.test")
	u.BackupEmailEncrypted, _ = h.cipher.Encrypt(t.Context(), []byte("backup@example.test"))
	h.store.users[u.ID] = u
	if _, err := h.svc.RequestDeletion(t.Context(), u.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	w, store := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
	var attempts []DeletionNotice
	failBackup := true
	w.notifier = notifierFunc(func(_ context.Context, n DeletionNotice) error {
		if store.inTx.Load() || n.BackupEmail != nil {
			t.Error("SMTP invoked under a database lock or with multiple recipients")
		}
		attempts = append(attempts, n)
		if n.PrimaryEmail == "backup@example.test" && failBackup {
			return errBoom
		}
		return nil
	})
	stats, err := w.RunOnce(t.Context())
	if err != nil || stats.Accepted != 1 || stats.Retried != 1 || stats.Cleaned != 1 || len(attempts) != 2 {
		t.Fatalf("independent delivery failed: %+v, %v", stats, err)
	}
	firstBackup := attempts[1]
	failBackup = false
	h.clock.advance(time.Hour)
	stats, err = w.RunOnce(t.Context())
	if err != nil || stats.Accepted != 1 || stats.Claimed != 1 || stats.Cleaned != 1 || len(attempts) != 3 || attempts[2] != firstBackup {
		t.Fatalf("retry changed identity/token/deadline or remailed primary: %+v, %v", stats, err)
	}
	if stats, err = w.RunOnce(t.Context()); err != nil || stats.Claimed != 0 {
		t.Fatal("accepted recipient delivered again", err)
	}
	row := h.store.notifications[firstBackup.DeliveryID]
	affected, err := h.store.CreateDeletionNotification(t.Context(), db.CreateDeletionNotificationParams{ID: uuid.New(), UserID: row.UserID, RequestID: row.RequestID, RecipientRole: row.RecipientRole, PayloadEncrypted: []byte("must not replace"), ExpiresAt: row.ExpiresAt})
	if err != nil || affected != 0 || len(h.store.notifications) != 2 {
		t.Fatal("duplicate enqueue replaced the accepted delivery", err)
	}
}

func TestNotificationCrashLeaseAndUnknownAcknowledgement(t *testing.T) {
	h := newHarness(t, Config{})
	requestDeletionAndToken(t, h, "lease@example.test")
	id := h.store.notificationIDs[0]
	r := h.store.notifications[id]
	r.LeaseToken, r.LeaseUntil, r.Attempts = uuid.NullUUID{UUID: uuid.New(), Valid: true}, ts(h.clock.now().Add(time.Minute)), 1
	h.store.notifications[id] = r
	w, store := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Claimed != 0 {
		t.Fatal("active lease was stolen", err)
	}
	h.clock.advance(2 * time.Minute)
	store.ackErr = errBoom // Relay succeeds, then ACK persistence fails.
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Accepted != 0 || stats.Failed != 1 || h.notifier.count() != 1 {
		t.Fatal("unknown acknowledgement incorrectly recorded accepted", err)
	}
	first, _ := h.notifier.last()
	store.ackErr = nil
	h.clock.advance(2 * time.Minute)
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Accepted != 1 || h.notifier.count() != 2 {
		t.Fatal("crash-expired lease did not recover", err)
	}
	second, _ := h.notifier.last()
	if first != second || h.store.notifications[id].Attempts != 3 {
		t.Fatal("ambiguous delivery retry changed stable message identity")
	}
}

func TestNotificationResultsFencedByLeaseAndRequest(t *testing.T) {
	for _, race := range []string{"lease", "reclaim", "retire", "expiry"} {
		t.Run(race, func(t *testing.T) {
			h := newHarness(t, Config{})
			token, _ := requestDeletionAndToken(t, h, "fence@example.test")
			w, _ := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
			w.notifier = notifierFunc(func(_ context.Context, n DeletionNotice) error {
				switch race {
				case "lease":
					r := h.store.notifications[n.DeliveryID]
					r.LeaseToken = uuid.NullUUID{UUID: uuid.New(), Valid: true}
					h.store.notifications[n.DeliveryID] = r
				case "reclaim":
					if err := h.svc.Reclaim(t.Context(), token, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
						t.Error(err)
					}
				case "retire":
					h.store.requests[0].ConsumedAt = ts(h.clock.now())
				case "expiry":
					h.clock.advance(defaultGracePeriod)
				}
				return nil
			})
			stats, err := w.RunOnce(t.Context())
			if err != nil || stats.Accepted != 0 || h.store.notifications[h.store.notificationIDs[0]].AcceptedAt.Valid {
				t.Fatal("stale result overwrote current request/lease state", err)
			}
			if race != "lease" && stats.Cleaned != 1 {
				t.Fatal("invalidated delivery ciphertext not cleaned")
			}
		})
	}
}

func TestNotificationPayloadBindingAndUnavailableKeys(t *testing.T) {
	for _, change := range []string{"version", "user", "request", "delivery", "role", "expiry", "token", "recipient", "malformed", "unknown_field", "swapped", "corrupt", "key_version"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t, Config{})
			requestDeletionAndToken(t, h, "binding@example.test")
			id := h.store.notificationIDs[0]
			r := h.store.notifications[id]
			plaintext, _ := h.cipher.Decrypt(t.Context(), r.PayloadEncrypted)
			var p notificationPayload
			if err := json.Unmarshal(plaintext, &p); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "version":
				p.Version++
			case "user":
				p.UserID = uuid.New()
			case "request":
				p.RequestID = uuid.New()
			case "delivery":
				p.DeliveryID = uuid.New()
			case "role":
				p.RecipientRole = "backup"
			case "expiry":
				p.ExpiresAt = p.ExpiresAt.Add(time.Second)
			case "token":
				p.Token, _, _ = NewReclaimToken()
			case "recipient":
				p.Recipient = "bad\r\n@example.test"
			}
			plaintext, _ = json.Marshal(p)
			switch change {
			case "malformed":
				plaintext = []byte("{not-json")
			case "unknown_field":
				plaintext = append(plaintext[:len(plaintext)-1], []byte(",\"unbound\":true}")...)
			}
			r.PayloadEncrypted, _ = h.cipher.Encrypt(t.Context(), plaintext)
			clear(plaintext)
			if change == "swapped" {
				requestDeletionAndToken(t, h, "another-account@example.test")
				other := h.store.notifications[h.store.notificationIDs[1]]
				r.PayloadEncrypted = other.PayloadEncrypted
				other.FailedAt = ts(h.clock.now())
				h.store.notifications[other.ID] = other
			}
			if change == "corrupt" {
				r.PayloadEncrypted[len(r.PayloadEncrypted)-1] ^= 1
			}
			if change == "key_version" {
				r.PayloadEncrypted[0] = 2
			}
			h.store.notifications[id] = r
			w, _ := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
			stats, err := w.RunOnce(t.Context())
			if err != nil || stats.Accepted != 0 || h.notifier.count() != 0 {
				t.Fatal("unbound or undecryptable payload reached SMTP", err)
			}
			if change == "corrupt" || change == "key_version" {
				if stats.Retried != 1 || len(h.store.notifications[id].PayloadEncrypted) == 0 {
					t.Fatal("key outage permanently discarded recovery material")
				}
			} else if stats.Failed != 1 {
				t.Fatal("authenticated malformed payload was not retired")
			}
		})
	}
}

func TestNotificationCleanupPreservesActiveAndUnknownHolds(t *testing.T) {
	for _, mode := range []string{"accepted", "expired", "canceled", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, Config{})
			_, id := requestDeletionAndToken(t, h, "hold@example.test")
			uid := mustParseUUID(t, id)
			w, store := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
			store.held[uid] = true
			wantAccepted := 1
			switch mode {
			case "expired":
				h.clock.advance(defaultGracePeriod)
				wantAccepted = 0
			case "canceled":
				h.store.requests[0].ConsumedAt = ts(h.clock.now())
				wantAccepted = 0
			case "unknown":
				store.holdErr = errBoom
			}
			stats, err := w.RunOnce(t.Context())
			rowID := h.store.notificationIDs[0]
			if err != nil || stats.Cleaned != 0 || stats.Accepted != wantAccepted || len(h.store.notifications[rowID].PayloadEncrypted) == 0 {
				t.Fatal("hold failed to preserve ciphertext or affected token validity", err)
			}
			before := h.notifier.count()
			if _, err := w.RunOnce(t.Context()); err != nil || h.notifier.count() != before {
				t.Fatal("held terminal work became deliverable again", err)
			}
			store.held[uid], store.holdErr = false, nil
			stats, err = w.RunOnce(t.Context())
			if err != nil || stats.Cleaned != 1 || len(h.store.notifications[rowID].PayloadEncrypted) != 0 || h.notifier.count() != before {
				t.Fatal("released payload did not clean without resend", err)
			}
		})
	}
}

func TestNotificationPermanentFailureAndSecretSafeDiagnostics(t *testing.T) {
	h := newHarness(t, Config{})
	token, _ := requestDeletionAndToken(t, h, "secret-recipient@example.test")
	w, _ := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
	var logs bytes.Buffer
	w.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	w.notifier = notifierFunc(func(context.Context, DeletionNotice) error {
		return errors.New("secret-recipient@example.test " + token + " smtp-password https://origin/recover#token=" + token)
	})
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Retried != 1 {
		t.Fatal(err)
	}
	events, err := json.Marshal(h.recorder.events)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, "secret-recipient@example.test", "smtp-password", "https://origin"} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) || bytes.Contains(events, []byte(secret)) {
			t.Fatal("notification diagnostics leaked delivery material")
		}
	}
	h.clock.advance(time.Hour)
	w.notifier = notifierFunc(func(context.Context, DeletionNotice) error { return permanentNotificationError{} })
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Failed != 1 || stats.Retried != 0 {
		t.Fatal("permanent failure not surfaced", err)
	}
	if stats, err := w.RunOnce(t.Context()); err != nil || stats.Claimed != 0 {
		t.Fatal("permanent failure retried automatically", err)
	}
}

func TestNotificationAcceptanceSurvivesShutdownCancellation(t *testing.T) {
	h := newHarness(t, Config{})
	requestDeletionAndToken(t, h, "shutdown@example.test")
	w, _ := newTestWorker(t, h, NotificationConfig{Concurrency: 1})
	ctx, cancel := context.WithCancel(t.Context())
	w.notifier = notifierFunc(func(context.Context, DeletionNotice) error { cancel(); return nil })
	stats, err := w.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) || stats.Accepted != 1 || !h.store.notifications[h.store.notificationIDs[0]].AcceptedAt.Valid {
		t.Fatal("shutdown cancellation lost positive acknowledgement", err)
	}
	if stats, err = w.RunOnce(t.Context()); err != nil || stats.Claimed != 0 || stats.Cleaned != 1 {
		t.Fatal("restart did not clean accepted payload", err)
	}
}

func TestNotificationRetryBackoffIsBounded(t *testing.T) {
	h := newHarness(t, Config{})
	w, _ := newTestWorker(t, h, NotificationConfig{RetryBase: time.Second, RetryMax: time.Minute})
	for attempt := int32(1); attempt < 100; attempt++ {
		delay := w.retryDelay(attempt)
		if delay < time.Second/2 || delay > time.Minute {
			t.Fatal("retry backoff outside bounds")
		}
	}
}

func TestNotificationInvalidHeldRowsDoNotStarveDelivery(t *testing.T) {
	h := newHarness(t, Config{})
	_, held := requestDeletionAndToken(t, h, "old-held@example.test")
	h.store.requests[0].ConsumedAt = ts(h.clock.now())
	requestDeletionAndToken(t, h, "live-queue@example.test")
	w, store := newTestWorker(t, h, NotificationConfig{BatchSize: 1, Concurrency: 1})
	store.held[mustParseUUID(t, held)] = true
	stats, err := w.RunOnce(t.Context())
	if err != nil || stats.Claimed != 1 || stats.Accepted != 1 {
		t.Fatal("undeliverable held row occupied the delivery batch", err)
	}
	notice, ok := h.notifier.last()
	if !ok || notice.PrimaryEmail != "live-queue@example.test" {
		t.Fatal("wrong request delivered")
	}
}

func TestNotificationConcurrencyIsBounded(t *testing.T) {
	h := newHarness(t, Config{})
	for _, address := range []string{"one@example.test", "two@example.test", "three@example.test", "four@example.test"} {
		requestDeletionAndToken(t, h, address)
	}
	w, _ := newTestWorker(t, h, NotificationConfig{Concurrency: 2})
	var active, maximum atomic.Int32
	started := make(chan struct{}, 4)
	proceed := make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	w.notifier = notifierFunc(func(ctx context.Context, _ DeletionNotice) error {
		current := active.Add(1)
		defer active.Add(-1)
		for previous := maximum.Load(); current > previous; previous = maximum.Load() {
			if maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	type outcome struct {
		stats NotificationStats
		err   error
	}
	done := make(chan outcome, 1)
	go func() { stats, err := w.RunOnce(t.Context()); done <- outcome{stats, err} }()
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not deliver concurrently outside database locks")
		}
	}
	release()
	result := <-done
	if result.err != nil || result.stats.Accepted != 4 || maximum.Load() != 2 {
		t.Fatal("worker exceeded or failed to use its concurrency bound", result.err)
	}
}
