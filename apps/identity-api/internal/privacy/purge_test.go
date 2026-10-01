package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ---------------------------------------------------------------------------
// fakePurgeWorld
// ---------------------------------------------------------------------------

// fakePurgeWorld is the committed database state plus the SubjectTxOpener over it.
//
// Per-subject transactions are simulated faithfully rather than approximated: a
// fakePurgeTx buffers its delete and its outbox insert and applies them to this
// world only on Commit. Without that, "rows != 1 must roll back the outbox event
// too" — the invariant that stops downstream services from scrubbing a live
// subject — would be untestable outside a real database.
type fakePurgeWorld struct {
	mu     sync.Mutex
	users  map[uuid.UUID]db.User
	holds  map[uuid.UUID]bool
	outbox []db.EnqueueOutboxEventParams

	// Injectable faults.
	listErr        error
	lockErr        error
	holdErr        error
	deleteErr      error
	enqueueErr     error
	beginErr       error
	commitErr      error
	accountLockErr error
	// failFor scopes lockErr/holdErr/deleteErr/commitErr to one subject, so batch
	// isolation can be asserted.
	failFor *uuid.UUID
	// forceDeleteRows overrides HardDeleteUser's affected-row count, simulating a
	// reclaim or a hold that landed between the check and the delete.
	forceDeleteRows *int64
	// reclaimOnLock flips this subject back to active at the moment the per-subject
	// lock reads it, reproducing a reclaim that commits between the (non
	// transactional) batch listing and the per-subject transaction.
	reclaimOnLock *uuid.UUID

	begun       int
	committed   int
	rolledBack  int
	deleteCalls int
}

func newFakePurgeWorld() *fakePurgeWorld {
	return &fakePurgeWorld{
		users: make(map[uuid.UUID]db.User),
		holds: make(map[uuid.UUID]bool),
	}
}

// addPendingUser inserts a soft-deleted account whose deleted_at is `age` in the
// past relative to now.
func (w *fakePurgeWorld) addPendingUser(now time.Time, age time.Duration) uuid.UUID {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := uuid.New()
	w.users[id] = db.User{
		ID:        id,
		Email:     id.String() + "@test.local",
		Status:    "pending_deletion",
		DeletedAt: ts(now.Add(-age)),
	}
	return id
}

// addActiveUser inserts an account that is not pending deletion.
func (w *fakePurgeWorld) addActiveUser() uuid.UUID {
	w.mu.Lock()
	defer w.mu.Unlock()
	id := uuid.New()
	w.users[id] = db.User{ID: id, Status: "active"}
	return id
}

func (w *fakePurgeWorld) exists(id uuid.UUID) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.users[id]
	return ok
}

func (w *fakePurgeWorld) outboxLen() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.outbox)
}

// shouldFail reports whether a scoped fault applies to id.
func (w *fakePurgeWorld) shouldFail(id uuid.UUID) bool {
	return w.failFor == nil || *w.failFor == id
}

// ListUsersDueForHardDelete mirrors the real query: pending_deletion rows whose
// deleted_at precedes the cutoff, oldest first, bounded by the limit.
func (w *fakePurgeWorld) ListUsersDueForHardDelete(_ context.Context, arg db.ListUsersDueForHardDeleteParams) ([]uuid.UUID, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.listErr != nil {
		return nil, w.listErr
	}

	type row struct {
		id        uuid.UUID
		deletedAt time.Time
	}
	var due []row
	for id, u := range w.users {
		if u.Status == "pending_deletion" && u.DeletedAt.Valid && u.DeletedAt.Time.Before(arg.DeletedAt.Time) {
			due = append(due, row{id: id, deletedAt: u.DeletedAt.Time})
		}
	}
	// Unheld candidates first so held oldest rows cannot monopolize the batch.
	for i := 1; i < len(due); i++ {
		for j := i; j > 0; j-- {
			leftHeld, rightHeld := w.holds[due[j].id], w.holds[due[j-1].id]
			if (!leftHeld && rightHeld) || (leftHeld == rightHeld && (due[j].deletedAt.Before(due[j-1].deletedAt) ||
				(due[j].deletedAt.Equal(due[j-1].deletedAt) && due[j].id.String() < due[j-1].id.String()))) {
				due[j], due[j-1] = due[j-1], due[j]
				continue
			}
			break
		}
	}

	out := make([]uuid.UUID, 0, len(due))
	for _, r := range due {
		if len(out) >= int(arg.Limit) {
			break
		}
		out = append(out, r.id)
	}
	return out, nil
}

// The pool-bound world also has to satisfy PurgeStore, since Purger takes one
// store for the batch listing. These per-subject methods are never reached through
// it — every subject goes through a fakePurgeTx — so they fail loudly if they are.
func (w *fakePurgeWorld) GetUserForUpdateIncludingDeleted(context.Context, uuid.UUID) (db.User, error) {
	return db.User{}, errors.New("privacy: per-subject read must go through a subject transaction")
}

func (w *fakePurgeWorld) HasActiveLegalHold(context.Context, uuid.UUID) (bool, error) {
	return false, errors.New("privacy: hold check must go through a subject transaction")
}

func (w *fakePurgeWorld) HardDeleteUser(context.Context, db.HardDeleteUserParams) (int64, error) {
	return 0, errors.New("privacy: hard delete must go through a subject transaction")
}

func (w *fakePurgeWorld) EnqueueOutboxEvent(context.Context, db.EnqueueOutboxEventParams) (db.EventOutbox, error) {
	return db.EventOutbox{}, errors.New("privacy: outbox insert must go through a subject transaction")
}

// BeginSubject implements SubjectTxOpener.
func (w *fakePurgeWorld) BeginSubject(context.Context) (SubjectTx, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.beginErr != nil {
		return nil, w.beginErr
	}
	w.begun++
	return &fakePurgeTx{w: w}, nil
}

// fakePurgeTx buffers one subject's mutations until Commit.
type fakePurgeTx struct {
	w             *fakePurgeWorld
	deletes       []uuid.UUID
	events        []db.EnqueueOutboxEventParams
	closed        bool
	accountLocked uuid.UUID
}

func (t *fakePurgeTx) Store() PurgeStore { return t }

func (t *fakePurgeTx) LockAccount(_ context.Context, account uuid.UUID) error {
	if t.w.accountLockErr != nil {
		return t.w.accountLockErr
	}
	t.accountLocked = account
	return nil
}

func (t *fakePurgeTx) ListUsersDueForHardDelete(ctx context.Context, arg db.ListUsersDueForHardDeleteParams) ([]uuid.UUID, error) {
	return t.w.ListUsersDueForHardDelete(ctx, arg)
}

func (t *fakePurgeTx) GetUserForUpdateIncludingDeleted(_ context.Context, id uuid.UUID) (db.User, error) {
	if t.accountLocked != id {
		return db.User{}, errors.New("account lock must precede user read")
	}
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	if t.w.lockErr != nil && t.w.shouldFail(id) {
		return db.User{}, t.w.lockErr
	}
	if t.w.reclaimOnLock != nil && *t.w.reclaimOnLock == id {
		if u, ok := t.w.users[id]; ok {
			u.Status = "active"
			u.DeletedAt = pgtype.Timestamptz{}
			t.w.users[id] = u
		}
	}
	u, ok := t.w.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (t *fakePurgeTx) HasActiveLegalHold(_ context.Context, accountRef uuid.UUID) (bool, error) {
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	if t.w.holdErr != nil && t.w.shouldFail(accountRef) {
		return false, t.w.holdErr
	}
	return t.w.holds[accountRef], nil
}

// HardDeleteUser mirrors the real query's guards, including the NOT EXISTS
// legal-hold predicate that closes the TOCTOU against the Go-side check.
func (t *fakePurgeTx) HardDeleteUser(_ context.Context, arg db.HardDeleteUserParams) (int64, error) {
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	t.w.deleteCalls++
	if t.w.deleteErr != nil && t.w.shouldFail(arg.ID) {
		return 0, t.w.deleteErr
	}
	if t.w.forceDeleteRows != nil {
		return *t.w.forceDeleteRows, nil
	}
	u, ok := t.w.users[arg.ID]
	if !ok || u.Status != "pending_deletion" || !u.DeletedAt.Valid {
		return 0, nil
	}
	if !u.DeletedAt.Time.Before(arg.DeletedAt.Time) {
		return 0, nil
	}
	if t.w.holds[arg.ID] {
		return 0, nil
	}
	t.deletes = append(t.deletes, arg.ID)
	return 1, nil
}

func (t *fakePurgeTx) EnqueueOutboxEvent(_ context.Context, arg db.EnqueueOutboxEventParams) (db.EventOutbox, error) {
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	if t.w.enqueueErr != nil {
		return db.EventOutbox{}, t.w.enqueueErr
	}
	t.events = append(t.events, arg)
	return db.EventOutbox{ID: uuid.New(), Subject: arg.Subject, Payload: arg.Payload}, nil
}

func (t *fakePurgeTx) Commit(context.Context) error {
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	if t.closed {
		return pgx.ErrTxClosed
	}
	if t.w.commitErr != nil && (len(t.deletes) == 0 || t.w.shouldFail(t.deletes[0])) {
		return t.w.commitErr
	}
	for _, id := range t.deletes {
		delete(t.w.users, id)
	}
	t.w.outbox = append(t.w.outbox, t.events...)
	t.closed = true
	t.w.committed++
	return nil
}

func (t *fakePurgeTx) Rollback(context.Context) error {
	t.w.mu.Lock()
	defer t.w.mu.Unlock()
	if t.closed {
		return pgx.ErrTxClosed
	}
	t.deletes = nil
	t.events = nil
	t.closed = true
	t.w.rolledBack++
	return nil
}

// fakeLocker reports a scripted TryLock result and counts releases.
type fakeLocker struct {
	acquired bool
	err      error
	released int
}

func (l *fakeLocker) TryLock(context.Context) (bool, func(), error) {
	if l.err != nil {
		return false, nil, l.err
	}
	if !l.acquired {
		return false, nil, nil
	}
	return true, func() { l.released++ }, nil
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type purgeHarness struct {
	purger   *Purger
	world    *fakePurgeWorld
	recorder *fakeRecorder
	clock    *testClock
}

func newPurgeHarness(t *testing.T, cfg PurgeConfig, opts ...PurgeOption) *purgeHarness {
	t.Helper()

	clock := &testClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	h := &purgeHarness{
		world:    newFakePurgeWorld(),
		recorder: &fakeRecorder{},
		clock:    clock,
	}
	all := append([]PurgeOption{WithPurgeLogger(discardLogger()), WithPurgeClock(clock.now)}, opts...)
	p, err := NewPurger(cfg, h.world, h.world, h.recorder, all...)
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	h.purger = p
	return h
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewPurgerRequiresCollaborators(t *testing.T) {
	world := newFakePurgeWorld()
	recorder := &fakeRecorder{}

	if _, err := NewPurger(PurgeConfig{}, nil, world, recorder); err == nil {
		t.Error("NewPurger with a nil store = nil error, want error")
	}
	if _, err := NewPurger(PurgeConfig{}, world, nil, recorder); err == nil {
		t.Error("NewPurger with a nil opener = nil error, want error")
	}
	if _, err := NewPurger(PurgeConfig{}, world, world, nil); err == nil {
		t.Error("NewPurger with a nil recorder = nil error, want error")
	}
}

// ---------------------------------------------------------------------------
// Happy path and cutoff arithmetic
// ---------------------------------------------------------------------------

func TestRunOncePurgesAndEnqueuesEvent(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: 720 * time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 721*time.Hour)

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if stats.Considered != 1 || stats.Purged != 1 || stats.SkippedLegalHold != 0 || stats.Failed != 0 {
		t.Errorf("stats = %+v, want 1 considered / 1 purged", stats)
	}
	if h.world.exists(subject) {
		t.Error("the subject was not deleted")
	}
	if h.world.committed != 1 {
		t.Errorf("commits = %d, want 1", h.world.committed)
	}
	if h.world.outboxLen() != 1 {
		t.Fatalf("outbox rows = %d, want 1", h.world.outboxLen())
	}

	event := h.world.outbox[0]
	if event.Subject != SubjectDeletedEvent {
		t.Errorf("outbox subject = %q, want %q", event.Subject, SubjectDeletedEvent)
	}
	// The payload must carry the user id and nothing else: these rows outlive the
	// account, so any PII here would escape the erasure entirely.
	var payload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatalf("outbox payload is not JSON: %v", err)
	}
	if len(payload) != 1 {
		t.Errorf("outbox payload = %v, want exactly one field", payload)
	}
	if payload["user_id"] != subject.String() {
		t.Errorf("outbox payload user_id = %v, want %s", payload["user_id"], subject)
	}

	if got := h.recorder.countOf(audit.EventDeletionPurged, audit.StatusSuccess); got != 1 {
		t.Errorf("%s events = %d, want 1", audit.EventDeletionPurged, got)
	}
	purged, _ := h.recorder.lastOf(audit.EventDeletionPurged)
	if purged.ActorSPIFFEID != audit.SystemActorSPIFFEID {
		t.Errorf("purge event actor = %q, want the worker identity %q",
			purged.ActorSPIFFEID, audit.SystemActorSPIFFEID)
	}
}

// TestRunOnceCutoffArithmetic pins the boundary: a subject one hour inside the
// window survives, one hour past it is purged, and an active account is never in
// the batch at all.
func TestRunOnceCutoffArithmetic(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: 720 * time.Hour, BatchSize: 10})
	inside := h.world.addPendingUser(h.clock.now(), 719*time.Hour)
	past := h.world.addPendingUser(h.clock.now(), 721*time.Hour)
	active := h.world.addActiveUser()

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Considered != 1 {
		t.Errorf("Considered = %d, want 1 (only the subject past the cutoff)", stats.Considered)
	}
	if !h.world.exists(inside) {
		t.Error("a subject still inside the grace window was purged")
	}
	if h.world.exists(past) {
		t.Error("a subject past the grace window was not purged")
	}
	if !h.world.exists(active) {
		t.Error("an active account was purged")
	}

	// Advancing past the remaining hour makes the second subject eligible, which
	// proves the cutoff moves with the clock rather than being captured once.
	h.clock.advance(2 * time.Hour)
	if _, err := h.purger.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if h.world.exists(inside) {
		t.Error("the subject was not purged after the window elapsed")
	}
}

func TestRunOnceRespectsBatchSize(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 2})
	for i := 0; i < 5; i++ {
		h.world.addPendingUser(h.clock.now(), time.Duration(10+i)*time.Hour)
	}

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Considered != 2 {
		t.Errorf("Considered = %d, want the batch size 2", stats.Considered)
	}
	if stats.Purged != 2 {
		t.Errorf("Purged = %d, want 2", stats.Purged)
	}
	if len(h.world.users) != 3 {
		t.Errorf("remaining users = %d, want 3", len(h.world.users))
	}
}

// ---------------------------------------------------------------------------
// Legal Hold: the fail-closed contract
// ---------------------------------------------------------------------------

func TestRunOnceSkipsSubjectUnderLegalHold(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	held := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	h.world.holds[held] = true

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.SkippedLegalHold != 1 || stats.Purged != 0 {
		t.Errorf("stats = %+v, want 1 skipped / 0 purged", stats)
	}
	if !h.world.exists(held) {
		t.Fatal("a subject under an active legal hold was purged")
	}
	if h.world.outboxLen() != 0 {
		t.Error("a skipped subject enqueued an event")
	}
	if h.world.committed != 0 {
		t.Error("a skipped subject committed its transaction")
	}
	if h.world.rolledBack != 1 {
		t.Errorf("rollbacks = %d, want 1", h.world.rolledBack)
	}
	if got := h.recorder.countOf(audit.EventDeletionSkippedLegalHold, audit.StatusSuccess); got != 1 {
		t.Errorf("%s events = %d, want 1", audit.EventDeletionSkippedLegalHold, got)
	}

	// Releasing the hold must let the next run purge, which is the other half of the
	// "holds outrank retention but do not resurrect data" contract.
	delete(h.world.holds, held)
	if _, err := h.purger.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce after release: %v", err)
	}
	if h.world.exists(held) {
		t.Error("the subject was not purged after the hold was released")
	}
}

// TestRunOnceNeverPurgesWhenHoldCheckErrors is the single most important property in
// this file: "we could not tell whether a hold exists" must resolve to "do not
// delete".
func TestRunOnceNeverPurgesWhenHoldCheckErrors(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	h.world.holdErr = errBoom

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce must not fail the whole run for one undecidable subject: %v", err)
	}
	if stats.Failed != 1 || stats.Purged != 0 {
		t.Errorf("stats = %+v, want 1 failed / 0 purged", stats)
	}
	if !h.world.exists(subject) {
		t.Fatal("a subject was purged despite an unanswerable legal-hold check")
	}
	if h.world.deleteCalls != 0 {
		t.Fatal("HardDeleteUser was called despite an unanswerable legal-hold check")
	}
	if h.world.outboxLen() != 0 {
		t.Error("an undecidable subject enqueued an event")
	}
	if h.world.rolledBack != 1 {
		t.Errorf("rollbacks = %d, want 1", h.world.rolledBack)
	}
	if got := h.recorder.countOf(audit.EventDeletionPurgeFailed, audit.StatusFailure); got != 1 {
		t.Errorf("%s events = %d, want 1", audit.EventDeletionPurgeFailed, got)
	}
}

// ---------------------------------------------------------------------------
// "No event without a commit, no commit without an event"
// ---------------------------------------------------------------------------

// TestRunOnceRollsBackWhenDeleteAffectsNoRows covers the raced reclaim and the hold
// caught by the query's own NOT EXISTS predicate: neither may leave an
// identity.user.deleted behind for a subject that still exists.
func TestRunOnceRollsBackWhenDeleteAffectsNoRows(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	zero := int64(0)
	h.world.forceDeleteRows = &zero

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 || stats.Purged != 0 {
		t.Errorf("stats = %+v, want 1 failed / 0 purged", stats)
	}
	if !h.world.exists(subject) {
		t.Error("the subject was removed despite the delete reporting no rows")
	}
	if h.world.outboxLen() != 0 {
		t.Fatal("an event was enqueued for a subject that was not deleted")
	}
	if h.world.committed != 0 {
		t.Error("the transaction committed after a zero-row delete")
	}
	failed, ok := h.recorder.lastOf(audit.EventDeletionPurgeFailed)
	if !ok {
		t.Fatal("no purge_failed event recorded")
	}
	if failed.Payload["stage"] != "hard_delete" {
		t.Errorf("purge_failed stage = %v, want hard_delete", failed.Payload["stage"])
	}
}

// TestRunOnceRollsBackWhenOutboxInsertFails is the mirror image: a delete that
// cannot be paired with its event must not commit.
func TestRunOnceRollsBackWhenOutboxInsertFails(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	h.world.enqueueErr = errBoom

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if !h.world.exists(subject) {
		t.Error("the subject was deleted without its event")
	}
	if h.world.committed != 0 {
		t.Error("the transaction committed without an event")
	}
}

// TestRunOnceCommitFailureIsNotAPartialPurge: a failed commit leaves the subject in
// place and enqueues nothing.
func TestRunOnceCommitFailureIsNotAPartialPurge(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	h.world.commitErr = errBoom

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if !h.world.exists(subject) {
		t.Error("the subject disappeared despite the commit failing")
	}
	if h.world.outboxLen() != 0 {
		t.Error("an event survived a failed commit")
	}
}

// ---------------------------------------------------------------------------
// Per-subject isolation
// ---------------------------------------------------------------------------

// TestRunOncePerSubjectIsolation: one poisoned subject must neither roll back nor
// block the rest of the batch.
func TestRunOncePerSubjectIsolation(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	poisoned := h.world.addPendingUser(h.clock.now(), 30*time.Hour)
	healthyA := h.world.addPendingUser(h.clock.now(), 20*time.Hour)
	healthyB := h.world.addPendingUser(h.clock.now(), 10*time.Hour)

	h.world.holdErr = errBoom
	h.world.failFor = &poisoned

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Considered != 3 {
		t.Errorf("Considered = %d, want 3", stats.Considered)
	}
	if stats.Purged != 2 {
		t.Errorf("Purged = %d, want 2", stats.Purged)
	}
	if stats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", stats.Failed)
	}
	if !h.world.exists(poisoned) {
		t.Error("the poisoned subject was purged")
	}
	if h.world.exists(healthyA) || h.world.exists(healthyB) {
		t.Error("a healthy subject was blocked by the poisoned one")
	}
	if h.world.outboxLen() != 2 {
		t.Errorf("outbox rows = %d, want 2", h.world.outboxLen())
	}
	if h.world.begun != 3 {
		t.Errorf("transactions begun = %d, want 3 (one per subject)", h.world.begun)
	}
}

// TestRunOnceSkipsSubjectReclaimedSinceListing: the batch listing is not
// transactional, so a subject reclaimed in between must be a quiet no-op rather than
// a failure. Without the in-transaction re-check the worker would trust the stale
// batch and try to delete an account the user just recovered.
func TestRunOnceSkipsSubjectReclaimedSinceListing(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	other := h.world.addPendingUser(h.clock.now(), 20*time.Hour)

	// The reclaim commits between the listing and the per-subject lock.
	h.world.reclaimOnLock = &subject

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Considered != 2 {
		t.Fatalf("Considered = %d, want 2 (the stale batch still lists the subject)", stats.Considered)
	}
	if stats.Purged != 1 {
		t.Errorf("Purged = %d, want 1 (only the untouched subject)", stats.Purged)
	}
	if stats.Failed != 0 {
		t.Errorf("Failed = %d, want 0 (a reclaim race is expected, not an error)", stats.Failed)
	}
	if !h.world.exists(subject) {
		t.Error("a reclaimed subject was purged")
	}
	if h.world.exists(other) {
		t.Error("the untouched subject was not purged")
	}
	if h.world.deleteCalls != 1 {
		t.Errorf("HardDeleteUser calls = %d, want 1 (never attempted on the reclaimed subject)",
			h.world.deleteCalls)
	}
	if h.world.outboxLen() != 1 {
		t.Errorf("outbox rows = %d, want 1", h.world.outboxLen())
	}
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

// TestRunOnceDryRunMutatesNothing: every read and decision happens, the intended
// outcome is reported, and nothing is deleted or enqueued.
func TestRunOnceDryRunMutatesNothing(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10, DryRun: true})
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)
	held := h.world.addPendingUser(h.clock.now(), 20*time.Hour)
	h.world.holds[held] = true

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Considered != 2 {
		t.Errorf("Considered = %d, want 2", stats.Considered)
	}
	if stats.Purged != 1 {
		t.Errorf("Purged = %d, want 1 (the intended outcome is still reported)", stats.Purged)
	}
	// The legal-hold decision must still be made and audited in a dry run, or the
	// dry run would not actually validate the thing operators care about.
	if stats.SkippedLegalHold != 1 {
		t.Errorf("SkippedLegalHold = %d, want 1", stats.SkippedLegalHold)
	}

	if !h.world.exists(subject) || !h.world.exists(held) {
		t.Error("a dry run deleted a subject")
	}
	if h.world.outboxLen() != 0 {
		t.Error("a dry run enqueued an event")
	}
	if h.world.committed != 0 {
		t.Error("a dry run committed a transaction")
	}
	if h.world.rolledBack != 2 {
		t.Errorf("rollbacks = %d, want 2 (every dry-run subject rolls back)", h.world.rolledBack)
	}
	if h.world.deleteCalls != 0 {
		t.Error("a dry run issued a DELETE")
	}
}

// ---------------------------------------------------------------------------
// Advisory lock
// ---------------------------------------------------------------------------

// TestRunOnceExitsCleanlyOnLockContention: an overlapping schedule tick is a normal
// condition, so contention must be a successful no-op rather than an error that
// pages somebody.
func TestRunOnceExitsCleanlyOnLockContention(t *testing.T) {
	locker := &fakeLocker{acquired: false}
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10},
		WithAdvisoryLocker(locker))
	subject := h.world.addPendingUser(h.clock.now(), 10*time.Hour)

	stats, err := h.purger.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce under contention = %v, want nil", err)
	}
	if stats != (PurgeStats{}) {
		t.Errorf("stats = %+v, want the zero value", stats)
	}
	if !h.world.exists(subject) {
		t.Error("a contended run still purged")
	}
	if h.world.begun != 0 {
		t.Error("a contended run opened a transaction")
	}
	if locker.released != 0 {
		t.Error("a lock that was never acquired was released")
	}
}

func TestRunOnceReleasesLockAfterRun(t *testing.T) {
	locker := &fakeLocker{acquired: true}
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10},
		WithAdvisoryLocker(locker))
	h.world.addPendingUser(h.clock.now(), 10*time.Hour)

	if _, err := h.purger.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if locker.released != 1 {
		t.Errorf("lock releases = %d, want 1", locker.released)
	}
}

// TestRunOnceLockErrorFailsRun: unlike contention, a lock that *errored* means the
// database is unhealthy, which is an infrastructural failure the CronJob should
// surface.
func TestRunOnceLockErrorFailsRun(t *testing.T) {
	locker := &fakeLocker{err: errBoom}
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10},
		WithAdvisoryLocker(locker))

	if _, err := h.purger.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce with a failing locker = nil error, want error")
	}
}

// TestRunOnceListErrorFailsRun: the batch listing failing means the run could not
// proceed at all, which is the one case that must exit non-zero.
func TestRunOnceListErrorFailsRun(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	h.world.listErr = errBoom

	if _, err := h.purger.RunOnce(context.Background()); err == nil {
		t.Fatal("RunOnce with a failing listing = nil error, want error")
	}
}

// TestRunOnceStopsOnCancelledContext: SIGTERM must stop the walk between subjects
// rather than have every remaining subject fail its transaction.
func TestRunOnceStopsOnCancelledContext(t *testing.T) {
	h := newPurgeHarness(t, PurgeConfig{GracePeriod: time.Hour, BatchSize: 10})
	for i := 0; i < 3; i++ {
		h.world.addPendingUser(h.clock.now(), time.Duration(10+i)*time.Hour)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stats, err := h.purger.RunOnce(ctx)
	// The listing itself is served by the fake without consulting ctx, so the run
	// still reports what it considered; the walk must not have started.
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if stats.Purged != 0 || stats.Failed != 0 {
		t.Errorf("stats = %+v, want no subject processed after cancellation", stats)
	}
	if h.world.begun != 0 {
		t.Errorf("transactions begun = %d, want 0", h.world.begun)
	}
}

// TestPurgeAdvisoryLockKeyIsStable guards the documented constant: changing it would
// silently let two runs proceed concurrently during a rolling deploy.
func TestPurgeAdvisoryLockKeyIsStable(t *testing.T) {
	if PurgeAdvisoryLockKey != 5100001 {
		t.Errorf("PurgeAdvisoryLockKey = %d; changing it lets two worker versions run concurrently",
			PurgeAdvisoryLockKey)
	}
}
