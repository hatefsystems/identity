package privacy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
)

// discardLogger keeps test output readable; the assertions inspect recorded audit
// events and fake call counts, never log text.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ts wraps a time as a valid pgtype.Timestamptz.
func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// ---------------------------------------------------------------------------
// fakeStore
// ---------------------------------------------------------------------------

// fakeStore is an in-memory Store that reproduces the *guards* of the real
// queries, not just their happy paths: SoftDeleteUser only fires while deleted_at
// is NULL, ReclaimUser only while the row is pending_deletion and inside the
// cutoff, and "active request" means consumed_at IS NULL AND expires_at > NOW().
// Those guards are what the idempotency and race behaviour rest on, so a fake that
// ignored them would validate nothing.
type fakeStore struct {
	mu       sync.Mutex
	users    map[uuid.UUID]db.User
	requests []db.DeletionRequest
	now      func() time.Time

	// Injectable faults, per method, so the "infrastructure error must not be
	// charged to the attempt budget" paths are reachable.
	getUserErr       error
	softDeleteErr    error
	createRequestErr error
	incrementErr     error
	lookupErr        error

	// Call counters for the assertions that care about *not* being called.
	incrementCalls int
	consumeCalls   int
	notifiedCalls  int
}

func newFakeStore(now func() time.Time) *fakeStore {
	return &fakeStore{users: make(map[uuid.UUID]db.User), now: now}
}

// addActiveUser inserts an active account and returns it.
func (f *fakeStore) addActiveUser(email string) db.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := db.User{ID: uuid.New(), Email: email, Status: "active"}
	f.users[u.ID] = u
	return u
}

// user returns the current stored row for id.
func (f *fakeStore) user(id uuid.UUID) db.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[id]
}

// requestByID returns the stored request row.
func (f *fakeStore) requestByID(id uuid.UUID) (db.DeletionRequest, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r.ID == id {
			return r, true
		}
	}
	return db.DeletionRequest{}, false
}

func (f *fakeStore) GetUserByIDForAdmin(_ context.Context, id uuid.UUID) (db.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getUserErr != nil {
		return db.User{}, f.getUserErr
	}
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeStore) SoftDeleteUser(_ context.Context, id uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.softDeleteErr != nil {
		return 0, f.softDeleteErr
	}
	u, ok := f.users[id]
	if !ok || u.DeletedAt.Valid {
		return 0, nil
	}
	u.Status = "pending_deletion"
	u.DeletedAt = ts(f.now())
	f.users[id] = u
	return 1, nil
}

func (f *fakeStore) ReclaimUser(_ context.Context, arg db.ReclaimUserParams) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[arg.ID]
	if !ok || u.Status != "pending_deletion" || !u.DeletedAt.Valid {
		return 0, nil
	}
	// Mirrors `deleted_at >= $2`.
	if u.DeletedAt.Time.Before(arg.DeletedAt.Time) {
		return 0, nil
	}
	u.Status = "active"
	u.DeletedAt = pgtype.Timestamptz{}
	f.users[arg.ID] = u
	return 1, nil
}

func (f *fakeStore) CreateDeletionRequest(_ context.Context, arg db.CreateDeletionRequestParams) (db.DeletionRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createRequestErr != nil {
		return db.DeletionRequest{}, f.createRequestErr
	}
	row := db.DeletionRequest{
		ID:          uuid.New(),
		UserID:      arg.UserID,
		TokenHash:   arg.TokenHash,
		RequestedIp: arg.RequestedIp,
		ExpiresAt:   arg.ExpiresAt,
		CreatedAt:   ts(f.now()),
	}
	f.requests = append(f.requests, row)
	return row, nil
}

// activeLocked reports whether r is still usable, mirroring
// `consumed_at IS NULL AND expires_at > NOW()`. The caller must hold f.mu.
func (f *fakeStore) activeLocked(r db.DeletionRequest) bool {
	return !r.ConsumedAt.Valid && r.ExpiresAt.Valid && r.ExpiresAt.Time.After(f.now())
}

func (f *fakeStore) GetActiveDeletionRequestByTokenHashForUpdate(_ context.Context, tokenHash string) (db.DeletionRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return db.DeletionRequest{}, f.lookupErr
	}
	for _, r := range f.requests {
		if r.TokenHash == tokenHash && f.activeLocked(r) {
			return r, nil
		}
	}
	return db.DeletionRequest{}, pgx.ErrNoRows
}

func (f *fakeStore) GetActiveDeletionRequestForUser(_ context.Context, userID uuid.UUID) (db.DeletionRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Newest-first, matching ORDER BY created_at DESC.
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].UserID == userID && f.activeLocked(f.requests[i]) {
			return f.requests[i], nil
		}
	}
	return db.DeletionRequest{}, pgx.ErrNoRows
}

func (f *fakeStore) IncrementDeletionRequestFailedAttempts(_ context.Context, id uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.incrementCalls++
	if f.incrementErr != nil {
		return 0, f.incrementErr
	}
	for i, r := range f.requests {
		if r.ID == id && !r.ConsumedAt.Valid {
			f.requests[i].FailedAttempts++
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeStore) MarkDeletionRequestNotified(_ context.Context, id uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifiedCalls++
	for i, r := range f.requests {
		if r.ID == id {
			f.requests[i].NotifiedAt = ts(f.now())
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeStore) ConsumeDeletionRequest(_ context.Context, id uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumeCalls++
	for i, r := range f.requests {
		if r.ID == id && !r.ConsumedAt.Valid {
			f.requests[i].ConsumedAt = ts(f.now())
			return 1, nil
		}
	}
	return 0, nil
}

func (f *fakeStore) ExpireDeletionRequestsForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var affected int64
	for i, r := range f.requests {
		if r.UserID == userID && !r.ConsumedAt.Valid {
			f.requests[i].ConsumedAt = ts(f.now())
			affected++
		}
	}
	return affected, nil
}

// ---------------------------------------------------------------------------
// collaborator fakes
// ---------------------------------------------------------------------------

// fakeNotifier records the notices it was handed. It keeps the plaintext token so
// tests can drive the reclaim ceremony with the same value a real user would read
// from their mail.
type fakeNotifier struct {
	mu      sync.Mutex
	notices []DeletionNotice
	err     error
	devOnly bool
}

func (f *fakeNotifier) NotifyDeletionRequested(_ context.Context, notice DeletionNotice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.notices = append(f.notices, notice)
	return nil
}

func (f *fakeNotifier) IsDevelopmentOnly() bool { return f.devOnly }

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.notices)
}

func (f *fakeNotifier) last() (DeletionNotice, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.notices) == 0 {
		return DeletionNotice{}, false
	}
	return f.notices[len(f.notices)-1], true
}

// fakeRecorder captures audit events in order.
type fakeRecorder struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (f *fakeRecorder) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return f.err
}

// countOf returns how many recorded events have the given type and status.
func (f *fakeRecorder) countOf(eventType, status string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.EventType == eventType && e.ActionStatus == status {
			n++
		}
	}
	return n
}

// lastOf returns the most recent event of the given type.
func (f *fakeRecorder) lastOf(eventType string) (audit.Event, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.events) - 1; i >= 0; i-- {
		if f.events[i].EventType == eventType {
			return f.events[i], true
		}
	}
	return audit.Event{}, false
}

// fakeRevoker counts revocations and can fail on demand.
type fakeRevoker struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeRevoker) RevokeAllForUser(userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, userID)
	return f.err
}

func (f *fakeRevoker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// rateCall records one limiter evaluation so tests can assert the *order* of the
// windows, which is the property that stops a saturated proxy from burning a
// targeted account's budget.
type rateCall struct {
	key    string
	limit  int
	window time.Duration
}

// fakeLimiter denies any key present in deny and records every call in order.
type fakeLimiter struct {
	mu    sync.Mutex
	calls []rateCall
	deny  map[string]bool
	err   error
}

func newFakeLimiter() *fakeLimiter {
	return &fakeLimiter{deny: make(map[string]bool)}
}

func (f *fakeLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rateCall{key: key, limit: limit, window: window})
	if f.err != nil {
		return false, f.err
	}
	return !f.deny[key], nil
}

func (f *fakeLimiter) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.key)
	}
	return out
}

// fakePasskeys is a PasskeyReclaimer whose Begin and Finish outcomes are scripted.
type fakePasskeys struct {
	mu sync.Mutex

	beginErr    error
	beginCalls  []string // request ids
	finishErr   error
	finishCalls []string // request ids
}

func (f *fakePasskeys) BeginReclaimAssertion(_ context.Context, _ uuid.UUID, requestID string) (*protocol.CredentialAssertion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.beginCalls = append(f.beginCalls, requestID)
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &protocol.CredentialAssertion{}, nil
}

func (f *fakePasskeys) FinishReclaimAssertion(_ context.Context, _ uuid.UUID, requestID string, _ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finishCalls = append(f.finishCalls, requestID)
	return f.finishErr
}

func (f *fakePasskeys) finishCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.finishCalls)
}

// fakeTOTP is a TOTPReclaimer that accepts exactly one code.
type fakeTOTP struct {
	mu       sync.Mutex
	accept   string
	err      error
	attempts []string
}

func (f *fakeTOTP) VerifyTOTPForReclaim(_ context.Context, _ uuid.UUID, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, code)
	if f.err != nil {
		return f.err
	}
	if code != f.accept {
		return mfa.ErrInvalidCode
	}
	return nil
}

func (f *fakeTOTP) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.attempts)
}

// fakeGuard is a ReplayGuard remembering keys in a map.
type fakeGuard struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func newFakeGuard() *fakeGuard {
	return &fakeGuard{seen: make(map[string]bool)}
}

func (f *fakeGuard) Remember(_ context.Context, key string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	return true, nil
}

// errBoom is a generic infrastructure fault for fault-injection paths.
var errBoom = errors.New("boom")

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// newUUID returns a fresh UUID for "no such subject" assertions.
func newUUID() uuid.UUID { return uuid.New() }

// mustParseUUID parses a UUID string or fails the test.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}

// dbRequestNotifiedAt builds a bare request row carrying only notified_at, for
// exercising the cooldown predicate directly.
func dbRequestNotifiedAt(at *time.Time) db.DeletionRequest {
	row := db.DeletionRequest{ID: uuid.New()}
	if at != nil {
		row.NotifiedAt = ts(*at)
	}
	return row
}
