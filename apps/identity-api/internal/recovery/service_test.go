package recovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// storedCode is one persisted recovery code in the fake store: the surrogate id
// the physical delete keys on, and the stored hash the lookup matches.
type storedCode struct {
	id       uuid.UUID
	codeHash string
}

// fakeRecoveryStore is an in-memory Store: a map of user id to that account's
// live code rows, plus optional error/collision injection. It is exercised
// directly (no Transacter), so runInTx calls fn against it and the full
// generate/verify logic runs without a database.
type fakeRecoveryStore struct {
	users map[uuid.UUID]db.User
	codes map[uuid.UUID][]storedCode

	// Error injection for the failure-path assertions.
	getUserErr error
	countErr   error

	// uniqueViolations makes the next N CreateRecoveryCodes calls fail with a
	// SQLSTATE 23505 error, to drive the one-shot regeneration retry.
	uniqueViolations int
	createCalls      int
}

func newFakeStore() *fakeRecoveryStore {
	return &fakeRecoveryStore{
		users: make(map[uuid.UUID]db.User),
		codes: make(map[uuid.UUID][]storedCode),
	}
}

// addUser registers an active account so loadUser succeeds for it.
func (f *fakeRecoveryStore) addUser() uuid.UUID {
	return f.addUserWithStatus("active")
}

// addUserWithStatus registers an account carrying an explicit users.status
// value, so the account-status gate in loadUser can be exercised for each state
// the CHECK constraint allows.
func (f *fakeRecoveryStore) addUserWithStatus(status string) uuid.UUID {
	id := uuid.New()
	f.users[id] = db.User{ID: id, Status: status}
	return id
}

func (f *fakeRecoveryStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	if f.getUserErr != nil {
		return db.User{}, f.getUserErr
	}
	u, ok := f.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (f *fakeRecoveryStore) CountActiveRecoveryCodes(_ context.Context, userID uuid.UUID) (int64, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return int64(len(f.codes[userID])), nil
}

func (f *fakeRecoveryStore) CreateRecoveryCodes(_ context.Context, arg []db.CreateRecoveryCodesParams) (int64, error) {
	f.createCalls++
	if f.uniqueViolations > 0 {
		f.uniqueViolations--
		return 0, &pgconn.PgError{Code: uniqueViolationSQLState}
	}
	for _, p := range arg {
		f.codes[p.UserID] = append(f.codes[p.UserID], storedCode{id: uuid.New(), codeHash: p.CodeHash})
	}
	return int64(len(arg)), nil
}

func (f *fakeRecoveryStore) DeleteAllRecoveryCodesForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	n := int64(len(f.codes[userID]))
	delete(f.codes, userID)
	return n, nil
}

func (f *fakeRecoveryStore) GetActiveRecoveryCodeForUpdate(_ context.Context, arg db.GetActiveRecoveryCodeForUpdateParams) (db.GetActiveRecoveryCodeForUpdateRow, error) {
	for _, c := range f.codes[arg.UserID] {
		if c.codeHash == arg.CodeHash {
			return db.GetActiveRecoveryCodeForUpdateRow{ID: c.id, UserID: arg.UserID, CodeHash: c.codeHash}, nil
		}
	}
	return db.GetActiveRecoveryCodeForUpdateRow{}, pgx.ErrNoRows
}

func (f *fakeRecoveryStore) DeleteRecoveryCodePhysically(_ context.Context, id uuid.UUID) (int64, error) {
	for userID, list := range f.codes {
		for i, c := range list {
			if c.id == id {
				f.codes[userID] = append(list[:i], list[i+1:]...)
				return 1, nil
			}
		}
	}
	return 0, nil
}

// fakeLimiter records the keys it is asked about and answers with a fixed
// verdict, so the rate-limit ordering and short-circuit can be asserted without
// Redis.
type fakeLimiter struct {
	allow bool
	err   error
	calls []string
}

func (f *fakeLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return false, f.err
	}
	return f.allow, nil
}

// ── New ──────────────────────────────────────────────────────────────────────

func TestNewAppliesDefaults(t *testing.T) {
	svc, err := New(Config{}, newFakeStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.count != defaultCount {
		t.Errorf("count = %d, want %d", svc.count, defaultCount)
	}
	if svc.lowThreshold != defaultLowThreshold {
		t.Errorf("lowThreshold = %d, want %d", svc.lowThreshold, defaultLowThreshold)
	}
	if svc.perAccountPerHour != defaultPerAccountPerHour {
		t.Errorf("perAccountPerHour = %d, want %d", svc.perAccountPerHour, defaultPerAccountPerHour)
	}
	if svc.perSubnetPerHour != defaultPerSubnetPerHour {
		t.Errorf("perSubnetPerHour = %d, want %d", svc.perSubnetPerHour, defaultPerSubnetPerHour)
	}
	if want := charsForBits(DefaultEntropyBits); svc.codeChars != want {
		t.Errorf("codeChars = %d, want %d (default entropy)", svc.codeChars, want)
	}
}

func TestNewRejectsLowEntropy(t *testing.T) {
	if _, err := New(Config{EntropyBits: MinEntropyBits - 1}, newFakeStore()); err == nil {
		t.Fatal("New with sub-floor entropy = nil error, want error")
	}
	// Exactly the floor is accepted.
	if _, err := New(Config{EntropyBits: MinEntropyBits}, newFakeStore()); err != nil {
		t.Errorf("New at the entropy floor = %v, want nil", err)
	}
}

func TestNewRejectsNilStore(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("New with nil store = nil error, want error")
	}
}

// ── Generate ─────────────────────────────────────────────────────────────────

func TestGenerateProducesDistinctBatch(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res.Count != defaultCount || len(res.Codes) != defaultCount {
		t.Errorf("batch size = %d/%d, want %d", res.Count, len(res.Codes), defaultCount)
	}
	if res.EntropyBits < MinEntropyBits {
		t.Errorf("EntropyBits = %d, want >= %d", res.EntropyBits, MinEntropyBits)
	}
	if got := len(store.codes[userID]); got != defaultCount {
		t.Errorf("stored codes = %d, want %d", got, defaultCount)
	}

	// Plaintext codes and stored hashes must both be internally distinct.
	seenPlain := make(map[string]struct{}, len(res.Codes))
	for _, c := range res.Codes {
		if _, dup := seenPlain[c]; dup {
			t.Errorf("duplicate plaintext code %q in batch", c)
		}
		seenPlain[c] = struct{}{}
	}
	seenHash := make(map[string]struct{}, len(store.codes[userID]))
	for _, c := range store.codes[userID] {
		if _, dup := seenHash[c.codeHash]; dup {
			t.Errorf("duplicate hash %q persisted", c.codeHash)
		}
		seenHash[c.codeHash] = struct{}{}
	}
}

func TestGenerateStoresHashesNotPlaintext(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	res, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// No stored value may equal a plaintext code (formatted or normalized): the
	// database holds only hashes.
	for _, plain := range res.Codes {
		norm := Normalize(plain)
		for _, sc := range store.codes[userID] {
			if sc.codeHash == plain || sc.codeHash == norm {
				t.Fatalf("plaintext %q leaked into storage", plain)
			}
			if len(sc.codeHash) != 64 {
				t.Errorf("stored hash %q length = %d, want 64", sc.codeHash, len(sc.codeHash))
			}
		}
	}
}

func TestGenerateWipesPreviousBatch(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	first, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate first: %v", err)
	}
	second, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate second: %v", err)
	}

	// A regeneration must leave exactly one batch live, never a union.
	if got := len(store.codes[userID]); got != defaultCount {
		t.Errorf("after regeneration stored codes = %d, want %d", got, defaultCount)
	}
	// A code from the first (destroyed) batch must no longer verify.
	if err := svc.Verify(context.Background(), userID, first.Codes[0], ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("old-batch code verify err = %v, want ErrInvalidCode", err)
	}
	// A code from the second (live) batch must verify.
	if err := svc.Verify(context.Background(), userID, second.Codes[0], ""); err != nil {
		t.Errorf("new-batch code verify err = %v, want nil", err)
	}
}

func TestGenerateUnknownUser(t *testing.T) {
	store := newFakeStore()
	svc, _ := New(Config{}, store)

	if _, err := svc.Generate(context.Background(), uuid.New(), ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Generate for unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestGenerateRetriesOnUniqueViolation(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	store.uniqueViolations = 1 // first insert collides, second succeeds
	svc, _ := New(Config{}, store)

	res, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate with one collision = %v, want nil (retry should recover)", err)
	}
	if len(res.Codes) != defaultCount {
		t.Errorf("recovered batch size = %d, want %d", len(res.Codes), defaultCount)
	}
	if store.createCalls != 2 {
		t.Errorf("CreateRecoveryCodes called %d times, want 2 (one retry)", store.createCalls)
	}
}

func TestGenerateFailsAfterRepeatedUniqueViolation(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	store.uniqueViolations = 5 // every attempt collides
	svc, _ := New(Config{}, store)

	if _, err := svc.Generate(context.Background(), userID, ""); err == nil {
		t.Fatal("Generate with persistent collisions = nil error, want error")
	}
	if len(store.codes[userID]) != 0 {
		t.Errorf("failed generation left %d codes, want 0", len(store.codes[userID]))
	}
}

// ── Verify ───────────────────────────────────────────────────────────────────

func TestVerifyConsumesExactlyOneCode(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	res, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := svc.Verify(context.Background(), userID, res.Codes[0], ""); err != nil {
		t.Fatalf("Verify valid code = %v, want nil", err)
	}
	if got := len(store.codes[userID]); got != defaultCount-1 {
		t.Errorf("after one verify stored codes = %d, want %d", got, defaultCount-1)
	}
	// The other codes must still be usable.
	if err := svc.Verify(context.Background(), userID, res.Codes[1], ""); err != nil {
		t.Errorf("Verify a second, different code = %v, want nil", err)
	}
}

func TestVerifyAcceptsFormattedAndMessyInput(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	res, _ := svc.Generate(context.Background(), userID, "")
	// The formatted code the user is shown carries dashes; lowercasing and
	// spacing it must still verify thanks to Normalize.
	messy := "  " + strings.ToLower(res.Codes[0]) + "  "
	if err := svc.Verify(context.Background(), userID, messy, ""); err != nil {
		t.Errorf("Verify messy-but-equivalent code = %v, want nil", err)
	}
}

func TestVerifyReplayIsRejected(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	res, _ := svc.Generate(context.Background(), userID, "")
	code := res.Codes[0]

	if err := svc.Verify(context.Background(), userID, code, ""); err != nil {
		t.Fatalf("first Verify = %v, want nil", err)
	}
	if err := svc.Verify(context.Background(), userID, code, ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("replayed Verify = %v, want ErrInvalidCode", err)
	}
}

func TestVerifyWrongCode(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	if _, err := svc.Generate(context.Background(), userID, ""); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := svc.Verify(context.Background(), userID, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("Verify wrong code = %v, want ErrInvalidCode", err)
	}
	if got := len(store.codes[userID]); got != defaultCount {
		t.Errorf("a failed verify consumed a code: stored = %d, want %d", got, defaultCount)
	}
}

func TestVerifyEmptyCode(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)
	_, _ = svc.Generate(context.Background(), userID, "")

	for _, in := range []string{"", "   ", "----", "!!!"} {
		if err := svc.Verify(context.Background(), userID, in, ""); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("Verify(%q) = %v, want ErrInvalidCode", in, err)
		}
	}
}

func TestVerifyCrossUserRejected(t *testing.T) {
	store := newFakeStore()
	victim := store.addUser()
	attacker := store.addUser()
	svc, _ := New(Config{}, store)

	res, err := svc.Generate(context.Background(), victim, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// The attacker holds a valid session for their own account and submits the
	// victim's code: the user_id scope on the lookup must reject it.
	if err := svc.Verify(context.Background(), attacker, res.Codes[0], ""); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("cross-user Verify = %v, want ErrInvalidCode", err)
	}
	// The victim's batch must be untouched.
	if got := len(store.codes[victim]); got != defaultCount {
		t.Errorf("victim lost codes to a cross-user attempt: stored = %d, want %d", got, defaultCount)
	}
}

func TestVerifyUnknownUser(t *testing.T) {
	store := newFakeStore()
	svc, _ := New(Config{}, store)

	if err := svc.Verify(context.Background(), uuid.New(), "ABCDE-ABCDE", ""); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Verify for unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestVerifyPropagatesStoreError(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	// A load-user failure that is not "no rows" must surface, not be masked as
	// an invalid code.
	sentinel := errors.New("db down")
	store.getUserErr = sentinel
	if err := svc.Verify(context.Background(), userID, "ABCDE", ""); !errors.Is(err, sentinel) {
		t.Errorf("Verify with store error = %v, want it to wrap %v", err, sentinel)
	}
}

// ── Status ───────────────────────────────────────────────────────────────────

func TestStatusReportsRemainingAndLow(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	// Fresh batch of 10, threshold 3 → not low.
	if _, err := svc.Generate(context.Background(), userID, ""); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	st, err := svc.Status(context.Background(), userID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Remaining != defaultCount {
		t.Errorf("Remaining = %d, want %d", st.Remaining, defaultCount)
	}
	if st.Low {
		t.Error("Low = true for a full batch, want false")
	}

	// Drop to the threshold and re-check.
	store.codes[userID] = store.codes[userID][:defaultLowThreshold]
	st, err = svc.Status(context.Background(), userID)
	if err != nil {
		t.Fatalf("Status (low): %v", err)
	}
	if st.Remaining != defaultLowThreshold {
		t.Errorf("Remaining = %d, want %d", st.Remaining, defaultLowThreshold)
	}
	if !st.Low {
		t.Error("Low = false at the threshold, want true")
	}
}

func TestStatusUnknownUser(t *testing.T) {
	store := newFakeStore()
	svc, _ := New(Config{}, store)
	if _, err := svc.Status(context.Background(), uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Status for unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestStatusPropagatesCountError(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	svc, _ := New(Config{}, store)

	sentinel := errors.New("count failed")
	store.countErr = sentinel
	if _, err := svc.Status(context.Background(), userID); !errors.Is(err, sentinel) {
		t.Errorf("Status with a count error = %v, want it to wrap %v", err, sentinel)
	}
}

// ── Account status gate ──────────────────────────────────────────────────────

// nonActiveStatuses is every users.status value the CHECK constraint in
// 00001_initial_schema.sql permits other than 'active'. None of them may
// authenticate, so none may touch recovery codes.
var nonActiveStatuses = []string{"suspended", "pending_verification", "pending_deletion"}

// TestGenerateRequiresActiveAccount proves a non-active account cannot mint a
// fresh batch. Sessions are validated without re-reading account status, so
// loadUser is the only place a mid-session suspension can be caught.
func TestGenerateRequiresActiveAccount(t *testing.T) {
	for _, status := range nonActiveStatuses {
		store := newFakeStore()
		userID := store.addUserWithStatus(status)
		svc, _ := New(Config{}, store)

		if _, err := svc.Generate(context.Background(), userID, ""); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Generate for a %s account = %v, want ErrAccountNotActive", status, err)
		}
		if got := len(store.codes[userID]); got != 0 {
			t.Errorf("Generate for a %s account wrote %d codes, want 0", status, got)
		}
	}
}

// TestVerifyRequiresActiveAccount proves a code minted while active stops
// working the moment the account leaves the active state, and that the refusal
// does not consume it.
func TestVerifyRequiresActiveAccount(t *testing.T) {
	for _, status := range nonActiveStatuses {
		store := newFakeStore()
		userID := store.addUser()
		svc, _ := New(Config{}, store)

		res, err := svc.Generate(context.Background(), userID, "")
		if err != nil {
			t.Fatalf("Generate while active: %v", err)
		}

		// The account is suspended after the batch was issued, which is exactly
		// the window a live session would otherwise keep open.
		store.users[userID] = db.User{ID: userID, Status: status}

		if err := svc.Verify(context.Background(), userID, res.Codes[0], ""); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Verify for a %s account = %v, want ErrAccountNotActive", status, err)
		}
		if got := len(store.codes[userID]); got != defaultCount {
			t.Errorf("a refused verify on a %s account consumed a code: stored = %d, want %d", status, got, defaultCount)
		}
	}
}

// TestStatusRequiresActiveAccount proves the status endpoint is gated too, so a
// non-active account cannot even enumerate how many codes it holds.
func TestStatusRequiresActiveAccount(t *testing.T) {
	for _, status := range nonActiveStatuses {
		store := newFakeStore()
		userID := store.addUserWithStatus(status)
		svc, _ := New(Config{}, store)

		if _, err := svc.Status(context.Background(), userID); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Status for a %s account = %v, want ErrAccountNotActive", status, err)
		}
	}
}

// TestActiveAccountStillSucceeds guards against the gate being over-broad: an
// 'active' account must retain the full generate/status/verify path.
func TestActiveAccountStillSucceeds(t *testing.T) {
	store := newFakeStore()
	userID := store.addUserWithStatus("active")
	svc, _ := New(Config{}, store)

	res, err := svc.Generate(context.Background(), userID, "")
	if err != nil {
		t.Fatalf("Generate for an active account = %v, want nil", err)
	}
	if _, err := svc.Status(context.Background(), userID); err != nil {
		t.Errorf("Status for an active account = %v, want nil", err)
	}
	if err := svc.Verify(context.Background(), userID, res.Codes[0], ""); err != nil {
		t.Errorf("Verify for an active account = %v, want nil", err)
	}
}

// TestUnknownStatusIsRefused pins the gate as an allow-list: a status value not
// yet in the CHECK constraint (or an empty one from a partially-populated row)
// must fail closed rather than be treated as active.
func TestUnknownStatusIsRefused(t *testing.T) {
	for _, status := range []string{"", "banned", "ACTIVE", "active "} {
		store := newFakeStore()
		userID := store.addUserWithStatus(status)
		svc, _ := New(Config{}, store)

		if _, err := svc.Status(context.Background(), userID); !errors.Is(err, ErrAccountNotActive) {
			t.Errorf("Status for status %q = %v, want ErrAccountNotActive", status, err)
		}
	}
}

// ── Rate limiting ────────────────────────────────────────────────────────────

func TestGenerateRateLimited(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	limiter := &fakeLimiter{allow: false}
	svc, err := New(Config{}, store, WithRateLimiter(limiter))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := svc.Generate(context.Background(), userID, "203.0.113.5:1234"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("rate-limited Generate = %v, want ErrRateLimited", err)
	}
	if len(store.codes[userID]) != 0 {
		t.Error("a rate-limited Generate still wrote codes")
	}
	// The subnet dimension must be consulted before the account dimension so a
	// saturated proxy cannot burn a targeted account's budget.
	if len(limiter.calls) == 0 || !strings.HasPrefix(limiter.calls[0], "rate:recovery:generate:subnet:") {
		t.Errorf("first limiter key = %v, want a generate:subnet key first", limiter.calls)
	}
}

func TestVerifyRateLimited(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	limiter := &fakeLimiter{allow: false}
	svc, _ := New(Config{}, store, WithRateLimiter(limiter))

	if err := svc.Verify(context.Background(), userID, "ABCDE", "203.0.113.5:1234"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("rate-limited Verify = %v, want ErrRateLimited", err)
	}
	if len(limiter.calls) == 0 || !strings.HasPrefix(limiter.calls[0], "rate:recovery:verify:subnet:") {
		t.Errorf("first limiter key = %v, want a verify:subnet key first", limiter.calls)
	}
}

func TestRateLimiterAllowsWhenUnderBudget(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	limiter := &fakeLimiter{allow: true}
	svc, _ := New(Config{}, store, WithRateLimiter(limiter))

	if _, err := svc.Generate(context.Background(), userID, "203.0.113.5:1234"); err != nil {
		t.Fatalf("Generate under budget = %v, want nil", err)
	}
	// Both dimensions are consulted when the first passes.
	if len(limiter.calls) != 2 {
		t.Errorf("limiter consulted %d times, want 2 (subnet + account)", len(limiter.calls))
	}
}

func TestRateLimiterErrorPropagates(t *testing.T) {
	store := newFakeStore()
	userID := store.addUser()
	sentinel := errors.New("redis down")
	limiter := &fakeLimiter{err: sentinel}
	svc, _ := New(Config{}, store, WithRateLimiter(limiter))

	if _, err := svc.Generate(context.Background(), userID, "203.0.113.5:1234"); !errors.Is(err, sentinel) {
		t.Errorf("Generate with limiter error = %v, want it to wrap %v", err, sentinel)
	}
}

// ── Transaction bookkeeping ──────────────────────────────────────────────────

// The Transacter path replaces the store with db.New(tx) inside the closure, so
// these tests assert only the commit/rollback bookkeeping (mirroring the
// WebAuthn suite); the business-logic assertions above run without a Transacter
// so they exercise the fake store directly.

type fakeTransacter struct {
	beginCalled    bool
	commitCalled   bool
	rollbackCalled bool
	beginErr       error
	commitErr      error
}

type fakeTx struct {
	ft *fakeTransacter
}

func (ft *fakeTransacter) Begin(_ context.Context) (pgx.Tx, error) {
	ft.beginCalled = true
	if ft.beginErr != nil {
		return nil, ft.beginErr
	}
	return &fakeTx{ft: ft}, nil
}

func (f *fakeTx) Begin(_ context.Context) (pgx.Tx, error) { return f, nil }

func (f *fakeTx) Commit(_ context.Context) error {
	f.ft.commitCalled = true
	return f.ft.commitErr
}

func (f *fakeTx) Rollback(_ context.Context) error {
	f.ft.rollbackCalled = true
	return nil
}

func (f *fakeTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, _ pgx.CopyFromSource) (int64, error) {
	return 0, nil
}

func (f *fakeTx) SendBatch(_ context.Context, _ *pgx.Batch) pgx.BatchResults { return nil }

func (f *fakeTx) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }

func (f *fakeTx) Prepare(_ context.Context, _, _ string) (*pgconn.StatementDescription, error) {
	return nil, nil
}

func (f *fakeTx) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakeTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return nil, nil
}

func (f *fakeTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row { return nil }

func (f *fakeTx) Conn() *pgx.Conn { return nil }

func TestRunInTxCommitsOnSuccess(t *testing.T) {
	ft := &fakeTransacter{}
	svc, err := New(Config{}, newFakeStore(), WithTransacter(ft))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := svc.runInTx(context.Background(), func(_ Store) error { return nil }); err != nil {
		t.Fatalf("runInTx: %v", err)
	}
	if !ft.beginCalled || !ft.commitCalled {
		t.Errorf("beginCalled=%v commitCalled=%v, want both true", ft.beginCalled, ft.commitCalled)
	}
	if ft.rollbackCalled {
		t.Error("rollback called on a successful commit")
	}
}

func TestRunInTxRollsBackOnError(t *testing.T) {
	ft := &fakeTransacter{}
	svc, _ := New(Config{}, newFakeStore(), WithTransacter(ft))

	sentinel := errors.New("fn failed")
	if err := svc.runInTx(context.Background(), func(_ Store) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("runInTx err = %v, want %v", err, sentinel)
	}
	if !ft.rollbackCalled {
		t.Error("rollbackCalled = false, want true on fn error")
	}
	if ft.commitCalled {
		t.Error("commit called despite fn error")
	}
}

func TestRunInTxBeginError(t *testing.T) {
	ft := &fakeTransacter{beginErr: errors.New("cannot begin")}
	svc, _ := New(Config{}, newFakeStore(), WithTransacter(ft))

	if err := svc.runInTx(context.Background(), func(_ Store) error { return nil }); err == nil {
		t.Fatal("runInTx with a begin error = nil, want error")
	}
	if ft.commitCalled || ft.rollbackCalled {
		t.Error("commit/rollback attempted after Begin failed")
	}
}

func TestRunInTxNilTransacterUsesStore(t *testing.T) {
	store := newFakeStore()
	svc, _ := New(Config{}, store) // no Transacter

	// Without a Transacter the closure receives the service's own store.
	called := false
	err := svc.runInTx(context.Background(), func(s Store) error {
		called = true
		if s == nil {
			t.Error("closure received a nil store")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runInTx: %v", err)
	}
	if !called {
		t.Error("closure was not invoked")
	}
}
