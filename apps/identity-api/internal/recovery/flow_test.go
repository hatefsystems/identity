package recovery

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type flowTransactionSpy struct {
	hash   string
	userID uuid.UUID
	ttl    time.Duration
}

func (s *flowTransactionSpy) Save(_ context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	s.hash, s.userID, s.ttl = tokenHash, userID, ttl
	return nil
}

func (s *flowTransactionSpy) Take(_ context.Context, _ string) (uuid.UUID, error) {
	return uuid.Nil, errTransactionNotFound
}

type flowCodeRow struct {
	id       uuid.UUID
	userID   uuid.UUID
	codeHash string
}

type flowStore struct {
	mu      sync.Mutex
	users   map[uuid.UUID]db.User
	byEmail map[string]uuid.UUID
	codes   []flowCodeRow
	deletes int
}

func newFlowStore(user db.User) *flowStore {
	return &flowStore{
		users:   map[uuid.UUID]db.User{user.ID: user},
		byEmail: map[string]uuid.UUID{user.Email: user.ID},
	}
}

func (s *flowStore) GetUserByID(_ context.Context, id uuid.UUID) (db.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return user, nil
}

func (s *flowStore) GetUserByEmail(_ context.Context, email string) (db.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[email]
	if !ok {
		return db.User{}, pgx.ErrNoRows
	}
	return s.users[id], nil
}

func (s *flowStore) CountActiveRecoveryCodes(_ context.Context, userID uuid.UUID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for _, row := range s.codes {
		if row.userID == userID {
			count++
		}
	}
	return count, nil
}

func (s *flowStore) CreateRecoveryCodes(_ context.Context, args []db.CreateRecoveryCodesParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, arg := range args {
		s.codes = append(s.codes, flowCodeRow{id: uuid.New(), userID: arg.UserID, codeHash: arg.CodeHash})
	}
	return int64(len(args)), nil
}

func (s *flowStore) DeleteAllRecoveryCodesForUser(_ context.Context, userID uuid.UUID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.codes[:0]
	var deleted int64
	for _, row := range s.codes {
		if row.userID == userID {
			deleted++
			continue
		}
		kept = append(kept, row)
	}
	s.codes = kept
	return deleted, nil
}

func (s *flowStore) GetActiveRecoveryCodeForUpdate(_ context.Context, arg db.GetActiveRecoveryCodeForUpdateParams) (db.GetActiveRecoveryCodeForUpdateRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range s.codes {
		if row.userID == arg.UserID && row.codeHash == arg.CodeHash {
			return db.GetActiveRecoveryCodeForUpdateRow{ID: row.id, UserID: row.userID, CodeHash: row.codeHash}, nil
		}
	}
	return db.GetActiveRecoveryCodeForUpdateRow{}, pgx.ErrNoRows
}

func (s *flowStore) DeleteRecoveryCodePhysically(_ context.Context, id uuid.UUID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, row := range s.codes {
		if row.id == id {
			s.codes = append(s.codes[:i], s.codes[i+1:]...)
			s.deletes++
			return 1, nil
		}
	}
	return 0, nil
}

func TestFlowStartStoresOnlyAHashAddressedOpaqueTransaction(t *testing.T) {
	user := db.User{ID: uuid.New(), Email: "known@example.com", Status: "active"}
	store := newFlowStore(user)
	codes, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transactions := &flowTransactionSpy{}
	flow, err := NewFlowService(codes, store, transactions, 0)
	if err != nil {
		t.Fatalf("NewFlowService: %v", err)
	}

	result, err := flow.Start(context.Background(), "  KNOWN@example.com ")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(result.TransactionID)
	if err != nil || len(raw) != recoveryTransactionBytes {
		t.Fatalf("transaction = %d bytes, err %v; want %d bytes", len(raw), err, recoveryTransactionBytes)
	}
	if transactions.hash != hashTransactionToken(result.TransactionID) || transactions.hash == result.TransactionID {
		t.Fatalf("stored key is not exactly the transaction hash")
	}
	if transactions.userID != user.ID || transactions.ttl != RecoveryTransactionTTL {
		t.Fatalf("stored subject/ttl = %s/%v, want %s/%v", transactions.userID, transactions.ttl, user.ID, RecoveryTransactionTTL)
	}
}

func TestFlowStartUsesDecoySubjectsForUnknownAndInactiveAccounts(t *testing.T) {
	user := db.User{ID: uuid.New(), Email: "inactive@example.com", Status: "suspended"}
	store := newFlowStore(user)
	codes, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, email := range []string{"inactive@example.com", "unknown@example.com"} {
		t.Run(email, func(t *testing.T) {
			transactions := &flowTransactionSpy{}
			flow, err := NewFlowService(codes, store, transactions, 0)
			if err != nil {
				t.Fatalf("NewFlowService: %v", err)
			}
			if _, err := flow.Start(context.Background(), email); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if transactions.userID != decoyRecoverySubject(email) {
				t.Fatalf("subject = %s, want deterministic decoy", transactions.userID)
			}
			if transactions.userID == user.ID {
				t.Fatal("inactive account leaked its real subject into recovery state")
			}
		})
	}
}

func TestFlowVerifyConcurrentSubmissionHasOnePhysicalDelete(t *testing.T) {
	user := db.User{ID: uuid.New(), Email: "recover@example.com", Status: "active"}
	store := newFlowStore(user)
	codes, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	transactions := NewMemoryTransactionStore()
	flow, err := NewFlowService(codes, store, transactions, 0)
	if err != nil {
		t.Fatalf("NewFlowService: %v", err)
	}
	batch, err := codes.Generate(context.Background(), user.ID, "")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	tx, err := flow.Start(context.Background(), user.Email)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	const workers = 16
	results := make(chan error, workers)
	for range workers {
		go func() {
			_, err := flow.Verify(context.Background(), tx.TransactionID, batch.Codes[0], "203.0.113.9")
			results <- err
		}()
	}
	var succeeded, rejected int
	for range workers {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrInvalidCode):
			rejected++
		default:
			t.Fatalf("Verify returned unexpected error: %v", err)
		}
	}
	if succeeded != 1 || rejected != workers-1 {
		t.Fatalf("success/rejected = %d/%d, want 1/%d", succeeded, rejected, workers-1)
	}
	store.mu.Lock()
	deletes := store.deletes
	remaining := len(store.codes)
	store.mu.Unlock()
	if deletes != 1 || remaining != batch.Count-1 {
		t.Fatalf("physical deletes/remaining = %d/%d, want 1/%d", deletes, remaining, batch.Count-1)
	}
}

type failingTransactionStore struct{ err error }

func (f failingTransactionStore) Save(context.Context, string, uuid.UUID, time.Duration) error {
	return f.err
}

func (f failingTransactionStore) Take(context.Context, string) (uuid.UUID, error) {
	return uuid.Nil, f.err
}

func TestFlowVerifyDoesNotDisguiseTransactionStoreOutageAsBadCredentials(t *testing.T) {
	user := db.User{ID: uuid.New(), Email: "recover@example.com", Status: "active"}
	store := newFlowStore(user)
	codes, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	outage := errors.New("redis unavailable")
	flow, err := NewFlowService(codes, store, failingTransactionStore{err: outage}, 0)
	if err != nil {
		t.Fatalf("NewFlowService: %v", err)
	}
	_, err = flow.Verify(context.Background(), base64.RawURLEncoding.EncodeToString(make([]byte, recoveryTransactionBytes)), "code", "")
	if !errors.Is(err, outage) {
		t.Fatalf("Verify error = %v, want wrapped outage", err)
	}
}
