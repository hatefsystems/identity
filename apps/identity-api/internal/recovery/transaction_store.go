package recovery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var errTransactionNotFound = errors.New("recovery: transaction not found")

const recoveryTransactionKeyPrefix = "recovery:transaction:"

// RedisTransactionStore implements single-use recovery transactions with
// Redis GETDEL. The key contains only SHA-256(transaction_id).
type RedisTransactionStore struct {
	client redis.Cmdable
}

// NewRedisTransactionStore constructs a single-use transaction store backed by
// Redis.
func NewRedisTransactionStore(client redis.Cmdable) (*RedisTransactionStore, error) {
	if client == nil {
		return nil, errors.New("recovery: redis client is required")
	}
	return &RedisTransactionStore{client: client}, nil
}

// Save records a recovery transaction subject under an opaque hash until ttl.
func (s *RedisTransactionStore) Save(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	ok, err := s.client.SetNX(ctx, recoveryTransactionKeyPrefix+tokenHash, userID.String(), ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("recovery: transaction hash collision")
	}
	return nil
}

// Take atomically consumes a recovery transaction and returns its subject.
func (s *RedisTransactionStore) Take(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	raw, err := s.client.GetDel(ctx, recoveryTransactionKeyPrefix+tokenHash).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, errTransactionNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("recovery: corrupt transaction subject: %w", err)
	}
	return id, nil
}

type memoryTransaction struct {
	userID    uuid.UUID
	expiresAt time.Time
}

// MemoryTransactionStore is development/test-only and preserves the same
// atomic consume semantics under a mutex.
type MemoryTransactionStore struct {
	mu    sync.Mutex
	items map[string]memoryTransaction
	now   func() time.Time
}

// NewMemoryTransactionStore constructs a development/test transaction store.
func NewMemoryTransactionStore() *MemoryTransactionStore {
	return &MemoryTransactionStore{items: make(map[string]memoryTransaction), now: time.Now}
}

// Save records a recovery transaction subject under an opaque hash until ttl.
func (s *MemoryTransactionStore) Save(_ context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.items[tokenHash]; exists {
		return errors.New("recovery: transaction hash collision")
	}
	s.items[tokenHash] = memoryTransaction{userID: userID, expiresAt: s.now().Add(ttl)}
	return nil
}

// Take atomically consumes a recovery transaction and returns its subject.
func (s *MemoryTransactionStore) Take(_ context.Context, tokenHash string) (uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[tokenHash]
	if !ok {
		return uuid.Nil, errTransactionNotFound
	}
	delete(s.items, tokenHash)
	if s.now().After(entry.expiresAt) {
		return uuid.Nil, errTransactionNotFound
	}
	return entry.userID, nil
}
