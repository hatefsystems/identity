package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

const recoveryTransactionBytes = 32

// RecoveryTransactionTTL bounds both the opaque transaction and the
// restricted session it can mint.
const RecoveryTransactionTTL = 10 * time.Minute

// UserLookup is the account lookup needed by the enumeration-resistant start
// endpoint. *db.Queries satisfies it.
type UserLookup interface {
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
}

// TransactionStore holds only hash-addressed, short-lived recovery state.
// Take must atomically consume an entry.
type TransactionStore interface {
	Save(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error
	Take(ctx context.Context, tokenHash string) (uuid.UUID, error)
}

// FlowService starts anonymous recovery transactions and consumes them before
// delegating recovery-code destruction to Service's ACID transaction.
type FlowService struct {
	codes        *Service
	users        UserLookup
	transactions TransactionStore
	floor        time.Duration
	now          func() time.Time
	sleep        func(time.Duration)
}

// StartResult is deliberately identical for real, unavailable, and unknown
// accounts. TransactionID carries 256 bits of CSPRNG entropy.
type StartResult struct {
	TransactionID string
	ExpiresAt     time.Time
}

// NewFlowService constructs the restricted recovery workflow.
func NewFlowService(codes *Service, users UserLookup, transactions TransactionStore, floor time.Duration) (*FlowService, error) {
	if codes == nil {
		return nil, errors.New("recovery: code service is required")
	}
	if users == nil {
		return nil, errors.New("recovery: user lookup is required")
	}
	if transactions == nil {
		return nil, errors.New("recovery: transaction store is required")
	}
	if floor < 0 {
		return nil, errors.New("recovery: timing floor cannot be negative")
	}
	return &FlowService{
		codes:        codes,
		users:        users,
		transactions: transactions,
		floor:        floor,
		now:          time.Now,
		sleep:        time.Sleep,
	}, nil
}

// Start creates an opaque transaction while concealing whether email names an
// active account. Unavailable identities receive a deterministic decoy UUID.
func (s *FlowService) Start(ctx context.Context, email string) (*StartResult, error) {
	started := s.now()
	defer func() {
		if remaining := s.floor - s.now().Sub(started); remaining > 0 {
			s.sleep(remaining)
		}
	}()

	normalized := strings.ToLower(strings.TrimSpace(email))
	userID := decoyRecoverySubject(normalized)
	user, err := s.users.GetUserByEmail(ctx, normalized)
	switch {
	case err == nil && user.Status == "active":
		userID = user.ID
	case err == nil:
		// Non-active accounts intentionally retain the decoy subject.
	case errors.Is(err, pgx.ErrNoRows):
		// Unknown accounts intentionally retain the decoy subject.
	default:
		return nil, fmt.Errorf("recovery: lookup recovery subject: %w", err)
	}

	raw := make([]byte, recoveryTransactionBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("recovery: generate transaction: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := s.now().Add(RecoveryTransactionTTL)
	if err := s.transactions.Save(ctx, hashTransactionToken(token), userID, RecoveryTransactionTTL); err != nil {
		return nil, fmt.Errorf("recovery: save transaction: %w", err)
	}
	return &StartResult{TransactionID: token, ExpiresAt: expiresAt}, nil
}

// Verify consumes the recovery transaction before checking the backup code.
// A wrong code therefore cannot be retried under the same transaction, and
// concurrent submissions have exactly one database candidate.
func (s *FlowService) Verify(ctx context.Context, transactionID, code, clientIP string) (uuid.UUID, error) {
	id, _, err := s.VerifyWithVersion(ctx, transactionID, code, clientIP)
	return id, err
}

// VerifyWithVersion binds the restricted session to the consumed proof's state.
func (s *FlowService) VerifyWithVersion(ctx context.Context, transactionID, code, clientIP string) (uuid.UUID, int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(transactionID)
	if err != nil || len(raw) != recoveryTransactionBytes {
		return uuid.Nil, 0, ErrInvalidCode
	}
	userID, err := s.transactions.Take(ctx, hashTransactionToken(transactionID))
	if err != nil {
		if errors.Is(err, errTransactionNotFound) {
			return uuid.Nil, 0, ErrInvalidCode
		}
		return uuid.Nil, 0, fmt.Errorf("recovery: consume transaction: %w", err)
	}
	version, err := s.codes.VerifyWithVersion(ctx, userID, code, clientIP)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrUserNotFound), errors.Is(err, ErrAccountNotActive):
			return uuid.Nil, 0, ErrInvalidCode
		default:
			return uuid.Nil, 0, err
		}
	}
	return userID, version, nil
}

func hashTransactionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decoyRecoverySubject(email string) uuid.UUID {
	return uuid.NewSHA1(uuid.Nil, []byte("recovery-decoy:"+email))
}
