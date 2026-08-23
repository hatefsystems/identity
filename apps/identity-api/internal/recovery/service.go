package recovery

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

// uniqueViolationSQLState is the PostgreSQL error code raised when an insert
// collides with a unique index — here, the partial unique index on
// recovery_codes.code_hash. It drives the one-shot regeneration retry so an
// astronomically-unlikely hash collision surfaces as a fresh batch rather than
// a 500.
const uniqueViolationSQLState = "23505"

// Store is the database query subset the recovery service needs. It is
// satisfied by *db.Queries — both the pool-bound instance and the transaction
// bound one returned by db.New(tx) — so runInTx can execute the very same calls
// inside or outside a transaction without a second interface.
type Store interface {
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	CountActiveRecoveryCodes(ctx context.Context, userID uuid.UUID) (int64, error)
	CreateRecoveryCodes(ctx context.Context, arg []db.CreateRecoveryCodesParams) (int64, error)
	DeleteAllRecoveryCodesForUser(ctx context.Context, userID uuid.UUID) (int64, error)
	GetActiveRecoveryCodeForUpdate(ctx context.Context, arg db.GetActiveRecoveryCodeForUpdateParams) (db.GetActiveRecoveryCodeForUpdateRow, error)
	DeleteRecoveryCodePhysically(ctx context.Context, id uuid.UUID) (int64, error)
}

// Transacter opens database transactions for the atomic verify and regenerate
// commits. *pgxpool.Pool satisfies it.
type Transacter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Config carries the recovery-code policy. Zero-valued fields fall back to the
// documented defaults in New; EntropyBits below MinEntropyBits is rejected
// rather than defaulted, so a weakened policy fails fast at startup.
type Config struct {
	// Count is the number of codes minted per batch (default 10).
	Count int
	// EntropyBits is the per-code entropy budget (default 160). Values below
	// MinEntropyBits (128) are rejected.
	EntropyBits int
	// LowThreshold is the remaining-code count at or below which Status reports
	// Low, prompting the UI to nudge a regeneration (default 3).
	LowThreshold int
	// HashPepper optionally keys the stored hash (HMAC-SHA-256) so a database
	// dump alone cannot be used to test candidate codes offline. When empty a
	// plain SHA-256 is used. Injected by the KMS/secrets manager; never
	// hardcoded.
	HashPepper []byte

	// PerAccountPerHour / PerSubnetPerHour bound generate and verify attempts
	// when a rate limiter is configured (defaults 10 and 20). They are applied
	// per operation under independent keys.
	PerAccountPerHour int
	PerSubnetPerHour  int
}

// Recovery-code default policy values applied when the corresponding Config
// field is zero (docs/data-architecture.md §1.2, docs/api-design.md §1.3).
const (
	defaultCount             = 10
	defaultLowThreshold      = 3
	defaultPerAccountPerHour = 10
	defaultPerSubnetPerHour  = 20
)

// Service orchestrates recovery-code generation, status, and single-use
// verification. Construct it with New; the zero value is not usable.
type Service struct {
	store   Store
	tx      Transacter
	limiter ratelimit.Limiter

	count        int
	codeChars    int
	lowThreshold int
	hashPepper   []byte

	perAccountPerHour int
	perSubnetPerHour  int
}

// Option configures optional behavior on a Service.
type Option func(*Service)

// WithTransacter sets the database transaction opener used to make the
// verify (read-lock, compare, delete) and regenerate (delete-all, insert)
// flows atomic. Without it those flows run directly against the store, which is
// only appropriate for tests with a fake.
func WithTransacter(tx Transacter) Option {
	return func(s *Service) {
		s.tx = tx
	}
}

// WithRateLimiter attaches a sliding-window limiter so generate and verify are
// throttled per account and per subnet. When omitted the service applies no
// rate limiting (the nil-safe default), which keeps unit tests lightweight.
func WithRateLimiter(l ratelimit.Limiter) Option {
	return func(s *Service) {
		s.limiter = l
	}
}

// New constructs a Service, applying default policy for unset fields and
// rejecting an entropy budget below the mandated floor.
func New(cfg Config, store Store, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("recovery: store is required")
	}

	entropyBits := cfg.EntropyBits
	if entropyBits <= 0 {
		entropyBits = DefaultEntropyBits
	}
	if entropyBits < MinEntropyBits {
		return nil, fmt.Errorf("recovery: entropy bits %d is below the %d-bit minimum", entropyBits, MinEntropyBits)
	}

	s := &Service{
		store:             store,
		count:             cfg.Count,
		codeChars:         charsForBits(entropyBits),
		lowThreshold:      cfg.LowThreshold,
		hashPepper:        cfg.HashPepper,
		perAccountPerHour: cfg.PerAccountPerHour,
		perSubnetPerHour:  cfg.PerSubnetPerHour,
	}

	if s.count <= 0 {
		s.count = defaultCount
	}
	if s.lowThreshold <= 0 {
		s.lowThreshold = defaultLowThreshold
	}
	if s.perAccountPerHour <= 0 {
		s.perAccountPerHour = defaultPerAccountPerHour
	}
	if s.perSubnetPerHour <= 0 {
		s.perSubnetPerHour = defaultPerSubnetPerHour
	}

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// GenerateResult is the one-time plaintext batch returned to the caller. The
// plaintext exists only in this value and the HTTP response; only the hashes
// are ever persisted, so a lost batch can only be replaced, never recovered.
type GenerateResult struct {
	// Codes are the formatted (grouped) plaintext codes, shown to the user
	// exactly once.
	Codes []string
	// Count is len(Codes), surfaced separately for convenience.
	Count int
	// EntropyBits is the realized per-code entropy, for logging/audit.
	EntropyBits int
}

// StatusResult reports how many unused codes remain for an account.
type StatusResult struct {
	// Remaining is the number of unused codes.
	Remaining int
	// Low is true when Remaining is at or below the configured low-water mark,
	// signalling the client to prompt a regeneration.
	Low bool
}

// Generate mints a fresh batch for userID, atomically destroying any existing
// batch first so a regeneration can never leave a mix of old and new codes
// valid at once (docs/api-design.md §1.3). It returns the plaintext once; only
// the SHA-256/HMAC hashes are stored. clientIP feeds the optional per-subnet
// rate limit.
func (s *Service) Generate(ctx context.Context, userID uuid.UUID, clientIP string) (*GenerateResult, error) {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := s.checkRateLimits(ctx, userID, clientIP, "generate"); err != nil {
		return nil, err
	}

	// A hash collision against another account's live code would abort the
	// insert; one regeneration with fresh randomness clears it. Two failures in
	// a row are not statistically credible for >=128-bit codes and surface as
	// an error rather than an unbounded loop.
	const maxAttempts = 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		plaintext, params, err := s.buildBatch(userID)
		if err != nil {
			return nil, err
		}

		err = s.runInTx(ctx, func(store Store) error {
			if _, err := store.DeleteAllRecoveryCodesForUser(ctx, userID); err != nil {
				return fmt.Errorf("recovery: delete existing codes: %w", err)
			}
			if _, err := store.CreateRecoveryCodes(ctx, params); err != nil {
				return fmt.Errorf("recovery: insert codes: %w", err)
			}
			return nil
		})
		if err != nil {
			if isUniqueViolation(err) && attempt < maxAttempts-1 {
				continue
			}
			return nil, err
		}

		return &GenerateResult{
			Codes:       plaintext,
			Count:       len(plaintext),
			EntropyBits: EntropyBits(s.codeChars),
		}, nil
	}

	return nil, errors.New("recovery: exhausted retries generating a unique code batch")
}

// Status reports the number of unused codes for userID and whether the account
// is running low.
func (s *Service) Status(ctx context.Context, userID uuid.UUID) (*StatusResult, error) {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return nil, err
	}

	count, err := s.store.CountActiveRecoveryCodes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("recovery: count codes: %w", err)
	}

	return &StatusResult{
		Remaining: int(count),
		Low:       count <= int64(s.lowThreshold),
	}, nil
}

// Verify consumes a single recovery code for userID. The match and the physical
// row delete run in one ACID transaction with the row held under FOR UPDATE, so
// two concurrent submissions of the same code cannot both succeed: the second
// blocks on the lock, then finds the row already gone and fails. Every failure
// mode (unknown code, already used, wrong account, empty input) collapses to
// ErrInvalidCode so nothing distinguishes them to the caller. clientIP feeds the
// optional per-subnet rate limit.
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, code, clientIP string) error {
	if _, err := s.loadUser(ctx, userID); err != nil {
		return err
	}
	if err := s.checkRateLimits(ctx, userID, clientIP, "verify"); err != nil {
		return err
	}

	normalized := Normalize(code)
	if normalized == "" {
		return ErrInvalidCode
	}
	hash := hashCode(s.hashPepper, normalized)

	return s.runInTx(ctx, func(store Store) error {
		row, err := store.GetActiveRecoveryCodeForUpdate(ctx, db.GetActiveRecoveryCodeForUpdateParams{
			CodeHash: hash,
			UserID:   userID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidCode
			}
			return fmt.Errorf("recovery: load code: %w", err)
		}

		// The lookup already matched on hash equality; the constant-time compare
		// is belt-and-braces so no later refactor can reintroduce a data-dependent
		// comparison timing (docs/architecture.md "Timing Attack Resistance").
		if subtle.ConstantTimeCompare([]byte(row.CodeHash), []byte(hash)) != 1 {
			return ErrInvalidCode
		}

		affected, err := store.DeleteRecoveryCodePhysically(ctx, row.ID)
		if err != nil {
			return fmt.Errorf("recovery: delete code: %w", err)
		}
		if affected == 0 {
			// Under FOR UPDATE the locked row cannot disappear before this
			// delete; treat the impossible as a failed attempt rather than a
			// silent success.
			return ErrInvalidCode
		}
		return nil
	})
}

// buildBatch generates s.count distinct codes, returning the formatted plaintext
// (for display) alongside the insert params carrying only the hashes. Hashes are
// de-duplicated within the batch so a within-batch collision cannot trip the
// unique index.
func (s *Service) buildBatch(userID uuid.UUID) ([]string, []db.CreateRecoveryCodesParams, error) {
	plaintext := make([]string, 0, s.count)
	params := make([]db.CreateRecoveryCodesParams, 0, s.count)
	seen := make(map[string]struct{}, s.count)

	for len(plaintext) < s.count {
		raw, err := generateCode(s.codeChars)
		if err != nil {
			return nil, nil, err
		}
		hash := hashCode(s.hashPepper, Normalize(raw))
		if _, dup := seen[hash]; dup {
			continue
		}
		seen[hash] = struct{}{}
		plaintext = append(plaintext, format(raw))
		params = append(params, db.CreateRecoveryCodesParams{UserID: userID, CodeHash: hash})
	}

	return plaintext, params, nil
}

// runInTx executes fn inside a database transaction when a Transacter is
// configured, or directly against s.store otherwise. The commit/rollback
// bookkeeping mirrors the WebAuthn service so the atomicity guarantee is
// identical across the codebase.
func (s *Service) runInTx(ctx context.Context, fn func(store Store) error) error {
	if s.tx == nil {
		return fn(s.store)
	}

	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("recovery: begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	txStore := db.New(tx)
	if err := fn(txStore); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("recovery: commit transaction: %w", err)
	}
	committed = true
	return nil
}

// loadUser confirms the account exists, mapping a missing row to
// ErrUserNotFound.
func (s *Service) loadUser(ctx context.Context, userID uuid.UUID) (db.User, error) {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("recovery: load user: %w", err)
	}
	return user, nil
}

// checkRateLimits enforces the per-subnet then per-account windows for op when a
// limiter is configured. The subnet is checked first so a saturated proxy cannot
// consume a targeted account's budget. It is a no-op when no limiter is set.
func (s *Service) checkRateLimits(ctx context.Context, userID uuid.UUID, clientIP, op string) error {
	if s.limiter == nil {
		return nil
	}

	subnet := ratelimit.Subnet(clientIP)
	okSubnet, err := s.limiter.Allow(ctx, subnetRateKey(op, subnet), s.perSubnetPerHour, time.Hour)
	if err != nil {
		return err
	}
	if !okSubnet {
		return ErrRateLimited
	}

	okAccount, err := s.limiter.Allow(ctx, accountRateKey(op, userID), s.perAccountPerHour, time.Hour)
	if err != nil {
		return err
	}
	if !okAccount {
		return ErrRateLimited
	}
	return nil
}

// accountRateKey builds the rate:recovery:{op}:account:{user} ZSET key.
func accountRateKey(op string, userID uuid.UUID) string {
	return "rate:recovery:" + op + ":account:" + userID.String()
}

// subnetRateKey builds the rate:recovery:{op}:subnet:{subnet} ZSET key.
func subnetRateKey(op, subnet string) string {
	return "rate:recovery:" + op + ":subnet:" + subnet
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint
// violation (SQLSTATE 23505), used to trigger the one-shot regeneration retry.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == uniqueViolationSQLState
	}
	return false
}
