package privacy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// statusPendingDeletion is the only users.status value the reclaim ceremony
// accepts. It is checked explicitly rather than through webauthn.isLoginEligible,
// which this flow deliberately bypasses: pending_deletion is exactly the status
// that cannot log in, and reclaiming is the documented separate flow for it
// (docs/architecture.md "Account Reclamation").
const statusPendingDeletion = "pending_deletion"

// Reclaim factor method names, as they appear on the wire.
const (
	// FactorWebAuthn is a user-verification-required passkey assertion.
	FactorWebAuthn = "webauthn"
	// FactorTOTP is a 6-digit authenticator passcode.
	FactorTOTP = "totp"
)

// totpReplayWindow is how long a submitted reclaim passcode is remembered as
// spent. totp.ValidateCode accepts the current step plus one on either side, so a
// code stays valid for 90 seconds; remembering it for that long covers its whole
// acceptance window without this package needing to know which step matched.
// Mirrors stepup.totpReplayWindow.
const totpReplayWindow = 90 * time.Second

// Store is the database query subset the privacy service needs. It is satisfied
// by *db.Queries — both the pool-bound instance and the transaction-bound one
// returned by db.New(tx) — so runInTx can execute the same calls inside or outside
// a transaction without a second interface.
type Store interface {
	// GetUserByIDForAdmin resolves an account *including* soft-deleted ones. Every
	// lookup in this package uses it: GetUserByID filters deleted_at IS NULL and
	// would therefore be blind to exactly the accounts this flow operates on.
	GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error)
	SoftDeleteUser(ctx context.Context, id uuid.UUID) (int64, error)
	ReclaimUser(ctx context.Context, arg db.ReclaimUserParams) (int64, error)
	CreateDeletionRequest(ctx context.Context, arg db.CreateDeletionRequestParams) (db.DeletionRequest, error)
	GetActiveDeletionRequestByTokenHashForUpdate(ctx context.Context, tokenHash string) (db.DeletionRequest, error)
	GetActiveDeletionRequestForUser(ctx context.Context, userID uuid.UUID) (db.DeletionRequest, error)
	IncrementDeletionRequestFailedAttempts(ctx context.Context, id uuid.UUID) (int64, error)
	MarkDeletionRequestNotified(ctx context.Context, id uuid.UUID) (int64, error)
	ConsumeDeletionRequest(ctx context.Context, id uuid.UUID) (int64, error)
	ExpireDeletionRequestsForUser(ctx context.Context, userID uuid.UUID) (int64, error)
}

// userLockingStore is implemented by the sqlc query set once bound to a
// PostgreSQL transaction. Keeping it separate from Store preserves lightweight
// map-backed unit fakes, while a configured production Transacter fails closed if
// its transaction-bound query set ever stops providing the mutex. Mirrors
// recovery.userLockingStore.
type userLockingStore interface {
	GetUserForUpdateIncludingDeleted(ctx context.Context, id uuid.UUID) (db.User, error)
}

// Transacter opens database transactions for the atomic deactivate and reclaim
// commits. *pgxpool.Pool satisfies it.
type Transacter interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// SessionRevoker kills every stateful browser session for an account.
// *session.Manager satisfies it.
type SessionRevoker interface {
	RevokeAllForUser(userID string) error
}

// TokenRevoker kills every refresh-token family for an account.
// token.RefreshTokenStore satisfies it.
type TokenRevoker interface {
	RevokeAllForUser(userID string) error
}

// PasskeyReclaimer runs the dedicated, distinctly tagged WebAuthn ceremony that a
// pending_deletion account may complete. *webauthn.Service satisfies it.
type PasskeyReclaimer interface {
	BeginReclaimAssertion(ctx context.Context, userID uuid.UUID, requestID string) (*protocol.CredentialAssertion, error)
	FinishReclaimAssertion(ctx context.Context, userID uuid.UUID, requestID string, body []byte) error
}

// TOTPReclaimer verifies a passcode against a pending_deletion account.
// *mfa.Service satisfies it.
type TOTPReclaimer interface {
	VerifyTOTPForReclaim(ctx context.Context, userID uuid.UUID, code string) error
}

// ReplayGuard provides single-use enforcement for a submitted reclaim passcode
// across its whole acceptance window. It is deliberately the same shape as
// stepup.ReplayGuard, so the existing in-memory and Redis-backed guards can be
// reused verbatim.
type ReplayGuard interface {
	Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error)
}

// Decryptor decrypts an envelope-encrypted PII payload. It is optional and used
// only to recover the backup email so the deletion notice can reach a second
// mailbox — which is what protects a user whose primary mailbox was taken over as
// part of the takeover that triggered the deletion. Without it only the primary
// address is notified.
type Decryptor interface {
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Config carries the deletion/reclaim policy. Zero-valued fields fall back to the
// documented defaults in New.
type Config struct {
	// GracePeriod is the recovery window: simultaneously the reclaim token's
	// lifetime and the purge cutoff (default 720h). See config.PrivacyConfig.
	GracePeriod time.Duration
	// ReclaimMaxAttempts caps failed factor checks per request (default 5).
	ReclaimMaxAttempts int
	// ReclaimPerAccountPerHour / ReclaimPerSubnetPerHour bound reclaim attempts
	// (defaults 10, 20).
	ReclaimPerAccountPerHour int
	ReclaimPerSubnetPerHour  int
	// DeletePerAccountPerDay bounds deletion requests per account (default 3).
	DeletePerAccountPerDay int
	// DeleteResendCooldown is the minimum interval between two notices for the
	// same account (default 1h).
	DeleteResendCooldown time.Duration
}

// Privacy default policy values, mirroring config.LoadPrivacy so a Service built
// without a loaded config still behaves like production.
const (
	defaultGracePeriod              = 720 * time.Hour
	defaultReclaimMaxAttempts       = 5
	defaultReclaimPerAccountPerHour = 10
	defaultReclaimPerSubnetPerHour  = 20
	defaultDeletePerAccountPerDay   = 3
	defaultDeleteResendCooldown     = time.Hour
)

// Service orchestrates soft deactivation and the reclaim ceremony. Construct it
// with New; the zero value is not usable.
type Service struct {
	store    Store
	tx       Transacter
	notifier Notifier
	recorder audit.Recorder
	limiter  ratelimit.Limiter
	sessions SessionRevoker
	tokens   TokenRevoker
	passkeys PasskeyReclaimer
	totp     TOTPReclaimer
	guard    ReplayGuard
	decrypt  Decryptor
	logger   *slog.Logger

	gracePeriod              time.Duration
	reclaimMaxAttempts       int
	reclaimPerAccountPerHour int
	reclaimPerSubnetPerHour  int
	deletePerAccountPerDay   int
	deleteResendCooldown     time.Duration

	// now is injectable so cooldown and cutoff arithmetic is deterministic in
	// tests.
	now func() time.Time
}

// Option configures optional behavior on a Service.
type Option func(*Service)

// WithTransacter sets the database transaction opener that makes the deactivate
// (lock, soft-delete, mint token) and reclaim (lock, restore, invalidate tokens)
// flows atomic. Without it those flows run directly against the store, which is
// only appropriate for tests with a fake.
func WithTransacter(tx Transacter) Option {
	return func(s *Service) { s.tx = tx }
}

// WithRateLimiter attaches a sliding-window limiter so deletion and reclaim are
// throttled per account and per subnet. When omitted no rate limiting is applied,
// which keeps unit tests lightweight.
func WithRateLimiter(l ratelimit.Limiter) Option {
	return func(s *Service) { s.limiter = l }
}

// WithSessionRevoker attaches the session manager whose sessions are killed at
// soft-delete.
func WithSessionRevoker(r SessionRevoker) Option {
	return func(s *Service) { s.sessions = r }
}

// WithTokenRevoker attaches the refresh-token store whose families are revoked at
// soft-delete.
func WithTokenRevoker(r TokenRevoker) Option {
	return func(s *Service) { s.tokens = r }
}

// WithPasskeyReclaimer attaches the WebAuthn reclaim ceremony. Without it, only
// TOTP can satisfy a reclaim, which would strand passkey-only accounts.
func WithPasskeyReclaimer(p PasskeyReclaimer) Option {
	return func(s *Service) { s.passkeys = p }
}

// WithTOTPReclaimer attaches the TOTP reclaim verifier.
func WithTOTPReclaimer(t TOTPReclaimer) Option {
	return func(s *Service) { s.totp = t }
}

// WithReplayGuard attaches single-use enforcement for reclaim passcodes.
func WithReplayGuard(g ReplayGuard) Option {
	return func(s *Service) { s.guard = g }
}

// WithDecryptor attaches the envelope decryptor used to recover the backup email
// for the deletion notice.
func WithDecryptor(d Decryptor) Option {
	return func(s *Service) { s.decrypt = d }
}

// WithLogger overrides the service logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock overrides the service time source, for deterministic cooldown and
// cutoff assertions in tests.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New constructs a Service, applying default policy for unset fields.
//
// The notifier is required, not optional. A deletion whose reclaim token cannot be
// delivered has no recovery window, so there is no safe "deletion without
// notification" mode to fall back to; wiring decides whether a real notifier
// exists and leaves the routes unmounted when it does not.
func New(cfg Config, store Store, notifier Notifier, recorder audit.Recorder, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("privacy: store is required")
	}
	if notifier == nil {
		return nil, errors.New("privacy: notifier is required")
	}
	if recorder == nil {
		return nil, errors.New("privacy: audit recorder is required")
	}

	s := &Service{
		store:                    store,
		notifier:                 notifier,
		recorder:                 recorder,
		logger:                   slog.Default(),
		gracePeriod:              cfg.GracePeriod,
		reclaimMaxAttempts:       cfg.ReclaimMaxAttempts,
		reclaimPerAccountPerHour: cfg.ReclaimPerAccountPerHour,
		reclaimPerSubnetPerHour:  cfg.ReclaimPerSubnetPerHour,
		deletePerAccountPerDay:   cfg.DeletePerAccountPerDay,
		deleteResendCooldown:     cfg.DeleteResendCooldown,
		now:                      time.Now,
	}

	if s.gracePeriod <= 0 {
		s.gracePeriod = defaultGracePeriod
	}
	if s.reclaimMaxAttempts <= 0 {
		s.reclaimMaxAttempts = defaultReclaimMaxAttempts
	}
	if s.reclaimPerAccountPerHour <= 0 {
		s.reclaimPerAccountPerHour = defaultReclaimPerAccountPerHour
	}
	if s.reclaimPerSubnetPerHour <= 0 {
		s.reclaimPerSubnetPerHour = defaultReclaimPerSubnetPerHour
	}
	if s.deletePerAccountPerDay <= 0 {
		s.deletePerAccountPerDay = defaultDeletePerAccountPerDay
	}
	if s.deleteResendCooldown <= 0 {
		s.deleteResendCooldown = defaultDeleteResendCooldown
	}

	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// GracePeriod reports the configured recovery window, so the purge worker and the
// HTTP layer read the same value the tokens were minted against.
func (s *Service) GracePeriod() time.Duration { return s.gracePeriod }

// DeletionResult describes the outcome of a deletion request. The endpoint answers
// 204 for every one of these; the fields exist for logging and tests, not for the
// wire, because distinguishing "newly deactivated" from "already pending" to the
// caller would serve no purpose beyond confirming prior state.
type DeletionResult struct {
	// AlreadyPending reports that the account was already in pending_deletion, so
	// this call was an idempotent repeat.
	AlreadyPending bool
	// TokenMinted reports that a fresh reclaim token was created (a first request,
	// or a resend outside the cooldown).
	TokenMinted bool
	// Notified reports that the notifier accepted a message during this call.
	Notified bool
	// ExpiresAt is when the live reclaim token stops working, which is also when
	// the purge worker becomes eligible to erase the account.
	ExpiresAt time.Time
}

// ReclaimChallenge tells the client which factor to present. Exactly one factor is
// offered: WebAuthn when the account holds a passkey, TOTP otherwise. There is no
// "here are all your options" response, because listing them would disclose an
// unauthenticated caller's factor inventory.
type ReclaimChallenge struct {
	// Factor is FactorWebAuthn or FactorTOTP.
	Factor string
	// WebAuthn carries the UV-required assertion options for FactorWebAuthn, and
	// is nil for FactorTOTP.
	WebAuthn *protocol.CredentialAssertion
}

// ReclaimAttempt is one presented factor.
type ReclaimAttempt struct {
	// Method selects the factor: FactorWebAuthn or FactorTOTP.
	Method string
	// Assertion is the raw navigator.credentials.get() JSON for FactorWebAuthn.
	Assertion []byte
	// Code is the passcode for FactorTOTP.
	Code string
	// ClientIP is the resolved client address feeding the per-subnet limit.
	ClientIP string
}

// RequestDeletion performs the step-up-gated soft deactivation behind
// DELETE /api/v1/users/me.
//
// It is idempotent: a repeat call on an account already in pending_deletion
// succeeds without deactivating twice. Whether it also mints and re-sends a fresh
// reclaim token is governed by the resend cooldown — a user who lost the first
// mail can retry, but the endpoint cannot be turned into an email bomb.
//
// Revocation, notification, and auditing happen *after* the commit and are
// deliberately non-fatal. The account is already suspended from every user-facing
// service at that point, which is the fail-safe direction; rolling the deletion
// back because a mail server hiccuped would leave a user who asked to be forgotten
// fully active instead.
func (s *Service) RequestDeletion(ctx context.Context, userID uuid.UUID, clientIP string) (DeletionResult, error) {
	if err := s.checkDeleteRateLimit(ctx, userID); err != nil {
		return DeletionResult{}, err
	}

	// Loaded before the transaction purely for the notification addresses; the
	// authoritative state read is the locked row inside the transaction.
	user, err := s.store.GetUserByIDForAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeletionResult{}, ErrUserNotFound
		}
		return DeletionResult{}, fmt.Errorf("privacy: load user: %w", err)
	}

	token, tokenHash, err := NewReclaimToken()
	if err != nil {
		return DeletionResult{}, err
	}

	var (
		result  DeletionResult
		request db.DeletionRequest
	)
	err = s.runInTx(ctx, func(store Store) error {
		locked, lockErr := s.lockUser(ctx, store, userID)
		if lockErr != nil {
			return lockErr
		}

		affected, softErr := store.SoftDeleteUser(ctx, userID)
		if softErr != nil {
			return fmt.Errorf("privacy: soft delete user: %w", softErr)
		}

		deletedAt := locked.DeletedAt
		if affected == 0 {
			// Zero rows means deleted_at was already set: the account is already
			// pending_deletion and this is an idempotent repeat.
			result.AlreadyPending = true

			existing, getErr := store.GetActiveDeletionRequestForUser(ctx, userID)
			switch {
			case getErr == nil:
				request = existing
				result.ExpiresAt = existing.ExpiresAt.Time
				if s.withinResendCooldown(existing) {
					// A live, recently-notified request already exists. Do not
					// mint, do not resend.
					return nil
				}
			case errors.Is(getErr, pgx.ErrNoRows):
				// No live request: the previous one lapsed or was retired. Mint a
				// replacement so the account is still recoverable.
			default:
				return fmt.Errorf("privacy: load active deletion request: %w", getErr)
			}
		} else {
			// Re-read inside the transaction so expires_at is derived from the
			// database's own deleted_at. That is what makes the token expiry and
			// the purge cutoff arithmetically inseparable rather than two clocks
			// that happen to agree.
			refreshed, readErr := store.GetUserByIDForAdmin(ctx, userID)
			if readErr != nil {
				return fmt.Errorf("privacy: reload user after soft delete: %w", readErr)
			}
			deletedAt = refreshed.DeletedAt
		}

		if !deletedAt.Valid {
			// Unreachable: either the update set it or the guard proved it set.
			return errors.New("privacy: account has no deleted_at after soft delete")
		}

		if _, expErr := store.ExpireDeletionRequestsForUser(ctx, userID); expErr != nil {
			return fmt.Errorf("privacy: invalidate outstanding deletion requests: %w", expErr)
		}
		created, createErr := store.CreateDeletionRequest(ctx, db.CreateDeletionRequestParams{
			UserID:      userID,
			TokenHash:   tokenHash,
			RequestedIp: optionalString(clientIP),
			ExpiresAt:   pgtype.Timestamptz{Time: deletedAt.Time.Add(s.gracePeriod), Valid: true},
		})
		if createErr != nil {
			return fmt.Errorf("privacy: create deletion request: %w", createErr)
		}
		request = created
		result.TokenMinted = true
		result.ExpiresAt = created.ExpiresAt.Time
		return nil
	})
	if err != nil {
		return DeletionResult{}, err
	}

	s.revokeEverything(ctx, userID)

	if result.TokenMinted {
		result.Notified = s.deliverNotice(ctx, user, request, token, result.ExpiresAt)
	}

	s.record(ctx, audit.Event{
		EventType:     audit.EventDeletionRequested,
		ActionStatus:  audit.StatusSuccess,
		ActorID:       userID,
		SubjectID:     &userID,
		ClientIP:      clientIP,
		ActorSPIFFEID: "",
		Payload: map[string]any{
			"already_pending": result.AlreadyPending,
			"token_minted":    result.TokenMinted,
			"notified":        result.Notified,
			"expires_at":      result.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})

	return result, nil
}

// ReclaimOptions resolves a reclaim token and reports which factor the subject
// must present. It never consumes the token: the token has to survive being
// looked up, or a user who abandons the ceremony halfway would lose their only
// recovery path.
//
// Every failure — unknown token, expired, consumed, missing account, wrong status,
// or an account with no verifiable factor at all — returns ErrInvalidToken, so the
// endpoint is neither a deletion-existence oracle nor a factor-inventory oracle.
func (s *Service) ReclaimOptions(ctx context.Context, token, clientIP string) (ReclaimChallenge, error) {
	request, user, err := s.resolveReclaim(ctx, token, clientIP)
	if err != nil {
		return ReclaimChallenge{}, err
	}

	// The passkey ceremony is offered first: it is phishing-resistant and, unlike
	// TOTP, is available to accounts that never enrolled an authenticator app.
	if s.passkeys != nil {
		options, beginErr := s.passkeys.BeginReclaimAssertion(ctx, user.ID, request.ID.String())
		switch {
		case beginErr == nil:
			return ReclaimChallenge{Factor: FactorWebAuthn, WebAuthn: options}, nil
		case errors.Is(beginErr, webauthn.ErrNoCredentials),
			errors.Is(beginErr, webauthn.ErrUserNotFound),
			errors.Is(beginErr, webauthn.ErrAccountNotActive):
			// The account simply has no passkey to assert; fall through to TOTP.
		default:
			return ReclaimChallenge{}, fmt.Errorf("privacy: begin reclaim assertion: %w", beginErr)
		}
	}

	if s.totp != nil && user.IsMfaEnabled {
		return ReclaimChallenge{Factor: FactorTOTP}, nil
	}

	// No factor is verifiable. This is indistinguishable from an invalid token by
	// design: reporting it would tell an anonymous caller that the account exists,
	// is pending deletion, and holds neither a passkey nor TOTP.
	return ReclaimChallenge{}, ErrInvalidToken
}

// Reclaim cancels a pending deletion after verifying the presented factor.
//
// A failed factor increments the request's attempt counter and does NOT consume
// the token. That is the opposite trade-off from the single-use recovery-code
// transaction, and deliberately so: consuming a reclaim token on a mistyped
// passcode would permanently destroy the account's only recovery path. The
// attempt cap is what bounds abuse instead — reaching it retires the request.
func (s *Service) Reclaim(ctx context.Context, token string, attempt ReclaimAttempt) error {
	request, user, err := s.resolveReclaim(ctx, token, attempt.ClientIP)
	if err != nil {
		return err
	}

	if verifyErr := s.verifyFactor(ctx, user, request, attempt); verifyErr != nil {
		// A rate-limit or infrastructure fault must not be charged to the user's
		// attempt budget: only an actual failed factor check counts.
		if errors.Is(verifyErr, ErrRateLimited) {
			return verifyErr
		}
		if !isFactorRejection(verifyErr) {
			return verifyErr
		}
		s.recordFailedAttempt(ctx, request, user, attempt.Method, attempt.ClientIP)
		return ErrInvalidToken
	}

	cutoff := pgtype.Timestamptz{Time: s.now().Add(-s.gracePeriod), Valid: true}
	err = s.runInTx(ctx, func(store Store) error {
		if _, lockErr := s.lockUser(ctx, store, user.ID); lockErr != nil {
			return lockErr
		}
		affected, reclaimErr := store.ReclaimUser(ctx, db.ReclaimUserParams{
			ID:        user.ID,
			DeletedAt: cutoff,
		})
		if reclaimErr != nil {
			return fmt.Errorf("privacy: reclaim user: %w", reclaimErr)
		}
		if affected != 1 {
			// The account left pending_deletion, or fell past the cutoff, between
			// the factor check and this commit — a concurrent reclaim or the purge
			// worker won the row. Refuse rather than report a success that did not
			// happen.
			return ErrInvalidToken
		}
		if _, expErr := store.ExpireDeletionRequestsForUser(ctx, user.ID); expErr != nil {
			return fmt.Errorf("privacy: invalidate outstanding deletion requests: %w", expErr)
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.record(ctx, audit.Event{
		EventType:    audit.EventDeletionReclaimed,
		ActionStatus: audit.StatusSuccess,
		ActorID:      user.ID,
		SubjectID:    &user.ID,
		ClientIP:     attempt.ClientIP,
		Payload: map[string]any{
			"factor":     attempt.Method,
			"request_id": request.ID.String(),
		},
	})
	return nil
}

// resolveReclaim applies the rate limits, resolves a token to its live request and
// subject, and enforces that the subject is genuinely pending deletion. It is
// shared by ReclaimOptions and Reclaim so the two endpoints cannot drift into
// disagreeing about what makes a token usable.
func (s *Service) resolveReclaim(ctx context.Context, token, clientIP string) (db.DeletionRequest, db.User, error) {
	if err := s.checkReclaimSubnetLimit(ctx, clientIP); err != nil {
		return db.DeletionRequest{}, db.User{}, err
	}
	if token == "" {
		return db.DeletionRequest{}, db.User{}, ErrInvalidToken
	}

	// The query row-locks the request. Run outside an explicit transaction the lock
	// lasts only for the statement's implicit transaction, which is what we want
	// here: the authoritative serialization point is the users-row lock taken by
	// the reclaim commit, and holding a lock across the (potentially slow) factor
	// verification would let one caller stall the purge worker.
	request, err := s.store.GetActiveDeletionRequestByTokenHashForUpdate(ctx, HashReclaimToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Unknown, expired, and already-consumed all land here.
			return db.DeletionRequest{}, db.User{}, ErrInvalidToken
		}
		return db.DeletionRequest{}, db.User{}, fmt.Errorf("privacy: load deletion request: %w", err)
	}

	// The per-account window is only applicable once a token resolves an account.
	// Unresolvable probing is bounded by the subnet window above, which is the only
	// dimension available before an account is known.
	if err := s.checkReclaimAccountLimit(ctx, request.UserID); err != nil {
		return db.DeletionRequest{}, db.User{}, err
	}

	user, err := s.store.GetUserByIDForAdmin(ctx, request.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.DeletionRequest{}, db.User{}, ErrInvalidToken
		}
		return db.DeletionRequest{}, db.User{}, fmt.Errorf("privacy: load user: %w", err)
	}
	if user.Status != statusPendingDeletion {
		return db.DeletionRequest{}, db.User{}, ErrInvalidToken
	}
	return request, user, nil
}

// verifyFactor checks the presented factor. It returns a factor rejection (which
// the caller charges to the attempt budget) or an infrastructure error (which it
// does not).
func (s *Service) verifyFactor(ctx context.Context, user db.User, request db.DeletionRequest, attempt ReclaimAttempt) error {
	switch attempt.Method {
	case FactorWebAuthn:
		if s.passkeys == nil {
			return ErrUnsupportedFactor
		}
		return s.passkeys.FinishReclaimAssertion(ctx, user.ID, request.ID.String(), attempt.Assertion)
	case FactorTOTP:
		if s.totp == nil {
			return ErrUnsupportedFactor
		}
		return s.verifyTOTP(ctx, user.ID, attempt.Code)
	default:
		return ErrUnsupportedFactor
	}
}

// verifyTOTP claims the passcode in the replay guard *before* validating it, which
// is the only ordering that actually prevents reuse: claiming afterwards would let
// two concurrent requests both validate the same code. A wrong code also burns its
// guard slot, which is harmless — it was never usable. Mirrors stepup.verifyTOTP.
func (s *Service) verifyTOTP(ctx context.Context, userID uuid.UUID, code string) error {
	canonical, err := totp.CanonicalizeCode(code)
	if err != nil {
		return ErrInvalidToken
	}

	if s.guard != nil {
		fresh, guardErr := s.guard.Remember(ctx, reclaimTOTPGuardKey(userID, canonical), s.now().Add(totpReplayWindow))
		if guardErr != nil {
			return fmt.Errorf("privacy: claim reclaim passcode: %w", guardErr)
		}
		if !fresh {
			return ErrInvalidToken
		}
	}

	return s.totp.VerifyTOTPForReclaim(ctx, userID, canonical)
}

// isFactorRejection reports whether err is "the presented factor was wrong"
// rather than an infrastructure fault. Only the former is charged to the request's
// attempt budget, so a database or Redis outage cannot burn through a user's
// recovery attempts.
func isFactorRejection(err error) bool {
	switch {
	case errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrUnsupportedFactor),
		errors.Is(err, mfa.ErrInvalidCode),
		errors.Is(err, mfa.ErrMfaNotSetup),
		errors.Is(err, mfa.ErrUserNotFound),
		errors.Is(err, mfa.ErrAccountNotActive),
		errors.Is(err, webauthn.ErrInvalidResponse),
		errors.Is(err, webauthn.ErrChallengeNotFound),
		errors.Is(err, webauthn.ErrChallengeExpired),
		errors.Is(err, webauthn.ErrChallengeFlowMismatch),
		errors.Is(err, webauthn.ErrVerification),
		errors.Is(err, webauthn.ErrCredentialCloned),
		errors.Is(err, webauthn.ErrUserVerificationRequired),
		errors.Is(err, webauthn.ErrNoCredentials),
		errors.Is(err, webauthn.ErrUserNotFound),
		errors.Is(err, webauthn.ErrAccountNotActive):
		return true
	default:
		return false
	}
}

// recordFailedAttempt charges one failed factor check to the request and retires
// it when the cap is reached.
//
// Failures here are logged rather than returned: the caller has already decided to
// answer with the opaque ErrInvalidToken, and turning a bookkeeping failure into a
// different response would itself be an oracle.
func (s *Service) recordFailedAttempt(ctx context.Context, request db.DeletionRequest, user db.User, method, clientIP string) {
	exhausted := int(request.FailedAttempts)+1 >= s.reclaimMaxAttempts

	if _, err := s.store.IncrementDeletionRequestFailedAttempts(ctx, request.ID); err != nil {
		s.logger.Error("privacy: record failed reclaim attempt", slog.String("error", err.Error()))
	}
	if exhausted {
		if _, err := s.store.ConsumeDeletionRequest(ctx, request.ID); err != nil {
			s.logger.Error("privacy: retire exhausted deletion request", slog.String("error", err.Error()))
		}
	}

	s.record(ctx, audit.Event{
		EventType:    audit.EventDeletionReclaimFailed,
		ActionStatus: audit.StatusFailure,
		ActorID:      user.ID,
		SubjectID:    &user.ID,
		ClientIP:     clientIP,
		Payload: map[string]any{
			"factor":     method,
			"request_id": request.ID.String(),
			"attempts":   int(request.FailedAttempts) + 1,
			"exhausted":  exhausted,
		},
	})
}

// revokeEverything kills the account's stateful sessions and refresh-token
// families after a committed soft delete.
//
// Failures are logged and audited but never returned: the account is already
// pending_deletion, so failing the request would leave the user believing the
// deletion did not happen while it in fact did. The residual authority this leaves
// is bounded — an already-issued access token remains valid until it expires, at
// most the access-token TTL (see the package doc).
func (s *Service) revokeEverything(ctx context.Context, userID uuid.UUID) {
	if s.sessions != nil {
		if err := s.sessions.RevokeAllForUser(userID.String()); err != nil {
			s.logger.Error("privacy: revoke sessions after deletion request",
				slog.String("user_id", userID.String()), slog.String("error", err.Error()))
			s.record(ctx, audit.Event{
				EventType:    audit.EventDeletionRequested,
				ActionStatus: audit.StatusFailure,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload:      map[string]any{"stage": "revoke_sessions"},
			})
		}
	}
	if s.tokens != nil {
		if err := s.tokens.RevokeAllForUser(userID.String()); err != nil {
			s.logger.Error("privacy: revoke refresh tokens after deletion request",
				slog.String("user_id", userID.String()), slog.String("error", err.Error()))
			s.record(ctx, audit.Event{
				EventType:    audit.EventDeletionRequested,
				ActionStatus: audit.StatusFailure,
				ActorID:      userID,
				SubjectID:    &userID,
				Payload:      map[string]any{"stage": "revoke_refresh_tokens"},
			})
		}
	}
}

// deliverNotice sends the reclaim token and stamps notified_at on success. It
// reports whether the notifier accepted the message.
//
// notified_at is only stamped on success, so a failed send leaves the resend
// cooldown unarmed and the user's next request retries the delivery instead of
// silently doing nothing.
func (s *Service) deliverNotice(
	ctx context.Context,
	user db.User,
	request db.DeletionRequest,
	token string,
	expiresAt time.Time,
) bool {
	notice := DeletionNotice{
		PrimaryEmail: user.Email,
		BackupEmail:  s.backupEmail(ctx, user),
		ReclaimToken: token,
		ExpiresAt:    expiresAt,
	}
	if err := s.notifier.NotifyDeletionRequested(ctx, notice); err != nil {
		s.logger.Error("privacy: deliver deletion notice",
			slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
		s.record(ctx, audit.Event{
			EventType:    audit.EventDeletionRequested,
			ActionStatus: audit.StatusFailure,
			ActorID:      user.ID,
			SubjectID:    &user.ID,
			Payload:      map[string]any{"stage": "notify"},
		})
		return false
	}
	if _, err := s.store.MarkDeletionRequestNotified(ctx, request.ID); err != nil {
		// The message went out; only the bookkeeping failed. The worst case is a
		// duplicate notice on the next request, which is preferable to reporting a
		// failed deletion.
		s.logger.Error("privacy: stamp deletion notice delivery",
			slog.String("error", err.Error()))
	}
	return true
}

// backupEmail decrypts the account's backup address when a decryptor is
// configured. A decryption failure is logged and treated as "no backup address":
// losing the second delivery channel is strictly better than failing a deletion
// the user asked for.
func (s *Service) backupEmail(ctx context.Context, user db.User) *string {
	if s.decrypt == nil || len(user.BackupEmailEncrypted) == 0 {
		return nil
	}
	plaintext, err := s.decrypt.Decrypt(ctx, user.BackupEmailEncrypted)
	if err != nil {
		s.logger.Error("privacy: decrypt backup email for deletion notice",
			slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
		return nil
	}
	value := string(plaintext)
	if value == "" {
		return nil
	}
	return &value
}

// withinResendCooldown reports whether request was notified recently enough that a
// repeat deletion request must not mint and re-send a replacement token.
//
// A request that has never been notified is never inside the cooldown: the point
// of the cooldown is to bound *delivered* mail, so an undelivered notice should be
// retried immediately.
func (s *Service) withinResendCooldown(request db.DeletionRequest) bool {
	if !request.NotifiedAt.Valid {
		return false
	}
	return s.now().Sub(request.NotifiedAt.Time) < s.deleteResendCooldown
}

// record persists an audit event, logging (never propagating) a transport failure.
// An audit transport being down is a monitoring problem; refusing to complete a
// deletion because of it would be a compliance failure.
func (s *Service) record(ctx context.Context, e audit.Event) {
	if s.recorder == nil {
		return
	}
	if err := s.recorder.Record(ctx, e); err != nil {
		s.logger.Error("privacy: record audit event",
			slog.String("event_type", e.EventType), slog.String("error", err.Error()))
	}
}

// runInTx executes fn inside a database transaction when a Transacter is
// configured, or directly against s.store otherwise. The commit/rollback
// bookkeeping mirrors recovery.Service.runInTx so the atomicity guarantee is
// identical across the codebase.
func (s *Service) runInTx(ctx context.Context, fn func(store Store) error) error {
	if s.tx == nil {
		return fn(s.store)
	}

	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("privacy: begin transaction: %w", err)
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
		return fmt.Errorf("privacy: commit transaction: %w", err)
	}
	committed = true
	return nil
}

// lockUser takes the per-account mutex, using the soft-delete-blind FOR UPDATE
// variant because every flow here operates on rows the filtered lock cannot see.
// The plain-store fallback exists only for unit fakes, where runInTx has no real
// transaction to make atomic.
func (s *Service) lockUser(ctx context.Context, store Store, userID uuid.UUID) (db.User, error) {
	get := store.GetUserByIDForAdmin
	if s.tx != nil {
		locking, ok := store.(userLockingStore)
		if !ok {
			return db.User{}, errors.New("privacy: transaction store does not support user row locking")
		}
		get = locking.GetUserForUpdateIncludingDeleted
	}

	user, err := get(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("privacy: lock user: %w", err)
	}
	return user, nil
}

// checkDeleteRateLimit enforces the per-account daily bound on deletion requests.
// There is no subnet dimension here: the endpoint requires both a live session and
// a step-up grant, so the account is always known and a shared proxy carries no
// useful signal.
func (s *Service) checkDeleteRateLimit(ctx context.Context, userID uuid.UUID) error {
	if s.limiter == nil {
		return nil
	}
	ok, err := s.limiter.Allow(ctx, deleteAccountRateKey(userID), s.deletePerAccountPerDay, 24*time.Hour)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	return nil
}

// checkReclaimSubnetLimit enforces the per-subnet reclaim window. It is evaluated
// before the per-account window (and before any lookup) so a saturated shared
// proxy cannot consume a targeted account's budget, matching the stepup and
// recovery precedent.
func (s *Service) checkReclaimSubnetLimit(ctx context.Context, clientIP string) error {
	if s.limiter == nil {
		return nil
	}
	ok, err := s.limiter.Allow(ctx,
		reclaimSubnetRateKey(ratelimit.Subnet(clientIP)), s.reclaimPerSubnetPerHour, time.Hour)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	return nil
}

// checkReclaimAccountLimit enforces the per-account reclaim window.
func (s *Service) checkReclaimAccountLimit(ctx context.Context, userID uuid.UUID) error {
	if s.limiter == nil {
		return nil
	}
	ok, err := s.limiter.Allow(ctx,
		reclaimAccountRateKey(userID), s.reclaimPerAccountPerHour, time.Hour)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRateLimited
	}
	return nil
}

// deleteAccountRateKey builds the rate:privacy:delete:account:{user} ZSET key.
func deleteAccountRateKey(userID uuid.UUID) string {
	return "rate:privacy:delete:account:" + userID.String()
}

// reclaimAccountRateKey builds the rate:privacy:reclaim:account:{user} ZSET key.
func reclaimAccountRateKey(userID uuid.UUID) string {
	return "rate:privacy:reclaim:account:" + userID.String()
}

// reclaimSubnetRateKey builds the rate:privacy:reclaim:subnet:{subnet} ZSET key.
func reclaimSubnetRateKey(subnet string) string {
	return "rate:privacy:reclaim:subnet:" + subnet
}

// reclaimTOTPGuardKey namespaces a submitted reclaim passcode per account inside
// the replay guard and keeps the plaintext out of the in-memory implementation.
// SHA-256 alone is not sufficient secrecy for a six-digit value, which is why the
// Redis guard HMACs this whole logical key before it reaches the keyspace.
func reclaimTOTPGuardKey(userID uuid.UUID, code string) string {
	return "privacy:reclaim:totp:" + userID.String() + ":" + HashReclaimToken(code)
}

// optionalString maps an empty string to a nil pointer for a nullable column.
func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
