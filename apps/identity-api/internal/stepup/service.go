package stepup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa"
	"github.com/hatefsystems/identity/apps/identity-api/internal/mfa/totp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/webauthn"
)

// ChallengeResult describes how an account may raise its authentication context.
type ChallengeResult struct {
	// Methods lists the step-up methods this account can currently present, in
	// preference order (WebAuthn before TOTP).
	Methods []string
	// WebAuthn carries the UV-required assertion options when a passkey
	// ceremony was started, and is nil otherwise.
	WebAuthn *protocol.CredentialAssertion
}

// VerifyParams describes a step-up verification attempt.
type VerifyParams struct {
	// UserID is the account from the caller's session (required).
	UserID uuid.UUID
	// SessionID is the caller's session ID, minted into the grant's sid claim
	// (required).
	SessionID string
	// Method selects the factor: MethodWebAuthn or MethodTOTP.
	Method string
	// Assertion is the raw navigator.credentials.get() JSON for MethodWebAuthn.
	Assertion []byte
	// Code is the passcode for MethodTOTP.
	Code string
	// ClientIP is the resolved client address feeding the per-subnet limit.
	ClientIP string
	// DPoPJKT propagates the earning session's DPoP thumbprint into the grant
	// when the session is sender-constrained.
	DPoPJKT string
}

// Challenge reports which factors the account can present and, when it holds a
// passkey, starts a user-verification-required assertion ceremony.
//
// Unlike the login ceremonies this endpoint has no account-enumeration surface
// to defend: the caller already holds a valid session for this exact account, so
// the mock-challenge machinery in internal/webauthn/mock.go is deliberately not
// used here. Telling the caller which of their own factors are available is
// information they are entitled to, and withholding it would leave the portal
// unable to explain why a sensitive action is unreachable.
func (s *Service) Challenge(ctx context.Context, userID uuid.UUID, sessionID string) (*ChallengeResult, error) {
	if sessionID == "" {
		return nil, errors.New("stepup: session id is required")
	}
	user, err := s.loadActiveUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := s.checkSessionVersion(ctx, user, sessionID); err != nil {
		return nil, err
	}

	result := &ChallengeResult{Methods: make([]string, 0, 2)}

	if s.passkeys != nil {
		options, err := s.passkeys.BeginStepUp(ctx, userID, sessionID)
		switch {
		case err == nil:
			result.Methods = append(result.Methods, MethodWebAuthn)
			result.WebAuthn = options
		case errors.Is(err, webauthn.ErrNoCredentials):
			// The account simply has no passkey to assert; fall through to the
			// TOTP option rather than failing the whole challenge.
		case errors.Is(err, webauthn.ErrUserNotFound):
			return nil, ErrUserNotFound
		case errors.Is(err, webauthn.ErrAccountNotActive):
			return nil, ErrAccountNotActive
		default:
			return nil, fmt.Errorf("stepup: begin passkey challenge: %w", err)
		}
	}

	if s.totp != nil && user.IsMfaEnabled {
		result.Methods = append(result.Methods, MethodTOTP)
	}

	if len(result.Methods) == 0 {
		return nil, ErrNoFactorAvailable
	}
	return result, nil
}

// Verify validates a presented factor and, on success, mints a single-use
// step-up grant bound to the caller's session.
func (s *Service) Verify(ctx context.Context, p VerifyParams) (string, time.Time, error) {
	if p.SessionID == "" {
		return "", time.Time{}, errors.New("stepup: session id is required")
	}
	user, err := s.loadActiveUser(ctx, p.UserID)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.checkSessionVersion(ctx, user, p.SessionID); err != nil {
		return "", time.Time{}, err
	}

	// Throttle before touching a factor so a brute-force attempt cannot spend
	// unbounded verification work, and so the 6-digit TOTP space stays out of
	// reach.
	if err := s.checkRateLimits(ctx, p.UserID, p.ClientIP); err != nil {
		return "", time.Time{}, err
	}

	var amr []string
	switch p.Method {
	case MethodWebAuthn:
		if s.passkeys == nil {
			return "", time.Time{}, ErrMethodUnavailable
		}
		if err := s.verifyPasskey(ctx, p); err != nil {
			return "", time.Time{}, err
		}
		amr = amrWebAuthnUV
	case MethodTOTP:
		if s.totp == nil {
			return "", time.Time{}, ErrMethodUnavailable
		}
		if err := s.verifyTOTP(ctx, p); err != nil {
			return "", time.Time{}, err
		}
		amr = amrTOTP
	default:
		return "", time.Time{}, fmt.Errorf("%w: %q", ErrUnsupportedMethod, p.Method)
	}

	return s.MintContext(ctx, MintParams{
		AuthVersion:    user.AuthVersion,
		AuthVersionSet: true,
		UserID:         p.UserID.String(),
		SessionID:      p.SessionID,
		AMR:            amr,
		DPoPJKT:        p.DPoPJKT,
	})
}

// verifyPasskey completes the UV-required assertion ceremony, translating the
// webauthn package's domain errors into this package's.
func (s *Service) verifyPasskey(ctx context.Context, p VerifyParams) error {
	err := s.passkeys.FinishStepUp(ctx, p.UserID, p.SessionID, p.Assertion)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, webauthn.ErrUserVerificationRequired):
		// Kept distinct from ErrInvalidCredentials: the caller is already
		// authenticated as this account, so nothing is leaked by saying the
		// assertion lacked user verification, and it is the only failure the
		// user can actually act on (use a PIN-capable authenticator, or TOTP).
		return ErrUserVerificationRequired
	case errors.Is(err, webauthn.ErrNoCredentials):
		return ErrMethodUnavailable
	case errors.Is(err, webauthn.ErrUserNotFound):
		return ErrUserNotFound
	case errors.Is(err, webauthn.ErrAccountNotActive):
		return ErrAccountNotActive
	case errors.Is(err, webauthn.ErrInvalidResponse),
		errors.Is(err, webauthn.ErrChallengeNotFound),
		errors.Is(err, webauthn.ErrChallengeExpired),
		errors.Is(err, webauthn.ErrChallengeFlowMismatch),
		errors.Is(err, webauthn.ErrCredentialCloned),
		errors.Is(err, webauthn.ErrVerification):
		return ErrInvalidCredentials
	default:
		return fmt.Errorf("stepup: verify passkey: %w", err)
	}
}

// verifyTOTP validates a passcode and burns it.
//
// The code is claimed in the replay guard *before* it is validated, which is the
// only ordering that actually prevents reuse: claiming afterwards would let two
// concurrent requests both validate the same code and both mint a grant. The
// cost is that a wrong code also consumes its guard slot, which is harmless — a
// wrong code was never usable.
func (s *Service) verifyTOTP(ctx context.Context, p VerifyParams) error {
	canonicalCode, err := totp.CanonicalizeCode(p.Code)
	if err != nil {
		return ErrInvalidCredentials
	}

	fresh, err := s.guard.Remember(ctx, totpGuardKey(p.UserID, canonicalCode), s.now().Add(totpReplayWindow))
	if err != nil {
		return fmt.Errorf("stepup: claim passcode: %w", err)
	}
	if !fresh {
		return ErrCodeReplayed
	}

	switch err := s.totp.VerifyEnabledCode(ctx, p.UserID, canonicalCode); {
	case err == nil:
		return nil
	case errors.Is(err, mfa.ErrInvalidCode):
		return ErrInvalidCredentials
	case errors.Is(err, mfa.ErrMfaNotSetup):
		return ErrMethodUnavailable
	case errors.Is(err, mfa.ErrUserNotFound):
		return ErrUserNotFound
	default:
		return fmt.Errorf("stepup: verify passcode: %w", err)
	}
}

// totpGuardKey namespaces a submitted passcode per account inside the replay
// guard and keeps plaintext out of the in-memory implementation. SHA-256 alone
// is not sufficient secrecy for a six-digit value; RedisReplayGuard therefore
// HMACs this entire logical key before it reaches the Redis keyspace.
func totpGuardKey(userID uuid.UUID, code string) string {
	sum := sha256.Sum256([]byte(code))
	return "stepup:totp:" + userID.String() + ":" + hex.EncodeToString(sum[:])
}

// loadActiveUser resolves the account and refuses any status other than active.
//
// GetUserByID filters deleted_at IS NULL but not status, so the check cannot be
// delegated to the query: a suspended account holding a live session must not be
// able to raise its authentication context and reach the gated operations.
func (s *Service) loadActiveUser(ctx context.Context, userID uuid.UUID) (db.User, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("stepup: load user: %w", err)
	}
	if user.Status != statusActive {
		return db.User{}, ErrAccountNotActive
	}
	return user, nil
}

func (s *Service) checkSessionVersion(ctx context.Context, user db.User, sessionID string) error {
	if s.accounts == nil {
		return nil
	}
	current, ok := session.FromContext(ctx)
	if !ok || current.Kind != session.KindAuthenticated || !current.AuthVersionSet || current.UserID != user.ID.String() || current.ID != sessionID || current.AuthVersion != user.AuthVersion {
		return ErrAccountNotActive
	}
	return nil
}

// statusActive is the only users.status value permitted to raise its
// authentication context, matching webauthn.isLoginEligible.
const statusActive = "active"

// checkRateLimits enforces the per-subnet window, then the two per-account
// windows, when a limiter is configured.
//
// The subnet window is evaluated first so a saturated shared proxy cannot burn a
// targeted account's budget, matching recovery.Service.checkRateLimits. It is a
// no-op when no limiter is set.
func (s *Service) checkRateLimits(ctx context.Context, userID uuid.UUID, clientIP string) error {
	if s.limiter == nil {
		return nil
	}

	subnet := ratelimit.Subnet(clientIP)
	windows := []struct {
		key    string
		limit  int
		window time.Duration
	}{
		{subnetRateKey(subnet), s.perSubnetPerHour, time.Hour},
		{accountRateKey(userID), s.perAccountPerMinute, time.Minute},
		{accountRateKeyHourly(userID), s.perAccountPerHour, time.Hour},
	}

	for _, w := range windows {
		ok, err := s.limiter.Allow(ctx, w.key, w.limit, w.window)
		if err != nil {
			return err
		}
		if !ok {
			return ErrRateLimited
		}
	}
	return nil
}

// accountRateKey builds the per-minute account ZSET key.
func accountRateKey(userID uuid.UUID) string {
	return "rate:stepup:verify:account:minute:" + userID.String()
}

// accountRateKeyHourly builds the per-hour account ZSET key.
func accountRateKeyHourly(userID uuid.UUID) string {
	return "rate:stepup:verify:account:hour:" + userID.String()
}

// subnetRateKey builds the per-hour subnet ZSET key.
func subnetRateKey(subnet string) string {
	return "rate:stepup:verify:subnet:" + subnet
}
