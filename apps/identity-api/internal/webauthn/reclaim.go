package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// statusPendingDeletion is the only account status the reclaim ceremony accepts.
//
// Every other ceremony in this package gates on isLoginEligible, which requires
// "active". Reclaim is the deliberate inverse: it exists precisely for the status
// that cannot log in, so it checks for that exact value rather than negating the
// login gate. Spelling it positively is what stops the ceremony from silently
// accepting "suspended" or "pending_verification" if the login policy ever widens.
const statusPendingDeletion = "pending_deletion"

// BeginReclaimAssertion starts the user-verification-required assertion ceremony
// that lets the holder of a valid reclaim token cancel a pending account deletion
// (Task 5.1, docs/architecture.md "Account Reclamation").
//
// requestID is the deletion request the ceremony belongs to. It plays the role a
// session ID plays in the authenticated ceremonies: the challenge is bound to it,
// so an assertion obtained for one deletion request cannot complete another. There
// is no session here — the account is pending_deletion and cannot log in — which is
// why the binding has to come from the request instead.
//
// It differs from BeginStepUp in three ways, all deliberate:
//
//   - It accepts only a pending_deletion account. An active account has no
//     deletion to cancel, and a suspended one must not be able to launder itself
//     back to active through this path.
//   - There is no mock/decoy branch. The caller already proved possession of a
//     256-bit reclaim token that names exactly one account, so there is no
//     identity left to enumerate here. The *caller* of this method is what hides
//     factor availability: internal/privacy collapses "no passkey" into the same
//     opaque failure as an invalid token.
//   - Completing it grants no session and no step-up grant. Its only product is
//     the nil return that authorises the status change.
func (s *Service) BeginReclaimAssertion(ctx context.Context, userID uuid.UUID, requestID string) (*protocol.CredentialAssertion, error) {
	if requestID == "" {
		return nil, errors.New("webauthn: deletion request id is required")
	}

	user, err := s.loadReclaimUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(user.WebauthnUserHandle) == 0 {
		return nil, ErrNoCredentials
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNoCredentials
	}

	assertion, session, err := s.wa.BeginLogin(
		newUserAdapter(user, user.WebauthnUserHandle, dbToCredentials(rows)),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin reclaim assertion: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session:   *session,
		UserRef:   user.ID,
		SessionID: requestID,
		Flow:      FlowReclaim,
		Expires:   s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return assertion, nil
}

// FinishReclaimAssertion verifies a reclaim assertion for userID. A nil return is
// the proof that a user-verified assertion from one of the account's own
// credentials was presented for this exact deletion request; internal/privacy turns
// that into the status change.
//
// TakeBound is what enforces the tag and the request binding while holding the
// store lock, so neither a login challenge nor another request's reclaim challenge
// can be redeemed here, and a probe with the wrong request id cannot burn the
// legitimate caller's pending ceremony.
//
// User verification is checked twice for the same reasons as FinishStepUp: once
// early so the failure is actionable ("use a PIN-capable authenticator, or TOTP")
// rather than a generic verification error, and once after the library's validation
// so the guarantee does not rest solely on the stored SessionData field surviving
// the round trip. The early read is safe to trust for routing because the flag
// lives inside the signed authenticator data — forging it fails the signature check
// below and collapses into the generic rejection.
func (s *Service) FinishReclaimAssertion(ctx context.Context, userID uuid.UUID, requestID string, body []byte) error {
	if requestID == "" {
		return errors.New("webauthn: deletion request id is required")
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	pending, err := s.challenges.TakeBound(
		parsed.Response.CollectedClientData.Challenge, FlowReclaim, userID, requestID)
	if err != nil {
		return err
	}

	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return ErrUserVerificationRequired
	}

	user, err := s.loadReclaimUser(ctx, userID)
	if err != nil {
		return err
	}
	if !bytes.Equal(user.WebauthnUserHandle, pending.Session.UserID) {
		return ErrVerification
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(rows) == 0 {
		return ErrNoCredentials
	}

	cred, err := s.wa.ValidateLogin(
		newUserAdapter(user, pending.Session.UserID, dbToCredentials(rows)),
		pending.Session,
		parsed,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerification, err)
	}

	if !cred.Flags.UserVerified {
		return ErrUserVerificationRequired
	}
	if cred.Authenticator.CloneWarning {
		return ErrCredentialCloned
	}
	// Re-checked after verification: the account may have been reclaimed by
	// another ceremony, or purged, while this one was in flight.
	if user.Status != statusPendingDeletion {
		return ErrAccountNotActive
	}

	// A reclaim assertion advances the authenticator's counter exactly like a
	// login, so it must be persisted or the next authentication would compare
	// against a stale value — either failing a legitimate user or masking a
	// genuine cloned authenticator.
	return s.commitSignCount(ctx, cred)
}

// loadReclaimUser resolves the subject with the soft-delete-blind lookup and
// enforces the pending_deletion gate.
//
// GetUserByIDForAdmin is mandatory here: GetUserByID filters deleted_at IS NULL, so
// it cannot see the very accounts this ceremony serves. Centralising both the
// lookup and the status gate keeps Begin and Finish from drifting apart on which
// accounts may reclaim.
func (s *Service) loadReclaimUser(ctx context.Context, userID uuid.UUID) (db.User, error) {
	user, err := s.users.GetUserByIDForAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("webauthn: load user: %w", err)
	}
	if user.Status != statusPendingDeletion {
		return db.User{}, ErrAccountNotActive
	}
	return user, nil
}
