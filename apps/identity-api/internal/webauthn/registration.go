package webauthn

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// RegistrationAuthorization is either an already-consumed generic strong grant
// with its original bindings/deadline, or one fixed-purpose proof to spend in SQL.
// This package must not import stepup, which depends on WebAuthn.
type RegistrationAuthorization struct {
	UserID      uuid.UUID
	SessionID   string
	DPoPJKT     string
	AuthVersion int64
	ExpiresAt   time.Time
	Proof       string
}

// SessionReader checks raw liveness without account locks or activity renewal.
type SessionReader interface {
	LookupByID(context.Context, string, string) (session.Session, error)
}

// FirstPasskeyProofs separates non-consuming preflight, start spend and final read.
type FirstPasskeyProofs interface {
	CheckFirstPasskey(context.Context, session.Session, string) error
	ConsumeFirstPasskeyStartTx(context.Context, pgx.Tx, session.Session, string) (actionproof.FirstPasskeyAuthorization, error)
	ValidateFirstPasskeyTx(context.Context, pgx.Tx, session.Session, actionproof.FirstPasskeyAuthorization) error
}

// SetFirstPasskeyDependencies is configured before serving any enrollment.
// rawSessions must not perform nested account-state checks or renew activity.
func (s *Service) SetFirstPasskeyDependencies(proofs FirstPasskeyProofs, rawSessions SessionReader, usernames *username.Store) {
	s.firstProofs, s.firstSessions, s.firstUsernames = proofs, rawSessions, usernames
}

func (s *Service) registrationSession(ctx context.Context, user db.User, sessionID string) (session.Session, error) {
	current, ok := session.FromContext(ctx)
	if !ok || s.firstSessions == nil || current.Kind != session.KindAuthenticated || current.UserID != user.ID.String() ||
		current.ID != sessionID || !current.AuthVersionSet || current.AuthVersion < 0 || current.AuthVersion != user.AuthVersion ||
		current.DPoPJKT == "" || current.DPoPJKT != challengeDPoPJKT(ctx) {
		return session.Session{}, ErrRegistrationUnauthorized
	}
	live, err := s.firstSessions.LookupByID(ctx, current.UserID, current.ID)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) || errors.Is(err, session.ErrAccountIneligible) {
			return session.Session{}, ErrRegistrationUnauthorized
		}
		return session.Session{}, ErrChallengeStoreUnavailable
	}
	now := s.now()
	if live.Kind != current.Kind || live.UserID != current.UserID || live.ID != current.ID || !live.AuthVersionSet ||
		live.AuthVersion != current.AuthVersion || live.DPoPJKT != current.DPoPJKT || !now.Before(live.AbsoluteExpiry) || !now.Before(live.IdleExpiry) {
		return session.Session{}, ErrRegistrationUnauthorized
	}
	return live, nil
}

// BeginAuthorizedRegistration publishes authority only after a known SQL commit.
// A failed/uncertain publication is never retried and never refunds the proof.
func (s *Service) BeginAuthorizedRegistration(ctx context.Context, userID uuid.UUID, sessionID, name string, authorization RegistrationAuthorization) (*protocol.CredentialCreation, time.Time, error) {
	name, err := profile.NormalizeName(name)
	if err != nil {
		return nil, time.Time{}, err
	}
	current, ok := session.FromContext(ctx)
	if !ok || current.Kind != session.KindAuthenticated || current.ID != sessionID || current.UserID != userID.String() || !current.AuthVersionSet ||
		authorization.UserID != userID || authorization.SessionID != sessionID || authorization.DPoPJKT != current.DPoPJKT ||
		authorization.DPoPJKT != challengeDPoPJKT(ctx) || authorization.AuthVersion != current.AuthVersion {
		return nil, time.Time{}, ErrRegistrationUnauthorized
	}
	if authorization.Proof != "" {
		if s.firstProofs == nil || s.tx == nil {
			return nil, time.Time{}, ErrRegistrationUnauthorized
		}
		if err := s.firstProofs.CheckFirstPasskey(ctx, current, authorization.Proof); err != nil {
			return nil, time.Time{}, err
		}
	} else if !s.now().Before(authorization.ExpiresAt) {
		return nil, time.Time{}, ErrRegistrationUnauthorized
	}
	if authorization.Proof == "" {
		user, err := s.users.GetUserByID(ctx, userID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, ErrUserNotFound
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, userID)
		if err != nil {
			return nil, time.Time{}, err
		}
		if len(rows) > 0 {
			// Additional-key ceremonies retain their existing identity, provider
			// policy and lifetime. A concurrent loss of all keys is fail-closed
			// in both the ordinary Begin and final deciding transaction.
			if _, err := s.registrationSession(ctx, user, sessionID); err != nil {
				return nil, time.Time{}, err
			}
			if !s.now().Before(authorization.ExpiresAt) {
				return nil, time.Time{}, ErrRegistrationUnauthorized
			}
			creation, err := s.beginRegistration(ctx, userID, sessionID, FlowRegistration, false, name)
			return creation, time.Time{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var creation *protocol.CredentialCreation
	var pending PendingChallenge
	err = s.runRegistrationPolicyTx(ctx, userID, false, true, func(_ UserStore, creds CredentialStore, tx pgx.Tx, user db.User, state accountpolicy.State, display string) error {
		live, err := s.registrationSession(ctx, user, sessionID)
		if err != nil {
			return err
		}
		rows, err := creds.ListWebauthnCredentialsByUser(ctx, user.ID)
		if err != nil {
			return err
		}
		if state.Passkeys != 0 || len(rows) != 0 {
			return ErrRegistrationUnauthorized
		}
		if _, ok := s.challenges.(FirstRegistrationStore); !ok {
			return ErrRegistrationUnauthorized
		}
		metadata := &FirstRegistrationMetadata{Authorization: FirstPasskeyStepUp}
		deadline := authorization.ExpiresAt
		handle := user.WebauthnUserHandle
		if len(handle) == 0 {
			handle, err = newUserHandle()
			if err != nil {
				return err
			}
		}
		if len(handle) != userHandleByteLen {
			return ErrVerification
		}
		adapter := newUserAdapter(user, handle, dbToCredentials(rows))
		adapter.name = display
		if adapter.name == "" {
			adapter.name = base64.RawURLEncoding.EncodeToString(handle)
		}
		options := []gowebauthn.RegistrationOption{
			gowebauthn.WithExclusions(gowebauthn.Credentials(dbToCredentials(rows)).CredentialDescriptors()),
			gowebauthn.WithResidentKeyRequirement(s.residentKey),
			gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				RequireResidentKey: new(s.residentKey == protocol.ResidentKeyRequirementRequired), ResidentKey: s.residentKey, UserVerification: protocol.VerificationRequired,
			}),
		}
		var provider *gowebauthn.SessionData
		creation, provider, err = s.wa.BeginRegistration(adapter, options...)
		if err != nil {
			return err
		}
		if authorization.Proof != "" {
			spent, err := s.firstProofs.ConsumeFirstPasskeyStartTx(ctx, tx, live, authorization.Proof)
			if err != nil {
				return err
			}
			deadline = spent.ExpiresAt
			metadata = &FirstRegistrationMetadata{Authorization: FirstPasskeyEnrollment, Channel: spent.Channel, ContactBinding: append([]byte(nil), spent.ContactBinding...)}
		}
		for _, cap := range []time.Time{s.now().Add(s.challengeTTL), live.AbsoluteExpiry, live.IdleExpiry} {
			if cap.Before(deadline) {
				deadline = cap
			}
		}
		deadline = deadline.UTC().Truncate(time.Millisecond)
		remaining := deadline.Sub(s.now())
		if remaining < time.Millisecond {
			return ErrChallengeExpired
		}
		provider.Expires = deadline
		creation.Response.Timeout = int(remaining.Milliseconds())
		pending = PendingChallenge{AuthVersion: user.AuthVersion, Session: *provider, UserRef: user.ID,
			SessionID: sessionID, DPoPJKT: live.DPoPJKT, Name: name, Flow: FlowRegistration, Expires: deadline, FirstRegistration: metadata}
		return validatePendingChallenge(provider.Challenge, pending)
	})
	if err != nil {
		var commit *transactionCommitError
		if errors.As(err, &commit) {
			err = errors.Join(ErrRegistrationOutcomeUnknown, err)
		}
		return nil, time.Time{}, err
	}
	err = s.challenges.(FirstRegistrationStore).SaveFirstRegistration(ctx, pending.Session.Challenge, pending)
	if err != nil {
		if errors.Is(err, ErrChallengeStoreUnavailable) {
			err = errors.Join(ErrRegistrationOutcomeUnknown, err)
		}
		return nil, time.Time{}, err
	}
	session.OutcomeCommitted(ctx)
	remaining := pending.Expires.Sub(s.now())
	if remaining < time.Millisecond {
		return nil, time.Time{}, ErrChallengeExpired
	}
	creation.Response.Timeout = int(remaining.Milliseconds())
	return creation, pending.Expires, nil
}

func nullRegistrationUsername(user db.User) bool {
	return user.UsernameKey == nil && user.UsernameDetailsEncrypted == nil && !user.UsernamePolicyID.Valid &&
		user.UsernamePolicyFingerprint == nil && user.UsernamePolicyEpoch == nil && user.UsernameLookupKeyID == nil
}
