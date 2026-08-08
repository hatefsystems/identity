package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// BeginRegistration starts an attestation ceremony for an already-authenticated
// account and returns the PublicKeyCredentialCreationOptions the browser feeds
// to navigator.credentials.create().
//
// The options carry the account's anonymised 64-bit user handle (generated here
// on the first passkey and only persisted once the ceremony succeeds) plus an
// exclusion list of the credentials already registered, so an authenticator the
// user already enrolled refuses to create a duplicate. The generated challenge
// and its SessionData are held server-side under a short TTL; the response is
// only accepted if it echoes that exact challenge back.
func (s *Service) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, error) {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("webauthn: load user: %w", err)
	}

	// Reuse the persisted handle so every credential of an account signs over
	// the same user.id; mint one only for the first registration.
	handle := user.WebauthnUserHandle
	if len(handle) == 0 {
		if handle, err = newUserHandle(); err != nil {
			return nil, err
		}
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	existing := dbToCredentials(rows)

	creation, session, err := s.wa.BeginRegistration(
		newUserAdapter(user, handle, existing),
		gowebauthn.WithExclusions(gowebauthn.Credentials(existing).CredentialDescriptors()),
		// Ask for a discoverable (resident) credential so the authenticator
		// stores the user handle itself. Without this the key cannot be offered
		// in a usernameless ceremony, and the account would be permanently
		// stuck on the user-named fallback (Task 4.3).
		gowebauthn.WithResidentKeyRequirement(s.residentKey),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin registration: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		UserRef: user.ID,
		Flow:    FlowRegistration,
		Expires: s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return creation, nil
}

// FinishRegistration verifies an attestation response and stores the resulting
// credential for userID.
//
// body is the raw JSON returned by navigator.credentials.create(). It is parsed
// first so the challenge embedded in the signed clientDataJSON can locate the
// pending ceremony: the challenge itself is the lookup key, which means no
// client-supplied flow identifier is trusted. The pending entry is consumed on
// read (single-use) and must belong to the caller, then the library verifies
// origin, RP ID hash, client-data type, and attestation before the credential
// is persisted together with its initial signature counter.
func (s *Service) FinishRegistration(ctx context.Context, userID uuid.UUID, body []byte) (db.WebauthnCredential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return db.WebauthnCredential{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	pending, err := s.challenges.Take(parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return db.WebauthnCredential{}, err
	}
	// A challenge issued for another account is treated as unknown: the caller
	// learns nothing beyond "this challenge is not yours to complete".
	if pending.UserRef != userID {
		return db.WebauthnCredential{}, ErrChallengeNotFound
	}

	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.WebauthnCredential{}, ErrUserNotFound
		}
		return db.WebauthnCredential{}, fmt.Errorf("webauthn: load user: %w", err)
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return db.WebauthnCredential{}, fmt.Errorf("webauthn: list credentials: %w", err)
	}

	// The handle must come from the stored session, not the user row: on a
	// first registration the row is still NULL, and the library requires the
	// adapter's WebAuthnID to equal the SessionData UserID it issued.
	adapter := newUserAdapter(user, pending.Session.UserID, dbToCredentials(rows))

	cred, err := s.wa.CreateCredential(adapter, pending.Session, parsed)
	if err != nil {
		return db.WebauthnCredential{}, fmt.Errorf("%w: %v", ErrVerification, err)
	}

	var row db.WebauthnCredential
	err = s.runInTx(ctx, func(users UserStore, creds CredentialStore) error {
		// Persist the handle only after a successful ceremony, so a failed or
		// abandoned registration never pins a handle to the account.
		if len(user.WebauthnUserHandle) == 0 {
			affected, err := users.SetWebauthnUserHandle(ctx, db.SetWebauthnUserHandleParams{
				ID:                 user.ID,
				WebauthnUserHandle: pending.Session.UserID,
			})
			if err != nil {
				return fmt.Errorf("webauthn: persist user handle: %w", err)
			}
			if affected == 0 {
				// The query only writes while the column is NULL, so zero rows
				// means a concurrent first registration already pinned a different
				// handle. Storing this credential would bind it to a handle the
				// account no longer advertises, breaking later handle-based
				// lookups, so fail instead and let the user retry.
				return errors.New("webauthn: user handle was set by a concurrent registration")
			}
		} else if !bytes.Equal(user.WebauthnUserHandle, pending.Session.UserID) {
			return errors.New("webauthn: user handle was set by a concurrent registration")
		}

		var createErr error
		row, createErr = creds.CreateWebauthnCredential(ctx, credentialToCreateParams(user.ID, cred))
		if createErr != nil {
			return fmt.Errorf("webauthn: persist credential: %w", createErr)
		}
		return nil
	})
	if err != nil {
		return db.WebauthnCredential{}, err
	}
	return row, nil
}

// BeginDiscoverableLogin starts a usernameless assertion ceremony and returns
// the PublicKeyCredentialRequestOptions for navigator.credentials.get().
//
// This is the primary login path (docs/architecture.md, "User Harvesting &
// Timing Attack Defenses"). No identity is supplied and allowCredentials is
// empty, so the ceremony is identical for every caller: the authenticator
// prompts for user verification, picks a credential it holds for this RP ID,
// and reports the owning account only inside the signed assertion. Because the
// server never looks anything up before answering, there is simply no account
// to enumerate — the timing and content of this response carry no information
// about who does or does not have an account.
func (s *Service) BeginDiscoverableLogin(_ context.Context) (*protocol.CredentialAssertion, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin discoverable login: %w", err)
	}

	// UserRef stays uuid.Nil: the identity is unknown until the assertion
	// arrives and is resolved from the authenticator-reported user handle.
	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		Flow:    FlowLoginDiscoverable,
		Expires: s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return assertion, nil
}

// BeginLogin starts a user-named assertion ceremony for the given email and
// returns the PublicKeyCredentialRequestOptions for navigator.credentials.get().
//
// This is the legacy path, kept for flows that collect an email first. It never
// reports that an identity is unusable: an unknown email, an account with no
// passkey, and a non-active account all receive a mock ceremony that is
// structurally identical to a real one (see mock.go), so the response cannot be
// used to confirm whether an account exists. The only errors it returns are
// genuine infrastructure failures.
//
// Both branches are padded to the same minimum duration, so the difference in
// server-side work — a real lookup hits the database twice, a mock not at all —
// is not observable either. The residual client-side signal is documented in
// mock.go and is why discoverable login is preferred.
func (s *Service) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	defer s.enforceFloor(s.now())

	user, err := s.users.GetUserByEmail(ctx, email)
	switch {
	case err == nil:
		// Fall through to the checks below.
	case errors.Is(err, pgx.ErrNoRows):
		return s.beginMockLogin(email)
	default:
		return nil, fmt.Errorf("webauthn: load user: %w", err)
	}

	// A suspended or pending-deletion account must not be able to start a real
	// ceremony, but must not be distinguishable from a healthy one either.
	if !isLoginEligible(user.Status) {
		return s.beginMockLogin(email)
	}
	if len(user.WebauthnUserHandle) == 0 {
		return s.beginMockLogin(email)
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(rows) == 0 {
		return s.beginMockLogin(email)
	}

	assertion, session, err := s.wa.BeginLogin(
		newUserAdapter(user, user.WebauthnUserHandle, dbToCredentials(rows)),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin login: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		UserRef: user.ID,
		Flow:    FlowLoginNamed,
		Expires: s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return assertion, nil
}

// beginMockLogin builds the decoy ceremony for an identity that cannot log in.
//
// It runs the same s.wa.BeginLogin as the real path, over a synthetic user, so
// the emitted options match a genuine response field for field. The challenge is
// stored like any other: the ceremony must be completable-looking right up to
// the verify step, where it fails as an ordinary invalid assertion. Storing it
// also means the mock consumes the same code path on verify, rather than
// short-circuiting in a way that would itself be a distinguishing signal.
func (s *Service) beginMockLogin(email string) (*protocol.CredentialAssertion, error) {
	adapter := newMockUserAdapter(s.mockKey, email)

	assertion, session, err := s.wa.BeginLogin(adapter)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin mock login: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		Flow:    FlowLoginMock,
		Expires: s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return assertion, nil
}

// enforceFloor pads a user-named login options request out to
// s.namedLoginFloor measured from start, so the real and mock branches take the
// same observable time regardless of how much work each did.
func (s *Service) enforceFloor(start time.Time) {
	if s.namedLoginFloor <= 0 {
		return
	}
	if remaining := s.namedLoginFloor - s.now().Sub(start); remaining > 0 {
		s.sleep(remaining)
	}
}

// isLoginEligible reports whether an account's status permits authentication.
// Only fully active accounts may sign in: 'suspended' and 'banned' accounts are
// barred by moderation, 'pending_verification' has not proven ownership of its
// email, and 'pending_deletion' is inside the 30-day grace window, where
// reclamation is a separate, deliberate flow rather than an ordinary login
// (docs/architecture.md, "Grace Period & Soft Deletes").
func isLoginEligible(status string) bool {
	return status == "active"
}

// FinishLogin verifies an assertion response and returns the authenticated
// account's UUID, which the caller uses to issue a session. It serves all three
// login variants; which one applies is decided by the tag recorded when the
// challenge was issued, never by anything in the request body.
//
// The pending ceremony is located by the challenge inside the signed
// clientDataJSON and consumed on read, so an assertion cannot be replayed. The
// library verifies the origin against the configured RPOrigins, the RP ID hash,
// credential ownership, and the signature; this method then enforces the
// signature-counter policy from docs/architecture.md: the counter reported by
// the authenticator must strictly exceed the stored value (unless the
// authenticator does not implement a counter and reports zero), otherwise the
// credential is treated as cloned and the login is rejected.
func (s *Service) FinishLogin(ctx context.Context, body []byte) (uuid.UUID, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	pending, err := s.challenges.Take(parsed.Response.CollectedClientData.Challenge)
	if err != nil {
		return uuid.Nil, err
	}

	switch pending.Flow {
	case FlowLoginNamed:
		return s.finishNamedLogin(ctx, pending, parsed)
	case FlowLoginDiscoverable:
		return s.finishDiscoverableLogin(ctx, pending, parsed)
	case FlowLoginMock:
		// The caller completed a decoy. No signature over a credential that
		// does not exist can verify, so this is simply "invalid credentials",
		// and the handler renders it as the same opaque 401 as a genuinely
		// failed assertion.
		return uuid.Nil, ErrMockChallenge
	default:
		// A registration challenge submitted to the login verifier.
		return uuid.Nil, ErrChallengeFlowMismatch
	}
}

// finishNamedLogin completes a user-named assertion, where the challenge itself
// records which account the ceremony was issued for.
func (s *Service) finishNamedLogin(
	ctx context.Context,
	pending PendingChallenge,
	parsed *protocol.ParsedCredentialAssertionData,
) (uuid.UUID, error) {
	user, err := s.users.GetUserByID(ctx, pending.UserRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrUserNotFound
		}
		return uuid.Nil, fmt.Errorf("webauthn: load user: %w", err)
	}
	// Defensive: the account's handle must still be the one the challenge was
	// issued for, otherwise the assertion is validated against a different
	// identity than the browser was told about.
	if !bytes.Equal(user.WebauthnUserHandle, pending.Session.UserID) {
		return uuid.Nil, ErrVerification
	}

	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	if len(rows) == 0 {
		return uuid.Nil, ErrNoCredentials
	}

	adapter := newUserAdapter(user, pending.Session.UserID, dbToCredentials(rows))

	cred, err := s.wa.ValidateLogin(adapter, pending.Session, parsed)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	return s.completeLogin(ctx, user, cred)
}

// finishDiscoverableLogin completes a usernameless assertion.
//
// The account is unknown when the ceremony starts, so the library resolves it
// through a DiscoverableUserHandler callback, invoked with the credential ID and
// the user handle the authenticator reported. Resolution happens *inside*
// ValidatePasskeyLogin, before the signature is checked, which is why the
// handler must not trust its inputs: it only ever uses them as lookup keys, and
// the returned user's stored credentials are what the signature is then verified
// against. A handle naming a non-existent or ineligible account therefore fails
// exactly like a bad signature.
func (s *Service) finishDiscoverableLogin(
	ctx context.Context,
	pending PendingChallenge,
	parsed *protocol.ParsedCredentialAssertionData,
) (uuid.UUID, error) {
	var (
		resolved db.User
		// internalErr carries an infrastructure failure back out of the
		// callback. The library wraps whatever the handler returns in its own
		// lookup error, which would otherwise flatten a database outage into an
		// indistinguishable "verification failed" — a 401 where the caller
		// deserves a 500, and a silent way to lose an outage among ordinary
		// failed logins.
		internalErr error
	)

	handler := func(_, userHandle []byte) (gowebauthn.User, error) {
		user, err := s.resolveDiscoverableUser(ctx, userHandle)
		if err != nil {
			if !isDomainError(err) {
				internalErr = err
			}
			return nil, err
		}

		rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, user.ID)
		if err != nil {
			internalErr = fmt.Errorf("webauthn: list credentials: %w", err)
			return nil, internalErr
		}
		if len(rows) == 0 {
			return nil, ErrNoCredentials
		}

		resolved = user
		// The handle from the account row is authoritative; the library
		// compares it against the one the authenticator sent.
		return newUserAdapter(user, user.WebauthnUserHandle, dbToCredentials(rows)), nil
	}

	_, cred, err := s.wa.ValidatePasskeyLogin(handler, pending.Session, parsed)
	if err != nil {
		// An infrastructure fault must not be reported as a failed assertion.
		if internalErr != nil {
			return uuid.Nil, internalErr
		}
		return uuid.Nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}

	// Unreachable when err is nil, but asserted rather than assumed: the rest of
	// this function dereferences the resolved account.
	if resolved.ID == uuid.Nil {
		return uuid.Nil, ErrVerification
	}
	return s.completeLogin(ctx, resolved, cred)
}

// resolveDiscoverableUser maps the user handle an authenticator reported back to
// an account.
//
// The handle is only a *lookup key* here, never evidence of anything: whether
// the caller actually holds the corresponding private key is settled by the
// signature check the library performs immediately afterwards, against the
// credentials of whichever account this returns. A handle naming no account is
// therefore an ordinary authentication failure.
//
// The library rejects an assertion with a blank handle before this is reached
// (the spec requires a discoverable credential to return one), so there is no
// handle-less case to serve.
func (s *Service) resolveDiscoverableUser(ctx context.Context, userHandle []byte) (db.User, error) {
	user, err := s.users.GetUserByWebauthnUserHandle(ctx, userHandle)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, fmt.Errorf("webauthn: resolve discoverable user: %w", err)
	}

	// Checked here as well as in BeginLogin because the discoverable flow never
	// names an account up front: this is the first and only opportunity to
	// refuse a suspended or pending-deletion account.
	if !isLoginEligible(user.Status) {
		return db.User{}, ErrAccountNotActive
	}
	return user, nil
}

// completeLogin applies the checks shared by every login variant once the
// assertion has verified: clone detection, then the durable counter update.
func (s *Service) completeLogin(
	ctx context.Context,
	user db.User,
	cred *gowebauthn.Credential,
) (uuid.UUID, error) {
	// The library reports a non-increasing counter as a warning flag on the
	// credential rather than an error, so it must be inspected explicitly.
	if cred.Authenticator.CloneWarning {
		return uuid.Nil, ErrCredentialCloned
	}
	// Re-checked after verification: the named flow validated status at Begin,
	// but the account may have been suspended while the ceremony was in flight.
	if !isLoginEligible(user.Status) {
		return uuid.Nil, ErrAccountNotActive
	}

	if err := s.commitSignCount(ctx, cred); err != nil {
		return uuid.Nil, err
	}
	return user.ID, nil
}

// commitSignCount re-reads the credential with SELECT ... FOR UPDATE and
// persists the counter observed in the assertion. The re-read is what makes the
// check-then-write safe: the counter validated inside the library used the row
// as it looked when the ceremony's credential list was loaded, so a concurrent
// assertion could have advanced it since. Comparing against the locked row
// closes that window (and serialises competing assertions for the same
// credential once the store is a transaction-scoped *db.Queries).
func (s *Service) commitSignCount(ctx context.Context, cred *gowebauthn.Credential) error {
	return s.runInTx(ctx, func(_ UserStore, creds CredentialStore) error {
		row, err := creds.GetWebauthnCredentialForUpdate(ctx, cred.ID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// Deleted between the ceremony starting and completing.
				return ErrVerification
			}
			return fmt.Errorf("webauthn: lock credential: %w", err)
		}

		stored := signCountToUint32(row.SignCount)
		observed := cred.Authenticator.SignCount
		// Authenticators that do not implement a counter always report zero; that
		// is the one case where a non-increasing value is legitimate.
		if observed <= stored && (observed != 0 || stored != 0) {
			return ErrCredentialCloned
		}

		affected, err := creds.UpdateWebauthnSignCount(ctx, db.UpdateWebauthnSignCountParams{
			ID:        cred.ID,
			SignCount: int64(observed),
		})
		if err != nil {
			return fmt.Errorf("webauthn: update sign count: %w", err)
		}
		if affected == 0 {
			return ErrVerification
		}
		return nil
	})
}

// runInTx executes fn inside a database transaction if a Transacter is
// configured, or directly against s.users and s.creds otherwise.
func (s *Service) runInTx(ctx context.Context, fn func(users UserStore, creds CredentialStore) error) error {
	if s.tx == nil {
		return fn(s.users, s.creds)
	}

	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("webauthn: begin tx: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	txQueries := db.New(tx)
	if err := fn(txQueries, txQueries); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("webauthn: commit tx: %w", err)
	}
	committed = true
	return nil
}

// ListCredentials returns the credentials registered for an account, ordered by
// the underlying query, for the self-service key listing endpoint.
func (s *Service) ListCredentials(ctx context.Context, userID uuid.UUID) ([]db.WebauthnCredential, error) {
	rows, err := s.creds.ListWebauthnCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	return rows, nil
}
