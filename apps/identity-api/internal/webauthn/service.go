package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"

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
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin registration: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		UserRef: user.ID,
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

// BeginLogin starts a user-named assertion ceremony and returns the
// PublicKeyCredentialRequestOptions for navigator.credentials.get().
//
// The allowCredentials list is built from the account's registered credentials,
// which is why an account without a handle or without credentials cannot start
// the ceremony. Discoverable (usernameless) login, and the mock-challenge
// response that hides whether an email exists at all, are handled separately in
// Task 4.3; callers of this method must therefore collapse ErrUserNotFound and
// ErrNoCredentials into one indistinguishable outcome.
func (s *Service) BeginLogin(ctx context.Context, email string) (*protocol.CredentialAssertion, error) {
	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("webauthn: load user: %w", err)
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
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin login: %w", err)
	}

	if err := s.challenges.Save(session.Challenge, PendingChallenge{
		Session: *session,
		UserRef: user.ID,
		Expires: s.now().Add(s.challengeTTL),
	}); err != nil {
		return nil, fmt.Errorf("webauthn: save challenge: %w", err)
	}

	return assertion, nil
}

// FinishLogin verifies an assertion response and returns the authenticated
// account's UUID, which the caller uses to issue a session.
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
	// The library reports a non-increasing counter as a warning flag on the
	// credential rather than an error, so it must be inspected explicitly.
	if cred.Authenticator.CloneWarning {
		return uuid.Nil, ErrCredentialCloned
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
	return s.runInTx(ctx, func(users UserStore, creds CredentialStore) error {
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
