package webauthn

import (
	"context"
	"math"

	"github.com/google/uuid"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// UserStore is the subset of the generated db.Queries the WebAuthn service needs
// to resolve accounts and persist the anonymised user handle. Depending on an
// interface (rather than *db.Queries directly) keeps the service unit-testable
// with a fake and documents exactly which queries the flows touch. *db.Queries
// satisfies it.
type UserStore interface {
	// GetUserByEmail resolves an active (non-deleted) account by email; it
	// returns pgx.ErrNoRows when there is no match.
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	// GetUserByID resolves an active account by its UUID primary key.
	GetUserByID(ctx context.Context, id uuid.UUID) (db.User, error)
	// GetUserByIDForAdmin resolves an account *including* soft-deleted ones. It is
	// used only by the reclaim ceremony (Task 5.1), which by definition operates
	// on a pending_deletion account that every other lookup here filters out.
	GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error)
	// GetUserByIDForUpdate is the common account mutex for cross-factor
	// security mutations. It must be acquired before credential-row locks.
	GetUserByIDForUpdate(ctx context.Context, id uuid.UUID) (db.User, error)
	// GetUserByWebauthnUserHandle resolves an active account from the
	// anonymised user handle an authenticator returns in a discoverable
	// (usernameless) assertion. This is the User-Handle-first lookup path the
	// passkey flow depends on, and the reason the handle is persisted per user
	// rather than per credential.
	GetUserByWebauthnUserHandle(ctx context.Context, webauthnUserHandle []byte) (db.User, error)
	// SetWebauthnUserHandle persists the CSPRNG user handle on first passkey

	// registration; it only writes when the column is currently NULL and
	// reports the number of rows affected.
	SetWebauthnUserHandle(ctx context.Context, arg db.SetWebauthnUserHandleParams) (int64, error)
}

// CredentialStore is the subset of the generated db.Queries covering WebAuthn
// credential persistence and the race-free signature-counter update. *db.Queries
// satisfies it.
type CredentialStore interface {
	// CreateWebauthnCredential inserts a freshly registered credential.
	CreateWebauthnCredential(ctx context.Context, arg db.CreateWebauthnCredentialParams) (db.WebauthnCredential, error)
	// ListWebauthnCredentialsByUser returns every credential owned by a user,
	// used to build the allowCredentials list for a user-named login ceremony.
	ListWebauthnCredentialsByUser(ctx context.Context, userID uuid.UUID) ([]db.WebauthnCredential, error)
	// GetWebauthnCredentialForUpdate row-locks a credential (SELECT ... FOR

	// UPDATE) so the sign-count check-then-write during login is atomic across
	// concurrent assertions.
	GetWebauthnCredentialForUpdate(ctx context.Context, id []byte) (db.WebauthnCredential, error)
	// UpdateWebauthnSignCount persists the new counter and stamps last_used_at.
	UpdateWebauthnSignCount(ctx context.Context, arg db.UpdateWebauthnSignCountParams) (int64, error)
	// LockWebauthnCredentialsByUser row-locks every credential a user owns
	// (SELECT id ... FOR UPDATE) so the "don't remove the last authentication
	// factor" guard on deletion cannot be raced by two concurrent deletions.
	LockWebauthnCredentialsByUser(ctx context.Context, userID uuid.UUID) ([][]byte, error)
	// DeleteWebauthnCredential removes a credential, scoped to its owner so one
	// user can never delete another's authenticator. It reports rows affected.
	DeleteWebauthnCredential(ctx context.Context, arg db.DeleteWebauthnCredentialParams) (int64, error)
}

// signCountToUint32 clamps the DB's int64 sign_count into the uint32 domain the
// WebAuthn library (and the spec's 32-bit counter) uses. Stored values are
// always written from a uint32, so clamping is purely defensive against a
// corrupted or out-of-range row.
func signCountToUint32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// aaguidToBytes returns the 16-byte representation of a stored AAGUID for the
// library's Authenticator.AAGUID field.
func aaguidToBytes(id uuid.UUID) []byte {
	b := id
	return b[:]
}

// aaguidFromBytes converts an authenticator-reported AAGUID (raw bytes) into the
// uuid.UUID stored in the DB. A missing or malformed AAGUID maps to uuid.Nil,
// matching the library's own "no AAGUID" handling.
func aaguidFromBytes(b []byte) uuid.UUID {
	if len(b) == 0 {
		return uuid.Nil
	}
	id, err := uuid.FromBytes(b)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// dbToCredential maps a persisted row into the library's Credential shape. Only
// the fields consulted during an assertion ceremony are reconstructed: the
// credential ID and COSE public key (for signature verification), the stored
// sign count and AAGUID, and the flags (the login validator reads
// BackupEligible to detect a flag flip). The raw attestation blob is not stored,
// so Attestation is left zero — it is not read by ValidateLogin.
func dbToCredential(row db.WebauthnCredential) gowebauthn.Credential {
	return gowebauthn.Credential{
		ID:        row.ID,
		PublicKey: row.PublicKey,
		Flags: gowebauthn.CredentialFlags{
			UserPresent:    row.UserPresent,
			UserVerified:   row.UserVerified,
			BackupEligible: row.BackupEligible,
			BackupState:    row.BackupState,
		},
		Authenticator: gowebauthn.Authenticator{
			AAGUID:    aaguidToBytes(row.Aaguid),
			SignCount: signCountToUint32(row.SignCount),
		},
	}
}

// dbToCredentials maps a slice of persisted rows into library Credentials.
func dbToCredentials(rows []db.WebauthnCredential) []gowebauthn.Credential {
	out := make([]gowebauthn.Credential, len(rows))
	for i, row := range rows {
		out[i] = dbToCredential(row)
	}
	return out
}

// credentialToCreateParams maps a freshly verified library Credential into the
// insert parameters for a new row, binding it to the owning user.
func credentialToCreateParams(userID uuid.UUID, cred *gowebauthn.Credential) db.CreateWebauthnCredentialParams {
	return db.CreateWebauthnCredentialParams{
		ID:              cred.ID,
		UserID:          userID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		SignCount:       int64(cred.Authenticator.SignCount),
		UserPresent:     cred.Flags.UserPresent,
		UserVerified:    cred.Flags.UserVerified,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		Aaguid:          aaguidFromBytes(cred.Authenticator.AAGUID),
	}
}
