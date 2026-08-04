package webauthn

import (
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// userAdapter bridges a persisted db.User and its credentials to the
// gowebauthn.User interface the library's Begin/Validate methods consume. It is
// constructed per-ceremony and never stored, so it always reflects the current
// database state.
//
// Crucially, WebAuthnID returns the account's anonymised 64-bit handle
// (users.webauthn_user_handle), NOT the UUID primary key: the handle is the
// value the authenticator signs over and returns as userHandle, and keeping the
// real UUID out of the authenticator prevents cross-Relying-Party identity
// correlation (docs/architecture.md "Anonymized user.id Mapping").
type userAdapter struct {
	// handle is the CSPRNG 64-bit WebAuthn user handle.
	handle []byte
	// name is the human-palatable account name (the email).
	name string
	// credentials are the user's registered credentials in library form; empty
	// during the first registration ceremony.
	credentials []gowebauthn.Credential
}

// newUserAdapter builds an adapter from a persisted user, its resolved handle,
// and its existing credentials. The handle is passed explicitly because during
// the first registration ceremony it is freshly generated and not yet persisted
// on the user row.
func newUserAdapter(user db.User, handle []byte, creds []gowebauthn.Credential) *userAdapter {
	return &userAdapter{
		handle:      handle,
		name:        user.Email,
		credentials: creds,
	}
}

// WebAuthnID implements gowebauthn.User, returning the anonymised 64-bit handle.
func (u *userAdapter) WebAuthnID() []byte { return u.handle }

// WebAuthnName implements gowebauthn.User. The account email is used as the
// human-palatable name shown by authenticators and platform UIs.
func (u *userAdapter) WebAuthnName() string { return u.name }

// WebAuthnDisplayName implements gowebauthn.User. The MVP has no separate
// display name, so the email doubles as the display name.
func (u *userAdapter) WebAuthnDisplayName() string { return u.name }

// WebAuthnCredentials implements gowebauthn.User.
func (u *userAdapter) WebAuthnCredentials() []gowebauthn.Credential { return u.credentials }
