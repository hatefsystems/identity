package webauthn

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// Mock challenge generation for the user-named login fallback (Task 4.3).
//
// When a user-named login names an identity that cannot complete an assertion —
// the email is unregistered, the account never enrolled a passkey, or it is not
// active — returning an error would tell the caller that account does not exist.
// Instead the endpoint answers with a fully formed but uncompletable ceremony
// (docs/api-design.md §1.3, docs/frontend-pages.md §5.4).
//
// Two properties make the decoy hold up:
//
//   - Structural identity. The mock options are produced by the same
//     s.wa.BeginLogin call as a real ceremony, just fed a synthetic user. The
//     response therefore agrees with a genuine one on every field the library
//     controls (rpId, timeout, userVerification, challenge length, extensions)
//     by construction, rather than by a hand-written copy that would drift the
//     first time the library changes a default.
//
//   - Stability. A real account returns the same credential IDs on every call,
//     so a mock that re-randomised per request would be trivially separable by
//     asking twice. The decoy descriptors are therefore derived deterministically
//     from the email under a server-held key: identical across requests,
//     different per email, and unguessable without the key.
//
// The honest limitation, recorded in docs/frontend-pages.md §5.4: this closes
// the *server-side* signal only. Browsers reject an allowCredentials list whose
// entries all name unknown credentials faster than they prompt for a real one,
// so a client-side timing side-channel survives on the user-named path no matter
// what the server does. That is precisely why discoverable credentials — where
// allowCredentials is empty and no identity is ever named — are the primary
// login path, and this fallback exists only for legacy user-named flows.

// mockCredentialCount is how many decoy descriptors a mock ceremony advertises.
// Most accounts enrol a single passkey, so one descriptor is the least
// conspicuous choice.
const mockCredentialCount = 1

// mockCredentialIDLen is the byte length of a derived decoy credential ID. It
// matches the 32-byte IDs produced by common platform and roaming
// authenticators, so a decoy is indistinguishable by size.
const mockCredentialIDLen = 32

// domain-separation labels, so the handle and credential-ID derivations can
// never collide even though both are HMACs of the same email under the same key.
const (
	mockHandleLabel = "hatef.identity.webauthn.mock.handle.v1"
	mockCredLabel   = "hatef.identity.webauthn.mock.credential.v1"
)

// normalizeLoginIdentifier canonicalises a user-supplied email for mock
// derivation, so "User@Example.com " and "user@example.com" yield the same decoy
// rather than two different ones for what is the same account.
//
// It deliberately only trims and lowercases: this value is used exclusively to
// derive decoy bytes and never to look an account up, so it cannot widen or
// narrow any real lookup.
func normalizeLoginIdentifier(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// deriveMockBytes returns HMAC-SHA256(key, label || identifier), the primitive
// behind every derived decoy value. Using a keyed MAC (rather than a bare hash)
// means an attacker who can observe mock responses still cannot compute what the
// decoy for some *other* email would be, and so cannot confirm a guess by
// comparing a response against a locally computed value.
func deriveMockBytes(key []byte, label, identifier string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	mac.Write([]byte{0x00})
	mac.Write([]byte(identifier))
	return mac.Sum(nil)
}

// mockUserHandle derives the stable 64-bit user handle a mock ceremony reports.
// It is the same width as a real handle (newUserHandle) so SessionData.UserID is
// the same size on both paths.
func mockUserHandle(key []byte, identifier string) []byte {
	return deriveMockBytes(key, mockHandleLabel, identifier)[:userHandleByteLen]
}

// mockCredentials derives the decoy credentials whose IDs populate the mock
// ceremony's allowCredentials list.
//
// Only the ID is meaningful: the library reads nothing else when building the
// descriptor list, and no assertion against these credentials can ever be
// verified because no private key exists for them. The flags are left at their
// zero values, matching how a real credential registered by an authenticator
// without backup eligibility is stored.
func mockCredentials(key []byte, identifier string) []gowebauthn.Credential {
	out := make([]gowebauthn.Credential, 0, mockCredentialCount)
	for i := range mockCredentialCount {
		// The index is folded into the identifier so multiple descriptors would
		// derive to distinct IDs rather than repeating one value.
		seed := deriveMockBytes(key, mockCredLabel, identifier+string(rune('0'+i)))
		out = append(out, gowebauthn.Credential{ID: seed[:mockCredentialIDLen]})
	}
	return out
}

// newMockUserAdapter builds the synthetic gowebauthn.User handed to BeginLogin
// for an identity that cannot log in. Feeding a fake user through the real
// ceremony builder is what makes the mock structurally identical to a genuine
// response.
//
// The email is echoed as the WebAuthn name purely because the library requires a
// non-empty one; that field is never transmitted in an assertion ceremony's
// options (it appears only in *registration* options), so this leaks nothing.
func newMockUserAdapter(key []byte, email string) *userAdapter {
	identifier := normalizeLoginIdentifier(email)
	return &userAdapter{
		handle:      mockUserHandle(key, identifier),
		name:        email,
		credentials: mockCredentials(key, identifier),
	}
}
