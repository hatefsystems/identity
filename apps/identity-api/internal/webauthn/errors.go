package webauthn

import "errors"

// Package-level sentinel errors. Following the convention established by the
// session package, each carries a "webauthn: " prefix so a wrapped error is
// self-describing in logs, and handlers translate them into the appropriate
// HTTP status without leaking which specific check failed to an attacker (the
// login handler in particular collapses all of these into a single opaque
// 401 to neutralise account harvesting — docs/api-design.md §1.3).
var (
	// ErrUserNotFound indicates the target account does not exist (or is
	// soft-deleted). For the user-named login ceremony this is deliberately
	// indistinguishable to the caller from "user has no credentials".
	ErrUserNotFound = errors.New("webauthn: user not found")

	// ErrNoCredentials indicates the user has no registered WebAuthn
	// credentials, so an assertion ceremony cannot be started for them.
	ErrNoCredentials = errors.New("webauthn: user has no registered credentials")

	// ErrChallengeNotFound indicates the challenge echoed back in the
	// authenticator response is unknown, already consumed (challenges are
	// one-time), or was issued for a different user.
	ErrChallengeNotFound = errors.New("webauthn: challenge not found or already used")

	// ErrChallengeExpired indicates the challenge existed but its server-side
	// TTL had elapsed before the ceremony was completed.
	ErrChallengeExpired = errors.New("webauthn: challenge expired")

	// ErrInvalidResponse indicates the authenticator response body was missing
	// or could not be parsed into a WebAuthn credential response.
	ErrInvalidResponse = errors.New("webauthn: malformed authenticator response")

	// ErrVerification indicates the ceremony's cryptographic verification
	// failed: a bad origin, RP ID mismatch, invalid signature, failed
	// attestation, or a credential not owned by the user.
	ErrVerification = errors.New("webauthn: verification failed")

	// ErrCredentialCloned indicates the authenticator's signature counter did
	// not strictly increase, signalling a possible cloned authenticator
	// (docs/architecture.md "Signature Counter Auditing").
	ErrCredentialCloned = errors.New("webauthn: cloned authenticator detected")

	// ErrMockChallenge indicates the completed ceremony was started against a
	// mock challenge issued for an identity that cannot log in (unknown email,
	// or an account with no usable passkey). It is returned only from the
	// verify step, and only because the caller cannot possibly produce a valid
	// signature for a credential that does not exist; the handler maps it to
	// the same opaque 401 as every other login failure so the mock remains
	// indistinguishable from a real ceremony (docs/api-design.md §1.3).
	ErrMockChallenge = errors.New("webauthn: mock challenge cannot be completed")

	// ErrChallengeFlowMismatch indicates a challenge issued for one ceremony
	// was replayed into another — e.g. a registration challenge submitted to
	// the login verifier. The clientDataJSON ceremony type would also catch
	// this inside the library, but failing early keeps each flow's verifier
	// operating only on challenges it actually issued.
	ErrChallengeFlowMismatch = errors.New("webauthn: challenge belongs to a different ceremony")

	// ErrAccountNotActive indicates the assertion was cryptographically valid
	// but the account is suspended, awaiting verification, or queued for
	// deletion, so no session may be issued for it.
	ErrAccountNotActive = errors.New("webauthn: account is not active")
)

// isDomainError reports whether err is one of this package's sentinels, i.e. an
// expected authentication outcome rather than an infrastructure fault.
//
// It exists for the discoverable-login callback: the library wraps whatever the
// handler returns inside its own lookup error, so by the time the error comes
// back out it can no longer be told apart from a failed signature. Classifying
// it on the way in preserves the distinction that decides between an opaque 401
// and a 500 — without which a database outage would be silently reported to
// every user as "invalid credentials".
func isDomainError(err error) bool {
	switch {
	case errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrNoCredentials),
		errors.Is(err, ErrAccountNotActive),
		errors.Is(err, ErrVerification):
		return true
	default:
		return false
	}
}
