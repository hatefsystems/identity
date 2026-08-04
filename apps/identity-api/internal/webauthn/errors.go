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
)
