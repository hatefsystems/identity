package stepup

import "errors"

// Package-level sentinel errors. Following the convention of the session,
// webauthn, and recovery packages, each carries a "stepup: " prefix so a wrapped
// error is self-describing in logs while handlers translate them into responses
// that reveal only what the caller is entitled to know.
//
// The grant-validation errors are all rendered identically by the middleware (a
// 403 insufficient_user_authentication challenge); they are kept distinct so
// logs and tests can tell a missing header from a replayed grant.
var (
	// ErrNoGrant indicates the request carried no X-Step-Up-Auth header.
	ErrNoGrant = errors.New("stepup: no step-up grant presented")

	// ErrInvalidGrant indicates the grant was malformed, signed by an unknown
	// key, signed with an unsupported algorithm, carried the wrong typ or acr,
	// or failed signature or temporal validation.
	ErrInvalidGrant = errors.New("stepup: grant is invalid")

	// ErrGrantConsumed indicates the grant's jti has already been redeemed.
	// Grants are single-use, so this is either an honest double-submit or a
	// replay attempt.
	ErrGrantConsumed = errors.New("stepup: grant has already been used")

	// ErrGrantNotForSession indicates the grant is cryptographically valid but
	// was minted for a different subject or a different session, so pairing it
	// with the current session cookie is rejected.
	ErrGrantNotForSession = errors.New("stepup: grant was not issued for this session")

	// ErrUnsupportedMethod indicates the verify request named a step-up method
	// this service does not accept. Notably, recovery codes are not a step-up
	// factor by design.
	ErrUnsupportedMethod = errors.New("stepup: unsupported step-up method")

	// ErrMethodUnavailable indicates the named method is valid but not usable
	// for this account (no passkey enrolled, or TOTP not enabled).
	ErrMethodUnavailable = errors.New("stepup: step-up method is not available for this account")

	// ErrNoFactorAvailable indicates the account has neither a passkey nor an
	// enabled TOTP authenticator, so it cannot perform step-up at all and every
	// gated operation is out of reach until a factor is enrolled.
	ErrNoFactorAvailable = errors.New("stepup: account has no step-up factor enrolled")

	// ErrInvalidCredentials indicates the presented assertion or passcode did
	// not verify. Every distinct cause collapses into this one value so the
	// response cannot be used to probe which check failed.
	ErrInvalidCredentials = errors.New("stepup: invalid credentials")

	// ErrUserVerificationRequired indicates a WebAuthn assertion verified but
	// the authenticator did not perform user verification, so it proves
	// presence rather than the user's identity and cannot raise the
	// authentication context.
	ErrUserVerificationRequired = errors.New("stepup: user verification is required")

	// ErrCodeReplayed indicates the submitted TOTP passcode was already used to
	// mint a grant inside its acceptance window.
	ErrCodeReplayed = errors.New("stepup: passcode has already been used")

	// ErrUserNotFound indicates the account behind the session no longer
	// exists (deleted mid-session).
	ErrUserNotFound = errors.New("stepup: user not found")

	// ErrAccountNotActive indicates the account is suspended, awaiting
	// verification, or queued for deletion, so it may not raise its
	// authentication context.
	ErrAccountNotActive = errors.New("stepup: account is not active")

	// ErrRateLimited indicates a verification rate-limit window is saturated.
	ErrRateLimited = errors.New("stepup: rate limit exceeded")
)
