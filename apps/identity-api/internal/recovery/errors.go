package recovery

import "errors"

var (
	// ErrUserNotFound indicates the target account does not exist or is
	// soft-deleted.
	ErrUserNotFound = errors.New("recovery: user not found")

	// ErrInvalidCode indicates the submitted recovery code does not match any
	// unused code belonging to the account. It is deliberately the single
	// failure mode surfaced for a bad code: nothing distinguishes a malformed
	// code, an already-consumed code, or a code belonging to another account.
	ErrInvalidCode = errors.New("recovery: invalid recovery code")

	// ErrAccountNotActive indicates the account exists but its status forbids
	// authentication: 'suspended' accounts are barred by moderation,
	// 'pending_verification' has not proven ownership of its email, and
	// 'pending_deletion' is inside the 30-day grace window, where reclamation is
	// a separate deliberate flow rather than an ordinary login
	// (docs/architecture.md, "Grace Period & Soft Deletes").
	//
	// Recovery codes are an authentication path, so they follow the WebAuthn
	// precedent (webauthn.ErrAccountNotActive, internal/webauthn/service.go
	// isLoginEligible): sessions are validated without re-reading account
	// status, so this is the only point at which a user who was suspended after
	// their session was issued can be refused. The handler renders it as the
	// same opaque 401 as ErrUserNotFound, since "this account is suspended" is
	// itself an existence oracle.
	ErrAccountNotActive = errors.New("recovery: account is not active")

	// ErrRateLimited indicates a rate-limit window (per-account or per-subnet)
	// is saturated, so the request was rejected without touching the database.
	ErrRateLimited = errors.New("recovery: rate limit exceeded")
)
