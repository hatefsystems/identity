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

	// ErrNoCodesRemaining indicates the account has no unused recovery codes
	// left, so no verification can succeed until a new batch is generated.
	ErrNoCodesRemaining = errors.New("recovery: no recovery codes remaining")

	// ErrRateLimited indicates a rate-limit window (per-account or per-subnet)
	// is saturated, so the request was rejected without touching the database.
	ErrRateLimited = errors.New("recovery: rate limit exceeded")
)
