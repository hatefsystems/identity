package privacy

import "errors"

var (
	// ErrInvalidToken is the single failure surfaced for every reclaim problem:
	// an unknown token, an expired one, a consumed one, a wrong factor, a missing
	// account, or an account that holds no verifiable factor at all.
	//
	// Collapsing them is load-bearing. The reclaim endpoints are anonymous, so any
	// distinction between "no such request" and "wrong code" would confirm that a
	// given token — and therefore a given deletion — exists, and any distinction
	// around factor availability would disclose the account's factor inventory to
	// an unauthenticated caller.
	ErrInvalidToken = errors.New("privacy: invalid or expired reclaim token")

	// ErrRateLimited indicates a rate-limit window (per-account or per-subnet) is
	// saturated, so the request was rejected without touching the database.
	ErrRateLimited = errors.New("privacy: rate limit exceeded")

	// ErrUserNotFound indicates the account behind an authenticated deletion
	// request no longer exists — the session outlived its subject.
	ErrUserNotFound = errors.New("privacy: user not found")

	// ErrUnsupportedFactor indicates the caller named a reclaim factor this
	// service cannot verify (no such method, or its verifier is not configured).
	// It never reaches an anonymous caller as a distinct response; the handler
	// renders it as ErrInvalidToken.
	ErrUnsupportedFactor = errors.New("privacy: unsupported reclaim factor")
)
