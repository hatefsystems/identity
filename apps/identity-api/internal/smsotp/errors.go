package smsotp

import "errors"

var (
	// ErrUserNotFound indicates the target account does not exist or is
	// soft-deleted.
	ErrUserNotFound = errors.New("smsotp: user not found")
	// ErrAccountNotActive indicates a suspended or otherwise ineligible account.
	ErrAccountNotActive = errors.New("smsotp: account is not active")

	// ErrInvalidPhone indicates the submitted phone number is empty or not a
	// well-formed E.164 number.
	ErrInvalidPhone = errors.New("smsotp: invalid phone number")

	// ErrRateLimited indicates a send was refused because a per-phone or
	// per-subnet rate-limit window is saturated (threat-modeling D2).
	ErrRateLimited = errors.New("smsotp: rate limit exceeded")

	// ErrLockedOut indicates verification is temporarily blocked after too many
	// failed attempts (the 15-minute brute-force lockout).
	ErrLockedOut = errors.New("smsotp: too many failed attempts; temporarily locked out")

	// ErrNoActiveCode indicates there is no pending OTP challenge usable by the
	// caller (unknown, expired, consumed, malformed, or bound to another
	// account/session).
	ErrNoActiveCode = errors.New("smsotp: no active verification code")

	// ErrInvalidCode indicates the submitted OTP did not match the stored hash.
	ErrInvalidCode = errors.New("smsotp: invalid verification code")

	// ErrEncryptFailed indicates envelope encryption of the phone number failed.
	ErrEncryptFailed = errors.New("smsotp: failed to encrypt phone number")

	// ErrSendFailed indicates the SMS gateway rejected or failed to deliver the
	// message.
	ErrSendFailed = errors.New("smsotp: failed to send SMS")
)
