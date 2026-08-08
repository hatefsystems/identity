package mfa

import "errors"

var (
	// ErrUserNotFound indicates the target account does not exist or is soft-deleted.
	ErrUserNotFound = errors.New("mfa: user not found")

	// ErrMfaAlreadyEnabled indicates TOTP MFA is already enabled on the account.
	ErrMfaAlreadyEnabled = errors.New("mfa: TOTP MFA is already enabled")

	// ErrMfaNotSetup indicates no encrypted TOTP secret exists for the account.
	ErrMfaNotSetup = errors.New("mfa: TOTP MFA is not set up for this account")

	// ErrInvalidCode indicates the provided TOTP code is incorrect or expired.
	ErrInvalidCode = errors.New("mfa: invalid verification code")

	// ErrEncryptFailed indicates the secret envelope encryption failed.
	ErrEncryptFailed = errors.New("mfa: failed to encrypt MFA secret")

	// ErrDecryptFailed indicates the secret envelope decryption failed.
	ErrDecryptFailed = errors.New("mfa: failed to decrypt MFA secret")
)
