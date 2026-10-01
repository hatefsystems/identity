package legalhold

import "errors"

// Deliberately static: neither database errors nor input values may escape into
// HTTP errors, operational logs, or the long-lived audit payload.
var (
	ErrInvalidRequest            = errors.New("legalhold: invalid request")
	ErrUnsupportedIdentifierType = errors.New("legalhold: unsupported identifier type")
	ErrHoldNotFound              = errors.New("legalhold: hold not found")
	ErrIdempotencyConflict       = errors.New("legalhold: idempotency conflict")
	ErrUnavailable               = errors.New("legalhold: unavailable")
	ErrTransactionRequired       = errors.New("legalhold: request transaction required")
	ErrBackfillRequired          = errors.New("legalhold: encrypted backfill required")
)
