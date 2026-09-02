// Package privacy implements the GDPR "Right to be Forgotten" lifecycle for the
// identity-api service (Task 5.1):
//
//   - Soft deactivation (Service.RequestDeletion): revoke every stateful session
//     and refresh token, flip the account to pending_deletion, and email a
//     single-use reclaim token bounded by the grace window.
//   - The reclaim ceremony (Service.ReclaimOptions / Service.Reclaim): what makes
//     the 30-day window a genuine recovery mechanism rather than a delay. A
//     pending_deletion account cannot log in (webauthn.isLoginEligible), so
//     reclamation is a separate, deliberate flow: emailed token plus a
//     user-verified passkey assertion or a TOTP passcode.
//   - Physical erasure (Purger.RunOnce): the one-shot worker that hard-deletes
//     Class A data past the cutoff, fail-closed on Legal Hold, one ACID
//     transaction per subject, emitting identity.user.deleted through the
//     transactional outbox.
//
// Two properties are worth stating up front because they are easy to break:
//
// Residual access-token authority. Sessions and refresh tokens are revoked
// synchronously at soft-delete, but an already-issued access token stays valid
// until it expires — currently at most the 10-minute access-token TTL. There is no
// revocation epoch and no per-request status re-read; closing that window is a
// separate task (introspection or a per-user epoch). The bound is documented on
// the endpoint so clients do not assume instantaneous cutoff.
//
// Fail-closed notification. A deletion whose reclaim token cannot be delivered has
// no recovery window at all, so the deletion routes are only mounted when a real
// Notifier is configured. Outside development, an absent notifier leaves the routes
// unmounted (404) rather than accepting requests it cannot make recoverable.
package privacy

import (
	"context"
	"log/slog"
	"time"
)

// DeletionNotice is the message content for a "your account is scheduled for
// deletion" notification. It carries the plaintext reclaim token, which exists
// only in this value and the outbound message: the database holds only its
// SHA-256 hash.
type DeletionNotice struct {
	// PrimaryEmail is the account's primary address.
	PrimaryEmail string
	// BackupEmail is the verified backup address when one is set. Notifying both
	// is what protects a user whose primary mailbox was taken over as part of the
	// account takeover that triggered the deletion (docs/architecture.md
	// "Account Reclamation").
	BackupEmail *string
	// ReclaimToken is the plaintext single-use token the user presents to the
	// reclaim endpoints. Never persist or log it.
	ReclaimToken string
	// ExpiresAt is when the token stops working, which is exactly when the purge
	// worker becomes eligible to erase the account.
	ExpiresAt time.Time
}

// Notifier delivers a DeletionNotice. It is the seam that isolates the deletion
// flow from any specific email provider, mirroring smsotp.Sender.
//
// Implementations must not log the reclaim token or the recipient addresses.
type Notifier interface {
	// NotifyDeletionRequested delivers the notice. Returning an error does not
	// roll back the deletion — the account is already suspended from all
	// services, which is the fail-safe direction — but it does leave notified_at
	// unset so the next request inside the cooldown can retry the send.
	NotifyDeletionRequested(ctx context.Context, notice DeletionNotice) error

	// IsDevelopmentOnly reports whether this implementation is a stand-in that
	// cannot actually deliver anything. Wiring uses it to enforce the fail-closed
	// contract above: a development-only notifier must never mount the deletion
	// routes outside development, because the reclaim token would go nowhere.
	IsDevelopmentOnly() bool
}

// LogNotifier is a development Notifier that records only that a notice was
// "sent" — never the token, never the addresses — via the structured logger. It
// lets the deletion and reclaim flows run end-to-end locally without an email
// provider. It must never be used in production; see IsDevelopmentOnly.
type LogNotifier struct {
	logger *slog.Logger
}

// NewLogNotifier constructs a LogNotifier. A nil logger falls back to
// slog.Default.
func NewLogNotifier(logger *slog.Logger) *LogNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogNotifier{logger: logger}
}

// NotifyDeletionRequested implements Notifier by logging a fully redacted
// delivery notice. Only the token's expiry and whether a backup address exists are
// recorded: both are useful for local debugging and neither is a secret or a PII
// value. In particular the token is never logged, so a development log cannot be
// used to reclaim an account.
func (n *LogNotifier) NotifyDeletionRequested(_ context.Context, notice DeletionNotice) error {
	n.logger.Info("privacy: development deletion notifier invoked (token and addresses redacted)",
		slog.Bool("has_backup_email", notice.BackupEmail != nil),
		slog.Time("expires_at", notice.ExpiresAt),
	)
	return nil
}

// IsDevelopmentOnly implements Notifier. It always reports true: this notifier
// delivers nothing, so any deployment that would rely on it for a real user's
// recovery window must leave the deletion routes unmounted instead.
func (n *LogNotifier) IsDevelopmentOnly() bool { return true }
