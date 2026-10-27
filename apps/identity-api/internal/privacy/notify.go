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
// Account authority. Deletion advances the durable auth_version; live validation
// rejects previously issued authority even if bounded Redis cleanup fails.
//
// Fail-closed notification. New requests atomically enqueue encrypted delivery
// intent. Disabling new requests does not disable recovery or worker delivery.
package privacy

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// DeletionNotice is the message content for a "your account is scheduled for
// deletion" notification. The token and address are decrypted only for delivery;
// neither they nor a transport error containing them may enter diagnostics.
type DeletionNotice struct {
	// DeliveryID is the stable per-recipient message identity, including retries.
	DeliveryID uuid.UUID
	// PrimaryEmail is the sole recipient of this worker delivery (primary or backup).
	PrimaryEmail string
	// BackupEmail is retained in the transport shape, but queue deliveries always
	// leave it nil. A configured backup has its own delivery ID and independent row.
	BackupEmail *string
	// ReclaimToken is the plaintext single-use token. Never persist it unencrypted
	// or log it. Worker calls always leave BackupEmail nil.
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
	// NotifyDeletionRequested returns nil only after positive relay acceptance,
	// not inbox delivery. An error with Permanent() bool may stop automatic retry;
	// other failures retry the same delivery while the request remains live.
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
