package smsotp

import (
	"context"
	"log/slog"
)

// Sender delivers a rendered SMS message to a phone number via an upstream SMS
// gateway. It is the seam that isolates the OTP workflow from any specific
// provider: production wires a real HTTP gateway client, while development and
// tests use LogSender / an in-memory fake. Implementations must not log the
// message body (it contains the plaintext OTP).
type Sender interface {
	// Send delivers message to the E.164 phone number. It returns an error
	// (which the service maps to ErrSendFailed) when the gateway rejects or
	// fails to accept the message.
	Send(ctx context.Context, phone, message string) error
}

// LogSender is a development Sender that records only that a code was "sent"
// (never the code itself or the full message body) via the structured logger.
// It lets the phone-verification flow run end-to-end locally without a real SMS
// gateway or the associated toll costs. It must never be used in production.
type LogSender struct {
	logger *slog.Logger
}

// NewLogSender constructs a LogSender. A nil logger falls back to slog.Default.
func NewLogSender(logger *slog.Logger) *LogSender {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogSender{logger: logger}
}

// Send implements Sender by logging a redacted delivery notice. The phone number
// is logged at its length only, and the message body (which carries the OTP) is
// never logged, so development logs cannot leak a live code.
func (s *LogSender) Send(_ context.Context, phone, _ string) error {
	s.logger.Info("smsotp: development SMS sender invoked (message body redacted)",
		slog.Int("phone_len", len(phone)),
	)
	return nil
}
