package contactcode

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// MessageSender is the existing registration SMTP transport contract. Keeping
// the seam structural avoids coupling login proofs to signup's service graph.
type MessageSender interface {
	Send(context.Context, string, []byte) error
}

// Email reuses the registration SMTP transport seam, without reusing signup
// tokens, links or purpose. Transport failures may include lost DATA ACKs.
type Email struct {
	from      string
	transport MessageSender
}

// NewEmail validates the system sender and reuses the existing SMTP transport.
func NewEmail(from string, transport MessageSender) (*Email, error) {
	if missing(transport) || !emailaddress.ValidMailbox(from) || len(from) > 254 || strings.IndexFunc(from, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, ErrInvalid
	}
	return &Email{from, transport}, nil
}

// SendCode submits one sign-in message with its exact code, recipient and deadline.
// Ambiguous SMTP acceptance is returned as ErrOutcomeUnknown without retry.
func (e *Email) SendCode(ctx context.Context, destination, code string, expiresAt time.Time) error {
	if e == nil || !validDestination(ChannelEmail, destination) || !validCode(code) || !expiresAt.After(time.Now()) {
		return ErrInvalid
	}
	message := []byte(fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\nSubject: Your account sign-in code\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nEnter this code only in the browser where you started signing in:\r\n%s\r\n\r\nThis sign-in code expires at %s. It cannot verify a signup or change your contacts. If you did not request it, ignore this message.\r\n", e.from, destination, code, expiresAt.UTC().Format(time.RFC3339Nano)))
	defer clear(message)
	ctx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	if e.transport.Send(ctx, destination, message) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}
