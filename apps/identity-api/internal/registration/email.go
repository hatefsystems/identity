package registration

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

// MessageSender is the bounded TLS/SMTPUTF8 transport, not a delivery receipt.
type MessageSender interface {
	Send(context.Context, string, []byte) error
}

// EmailConfig binds signup mail to its system sender and public portal origin.
type EmailConfig struct{ From, PublicOrigin string }

// Email sends signup ownership proofs through the configured transport.
type Email struct {
	config EmailConfig
	sender MessageSender
}

// NewEmail validates the system sender and public origin without sending mail.
func NewEmail(cfg EmailConfig, sender MessageSender) (*Email, error) {
	u, err := url.Parse(cfg.PublicOrigin)
	if nilDependency(sender) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(cfg.PublicOrigin, "#") || !emailaddress.ValidMailbox(cfg.From) || len(cfg.From) > 254 {
		return nil, ErrInvalid
	}
	for _, c := range cfg.From {
		if c < 33 || c > 126 {
			return nil, ErrInvalid
		}
	}
	return &Email{config: cfg, sender: sender}, nil
}

// SendProof is invoked only after the token hash's SQL transaction commits. The
// independent raw token exists only in this message and the caller's stack.
func (e *Email) SendProof(ctx context.Context, attempt Attempt, token []byte) error {
	hash, err := HashCapability(token)
	if e == nil || err != nil || attempt.Record.State != "pending" || attempt.Details.Purpose != Purpose || attempt.Details.JKT != attempt.Record.Jkt || !ValidJKT(attempt.Record.Jkt) || subtle.ConstantTimeCompare(hash, attempt.Record.EmailTokenHash) != 1 || !emailaddress.ValidCanonicalMailbox(attempt.Details.Email) || attempt.Record.ID == uuid.Nil || attempt.Details.AttemptID != attempt.Record.ID || !attempt.Record.EmailTokenExpiresAt.Valid {
		return ErrInvalid
	}
	link := e.config.PublicOrigin + "/register/verify-email#attempt_id=" + attempt.Record.ID.String() + "&token=" + base64.RawURLEncoding.EncodeToString(token)
	message := []byte(fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\nSubject: Verify your email for account registration\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nConfirm your email in the browser where you started registration:\r\n%s\r\n\r\nThis link expires at %s. It does not sign you in. If you did not start registration, ignore this message.\r\n", e.config.From, attempt.Details.Email, link, attempt.Record.EmailTokenExpiresAt.Time.UTC().Format(time.RFC3339)))
	defer clear(message)
	ctx, cancel := context.WithDeadline(ctx, attempt.Record.EmailTokenExpiresAt.Time)
	defer cancel()
	if e.sender.Send(ctx, attempt.Details.Email, message) != nil {
		return ErrSendFailed
	}
	return nil
}
