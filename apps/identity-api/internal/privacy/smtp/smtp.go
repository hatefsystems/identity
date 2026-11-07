// Package smtp delivers one deletion notice through an authenticated, verified
// TLS relay. Delivery bookkeeping and retry decisions belong to the parent
// privacy package, which must not import this transport.
package smtp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

const (
	maxMessageBytes = smtptransport.MaxMessageBytes
)

// Notifier is safe for concurrent calls. Each call owns its connection and sends
// exactly one recipient. No message contents or raw relay errors are logged.
type Notifier struct {
	cfg       config.DeletionSMTPConfig
	transport *smtptransport.Transport
}

var _ privacy.Notifier = (*Notifier)(nil)

// deliveryError retains only a fixed stage, never a wrapped transport error.
// Permanent is the optional classification consumed by the outbox worker.
type deliveryError struct {
	stage     string
	permanent bool
}

func (e *deliveryError) Error() string   { return "deletion smtp: " + e.stage + " failed" }
func (e *deliveryError) Permanent() bool { return e.permanent }

// New validates configuration and loads an optional, bounded PEM CA bundle.
// Authentication always uses SASL PLAIN inside verified TLS 1.2 or newer.
func New(cfg config.DeletionSMTPConfig) (*Notifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	transport, err := smtptransport.New(smtptransport.Config{
		Host: cfg.Host, Port: cfg.Port, TLSMode: cfg.TLSMode,
		Username: cfg.Username, Password: cfg.Password, From: cfg.From,
		Timeout: cfg.Timeout, CABundlePath: cfg.CABundlePath,
	})
	if err != nil {
		return nil, err
	}
	return &Notifier{cfg: cfg, transport: transport}, nil
}

// IsDevelopmentOnly is false: success denotes the relay's positive DATA ACK,
// not inbox delivery. A lost acknowledgement may result in a duplicate retry.
func (*Notifier) IsDevelopmentOnly() bool { return false }

// NotifyDeletionRequested never fans out BackupEmail. The outbox supplies an
// independent DeliveryID and call for each server-selected recipient.
func (n *Notifier) NotifyDeletionRequested(ctx context.Context, notice privacy.DeletionNotice) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	message, err := n.message(notice)
	if err != nil {
		return err
	}
	defer clear(message)
	// Expiry is an absolute bound, not a fresh recovery window on every retry.
	ctx, cancelExpiry := context.WithDeadline(ctx, notice.ExpiresAt)
	defer cancelExpiry()
	return n.transport.Send(ctx, notice.PrimaryEmail, message)
}

func (n *Notifier) message(notice privacy.DeletionNotice) ([]byte, error) {
	invalid := &deliveryError{stage: "notice_validation", permanent: true}
	if notice.DeliveryID == uuid.Nil || notice.BackupEmail != nil ||
		!emailaddress.ValidMailbox(notice.PrimaryEmail) ||
		len(notice.ReclaimToken) != 43 || notice.ExpiresAt.IsZero() || !notice.ExpiresAt.After(time.Now()) || notice.ExpiresAt.UTC().Year() > 9999 {
		return nil, invalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(notice.ReclaimToken)
	if err != nil || len(raw) != 32 {
		clear(raw)
		return nil, invalid
	}
	clear(raw)
	link := n.cfg.PublicOrigin + "/recover-account#token=" + notice.ReclaimToken
	expires := notice.ExpiresAt.UTC().Format(time.RFC3339Nano)
	text := "Account deletion was requested. Access to your identity account has been deactivated.\r\n\r\n" +
		"You can recover your account until " + expires + " (UTC). This is the original recovery deadline; email retries do not extend it.\r\n\r\n" +
		"Open this link and verify with your configured passkey or authenticator app:\r\n" + link + "\r\n\r\n" +
		"Recovery requires a strong factor and does not sign you in automatically. If you did not request deletion, recover your account before the deadline.\r\n" +
		"After the deadline the account is eligible for erasure, subject to lawful retention. Do not forward this recovery link.\r\n"
	htmlBody := "<!doctype html><html><body><h1>Account deletion requested</h1>" +
		"<p>Access to your identity account has been deactivated.</p>" +
		"<p>You can recover your account until <strong>" + html.EscapeString(expires) + " (UTC)</strong>. This is the original recovery deadline; email retries do not extend it.</p>" +
		"<p><a href=\"" + html.EscapeString(link) + "\">Recover your account</a> and verify with your configured passkey or authenticator app.</p>" +
		"<p>Recovery requires a strong factor and does not sign you in automatically. If you did not request deletion, recover your account before the deadline.</p>" +
		"<p>After the deadline the account is eligible for erasure, subject to lawful retention. Do not forward this recovery link.</p></body></html>\r\n"
	var message bytes.Buffer
	boundary := "deletion-" + notice.DeliveryID.String()
	_, domain, _ := strings.Cut(n.cfg.From, "@")
	_, _ = fmt.Fprintf(&message, "From: <%s>\r\nTo: <%s>\r\nSubject: Account deletion requested\r\nDate: %s\r\nMessage-ID: <deletion.%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n",
		n.cfg.From, notice.PrimaryEmail, time.Now().UTC().Format(time.RFC1123Z), notice.DeliveryID, domain, boundary)
	writer := multipart.NewWriter(&message)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, invalid
	}
	for _, body := range []struct{ media, content string }{{"text/plain", text}, {"text/html", htmlBody}} {
		part, err := writer.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {body.media + "; charset=UTF-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, invalid
		}
		encoded := quotedprintable.NewWriter(part)
		if _, err := io.WriteString(encoded, body.content); err != nil {
			return nil, invalid
		}
		if err := encoded.Close(); err != nil {
			return nil, invalid
		}
	}
	if err := writer.Close(); err != nil || message.Len() > maxMessageBytes {
		return nil, invalid
	}
	return message.Bytes(), nil
}
