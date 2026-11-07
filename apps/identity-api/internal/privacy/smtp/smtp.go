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
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
	"github.com/hatefsystems/identity/apps/identity-api/internal/notification"
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
	catalog, ok := notification.Catalog(notice.Locale, notice.TemplateVersion)
	if !ok || notice.DeliveryID == uuid.Nil || notice.BackupEmail != nil ||
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
	expires := notice.ExpiresAt.UTC().Format(time.RFC3339Nano) + " (UTC)"
	template := catalog.Deletion
	text := template.Intro + " " + template.Deactivated + "\r\n\r\n" +
		fmt.Sprintf(template.Deadline, expires) + "\r\n\r\n" + template.Instructions + "\r\n" + link + "\r\n\r\n" +
		template.Recovery + "\r\n" + template.Retention + "\r\n"
	htmlBody := "<!doctype html><html lang=\"" + string(notice.Locale) + "\" dir=\"" + catalog.Direction + "\"><body><h1>" + html.EscapeString(template.Subject) + "</h1>" +
		"<p>" + html.EscapeString(template.Deactivated) + "</p>" +
		"<p>" + fmt.Sprintf(html.EscapeString(template.Deadline), "<bdi dir=\"ltr\">"+html.EscapeString(expires)+"</bdi>") + "</p>" +
		"<p>" + html.EscapeString(template.Instructions) + " <bdi dir=\"ltr\"><a href=\"" + html.EscapeString(link) + "\" lang=\"" + string(notice.Locale) + "\" dir=\"" + catalog.Direction + "\">" + html.EscapeString(template.LinkCaption) + "</a></bdi></p>" +
		"<p>" + html.EscapeString(template.Recovery) + "</p><p>" + html.EscapeString(template.Retention) + "</p></body></html>\r\n"
	var message bytes.Buffer
	boundary := "deletion-" + notice.DeliveryID.String()
	_, domain, _ := strings.Cut(n.cfg.From, "@")
	_, _ = fmt.Fprintf(&message, "From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <deletion.%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n",
		n.cfg.From, notice.PrimaryEmail, mime.QEncoding.Encode("UTF-8", template.Subject), time.Now().UTC().Format(time.RFC1123Z), notice.DeliveryID, domain, boundary)
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
