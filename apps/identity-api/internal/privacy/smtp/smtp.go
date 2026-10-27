// Package smtp delivers one deletion notice through an authenticated, verified
// TLS relay. Delivery bookkeeping and retry decisions belong to the parent
// privacy package, which must not import this transport.
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	netsmtp "net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
)

const (
	maxCABundleBytes = 1 << 20
	maxMessageBytes  = 16 << 10
	// This also bounds multiline/unterminated replies and TLS handshake input.
	maxRelayBytes = 128 << 10
)

// Notifier is safe for concurrent calls. Each call owns its connection and sends
// exactly one recipient. No message contents or raw relay errors are logged.
type Notifier struct {
	cfg       config.DeletionSMTPConfig
	tlsConfig *tls.Config
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
	var roots *x509.CertPool
	if cfg.CABundlePath != "" {
		var err error
		roots, err = loadRoots(cfg.CABundlePath)
		if err != nil {
			return nil, err
		}
	}
	return &Notifier{
		cfg: cfg,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: cfg.Host,
			RootCAs:    roots,
		},
	}, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	invalid := errors.New("deletion smtp: invalid trusted CA bundle")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxCABundleBytes {
		return nil, invalid
	}
	file, err := os.Open(path) // #nosec G304 -- explicit operator-supplied trust store, bounded below.
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxCABundleBytes+1))
	if err != nil || len(data) > maxCABundleBytes {
		return nil, invalid
	}
	roots := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, invalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, invalid
		}
		roots.AddCert(certificate)
		count++
		data = rest
	}
	if count == 0 {
		return nil, invalid
	}
	return roots, nil
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
	ctx, cancel := context.WithTimeout(ctx, n.cfg.Timeout)
	defer cancel()
	// Expiry is an absolute bound, not a fresh recovery window on every retry.
	ctx, cancelExpiry := context.WithDeadline(ctx, notice.ExpiresAt)
	defer cancelExpiry()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(n.cfg.Host, strconv.Itoa(n.cfg.Port)))
	if err != nil {
		return safeError(ctx, "connect", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return safeError(ctx, "deadline", err)
	}
	var transport net.Conn = &limitedConn{Conn: conn, remaining: maxRelayBytes}
	if n.cfg.TLSMode == config.DeletionSMTPImplicit {
		secure := tls.Client(transport, n.tlsConfig.Clone())
		if err := secure.HandshakeContext(ctx); err != nil {
			return safeError(ctx, "tls", err)
		}
		transport = secure
	}
	client, err := netsmtp.NewClient(transport, n.cfg.Host)
	if err != nil {
		return safeError(ctx, "greeting", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Hello("identity.invalid"); err != nil {
		return safeError(ctx, "hello", err)
	}
	if n.cfg.TLSMode == config.DeletionSMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return &deliveryError{stage: "tls_required"}
		}
		if err := client.StartTLS(n.tlsConfig.Clone()); err != nil {
			return safeError(ctx, "tls", err)
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return &deliveryError{stage: "tls_verification"}
	}
	ok, mechanisms := client.Extension("AUTH")
	plain := false
	for _, mechanism := range strings.Fields(mechanisms) {
		plain = plain || strings.EqualFold(mechanism, "PLAIN")
	}
	if !ok || !plain {
		return &deliveryError{stage: "authentication_required"}
	}
	if err := client.Auth(netsmtp.PlainAuth("", n.cfg.Username, n.cfg.Password, n.cfg.Host)); err != nil {
		return safeError(ctx, "authentication", err)
	}
	if err := client.Mail(n.cfg.From); err != nil {
		return safeError(ctx, "sender", err)
	}
	if err := client.Rcpt(notice.PrimaryEmail); err != nil {
		return safeError(ctx, "recipient", err)
	}
	if err := client.Text.PrintfLine("DATA"); err != nil {
		return safeError(ctx, "data", err)
	}
	if _, _, err := client.Text.ReadResponse(354); err != nil {
		return safeError(ctx, "data", err)
	}
	// net/smtp's DATA closer discards DotWriter.Close's flush error. Require
	// both a complete write and the positive ACK, even if a reply was buffered.
	data := client.Text.DotWriter()
	if _, err := data.Write(message); err != nil {
		// Do not close a partial DATA writer: that could submit a truncated mail.
		return safeError(ctx, "write", err)
	}
	if err := data.Close(); err != nil {
		return safeError(ctx, "write", err)
	}
	if _, _, err := client.Text.ReadResponse(250); err != nil {
		return safeError(ctx, "acknowledgement", err)
	}
	// Do not turn a QUIT/close failure into a retry after a positive DATA ACK.
	return nil
}

func safeError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return context.DeadlineExceeded
	}
	var reply *textproto.Error
	// Auth/TLS failures are operator-repairable, not permanent recipient failures.
	permanent := (stage == "sender" || stage == "recipient" || stage == "data" || stage == "acknowledgement") &&
		errors.As(err, &reply) && reply.Code >= 500 && reply.Code < 600
	return &deliveryError{stage: stage, permanent: permanent}
}

type limitedConn struct {
	net.Conn
	remaining int
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		return 0, errors.New("deletion smtp: relay response limit exceeded")
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func (n *Notifier) message(notice privacy.DeletionNotice) ([]byte, error) {
	invalid := &deliveryError{stage: "notice_validation", permanent: true}
	if notice.DeliveryID == uuid.Nil || notice.BackupEmail != nil ||
		config.ValidateDeletionSMTPAddress(notice.PrimaryEmail) != nil ||
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
