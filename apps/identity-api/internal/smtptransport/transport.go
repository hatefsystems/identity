// Package smtptransport sends a single bounded message through authenticated,
// verified TLS SMTP. Templates, delivery identities, expiry and retries belong
// to callers. No raw relay diagnostics or message material escape as errors.
package smtptransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/emailaddress"
)

const (
	// StartTLS upgrades the relay connection to verified TLS before authentication.
	StartTLS = "starttls"
	// Implicit establishes verified TLS before reading the relay greeting.
	Implicit = "implicit"

	// MaxCABundleBytes bounds the operator-supplied PEM trust store.
	MaxCABundleBytes = 1 << 20
	// MaxMessageBytes bounds each caller-rendered message.
	MaxMessageBytes = 16 << 10
	// MaxRelayBytes bounds multiline/unterminated responses and TLS handshake input.
	MaxRelayBytes = 128 << 10
)

// Config has no plaintext or skip-verification option. Never log its credentials.
// System sender/auth/host remain ASCII even when recipients require SMTPUTF8.
type Config struct {
	Host         string
	Port         int
	TLSMode      string
	Username     string
	Password     string
	From         string
	Timeout      time.Duration
	CABundlePath string
}

// Validate protects direct construction without dialing or reading a trust store.
func (c Config) Validate() error {
	if !validHost(c.Host) || c.Port < 1 || c.Port > 65535 ||
		(c.TLSMode != StartTLS && c.TLSMode != Implicit) ||
		!ascii(c.Username, 1, 256, false) || !ascii(c.Password, 1, 1024, true) || strings.TrimSpace(c.Password) == "" ||
		!ascii(c.From, 3, 254, false) || !emailaddress.ValidMailbox(c.From) ||
		c.Timeout < time.Millisecond || c.Timeout > time.Minute ||
		(c.CABundlePath != "" && (!ascii(c.CABundlePath, 1, 4096, true) || strings.TrimSpace(c.CABundlePath) != c.CABundlePath)) {
		return errors.New("smtp transport: invalid configuration")
	}
	return nil
}

func ascii(value string, minimum, maximum int, spaces bool) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for i := range len(value) {
		if value[i] < 33 && (!spaces || value[i] != ' ') || value[i] > 126 {
			return false
		}
	}
	return true
}

func validHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == host
	}
	if len(host) == 0 || len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Transport is immutable and safe for concurrent calls, each with its own socket.
type Transport struct {
	cfg       Config
	tlsConfig *tls.Config
}

// New loads an optional bounded PEM CA bundle. SASL PLAIN is only sent inside
// verified TLS 1.2 or newer; system roots are used without an explicit bundle.
func New(cfg Config) (*Transport, error) {
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
	return &Transport{cfg: cfg, tlsConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: cfg.Host, RootCAs: roots,
	}}, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	invalid := errors.New("smtp transport: invalid trusted CA bundle")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxCABundleBytes {
		return nil, invalid
	}
	file, err := os.Open(path) // #nosec G304 -- explicit operator-supplied trust store, bounded below.
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, MaxCABundleBytes+1))
	if err != nil || len(data) > MaxCABundleBytes {
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

// Error contains only a fixed stage and retry classification, never an underlying
// diagnostic. Operator-repairable TLS/auth/capability failures are retryable.
type Error struct {
	stage     string
	permanent bool
}

func (e *Error) Error() string { return "smtp transport: " + e.stage + " failed" }

// Permanent reports whether retrying this delivery failure is inappropriate.
func (e *Error) Permanent() bool { return e.permanent }

// Send submits one exact, already-bound recipient and caller-rendered message.
// It never canonicalizes/reroutes the recipient, retries, or modifies message
// bytes. Success requires complete DATA flush and a positive ACK, not delivery
// to an inbox. A lost ACK remains ambiguous; callers own duplicate-safe retries.
// Caller context must carry any absolute proof expiry; Timeout bounds each call.
func (t *Transport) Send(ctx context.Context, recipient string, message []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !emailaddress.ValidMailbox(recipient) {
		return &Error{stage: "recipient_validation", permanent: true}
	}
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return &Error{stage: "message_validation", permanent: true}
	}
	ctx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()
	local, _, _ := strings.Cut(recipient, "@")
	client, closeConnection, err := t.open(ctx, !ascii(local, 1, 64, false))
	if err != nil {
		return err
	}
	defer closeConnection()
	if err := client.Mail(t.cfg.From); err != nil {
		return safeError(ctx, "sender", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return safeError(ctx, "recipient", err)
	}
	return sendData(ctx, client.Text, message)
}

// Check verifies the configured relay's TLS, post-TLS EHLO capabilities and
// authenticated SASL PLAIN negotiation without sending MAIL, RCPT, DATA or any
// test message. When requireSMTPUTF8 is true, that capability must be advertised
// after verified TLS and before authentication. This is a bounded readiness
// probe, not proof of recipient acceptance or inbox delivery; Send rechecks each
// new connection independently. It never retries or relaxes TLS requirements.
func (t *Transport) Check(ctx context.Context, requireSMTPUTF8 bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()
	_, closeConnection, err := t.open(ctx, requireSMTPUTF8)
	if err != nil {
		return err
	}
	defer closeConnection()
	return ctx.Err()
}

// open shares the bounded, verified negotiation for sends and message-free
// probes. The caller supplies the whole-operation deadline and owns the returned
// cleanup; unsuccessful negotiation always closes its socket and cancellation hook.
func (t *Transport) open(ctx context.Context, requireSMTPUTF8 bool) (*smtp.Client, func(), error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.cfg.Host, strconv.Itoa(t.cfg.Port)))
	if err != nil {
		return nil, nil, safeError(ctx, "connect", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	closeConnection := func() { stop(); _ = conn.Close() }
	opened := false
	defer func() {
		if !opened {
			closeConnection()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, safeError(ctx, "deadline", err)
	}
	var transport net.Conn = &limitedConn{Conn: conn, remaining: MaxRelayBytes}
	if t.cfg.TLSMode == Implicit {
		secure := tls.Client(transport, t.tlsConfig.Clone())
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, nil, safeError(ctx, "tls", err)
		}
		transport = secure
	}
	client, err := smtp.NewClient(transport, t.cfg.Host)
	if err != nil {
		return nil, nil, safeError(ctx, "greeting", err)
	}
	if err := client.Hello("identity.invalid"); err != nil {
		return nil, nil, safeError(ctx, "hello", err)
	}
	if t.cfg.TLSMode == StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return nil, nil, &Error{stage: "tls_required"}
		}
		if err := client.StartTLS(t.tlsConfig.Clone()); err != nil {
			return nil, nil, safeError(ctx, "tls", err)
		}
	}
	if state, ok := client.TLSConnectionState(); !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return nil, nil, &Error{stage: "tls_verification"}
	}
	if requireSMTPUTF8 {
		// StartTLS reissues EHLO and discards pre-TLS capabilities. net/smtp only
		// adds SMTPUTF8 when advertised; it does not require it for EAI itself.
		if ok, _ := client.Extension("SMTPUTF8"); !ok {
			return nil, nil, &Error{stage: "smtputf8_required"}
		}
	}
	ok, mechanisms := client.Extension("AUTH")
	plain := false
	for _, mechanism := range strings.Fields(mechanisms) {
		plain = plain || strings.EqualFold(mechanism, "PLAIN")
	}
	if !ok || !plain {
		return nil, nil, &Error{stage: "authentication_required"}
	}
	if err := client.Auth(smtp.PlainAuth("", t.cfg.Username, t.cfg.Password, t.cfg.Host)); err != nil {
		return nil, nil, safeError(ctx, "authentication", err)
	}
	opened = true
	return client, func() { _ = client.Close(); closeConnection() }, nil
}

func sendData(ctx context.Context, wire *textproto.Conn, message []byte) error {
	if err := wire.PrintfLine("DATA"); err != nil {
		return safeError(ctx, "data", err)
	}
	if _, _, err := wire.ReadResponse(354); err != nil {
		return safeError(ctx, "data", err)
	}
	// net/smtp's DATA closer discards DotWriter.Close's flush error. Require
	// both complete write/flush and positive ACK, even if a reply was buffered.
	data := wire.DotWriter()
	if _, err := data.Write(message); err != nil {
		// Closing a partial DATA writer could submit a truncated message.
		return safeError(ctx, "write", err)
	}
	if err := data.Close(); err != nil {
		return safeError(ctx, "write", err)
	}
	if _, _, err := wire.ReadResponse(250); err != nil {
		return safeError(ctx, "acknowledgement", err)
	}
	// A QUIT/close failure cannot turn a positive DATA ACK into a retry.
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
	permanent := (stage == "sender" || stage == "recipient" || stage == "data" || stage == "acknowledgement") &&
		errors.As(err, &reply) && reply.Code >= 500 && reply.Code < 600
	return &Error{stage: stage, permanent: permanent}
}

type limitedConn struct {
	net.Conn
	remaining int
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.remaining == 0 {
		return 0, errors.New("smtp transport: relay response limit exceeded")
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}
