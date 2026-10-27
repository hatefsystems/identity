package smtp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
)

const privateReply = "private-recipient@example.test private-token private-password private-relay-reply"

type relayOptions struct {
	mode             string
	certificate      string
	noStartTLS       bool
	noAuth           bool
	noPlain          bool
	failStage        string
	failCode         int
	stallStage       string
	lostACK          bool
	oversizedReply   bool
	closeAfterAccept bool
	legacyTLS        bool
}

type relayCapture struct {
	from          string
	recipients    []string
	message       []byte
	authAttempted bool
	authenticated bool
	secured       bool
	hellos        int
}

// A real loopback TCP/TLS SMTP relay. It neither prints nor persists messages.
type testRelay struct {
	listener net.Listener
	options  relayOptions
	config   config.DeletionSMTPConfig
	tls      *tls.Config
	captures chan relayCapture
	reached  chan string
	count    atomic.Int32
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

func testCertificate(t *testing.T, variant string) (tls.Certificate, []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test SMTP CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test SMTP Relay"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	switch variant {
	case "wrong-host":
		leaf.IPAddresses, leaf.DNSNames = nil, []string{"other.example.test"}
	case "expired":
		leaf.NotAfter = now.Add(-time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func newTestRelay(t *testing.T, opts relayOptions) *testRelay {
	t.Helper()
	if opts.mode == "" {
		opts.mode = config.DeletionSMTPStartTLS
	}
	certificate, ca := testCertificate(t, opts.certificate)
	caPath := filepath.Join(t.TempDir(), "relay-ca.pem")
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	r := &testRelay{
		listener: listener, options: opts, captures: make(chan relayCapture, 32), reached: make(chan string, 64),
		conns: make(map[net.Conn]struct{}),
		tls:   &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		config: config.DeletionSMTPConfig{
			Host: host, Port: port, TLSMode: opts.mode, Username: "private-user", Password: "private-password",
			From: "accounts@example.test", PublicOrigin: "https://identity.example.test", Timeout: 2 * time.Second,
			CABundlePath: caPath,
		},
	}
	if opts.legacyTLS {
		// Exercise a real downgrade refusal; production TLS has no such option.
		r.tls.MinVersion = tls.VersionTLS10 //nolint:gosec // Intentional TLS 1.0/1.1-only test relay.
		r.tls.MaxVersion = tls.VersionTLS11
	}
	t.Cleanup(func() {
		_ = listener.Close()
		r.mu.Lock()
		for conn := range r.conns {
			_ = conn.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			r.count.Add(1)
			r.mu.Lock()
			r.conns[conn] = struct{}{}
			r.mu.Unlock()
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				defer func() { _ = conn.Close() }()
				defer func() { r.mu.Lock(); delete(r.conns, conn); r.mu.Unlock() }()
				r.serve(conn)
			}()
		}
	}()
	return r
}

func (r *testRelay) serve(conn net.Conn) {
	var capture relayCapture
	defer func() { r.captures <- capture }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	stall := func(stage string) bool {
		if r.options.stallStage != stage {
			return false
		}
		r.reached <- stage
		_, _ = io.Copy(io.Discard, conn)
		return true
	}
	if r.options.mode == config.DeletionSMTPImplicit {
		if stall("tls") {
			return
		}
		secure := tls.Server(conn, r.tls)
		if err := secure.Handshake(); err != nil {
			return
		}
		conn, capture.secured = secure, true
	}
	if stall("greeting") {
		return
	}
	wire := textproto.NewConn(conn)
	if r.options.oversizedReply {
		_, _ = io.WriteString(conn, "220 "+strings.Repeat("x", 2*maxRelayBytes))
		return
	}
	if err := wire.PrintfLine("220 test SMTP relay"); err != nil {
		return
	}
	for {
		line, err := wire.ReadLine()
		if err != nil {
			return
		}
		verb, _, _ := strings.Cut(line, " ")
		stage := strings.ToLower(verb)
		if stall(stage) {
			return
		}
		if r.options.failStage == stage {
			_ = wire.PrintfLine("%d %s", r.options.failCode, privateReply)
			continue
		}
		switch verb {
		case "EHLO":
			capture.hellos++
			_ = wire.PrintfLine("250-test relay")
			if !capture.secured && !r.options.noStartTLS {
				_ = wire.PrintfLine("250-STARTTLS")
			}
			if !r.options.noAuth {
				mechanism := "PLAIN"
				if r.options.noPlain {
					mechanism = "LOGIN"
				}
				_ = wire.PrintfLine("250-AUTH %s", mechanism)
			}
			_ = wire.PrintfLine("250 SIZE 16384")
		case "HELO":
			_ = wire.PrintfLine("250 test relay")
		case "STARTTLS":
			if err := wire.PrintfLine("220 start TLS"); err != nil || stall("tls") {
				return
			}
			secure := tls.Server(conn, r.tls)
			if err := secure.Handshake(); err != nil {
				return
			}
			conn, capture.secured = secure, true
			wire = textproto.NewConn(conn)
		case "AUTH":
			capture.authAttempted = true
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			capture.authenticated = err == nil && capture.secured && bytes.Equal(raw, []byte("\x00private-user\x00private-password"))
			if !capture.authenticated {
				_ = wire.PrintfLine("535 %s", privateReply)
				continue
			}
			_ = wire.PrintfLine("235 authenticated")
		case "MAIL":
			if !capture.authenticated {
				_ = wire.PrintfLine("530 authentication required")
				continue
			}
			capture.from = strings.TrimPrefix(line, "MAIL FROM:")
			_ = wire.PrintfLine("250 sender accepted")
		case "RCPT":
			capture.recipients = append(capture.recipients, strings.TrimPrefix(line, "RCPT TO:"))
			_ = wire.PrintfLine("250 recipient accepted")
		case "DATA":
			if err := wire.PrintfLine("354 send message"); err != nil {
				return
			}
			capture.message, err = io.ReadAll(io.LimitReader(wire.DotReader(), maxMessageBytes+1))
			if err != nil || stall("ack") || r.options.lostACK {
				return
			}
			if r.options.failStage == "ack" {
				_ = wire.PrintfLine("%d %s", r.options.failCode, privateReply)
				continue
			}
			_ = wire.PrintfLine("250 relay accepted")
			if r.options.closeAfterAccept {
				return
			}
		case "QUIT":
			_ = wire.PrintfLine("221 goodbye")
			return
		case "*":
			_ = wire.PrintfLine("501 authentication canceled")
		default:
			_ = wire.PrintfLine("500 unknown command")
		}
	}
}

func (r *testRelay) capture(t *testing.T) relayCapture {
	t.Helper()
	select {
	case capture := <-r.captures:
		return capture
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP connection did not close")
		return relayCapture{}
	}
}

func testNotice() privacy.DeletionNotice {
	return privacy.DeletionNotice{
		DeliveryID: uuid.New(), PrimaryEmail: "private-recipient@example.test",
		ReclaimToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7b}, 32)),
		ExpiresAt:    time.Now().Add(720 * time.Hour).Truncate(time.Second),
	}
}

func assertRedacted(t *testing.T, err error, notice privacy.DeletionNotice) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Error("delivery failure", "error", err)
	out := fmt.Sprintf("%v %+v %#v", err, err, err) + logs.String()
	for _, private := range []string{notice.PrimaryEmail, notice.ReclaimToken, privateReply, "private-user", "private-password", "private-relay-reply"} {
		if strings.Contains(out, private) {
			t.Fatal("SMTP error or log retained private material")
		}
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatal("SMTP error retained an underlying relay error")
	}
}

func TestSMTPVerifiedTLSAcceptanceAndStableMessages(t *testing.T) {
	for _, mode := range []string{config.DeletionSMTPStartTLS, config.DeletionSMTPImplicit} {
		t.Run(mode, func(t *testing.T) {
			relay := newTestRelay(t, relayOptions{mode: mode, closeAfterAccept: true})
			notifier, err := New(relay.config)
			if err != nil {
				t.Fatal(err)
			}
			if notifier.IsDevelopmentOnly() || notifier.tlsConfig.InsecureSkipVerify || notifier.tlsConfig.MinVersion < tls.VersionTLS12 {
				t.Fatal("transport did not enforce production TLS")
			}
			notice := testNotice()
			notice.PrimaryEmail = "private-recipient@EXAMPLE.test"
			notice.ExpiresAt = notice.ExpiresAt.Add(123456 * time.Microsecond).In(time.FixedZone("original", -7*60*60))
			var originalID string
			for range 2 {
				if err := notifier.NotifyDeletionRequested(context.Background(), notice); err != nil {
					t.Fatal(err)
				}
				capture := relay.capture(t)
				if !capture.secured || !capture.authenticated || len(capture.recipients) != 1 ||
					capture.recipients[0] != "<"+notice.PrimaryEmail+">" || capture.from != "<"+relay.config.From+">" || len(capture.message) > maxMessageBytes {
					t.Fatal("mail was not separately accepted with TLS/auth and the selected envelope")
				}
				if mode == config.DeletionSMTPStartTLS && capture.hellos != 2 {
					t.Fatal("STARTTLS capabilities were not re-negotiated")
				}
				message, err := mail.ReadMessage(bytes.NewReader(capture.message))
				if err != nil {
					t.Fatal("invalid mail serialization")
				}
				id := message.Header.Get("Message-ID")
				if id != "<deletion."+notice.DeliveryID.String()+"@example.test>" || originalID != "" && id != originalID {
					t.Fatal("Message-ID did not preserve the delivery identity")
				}
				originalID = id
				if message.Header.Get("Subject") != "Account deletion requested" || message.Header.Get("Bcc") != "" || message.Header.Get("Cc") != "" {
					t.Fatal("unexpected message headers")
				}
				if _, err := mail.ParseDate(message.Header.Get("Date")); err != nil {
					t.Fatal("missing valid Date header")
				}
				to, err := message.Header.AddressList("To")
				if err != nil || len(to) != 1 || to[0].Address != notice.PrimaryEmail {
					t.Fatal("multiple or wrong visible recipients")
				}
				mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
				if err != nil || mediaType != "multipart/alternative" {
					t.Fatal("missing multipart alternatives")
				}
				parts := multipart.NewReader(message.Body, params["boundary"])
				for _, expected := range []string{"text/plain", "text/html"} {
					part, err := parts.NextPart()
					if err != nil {
						t.Fatal("missing message alternative")
					}
					body, err := io.ReadAll(part)
					if err != nil || !strings.HasPrefix(part.Header.Get("Content-Type"), expected) {
						t.Fatal("invalid message alternative")
					}
					link := relay.config.PublicOrigin + "/recover-account#token=" + notice.ReclaimToken
					if !bytes.Contains(body, []byte(link)) || !bytes.Contains(body, []byte(notice.ExpiresAt.UTC().Format(time.RFC3339Nano))) ||
						!bytes.Contains(body, []byte("deactivated")) || !bytes.Contains(body, []byte("strong factor")) ||
						bytes.Contains(body, []byte("?token=")) || bytes.Contains(body, []byte("<img")) || bytes.Contains(body, []byte("<script")) {
						t.Fatal("recovery link/deadline changed, required explanation missing, or active/remote content added")
					}
				}
				if _, err := parts.NextPart(); !errors.Is(err, io.EOF) {
					t.Fatal("unexpected additional message part")
				}
			}
		})
	}
}

func TestSMTPFailureClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name      string
		opts      relayOptions
		permanent bool
	}{
		{"temporary recipient", relayOptions{failStage: "rcpt", failCode: 450}, false},
		{"permanent recipient", relayOptions{failStage: "rcpt", failCode: 550}, true},
		{"permanent sender", relayOptions{failStage: "mail", failCode: 550}, true},
		{"temporary data", relayOptions{failStage: "data", failCode: 451}, false},
		{"permanent data", relayOptions{failStage: "data", failCode: 554}, true},
		{"negative acceptance", relayOptions{failStage: "ack", failCode: 554}, true},
		{"temporary acceptance", relayOptions{failStage: "ack", failCode: 451}, false},
		{"malformed acceptance", relayOptions{failStage: "ack", failCode: 99}, false},
		{"lost acceptance", relayOptions{lostACK: true}, false},
		{"authentication rejection", relayOptions{failStage: "auth", failCode: 535}, false},
		{"oversized reply", relayOptions{oversizedReply: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relay := newTestRelay(t, tc.opts)
			notifier, err := New(relay.config)
			if err != nil {
				t.Fatal(err)
			}
			notice := testNotice()
			err = notifier.NotifyDeletionRequested(context.Background(), notice)
			var failure interface{ Permanent() bool }
			if err == nil || !errors.As(err, &failure) || failure.Permanent() != tc.permanent {
				t.Fatal("failure was accepted or its retry classification changed")
			}
			assertRedacted(t, err, notice)
			capture := relay.capture(t)
			if tc.opts.lostACK && len(capture.message) == 0 {
				t.Fatal("ambiguous acceptance test did not transmit DATA")
			}
		})
	}
}

func TestSMTPRefusesTLSAndAuthenticationDowngrades(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts relayOptions
	}{
		{"required STARTTLS absent", relayOptions{noStartTLS: true}},
		{"STARTTLS rejected", relayOptions{failStage: "starttls", failCode: 454}},
		{"EHLO downgrade", relayOptions{failStage: "ehlo", failCode: 500}},
		{"authentication absent", relayOptions{noAuth: true}},
		{"unsupported authentication", relayOptions{noPlain: true}},
		{"STARTTLS hostname mismatch", relayOptions{certificate: "wrong-host"}},
		{"implicit hostname mismatch", relayOptions{mode: config.DeletionSMTPImplicit, certificate: "wrong-host"}},
		{"expired STARTTLS certificate", relayOptions{certificate: "expired"}},
		{"expired implicit certificate", relayOptions{mode: config.DeletionSMTPImplicit, certificate: "expired"}},
		{"legacy STARTTLS version", relayOptions{legacyTLS: true}},
		{"legacy implicit TLS version", relayOptions{mode: config.DeletionSMTPImplicit, legacyTLS: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relay := newTestRelay(t, tc.opts)
			notifier, err := New(relay.config)
			if err != nil {
				t.Fatal(err)
			}
			notice := testNotice()
			err = notifier.NotifyDeletionRequested(context.Background(), notice)
			if err == nil {
				t.Fatal("TLS/auth downgrade accepted")
			}
			assertRedacted(t, err, notice)
			capture := relay.capture(t)
			if capture.authAttempted || capture.from != "" || len(capture.recipients) != 0 || len(capture.message) != 0 {
				t.Fatal("credentials, recipient, or token transmitted without verified TLS/auth")
			}
		})
	}
	for _, mode := range []string{config.DeletionSMTPStartTLS, config.DeletionSMTPImplicit} {
		t.Run("untrusted "+mode, func(t *testing.T) {
			relay := newTestRelay(t, relayOptions{mode: mode})
			cfg := relay.config
			cfg.CABundlePath = ""
			notifier, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			notice := testNotice()
			if err := notifier.NotifyDeletionRequested(context.Background(), notice); err == nil {
				t.Fatal("self-signed test CA trusted without explicit bundle")
			} else {
				assertRedacted(t, err, notice)
			}
			if relay.capture(t).authAttempted {
				t.Fatal("authentication attempted with untrusted certificate")
			}
		})
	}
}

func TestSMTPTimeoutsAndCancellationAtProtocolBoundaries(t *testing.T) {
	for _, mode := range []string{config.DeletionSMTPStartTLS, config.DeletionSMTPImplicit} {
		for _, stage := range []string{"greeting", "tls", "ehlo", "auth", "mail", "rcpt", "data", "ack"} {
			for _, cancellation := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cancel=%v", mode, stage, cancellation), func(t *testing.T) {
					relay := newTestRelay(t, relayOptions{mode: mode, stallStage: stage})
					cfg := relay.config
					cfg.Timeout = 150 * time.Millisecond
					if cancellation {
						cfg.Timeout = time.Second
					}
					notifier, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					notice := testNotice()
					result := make(chan error, 1)
					go func() { result <- notifier.NotifyDeletionRequested(ctx, notice) }()
					select {
					case <-relay.reached:
					case <-time.After(time.Second):
						t.Fatal("SMTP test did not reach its protocol boundary")
					}
					if cancellation {
						cancel()
					}
					select {
					case err := <-result:
						want := context.DeadlineExceeded
						if cancellation {
							want = context.Canceled
						}
						if !errors.Is(err, want) {
							t.Fatal("SMTP timeout/cancellation was lost")
						}
						assertRedacted(t, err, notice)
					case <-time.After(time.Second):
						t.Fatal("SMTP operation ignored cancellation/deadline")
					}
					relay.capture(t)
				})
			}
		}
	}
}

func TestSMTPRecipientIsolationAndNoticeValidation(t *testing.T) {
	relay := newTestRelay(t, relayOptions{})
	notifier, err := New(relay.config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*privacy.DeletionNotice)
	}{
		{"missing delivery identity", func(n *privacy.DeletionNotice) { n.DeliveryID = uuid.Nil }},
		{"backup recipient", func(n *privacy.DeletionNotice) { b := "private-backup@example.test"; n.BackupEmail = &b }},
		{"empty backup still rejected", func(n *privacy.DeletionNotice) { b := ""; n.BackupEmail = &b }},
		{"missing recipient", func(n *privacy.DeletionNotice) { n.PrimaryEmail = "" }},
		{"recipient headers", func(n *privacy.DeletionNotice) { n.PrimaryEmail += "\r\nBcc: private-backup@example.test" }},
		{"recipient envelope injection", func(n *privacy.DeletionNotice) { n.PrimaryEmail += ">\r\nRCPT TO:<private-backup@example.test>" }},
		{"recipient list", func(n *privacy.DeletionNotice) { n.PrimaryEmail += ",private-backup@example.test" }},
		{"recipient display name", func(n *privacy.DeletionNotice) { n.PrimaryEmail = "Someone <" + n.PrimaryEmail + ">" }},
		{"oversized recipient", func(n *privacy.DeletionNotice) { n.PrimaryEmail = strings.Repeat("x", 10000) + "@example.test" }},
		{"missing token", func(n *privacy.DeletionNotice) { n.ReclaimToken = "" }},
		{"oversized token", func(n *privacy.DeletionNotice) { n.ReclaimToken = strings.Repeat("x", 10000) }},
		{"padded token", func(n *privacy.DeletionNotice) { n.ReclaimToken += "=" }},
		{"noncanonical token", func(n *privacy.DeletionNotice) { n.ReclaimToken = strings.Repeat("A", 42) + "B" }},
		{"token URL injection", func(n *privacy.DeletionNotice) { n.ReclaimToken = strings.Repeat("A", 34) + "&token=xx" }},
		{"token control", func(n *privacy.DeletionNotice) { n.ReclaimToken = strings.Repeat("A", 41) + "\r\n" }},
		{"missing deadline", func(n *privacy.DeletionNotice) { n.ExpiresAt = time.Time{} }},
		{"expired deadline", func(n *privacy.DeletionNotice) { n.ExpiresAt = time.Now().Add(-time.Second) }},
		{"unformattable deadline", func(n *privacy.DeletionNotice) { n.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notice := testNotice()
			tc.mutate(&notice)
			err := notifier.NotifyDeletionRequested(context.Background(), notice)
			var failure interface{ Permanent() bool }
			if err == nil || !errors.As(err, &failure) || !failure.Permanent() {
				t.Fatal("invalid per-recipient notice accepted or marked retryable")
			}
			if strings.Contains(err.Error(), "private") || relay.count.Load() != 0 {
				t.Fatal("invalid notice leaked data or contacted relay")
			}
		})
	}
	first := testNotice()
	second := first
	second.DeliveryID, second.PrimaryEmail = uuid.New(), "private-backup@example.test"
	for _, notice := range []privacy.DeletionNotice{first, second} {
		if err := notifier.NotifyDeletionRequested(context.Background(), notice); err != nil {
			t.Fatal(err)
		}
		capture := relay.capture(t)
		if len(capture.recipients) != 1 || capture.recipients[0] != "<"+notice.PrimaryEmail+">" {
			t.Fatal("recipient calls were combined")
		}
		other := second.PrimaryEmail
		if notice.DeliveryID == second.DeliveryID {
			other = first.PrimaryEmail
		}
		if bytes.Contains(capture.message, []byte(other)) {
			t.Fatal("recipient learned another recipient's address")
		}
	}
}

func TestSMTPCABundleValidationAndConfigRedaction(t *testing.T) {
	relay := newTestRelay(t, relayOptions{})
	for _, data := range [][]byte{nil, []byte("private-token invalid PEM"), bytes.Repeat([]byte("x"), maxCABundleBytes+1)} {
		path := filepath.Join(t.TempDir(), "private-recipient@example.test.pem")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		cfg := relay.config
		cfg.CABundlePath = path
		if _, err := New(cfg); err == nil || strings.Contains(fmt.Sprintf("%v %#v", err, err), "private") {
			t.Fatal("invalid/oversized CA bundle accepted or error exposed its contents/path")
		}
	}
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "private-nonexistent.pem")} {
		cfg := relay.config
		cfg.CABundlePath = path
		if _, err := New(cfg); err == nil || strings.Contains(err.Error(), path) {
			t.Fatal("invalid trust-store path accepted or disclosed")
		}
	}
	cert, ca := testCertificate(t, "")
	for _, data := range [][]byte{
		append(bytes.Clone(ca), []byte("private trailing garbage")...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private-password")}),
	} {
		cfg := relay.config
		cfg.CABundlePath = filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(cfg.CABundlePath, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg); err == nil {
			t.Fatal("trust-store accepted non-CA, private-key, or extra content")
		}
	}
	cfg := relay.config
	cfg.From += "\r\nBcc: private-recipient@example.test"
	if _, err := New(cfg); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("sender header injection accepted or leaked")
	}
}

func TestSMTPContextAndOriginalExpiryBoundEveryAttempt(t *testing.T) {
	relay := newTestRelay(t, relayOptions{stallStage: "ack"})
	notifier, err := New(relay.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := notifier.NotifyDeletionRequested(ctx, testNotice()); !errors.Is(err, context.Canceled) || relay.count.Load() != 0 {
		t.Fatal("canceled operation attempted delivery")
	}
	for _, parentDeadline := range []bool{false, true} {
		t.Run(fmt.Sprint(parentDeadline), func(t *testing.T) {
			notice := testNotice()
			ctx := context.Background()
			cancel := func() {}
			if parentDeadline {
				ctx, cancel = context.WithTimeout(ctx, 150*time.Millisecond)
			} else {
				notice.ExpiresAt = time.Now().Add(150 * time.Millisecond)
			}
			defer cancel()
			start := time.Now()
			if err := notifier.NotifyDeletionRequested(ctx, notice); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
				t.Fatal("parent deadline or original expiry did not bound SMTP")
			}
			if len(relay.capture(t).message) == 0 {
				t.Fatal("expiry test did not reach an ambiguous acknowledgement")
			}
		})
	}
}

func TestSMTPConcurrentRecipientsUseSeparateConnectionsAndMessages(t *testing.T) {
	relay := newTestRelay(t, relayOptions{})
	notifier, err := New(relay.config)
	if err != nil {
		t.Fatal(err)
	}
	const count = 8
	results := make(chan error, count)
	expected := make(map[string]string, count)
	for i := range count {
		notice := testNotice()
		notice.PrimaryEmail = fmt.Sprintf("recipient%d@example.test", i)
		expected["<deletion."+notice.DeliveryID.String()+"@example.test>"] = notice.PrimaryEmail
		go func() { results <- notifier.NotifyDeletionRequested(context.Background(), notice) }()
	}
	for range count {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
		capture := relay.capture(t)
		message, err := mail.ReadMessage(bytes.NewReader(capture.message))
		if err != nil {
			t.Fatal("invalid concurrent message")
		}
		id := message.Header.Get("Message-ID")
		address, ok := expected[id]
		if !ok || len(capture.recipients) != 1 || capture.recipients[0] != "<"+address+">" {
			t.Fatal("concurrent calls mixed up delivery identities or recipients")
		}
		delete(expected, id)
	}
	if len(expected) != 0 || relay.count.Load() != count {
		t.Fatal("concurrent delivery was not one connection per recipient")
	}
}

func TestSMTPWrongCredentialsNeverSubmitRecipientOrToken(t *testing.T) {
	relay := newTestRelay(t, relayOptions{})
	cfg := relay.config
	cfg.Password = "wrong-private-password"
	notifier, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	notice := testNotice()
	err = notifier.NotifyDeletionRequested(context.Background(), notice)
	if err == nil {
		t.Fatal("wrong credentials accepted")
	}
	assertRedacted(t, err, notice)
	capture := relay.capture(t)
	if !capture.authAttempted || capture.authenticated || !capture.secured || len(capture.recipients) != 0 || len(capture.message) != 0 {
		t.Fatal("failed authentication sent recipient/token or skipped TLS")
	}
}
