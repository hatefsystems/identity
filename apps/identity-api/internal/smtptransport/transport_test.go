package smtptransport

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
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type relayResult struct {
	commands []string
	message  []byte
}

type relayBehavior struct {
	postUTF8   bool
	preUTF8    bool
	failStage  string
	failCode   int
	lostACK    bool
	oversized  bool
	noStartTLS bool
	noAuth     bool
	noPlain    bool
	wrongHost  bool
	expired    bool
	legacyTLS  bool
	stallStage string
	reached    chan<- string
}

// One real, deadline-bounded loopback SMTP/TLS exchange; no live mail or logging.
func smtpRelay(t *testing.T, mode string, behavior relayBehavior) (Config, <-chan relayResult) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if behavior.wrongHost {
		leaf.IPAddresses, leaf.DNSNames = nil, []string{"other.example.test"}
	}
	if behavior.expired {
		leaf.NotAfter = now.Add(-time.Minute)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "smtp-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600); err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}}}
	if behavior.legacyTLS {
		serverTLS.MinVersion = tls.VersionTLS10 //nolint:gosec // Intentional downgrade-only test relay.
		serverTLS.MaxVersion = tls.VersionTLS11
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	cfg := Config{Host: host, Port: port, TLSMode: mode, Username: "private-user", Password: "private-password",
		From: "accounts@example.test", Timeout: time.Second, CABundlePath: caPath}
	results := make(chan relayResult, 1)
	done := make(chan struct{})
	t.Cleanup(func() { _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		var result relayResult
		defer func() { results <- result }()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		stall := func(stage string) bool {
			if behavior.stallStage != stage {
				return false
			}
			if behavior.reached != nil {
				behavior.reached <- stage
			}
			_, _ = io.Copy(io.Discard, conn)
			return true
		}
		secure := false
		if mode == Implicit {
			if stall("tls") {
				return
			}
			conn = tls.Server(conn, serverTLS)
			secure = true
		}
		if stall("greeting") {
			return
		}
		wire := textproto.NewConn(conn)
		if behavior.oversized {
			_, _ = io.WriteString(conn, "220 "+strings.Repeat("x", 2*MaxRelayBytes))
			return
		}
		if err := wire.PrintfLine("220 bounded test relay"); err != nil {
			return
		}
		for {
			line, err := wire.ReadLine()
			if err != nil {
				return
			}
			result.commands = append(result.commands, line)
			verb, _, _ := strings.Cut(line, " ")
			if stall(strings.ToLower(verb)) || verb == "EHLO" && secure && stall("posttls_ehlo") {
				return
			}
			if strings.EqualFold(behavior.failStage, verb) {
				_ = wire.PrintfLine("%d private-relay-reply private-token", behavior.failCode)
				continue
			}
			switch verb {
			case "EHLO":
				_ = wire.PrintfLine("250-test relay")
				if !secure && !behavior.noStartTLS {
					_ = wire.PrintfLine("250-STARTTLS")
				}
				if secure && behavior.postUTF8 || !secure && behavior.preUTF8 {
					_ = wire.PrintfLine("250-SMTPUTF8")
				}
				if !behavior.noAuth {
					mechanism := "PLAIN"
					if behavior.noPlain {
						mechanism = "LOGIN"
					}
					_ = wire.PrintfLine("250-AUTH %s", mechanism)
				}
				_ = wire.PrintfLine("250 SIZE 16384")
			case "STARTTLS":
				_ = wire.PrintfLine("220 start TLS")
				if stall("tls") {
					return
				}
				conn = tls.Server(conn, serverTLS)
				wire = textproto.NewConn(conn)
				secure = true
			case "AUTH":
				raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if err != nil || !secure || !bytes.Equal(raw, []byte("\x00private-user\x00private-password")) {
					_ = wire.PrintfLine("535 private-relay-reply")
					continue
				}
				_ = wire.PrintfLine("235 authenticated")
			case "MAIL", "RCPT":
				_ = wire.PrintfLine("250 accepted")
			case "DATA":
				_ = wire.PrintfLine("354 message")
				result.message, err = io.ReadAll(io.LimitReader(wire.DotReader(), MaxMessageBytes+1))
				if err != nil || behavior.lostACK {
					return
				}
				if behavior.failStage == "ack" {
					_ = wire.PrintfLine("%d private-relay-reply private-token", behavior.failCode)
				} else {
					_ = wire.PrintfLine("250 accepted")
				}
				return // Close after DATA ACK, never require a successful QUIT.
			default:
				_ = wire.PrintfLine("500 unexpected command")
			}
		}
	}()
	return cfg, results
}

func captureRelay(t *testing.T, results <-chan relayResult) relayResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close within bound")
		return relayResult{}
	}
}

func TestSendPostTLSSMTPUTF8Gate(t *testing.T) {
	for _, mode := range []string{StartTLS, Implicit} {
		for _, tc := range []struct {
			name, recipient string
			behavior        relayBehavior
			accepted        bool
		}{
			{"Persian supported", "\u0639\u0644\u06cc@xn--mgbh0fb.xn--mgba3a4f16a", relayBehavior{postUTF8: true}, true},
			{"EAI unsupported", "\u0639\u0644\u06cc@example.test", relayBehavior{}, false},
			{"pre-TLS capability not authority", "\u0639\u0644\u06cc@example.test", relayBehavior{preUTF8: true}, false},
			{"ASCII IDNA no capability", "user@xn--bcher-kva.example", relayBehavior{}, true},
			{"bound local casing preserved", "\u00c9@EXAMPLE.test", relayBehavior{postUTF8: true}, true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				cfg, results := smtpRelay(t, mode, tc.behavior)
				transport, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if transport.tlsConfig.InsecureSkipVerify || transport.tlsConfig.MinVersion < tls.VersionTLS12 || transport.tlsConfig.ServerName != cfg.Host {
					t.Fatal("TLS verification was relaxed")
				}
				message := []byte("To: <" + tc.recipient + ">\r\nSubject: Verification\r\n\r\nprivate-token\r\n")
				err = transport.Send(t.Context(), tc.recipient, message)
				result := captureRelay(t, results)
				if tc.accepted {
					// DotReader removes SMTP framing and normalizes CRLF to LF.
					if err != nil || !bytes.Equal(result.message, bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n"))) {
						t.Fatal("supported exact message was not accepted", err)
					}
					hellos, auths, mails, rcpts := 0, 0, 0, 0
					for _, command := range result.commands {
						switch {
						case strings.HasPrefix(command, "EHLO "):
							hellos++
						case strings.HasPrefix(command, "AUTH "):
							auths++
						case strings.HasPrefix(command, "MAIL "):
							mails++
							want := "MAIL FROM:<" + cfg.From + ">"
							if tc.behavior.postUTF8 {
								want += " SMTPUTF8"
							}
							if command != want {
								t.Fatal("incorrect MAIL SMTPUTF8 negotiation")
							}
						case strings.HasPrefix(command, "RCPT "):
							rcpts++
							if command != "RCPT TO:<"+tc.recipient+">" {
								t.Fatal("bound recipient was changed")
							}
						}
					}
					wantHellos := 1
					if mode == StartTLS {
						wantHellos = 2
					}
					if hellos != wantHellos || auths != 1 || mails != 1 || rcpts != 1 {
						t.Fatal("missing post-TLS EHLO or duplicate transaction")
					}
				} else {
					var failure *Error
					if !errors.As(err, &failure) || failure.stage != "smtputf8_required" || failure.Permanent() || len(result.message) != 0 {
						t.Fatal("unsupported EAI was accepted or misclassified")
					}
					for _, command := range result.commands {
						if strings.HasPrefix(command, "AUTH ") || strings.HasPrefix(command, "MAIL ") || strings.HasPrefix(command, "RCPT ") || command == "DATA" {
							t.Fatal("secrets/addresses submitted before capability admission")
						}
					}
				}
			})
		}
	}
}

func TestSendClassifiedRedactedACKAndNoRetry(t *testing.T) {
	for _, tc := range []struct {
		name      string
		behavior  relayBehavior
		permanent bool
	}{
		{"lost ACK", relayBehavior{lostACK: true}, false},
		{"negative ACK", relayBehavior{failStage: "ack", failCode: 554}, true},
		{"temporary ACK", relayBehavior{failStage: "ack", failCode: 451}, false},
		{"malformed ACK", relayBehavior{failStage: "ack", failCode: 99}, false},
		{"recipient failure", relayBehavior{failStage: "RCPT", failCode: 550}, true},
		{"auth operator repair", relayBehavior{failStage: "AUTH", failCode: 535}, false},
		{"oversized reply", relayBehavior{oversized: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, results := smtpRelay(t, StartTLS, tc.behavior)
			transport, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = transport.Send(t.Context(), "private-recipient@example.test", []byte("private-token\r\n"))
			var failure *Error
			if !errors.As(err, &failure) || failure.Permanent() != tc.permanent || errors.Unwrap(err) != nil {
				t.Fatal("failure classification or redaction changed")
			}
			for _, sentinel := range []string{"private-recipient", "private-token", "private-relay-reply", cfg.Username, cfg.Password} {
				if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), sentinel) {
					t.Fatal("error retains confidential material")
				}
			}
			result := captureRelay(t, results)
			if tc.behavior.lostACK && len(result.message) == 0 {
				t.Fatal("lost-ACK test never sent data")
			}
			mails := 0
			for _, command := range result.commands {
				if strings.HasPrefix(command, "MAIL ") {
					mails++
				}
			}
			if mails > 1 {
				t.Fatal("transport retried automatically")
			}
		})
	}
}

func TestSendValidationBeforeDial(t *testing.T) {
	transport, err := New(Config{Host: "127.0.0.1", Port: 1, TLSMode: StartTLS, Username: "user", Password: "pass",
		From: "accounts@example.test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, recipient := range []string{"a\r\n@example.test", "a\u200cb@example.test", "a\xff@example.test", "ae\u0301@example.test", "a@b\u00fccher.example"} {
		var failure *Error
		if err := transport.Send(t.Context(), recipient, []byte("body")); !errors.As(err, &failure) || failure.stage != "recipient_validation" || !failure.Permanent() {
			t.Fatal("invalid bound recipient reached network")
		}
	}
	for _, message := range [][]byte{nil, bytes.Repeat([]byte("x"), MaxMessageBytes+1)} {
		var failure *Error
		if err := transport.Send(t.Context(), "a@example.test", message); !errors.As(err, &failure) || failure.stage != "message_validation" || !failure.Permanent() {
			t.Fatal("invalid message reached network")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := transport.Send(ctx, "a@example.test", []byte("body")); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context was lost")
	}
}

func TestSendMessageByteBoundaryAndDotFraming(t *testing.T) {
	cfg, results := smtpRelay(t, StartTLS, relayBehavior{})
	transport, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte(".private-token\r\n" + strings.Repeat("x", MaxMessageBytes-len(".private-token\r\n")-2) + "\r\n")
	if len(message) != MaxMessageBytes {
		t.Fatal("invalid boundary fixture")
	}
	if err := transport.Send(t.Context(), "user@example.test", message); err != nil {
		t.Fatal("maximum bounded message rejected", err)
	}
	result := captureRelay(t, results)
	if !bytes.Equal(result.message, bytes.ReplaceAll(message, []byte("\r\n"), []byte("\n"))) {
		t.Fatal("SMTP dot framing changed message content")
	}
}

func TestConfigMaintainsStrictASCIIAndTLSBounds(t *testing.T) {
	base := Config{Host: "localhost", Port: 587, TLSMode: StartTLS, Username: "user", Password: "pass",
		From: "accounts@example.test", Timeout: time.Second}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Host = "LOCALHOST" }, func(c *Config) { c.Host = "host\u200b.test" },
		func(c *Config) { c.Host = "::ffff:127.0.0.1" }, func(c *Config) { c.Host = "fe80::1%eth0" },
		func(c *Config) { c.Port = 0 }, func(c *Config) { c.Port = 65536 }, func(c *Config) { c.TLSMode = "plain" },
		func(c *Config) { c.Username = "user\u06cc" }, func(c *Config) { c.Username = "user name" },
		func(c *Config) { c.Password = "pass\u06cc" }, func(c *Config) { c.Password = " " },
		func(c *Config) { c.From = "\u0639\u0644\u06cc@example.test" }, func(c *Config) { c.From = "a@b\u00fccher.example" },
		func(c *Config) { c.From = "a@example.test\r\nBcc: other@example.test" },
		func(c *Config) { c.Timeout = 0 }, func(c *Config) { c.Timeout = time.Minute + 1 },
		func(c *Config) { c.CABundlePath = " private-path " },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := New(cfg); err == nil || err.Error() != "smtp transport: invalid configuration" {
			t.Fatal("unsafe direct config accepted or raw diagnostic returned")
		}
	}
}

type failedFlush struct {
	*bytes.Reader
	writes int
}

func (f *failedFlush) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == 1 { // DATA command succeeds; the small message fails at Close/flush.
		return len(p), nil
	}
	return 0, errors.New("private-token write failed")
}
func (*failedFlush) Close() error { return nil }

func TestDATAFlushFailureCannotUseBufferedPositiveACK(t *testing.T) {
	conn := &failedFlush{Reader: bytes.NewReader([]byte("354 send message\r\n250 accepted early\r\n"))}
	wire := textproto.NewConn(conn)
	var failure *Error
	err := sendData(t.Context(), wire, []byte("private-token\r\n"))
	if !errors.As(err, &failure) || failure.stage != "write" || failure.Permanent() || conn.writes != 2 {
		t.Fatal("buffered ACK concealed DATA flush failure")
	}
	if strings.Contains(err.Error(), "private-token") || errors.Unwrap(err) != nil {
		t.Fatal("flush diagnostic exposed message material")
	}
}

func assertProbeOnly(t *testing.T, result relayResult) {
	t.Helper()
	if len(result.message) != 0 {
		t.Fatal("readiness probe transmitted message data")
	}
	for _, command := range result.commands {
		verb, _, _ := strings.Cut(command, " ")
		if verb == "MAIL" || verb == "RCPT" || verb == "DATA" || strings.Contains(command, "accounts@example.test") {
			t.Fatal("readiness probe started a mail transaction")
		}
	}
}

func TestCheckAuthenticatedPostTLSCapabilityWithoutMail(t *testing.T) {
	for _, mode := range []string{StartTLS, Implicit} {
		for _, tc := range []struct {
			name    string
			utf8    bool
			feature bool
		}{
			{"required SMTPUTF8 supported", true, true},
			{"ASCII-only relay allowed", false, false},
			{"ASCII probe capable relay", false, true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				cfg, results := smtpRelay(t, mode, relayBehavior{postUTF8: tc.feature})
				transport, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := transport.Check(t.Context(), tc.utf8); err != nil {
					t.Fatal("supported authenticated readiness rejected", err)
				}
				result := captureRelay(t, results)
				assertProbeOnly(t, result)
				hellos, auths, upgrades := 0, 0, 0
				for _, command := range result.commands {
					verb, _, _ := strings.Cut(command, " ")
					switch verb {
					case "EHLO":
						hellos++
					case "AUTH":
						auths++
					case "STARTTLS":
						upgrades++
					default:
						t.Fatal("unexpected command during message-free readiness")
					}
				}
				wantHellos, wantUpgrades := 1, 0
				if mode == StartTLS {
					wantHellos, wantUpgrades = 2, 1
				}
				if hellos != wantHellos || upgrades != wantUpgrades || auths != 1 {
					t.Fatal("probe skipped post-TLS EHLO/auth or retried negotiation")
				}
			})
		}
	}
}

func TestCheckFailuresAreMessageFreeRedactedAndFailClosed(t *testing.T) {
	for _, mode := range []string{StartTLS, Implicit} {
		for _, tc := range []struct {
			name        string
			behavior    relayBehavior
			untrusted   bool
			stage       string
			authAttempt bool
		}{
			{"missing SMTPUTF8", relayBehavior{}, false, "smtputf8_required", false},
			{"pre-TLS feature discarded", relayBehavior{preUTF8: true}, false, "smtputf8_required", false},
			{"missing AUTH", relayBehavior{postUTF8: true, noAuth: true}, false, "authentication_required", false},
			{"unsupported AUTH", relayBehavior{postUTF8: true, noPlain: true}, false, "authentication_required", false},
			{"rejected credentials", relayBehavior{postUTF8: true, failStage: "AUTH", failCode: 535}, false, "authentication", true},
			{"wrong hostname", relayBehavior{postUTF8: true, wrongHost: true}, false, "", false},
			{"expired certificate", relayBehavior{postUTF8: true, expired: true}, false, "", false},
			{"untrusted certificate", relayBehavior{postUTF8: true}, true, "", false},
			{"legacy TLS refused", relayBehavior{postUTF8: true, legacyTLS: true}, false, "", false},
			{"oversized greeting", relayBehavior{postUTF8: true, oversized: true}, false, "", false},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				cfg, results := smtpRelay(t, mode, tc.behavior)
				if tc.untrusted {
					cfg.CABundlePath = ""
				}
				transport, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				err = transport.Check(t.Context(), true)
				var failure *Error
				if !errors.As(err, &failure) || failure.Permanent() || errors.Unwrap(err) != nil || tc.stage != "" && failure.stage != tc.stage {
					t.Fatal("unsafe probe succeeded or classification changed", err)
				}
				for _, private := range []string{cfg.Username, cfg.Password, "private-relay-reply", "private-token"} {
					if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), private) {
						t.Fatal("probe diagnostic retained confidential material")
					}
				}
				result := captureRelay(t, results)
				assertProbeOnly(t, result)
				auths := 0
				for _, command := range result.commands {
					if strings.HasPrefix(command, "AUTH ") {
						auths++
					}
				}
				wantAuths := 0
				if tc.authAttempt {
					wantAuths = 1
				}
				if auths != wantAuths {
					t.Fatal("credentials transmitted before verified capability admission or auth retried")
				}
			})
		}
	}
	for _, behavior := range []relayBehavior{
		{noStartTLS: true, postUTF8: true}, {failStage: "STARTTLS", failCode: 454, postUTF8: true},
		{failStage: "EHLO", failCode: 500, postUTF8: true},
	} {
		cfg, results := smtpRelay(t, StartTLS, behavior)
		transport, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := transport.Check(t.Context(), true); err == nil {
			t.Fatal("probe accepted insecure TLS/EHLO downgrade")
		}
		result := captureRelay(t, results)
		assertProbeOnly(t, result)
		for _, command := range result.commands {
			if strings.HasPrefix(command, "AUTH ") {
				t.Fatal("probe authenticated after insecure downgrade")
			}
		}
	}
}

func TestCheckCancellationAndTimeoutBoundAllNegotiation(t *testing.T) {
	for _, mode := range []string{StartTLS, Implicit} {
		for _, stage := range []string{"greeting", "tls", "ehlo", "posttls_ehlo", "auth"} {
			for _, cancellation := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cancel=%v", mode, stage, cancellation), func(t *testing.T) {
					reached := make(chan string, 1)
					cfg, captures := smtpRelay(t, mode, relayBehavior{postUTF8: true, stallStage: stage, reached: reached})
					cfg.Timeout = 100 * time.Millisecond
					if cancellation {
						cfg.Timeout = time.Second
					}
					transport, err := New(cfg)
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					result := make(chan error, 1)
					go func() { result <- transport.Check(ctx, true) }()
					select {
					case <-reached:
					case <-time.After(time.Second):
						t.Fatal("probe never reached selected protocol boundary")
					}
					want := context.DeadlineExceeded
					if cancellation {
						cancel()
						want = context.Canceled
					}
					select {
					case err := <-result:
						if !errors.Is(err, want) {
							t.Fatal("probe ignored deadline/cancellation", err)
						}
					case <-time.After(time.Second):
						t.Fatal("probe exceeded bounded negotiation")
					}
					assertProbeOnly(t, captureRelay(t, captures))
				})
			}
		}
	}
	transport, err := New(Config{Host: "127.0.0.1", Port: 1, TLSMode: StartTLS, Username: "user", Password: "pass",
		From: "accounts@example.test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := transport.Check(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled probe attempted negotiation")
	}
	for _, bound := range []time.Duration{0, 50 * time.Millisecond} {
		cfg, captures := smtpRelay(t, StartTLS, relayBehavior{postUTF8: true, stallStage: "auth"})
		transport, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), bound)
		err = transport.Check(ctx, true)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("probe ignored caller's earlier deadline")
		}
		if bound > 0 {
			assertProbeOnly(t, captureRelay(t, captures))
		}
	}
}
