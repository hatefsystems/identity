package smsir

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "unit-test-only-never-a-provider-key"
const success = `{"status":1,"message":"ignored-private-body","data":{"messageId":42,"cost":1.0}}`

// Route the fixed provider hostname to controlled TLS while retaining URL/Host.
func tlsSender(t *testing.T, handler http.HandlerFunc) (*Sender, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	sender, err := New(Config{testKey, 42, "Code"})
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	sender.client.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)
	return sender, server
}
func TestSMSIRExactVerifyContract(t *testing.T) {
	sender, _ := tlsSender(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/send/verify" || r.Host != "api.sms.ir" || r.URL.RawQuery != "" {
			t.Error("wrong request target")
		}
		if r.Header.Get("X-API-Key") != testKey || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Error("wrong headers")
		}
		var body struct {
			Mobile     string                         `json:"mobile"`
			TemplateID int64                          `json:"templateId"`
			Parameters []struct{ Name, Value string } `json:"parameters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Mobile != "9123456789" || body.TemplateID != 42 || len(body.Parameters) != 1 || body.Parameters[0].Name != "Code" || body.Parameters[0].Value != "000042" {
			t.Error("payload contract mismatch")
		}
		if _, err := fmt.Fprint(w, success); err != nil {
			t.Error(err)
		}
	})
	if sender.client.Timeout != 5*time.Second {
		t.Fatal("unbounded timeout")
	}
	if err := sender.SendCode(context.Background(), "+989123456789", "000042"); err != nil {
		t.Fatal(err)
	}
}
func TestSMSIRRejectsInvalidInputsWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	sender, _ := tlsSender(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if _, err := fmt.Fprint(w, success); err != nil {
			t.Error(err)
		}
	})
	for _, phone := range []string{"+15550102020", "09123456789", "+98912345678", "+9891234567890", "+98912345678a"} {
		if err := sender.SendCode(context.Background(), phone, "000042"); err == nil {
			t.Fatal("invalid mobile accepted")
		}
	}
	for _, code := range []string{"42", "00004x", "0000042", " 000042"} {
		if err := sender.SendCode(context.Background(), "+989123456789", code); err == nil {
			t.Fatal("invalid code accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input made a request")
	}
}
func TestSMSIRFailuresAreTypedRedactedAndNotRetried(t *testing.T) {
	cases := []struct {
		status int
		body   string
		reason Reason
	}{
		{400, success, Rejected}, {401, success, Credentials}, {429, success, Throttle}, {500, success, Unavailable},
		{200, `{"status":1,"data":{"messageId":0,"cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":-1,"cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":1.2,"cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":"42","cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":9223372036854775808,"cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":42,"cost":-1}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":42,"cost":"0"}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":42,"cost":null}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":42,"cost":1e999}}`, Rejected},
		{200, `{"status":1.0,"data":{"messageId":42,"cost":0}}`, Rejected},
		{200, `{"status":null}`, Rejected}, {200, `{"status":1}`, Rejected},
		{200, `{"status":10,"status":1,"data":{"messageId":42,"cost":0}}`, Rejected},
		{200, `{"status":1,"STATUS":1,"data":{"messageId":42,"cost":0}}`, Rejected},
		{200, `{"status":1,"data":{"messageId":0,"messageId":42,"cost":0}}`, Rejected},
		{200, success + ` {}`, Rejected}, {200, `private-body ` + testKey, Rejected},
		{200, strings.Repeat("p", responseLimit+1), Unavailable},
	}
	for _, status := range []int64{0, 10, 11, 12, 13, 14, 20, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 123, 999} {
		cases = append(cases, struct {
			status int
			body   string
			reason Reason
		}{200, fmt.Sprintf(`{"status":%d,"message":"private-body %s"}`, status, testKey), classify(status)})
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var calls atomic.Int32
			sender, _ := tlsSender(t, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				if _, err := fmt.Fprint(w, tc.body); err != nil {
					t.Error(err)
				}
			})
			err := sender.SendCode(context.Background(), "+989123456789", "000042")
			var classified *Error
			if !errors.As(err, &classified) || classified.Reason != tc.reason || calls.Load() != 1 {
				t.Fatalf("unexpected fixed failure: %v", err)
			}
			for _, secret := range []string{testKey, "private-body", "+989123456789", "000042"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("private data leaked")
				}
			}
		})
	}
}
func TestSMSIRNeverFollowsRedirects(t *testing.T) {
	for _, status := range []int{300, 301, 302, 303, 304, 305, 306, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var targetCalls atomic.Int32
			target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
			defer target.Close()
			sender, _ := tlsSender(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
				if _, err := fmt.Fprint(w, success); err != nil && (status != http.StatusNotModified || !errors.Is(err, http.ErrBodyNotAllowed)) {
					t.Error(err)
				}
			})
			if err := sender.SendCode(context.Background(), "+989123456789", "000042"); err == nil {
				t.Fatal("redirect accepted")
			}
			if targetCalls.Load() != 0 {
				t.Fatal("redirect target received request/key")
			}
		})
	}
}
func TestSMSIRTLSAndCancellationFailClosed(t *testing.T) {
	sender, _ := tlsSender(t, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := fmt.Fprint(w, success); err != nil {
			t.Error(err)
		}
	})
	sender.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if err := sender.SendCode(context.Background(), "+989123456789", "000042"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sender.SendCode(ctx, "+989123456789", "000042"); err == nil {
		t.Fatal("cancelled send accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSMSIRTransportErrorsHaveNoReplayBodyOrRawDiagnostic(t *testing.T) {
	sender, err := New(Config{testKey, 42, "Code"})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	sender.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.GetBody != nil {
			t.Error("SMS request body can be automatically replayed")
		}
		return nil, errors.New("private-key private-phone private-provider-body")
	})
	err = sender.SendCode(context.Background(), "+989123456789", "000042")
	if calls != 1 || err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("transport retried or leaked raw diagnostic")
	}
}
