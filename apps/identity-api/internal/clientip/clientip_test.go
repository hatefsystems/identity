package clientip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func prefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func resolveRequest(t *testing.T, trusted []netip.Prefix, remoteAddr string, headers http.Header) (string, string, bool) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://identity.test/", nil)
	req.RemoteAddr = remoteAddr
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	var (
		resolved string
		stored   bool
		seenPeer string
	)
	handler := Middleware(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = FromRequest(r)
		_, stored = FromContext(r.Context())
		seenPeer = r.RemoteAddr
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return resolved, seenPeer, stored
}

func TestMiddlewareDirectPeerAndSpoofedHeaders(t *testing.T) {
	headers := http.Header{
		"X-Forwarded-For": {"203.0.113.99"},
		"X-Real-Ip":       {"203.0.113.98"},
		"True-Client-Ip":  {"203.0.113.97"},
	}
	got, remoteAddr, stored := resolveRequest(t, prefixes("10.0.0.0/8"), "198.51.100.8:43123", headers)
	if got != "198.51.100.8" {
		t.Fatalf("resolved IP = %q, want socket peer %q", got, "198.51.100.8")
	}
	if !stored {
		t.Fatal("resolved peer was not stored in context")
	}
	if remoteAddr != "198.51.100.8:43123" {
		t.Errorf("RemoteAddr mutated to %q", remoteAddr)
	}
}

func TestMiddlewareTrustedProxyUsesXForwardedFor(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		xff        []string
		want       string
	}{
		{
			name:       "single IPv4 proxy",
			trusted:    prefixes("127.0.0.0/8"),
			remoteAddr: "127.0.0.1:8080",
			xff:        []string{"198.51.100.22"},
			want:       "198.51.100.22",
		},
		{
			name:       "right to left skips trusted hops",
			trusted:    prefixes("10.0.0.0/8"),
			remoteAddr: "10.0.0.5:8080",
			xff:        []string{"198.51.100.23, 10.1.2.3, 10.4.5.6"},
			want:       "198.51.100.23",
		},
		{
			name:       "untrusted rightmost defeats spoofed leftmost",
			trusted:    prefixes("10.0.0.0/8"),
			remoteAddr: "10.0.0.5:8080",
			xff:        []string{"203.0.113.250, 198.51.100.24"},
			want:       "198.51.100.24",
		},
		{
			name:       "multiple header lines form one chain",
			trusted:    prefixes("10.0.0.0/8"),
			remoteAddr: "10.0.0.5:8080",
			xff:        []string{"198.51.100.25", "10.1.2.3"},
			want:       "198.51.100.25",
		},
		{
			name:       "IPv6 chain",
			trusted:    prefixes("2001:db8:ffff::/48"),
			remoteAddr: "[2001:db8:ffff::5]:8080",
			xff:        []string{"2001:db8:1234::9, 2001:db8:ffff::4"},
			want:       "2001:db8:1234::9",
		},
		{
			name:       "IPv4 mapped peer is normalized",
			trusted:    prefixes("127.0.0.0/8"),
			remoteAddr: "[::ffff:127.0.0.1]:8080",
			xff:        []string{"198.51.100.26"},
			want:       "198.51.100.26",
		},
		{
			name:       "all forwarded hops trusted falls back to peer",
			trusted:    prefixes("10.0.0.0/8"),
			remoteAddr: "10.0.0.5:8080",
			xff:        []string{"10.1.2.3, 10.4.5.6"},
			want:       "10.0.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for _, value := range tt.xff {
				headers.Add("X-Forwarded-For", value)
			}
			got, _, _ := resolveRequest(t, tt.trusted, tt.remoteAddr, headers)
			if got != tt.want {
				t.Errorf("resolved IP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMiddlewareIgnoresNonXForwardedHeaders(t *testing.T) {
	headers := http.Header{
		"X-Real-Ip":      {"198.51.100.31"},
		"True-Client-Ip": {"198.51.100.32"},
	}
	got, _, _ := resolveRequest(t, prefixes("127.0.0.0/8"), "127.0.0.1:8080", headers)
	if got != "127.0.0.1" {
		t.Errorf("resolved IP = %q, want trusted socket peer when XFF is absent", got)
	}
}

func TestMiddlewareMalformedForwardedChain(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{name: "malformed rightmost", xff: "198.51.100.40, not-an-ip", want: "127.0.0.1"},
		{name: "empty rightmost", xff: "198.51.100.41,", want: "127.0.0.1"},
		{
			name: "malformed value left of authoritative client is irrelevant",
			xff:  "not-an-ip, 198.51.100.42",
			want: "198.51.100.42",
		},
		{name: "host port is not a valid XFF address", xff: "198.51.100.43:9000", want: "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := resolveRequest(t, prefixes("127.0.0.0/8"), "127.0.0.1:8080", http.Header{
				"X-Forwarded-For": {tt.xff},
			})
			if got != tt.want {
				t.Errorf("resolved IP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMiddlewareForwardedChainEntryLimit(t *testing.T) {
	sixteen := make([]string, maxForwardedForEntries)
	for i := range sixteen {
		sixteen[i] = "10.0.0.1"
	}
	sixteen[0] = "198.51.100.50"

	got, _, _ := resolveRequest(t, prefixes("127.0.0.0/8", "10.0.0.0/8"), "127.0.0.1:8080", http.Header{
		"X-Forwarded-For": {strings.Join(sixteen, ",")},
	})
	if got != "198.51.100.50" {
		t.Errorf("16-entry chain resolved to %q, want %q", got, "198.51.100.50")
	}

	seventeen := append(append([]string(nil), sixteen...), "10.0.0.2")
	got, _, _ = resolveRequest(t, prefixes("127.0.0.0/8", "10.0.0.0/8"), "127.0.0.1:8080", http.Header{
		"X-Forwarded-For": {strings.Join(seventeen, ",")},
	})
	if got != "127.0.0.1" {
		t.Errorf("17-entry chain resolved to %q, want socket-peer fallback", got)
	}
}

func TestMiddlewareBareAndInvalidRemoteAddr(t *testing.T) {
	got, _, stored := resolveRequest(t, nil, "2001:db8::7", nil)
	if got != "2001:db8::7" || !stored {
		t.Errorf("bare IPv6 resolved to %q (stored=%v), want 2001:db8::7 and stored", got, stored)
	}

	got, _, stored = resolveRequest(t, prefixes("127.0.0.0/8"), "invalid-remote", http.Header{
		"X-Forwarded-For": {"198.51.100.60"},
	})
	if got != "" || stored {
		t.Errorf("invalid peer resolved to %q (stored=%v), want empty and unstored", got, stored)
	}
}

func TestFromRequestWithoutMiddlewareUsesSocketPeerOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://identity.test/", nil)
	req.RemoteAddr = "198.51.100.70:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.70")
	if got := FromRequest(req); got != "198.51.100.70" {
		t.Errorf("FromRequest = %q, want socket peer", got)
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Error("empty context unexpectedly contained a client IP")
	}
	if got := FromRequest(nil); got != "" {
		t.Errorf("FromRequest(nil) = %q, want empty", got)
	}
}
