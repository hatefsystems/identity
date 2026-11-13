package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthy(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
			}))
			defer server.Close()
			port := server.Listener.Addr().(*net.TCPAddr).Port
			if got := healthy(port); got != (status == http.StatusOK) {
				t.Fatalf("healthy returned %v for HTTP %d", got, status)
			}
		})
	}
}

func TestInvalidPort(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if healthy(port) {
			t.Fatalf("invalid port %d accepted", port)
		}
	}
}
