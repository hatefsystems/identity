// Command healthcheck probes the local API without adding a shell to its image.
package main

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

func healthy(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	client := &http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	// #nosec G704 -- Fixed loopback host/path and a range-checked integer port; proxies and redirects are disabled.
	response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/readyz")
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode == http.StatusOK
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || !healthy(parsed) {
		os.Exit(1)
	}
}
