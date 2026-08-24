// Package clientip resolves the network address used for security decisions.
// Forwarded addresses are accepted only from explicitly trusted socket peers;
// direct clients can therefore never choose their own rate-limit or audit IP.
package clientip

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

const maxForwardedForEntries = 16

type contextKey struct{}

// Middleware resolves the client address once and stores the bare IP in the
// request context. It deliberately leaves Request.RemoteAddr untouched so the
// original transport peer remains available for diagnostics and trust checks.
//
// X-Forwarded-For is considered only when the immediate socket peer belongs to
// trustedProxyCIDRs. The chain is walked from right to left, skipping trusted
// proxy hops and selecting the first untrusted address. X-Real-IP and
// True-Client-IP are intentionally ignored.
func Middleware(trustedProxyCIDRs []netip.Prefix) func(http.Handler) http.Handler {
	trusted := append([]netip.Prefix(nil), trustedProxyCIDRs...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, ok := parseRemoteAddr(r.RemoteAddr)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			resolved := peer
			if contains(trusted, peer) {
				resolved = resolveForwardedFor(peer, r.Header.Values("X-Forwarded-For"), trusted)
			}

			ctx := context.WithValue(r.Context(), contextKey{}, resolved)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the resolved bare client IP stored by Middleware.
func FromContext(ctx context.Context) (netip.Addr, bool) {
	if ctx == nil {
		return netip.Addr{}, false
	}
	addr, ok := ctx.Value(contextKey{}).(netip.Addr)
	return addr, ok && addr.IsValid()
}

// FromRequest returns the resolved client IP as a bare address string. When a
// handler is exercised without Middleware (for example, in a focused unit
// test), it safely falls back to the untrusted socket peer and never consults
// forwarding headers.
func FromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if addr, ok := FromContext(r.Context()); ok {
		return addr.String()
	}
	if addr, ok := parseRemoteAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return ""
}

func resolveForwardedFor(peer netip.Addr, headerValues []string, trusted []netip.Prefix) netip.Addr {
	if len(headerValues) == 0 {
		return peer
	}

	entries := strings.Split(strings.Join(headerValues, ","), ",")
	if len(entries) == 0 || len(entries) > maxForwardedForEntries {
		return peer
	}

	for i := len(entries) - 1; i >= 0; i-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			// A malformed hop between the socket peer and the first untrusted
			// address makes the asserted chain unusable. Fall back to the peer.
			return peer
		}
		candidate = normalize(candidate)
		if !contains(trusted, candidate) {
			return candidate
		}
	}

	// An all-trusted chain has no independently attributable client address.
	return peer
}

func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	raw := strings.TrimSpace(remoteAddr)
	if raw == "" {
		return netip.Addr{}, false
	}

	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return normalize(addrPort.Addr()), true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalize(addr), true
}

func normalize(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}
