// Package ratelimit implements the independent-dimension SMS OTP rate limiting
// described in docs/architecture.md ("Independent Dimension Rate Limiting") and
// docs/data-architecture.md §3.2. It provides a sliding-window limiter backed by
// Redis sorted sets (ZSET) driven by an atomic Lua script, plus the IP-subnet
// grouping (/24 for IPv4, /48 for IPv6) used to blunt proxy-rotation abuse.
package ratelimit

import (
	"fmt"
	"net"
	"net/netip"
)

// IPv4SubnetBits and IPv6SubnetBits are the prefix lengths SMS OTP requests are
// grouped into for the per-subnet rate limit. Grouping IPv4 to /24 and IPv6 to
// /48 (docs/data-architecture.md §3.2) means an attacker rotating through the
// individual addresses of a single allocation still shares one rate-limit
// bucket, defeating distributed SMS-bombing / toll-fraud (threat-modeling D2).
const (
	IPv4SubnetBits = 24
	IPv6SubnetBits = 48
)

// Subnet reduces a client IP to its rate-limiting bucket key: the /24 network
// for IPv4 and the /48 network for IPv6, returned as a canonical CIDR string
// (e.g. "203.0.113.0/24", "2001:db8::/48"). The result is the {ip_subnet}
// component of the rate:otp:subnet:{ip_subnet} Redis key.
//
// The input may be a bare IP ("203.0.113.5") or a host:port pair
// ("203.0.113.5:54321" / "[2001:db8::1]:443") as seen on http.Request.RemoteAddr;
// the port is stripped. An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is folded
// back to IPv4 so it groups with its native /24. A value that cannot be parsed
// as an IP is returned verbatim (prefixed) so a malformed source still maps to a
// stable, self-consistent bucket rather than being silently exempted.
func Subnet(ip string) string {
	if len(ip) > 128 {
		ip = ip[:128]
	}

	addr, err := parseAddr(ip)
	if err != nil {
		// Unparseable source: fall back to a stable literal bucket so it is
		// still rate-limited (fail closed) instead of bypassing the limiter.
		return "invalid/" + ip
	}

	bits := IPv6SubnetBits
	if addr.Is4() {
		bits = IPv4SubnetBits
	}

	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "invalid/" + ip
	}
	return prefix.Masked().String()
}

// parseAddr accepts a bare IP or a host:port pair and returns the unmapped
// netip.Addr. IPv4-mapped IPv6 addresses are unmapped to their IPv4 form so the
// correct (/24 vs /48) prefix length is applied.
func parseAddr(ip string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.Unmap(), nil
	}

	// Try host:port (RemoteAddr form).
	if host, _, err := net.SplitHostPort(ip); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.Unmap(), nil
		}
	}

	return netip.Addr{}, fmt.Errorf("ratelimit: cannot parse IP %q", ip)
}
