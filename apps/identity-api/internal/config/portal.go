package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// EnvPortalOrigin names the canonical first-party browser origin setting.
const EnvPortalOrigin = "PORTAL_ORIGIN"

// LoadPortal pins the browser proof/Origin boundary to trusted configuration,
// never to Host or forwarding headers. An issuer may have a path; its origin
// must still be exactly the origin used for first-party browser ceremonies.
func LoadPortal(environment, issuer string, webauthnOrigins []string) (string, error) {
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.User != nil || issuerURL.Opaque != "" || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return "", errors.New("config: invalid issuer for portal origin")
	}
	issuerOrigin, err := canonicalPortalOrigin(issuerURL.Scheme+"://"+issuerURL.Host, environment)
	if err != nil {
		return "", err
	}
	origin := os.Getenv(EnvPortalOrigin)
	if origin == "" && environment == "development" {
		origin = issuerOrigin
	}
	if origin == "" {
		return "", fmt.Errorf("config: %s is required outside development", EnvPortalOrigin)
	}
	origin, err = canonicalPortalOrigin(origin, environment)
	if err != nil {
		return "", err
	}
	if origin != issuerOrigin {
		return "", errors.New("config: PORTAL_ORIGIN must match the OIDC issuer origin")
	}
	for _, allowed := range webauthnOrigins {
		if allowed == origin {
			return origin, nil
		}
	}
	return "", errors.New("config: PORTAL_ORIGIN must be an allowed WebAuthn origin")
}

func canonicalPortalOrigin(raw, environment string) (string, error) {
	invalid := errors.New("config: PORTAL_ORIGIN must be a canonical HTTPS origin (local HTTP is development-only)")
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" || u.Path != "" || u.RawPath != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") || strings.TrimSpace(raw) != raw {
		return "", invalid
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", invalid
	}
	host := u.Hostname()
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return "", invalid
	}
	local := host == "localhost"
	canonicalHost := host
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" || address.Is4In6() {
			return "", invalid
		}
		local = address.IsLoopback()
		canonicalHost = address.String()
		if address.Is6() {
			canonicalHost = "[" + canonicalHost + "]"
		}
	} else {
		if len(host) > 253 {
			return "", invalid
		}
		labels := strings.Split(host, ".")
		// WHATWG URLs interpret numeric final labels as IPv4, accepting spellings
		// such as 127.1, 0177.0.0.1 and 0x7f000001. Only netip's canonical IPv4
		// branch above can admit them without disagreeing with browser Origin.
		last := labels[len(labels)-1]
		hex := strings.HasPrefix(last, "0x")
		if hex {
			last = last[2:]
		}
		numeric := true
		for _, c := range last {
			if (c < '0' || c > '9') && (!hex || c < 'a' || c > 'f') {
				numeric = false
			}
		}
		if numeric {
			return "", invalid
		}
		for _, label := range labels {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", invalid
			}
			for _, c := range label {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
					return "", invalid
				}
			}
		}
	}
	if u.Scheme == "http" && (environment != "development" || !local) {
		return "", invalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port ||
			(u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
			return "", invalid
		}
		canonicalHost += ":" + port
	}
	if raw != u.Scheme+"://"+canonicalHost {
		return "", invalid
	}
	return raw, nil
}
