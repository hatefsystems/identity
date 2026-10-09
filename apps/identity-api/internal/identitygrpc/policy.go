package identitygrpc

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type validationPolicy struct {
	audiences map[string]struct{}
	origins   map[string]struct{}
}

var errInvalidResourceURI = errors.New("invalid resource URI")

func copyPolicies(input map[string]ValidationPolicy, allowHTTP bool) (map[spiffeid.ID]validationPolicy, error) {
	policies := make(map[spiffeid.ID]validationPolicy, len(input))
	for rawID, entry := range input {
		id, err := spiffeid.FromString(rawID)
		if err != nil || id.Path() == "" || len(rawID) > maxContextLength || id.String() != rawID {
			return nil, errors.New("identitygrpc: invalid workload identity in validation policy")
		}
		if len(entry.Audiences) == 0 {
			return nil, errors.New("identitygrpc: validation policy requires an audience")
		}
		policy := validationPolicy{audiences: make(map[string]struct{}, len(entry.Audiences)), origins: make(map[string]struct{}, len(entry.Origins))}
		for _, audience := range entry.Audiences {
			if !validAudience(audience) {
				return nil, errors.New("identitygrpc: invalid audience in validation policy")
			}
			policy.audiences[audience] = struct{}{}
		}
		for _, rawOrigin := range entry.Origins {
			u, origin, err := resourceURI(rawOrigin, allowHTTP)
			if err != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || rawOrigin != origin {
				return nil, errors.New("identitygrpc: validation policy requires canonical resource origins")
			}
			policy.origins[origin] = struct{}{}
		}
		policies[id] = policy
	}
	return policies, nil
}

func validAudience(value string) bool {
	return value != "" && len(value) <= maxContextLength && utf8.ValidString(value) &&
		!strings.ContainsAny(value, "*\\") && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func validHTTPMethod(method string) bool {
	if len(method) == 0 || len(method) > 64 {
		return false
	}
	for i := range len(method) {
		c := method[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// resourceURI validates an independently observed absolute HTTP URI and returns
// its canonical origin. No DNS lookup or network request is involved.
func resourceURI(raw string, allowHTTP bool) (*url.URL, string, error) {
	invalid := errInvalidResourceURI
	if raw == "" || len(raw) > maxContextLength || strings.ContainsAny(raw, "#\\") {
		return nil, "", invalid
	}
	for i := range len(raw) {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return nil, "", invalid
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || strings.HasSuffix(u.Host, ":") ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return nil, "", invalid
	}
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return nil, "", invalid
	}
	host := strings.ToLower(u.Hostname())
	ip, ipErr := netip.ParseAddr(host)
	if strings.HasPrefix(u.Host, "[") != (ipErr == nil && ip.Is6()) {
		return nil, "", invalid
	}
	if ipErr == nil {
		if ip.Zone() != "" {
			return nil, "", invalid
		}
		host = ip.String()
	} else {
		if host == "" || len(host) > 253 {
			return nil, "", invalid
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, "", invalid
			}
			for i := range len(label) {
				c := label[i]
				if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
					return nil, "", invalid
				}
			}
		}
	}
	loopback := host == "localhost" || ipErr == nil && ip.Unmap().IsLoopback()
	if u.Scheme == "http" && (!allowHTTP || !loopback) {
		return nil, "", invalid
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, "", invalid
		}
		port = strconv.FormatUint(n, 10)
		if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
			port = ""
		}
	}
	authority := host
	if port != "" {
		authority = net.JoinHostPort(host, port)
	} else if ipErr == nil && ip.Is6() {
		authority = "[" + host + "]"
	}
	return u, u.Scheme + "://" + authority, nil
}
