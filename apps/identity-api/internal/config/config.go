// Package config loads runtime configuration for the identity-api service
// exclusively from environment variables. No secrets or credentials are ever
// hardcoded here (see Definition of Done #3); sensitive values are expected to
// be injected at runtime via the KMS/secrets manager (Infisical) or the
// container environment.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Default configuration values. The HTTP port defaults to 8080 to match the
// reverse-proxy routing defined in the DevOps playbook (Nginx/Traefik forward
// /api, /.well-known and /oauth2 to the Go backend on :8080).
const (
	defaultHost            = "0.0.0.0"
	defaultPort            = 8080
	defaultReadTimeout     = 10 * time.Second
	defaultWriteTimeout    = 10 * time.Second
	defaultIdleTimeout     = 60 * time.Second
	defaultShutdownTimeout = 15 * time.Second

	// Session defaults: 24h absolute lifetime, 2h idle window, __Host- prefix
	// with Secure=true for production. Set SESSION_COOKIE_SECURE=false and
	// SESSION_COOKIE_NAME to a non-prefixed name for plain-HTTP local dev.
	defaultSessionCookieName   = "__Host-session"
	defaultSessionCookieSecure = true
	defaultSessionAbsoluteTTL  = 24 * time.Hour
	defaultSessionIdleTTL      = 2 * time.Hour
)

// EnvTrustedProxyCIDRs names the comma-separated CIDR allow-list of immediate
// reverse-proxy peers whose X-Forwarded-For chains the server may trust.
const EnvTrustedProxyCIDRs = "TRUSTED_PROXY_CIDRS"

// Config holds the runtime configuration for the HTTP server.
type Config struct {
	// Host is the network interface the server binds to.
	Host string
	// Port is the TCP port the HTTP server listens on.
	Port int
	// Environment identifies the deployment environment (e.g. "development",
	// "production"). It is informational and used for readiness reporting.
	Environment string
	// TrustedProxyCIDRs contains the immediate reverse-proxy networks allowed to
	// assert X-Forwarded-For. An empty slice is the secure default: all forwarding
	// headers are ignored and the socket peer is treated as the client.
	TrustedProxyCIDRs []netip.Prefix
	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration
	// IdleTimeout is the maximum time to wait for the next request on a keep-alive connection.
	IdleTimeout time.Duration
	// ShutdownTimeout bounds how long graceful shutdown waits for in-flight requests.
	ShutdownTimeout time.Duration
	// Admin bounds the administrative REST surface at /api/v1/admin/*. It
	// lives on the base Config rather than being handed to a service because
	// the values are consumed by the HTTP handlers themselves (page sizes,
	// time windows), not by any domain package.
	Admin AdminConfig
}

// Addr returns the host:port address string the server should listen on.
func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// SessionConfig holds the stateful-session cookie and lifetime policy. The
// cookie is hardened per docs/architecture.md ("Session Management & Transport
// Hardening"): the __Host- name prefix plus Secure pin it to the exact origin.
type SessionConfig struct {
	// CookieName is the session cookie name. In production it must carry the
	// __Host- prefix, which the browser only honors alongside Secure=true.
	CookieName string
	// CookieSecure sets the cookie Secure attribute. It must be true whenever
	// CookieName uses the __Host- prefix; it is only disabled for plain-HTTP
	// local development (with a non-prefixed cookie name).
	CookieSecure bool
	// AbsoluteTTL is the hard ceiling on a session's lifetime regardless of
	// activity; it also bounds the cookie MaxAge.
	AbsoluteTTL time.Duration
	// IdleTTL is the inactivity window after which a session lapses. It must
	// not exceed AbsoluteTTL.
	IdleTTL time.Duration
}

// LoadSession builds the SessionConfig from environment variables, applying the
// production-safe defaults (24h absolute, 2h idle, __Host- prefixed Secure
// cookie). It fails fast on a malformed value or an idle window that exceeds
// the absolute window; the __Host-/Secure invariant itself is enforced when the
// cookie codec is constructed.
func LoadSession() (SessionConfig, error) {
	secure, err := getEnvBool("SESSION_COOKIE_SECURE", defaultSessionCookieSecure)
	if err != nil {
		return SessionConfig{}, err
	}

	absoluteTTL, err := getEnvDuration("SESSION_ABSOLUTE_TTL", defaultSessionAbsoluteTTL)
	if err != nil {
		return SessionConfig{}, err
	}

	idleTTL, err := getEnvDuration("SESSION_IDLE_TTL", defaultSessionIdleTTL)
	if err != nil {
		return SessionConfig{}, err
	}

	if idleTTL > absoluteTTL {
		return SessionConfig{}, fmt.Errorf(
			"config: SESSION_IDLE_TTL %v must not exceed SESSION_ABSOLUTE_TTL %v", idleTTL, absoluteTTL)
	}

	return SessionConfig{
		CookieName:   getEnv("SESSION_COOKIE_NAME", defaultSessionCookieName),
		CookieSecure: secure,
		AbsoluteTTL:  absoluteTTL,
		IdleTTL:      idleTTL,
	}, nil
}

// Load builds a Config from environment variables, applying sane defaults for
// any value that is not set. It returns an error only when a provided value is
// malformed (e.g. a non-numeric PORT), so that misconfiguration fails fast at
// startup rather than surfacing as confusing runtime behavior.
func Load() (Config, error) {
	cfg := Config{
		Host:            getEnv("HOST", defaultHost),
		Port:            defaultPort,
		Environment:     getEnv("APP_ENV", "development"),
		ReadTimeout:     defaultReadTimeout,
		WriteTimeout:    defaultWriteTimeout,
		IdleTimeout:     defaultIdleTimeout,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if raw, ok := os.LookupEnv("PORT"); ok && raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("config: invalid PORT %q: %w", raw, err)
		}
		if port < 1 || port > 65535 {
			return Config{}, fmt.Errorf("config: PORT %d out of range (1-65535)", port)
		}
		cfg.Port = port
	}

	trustedProxyCIDRs, err := parseTrustedProxyCIDRs(os.Getenv(EnvTrustedProxyCIDRs))
	if err != nil {
		return Config{}, err
	}
	cfg.TrustedProxyCIDRs = trustedProxyCIDRs
	cfg.Admin, err = LoadAdmin()
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// parseTrustedProxyCIDRs parses the explicit trust boundary for forwarded
// client addresses. Host addresses without a prefix and empty list entries are
// rejected rather than guessed. Universal /0 prefixes are also rejected: they
// would make every direct Internet client a trusted proxy and allow trivial IP
// spoofing of rate limits and audit records.
func parseTrustedProxyCIDRs(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for i, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("config: invalid %s entry %d: empty CIDR", EnvTrustedProxyCIDRs, i+1)
		}

		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("config: invalid %s entry %q: %w", EnvTrustedProxyCIDRs, value, err)
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("config: invalid %s entry %q: universal /0 prefixes are not allowed", EnvTrustedProxyCIDRs, value)
		}

		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// getEnv returns the value of the environment variable named by key, or
// fallback when the variable is unset or empty.
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// getEnvBool parses a boolean environment variable, returning fallback when it
// is unset or empty and an error when it is set to an unparseable value (so a
// typo like SESSION_COOKIE_SECURE=yes fails fast rather than silently
// disabling Secure).
func getEnvBool(key string, fallback bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: invalid %s %q: %w", key, raw, err)
	}
	return v, nil
}

// getEnvDuration parses a Go duration string (e.g. "24h", "30m") from the named
// environment variable, returning fallback when unset/empty and an error when
// the value is unparseable or non-positive.
func getEnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s %q: %w", key, raw, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("config: %s %v must be positive", key, v)
	}
	return v, nil
}
