// Package config loads runtime configuration for the identity-api service
// exclusively from environment variables. No secrets or credentials are ever
// hardcoded here (see Definition of Done #3); sensitive values are expected to
// be injected at runtime via the KMS/secrets manager (Infisical) or the
// container environment.
package config

import (
	"fmt"
	"os"
	"strconv"
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
)

// Config holds the runtime configuration for the HTTP server.
type Config struct {
	// Host is the network interface the server binds to.
	Host string
	// Port is the TCP port the HTTP server listens on.
	Port int
	// Environment identifies the deployment environment (e.g. "development",
	// "production"). It is informational and used for readiness reporting.
	Environment string
	// ReadTimeout is the maximum duration for reading the entire request.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout time.Duration
	// IdleTimeout is the maximum time to wait for the next request on a keep-alive connection.
	IdleTimeout time.Duration
	// ShutdownTimeout bounds how long graceful shutdown waits for in-flight requests.
	ShutdownTimeout time.Duration
}

// Addr returns the host:port address string the server should listen on.
func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
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

	return cfg, nil
}

// getEnv returns the value of the environment variable named by key, or
// fallback when the variable is unset or empty.
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
