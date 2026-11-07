// OIDC configuration loading covers the issuer URL and the three signing-key
// slots for the graceful JWKS rotation cycle (active/next/previous). Key
// material is injected via environment variables (PEM content), sourced from
// the KMS (Infisical) in production per docs/devops-operations.md — never from
// files committed to the repository.

package config

import (
	"fmt"
	"os"
	"strings"
)

// Environment variable names for the OIDC issuer and signing-key slots. The
// previous slot is optional (empty on a fresh deployment that has never
// rotated); active and next are mandatory in production.
const (
	EnvOIDCIssuer         = "OIDC_ISSUER"
	EnvOIDCSigningKey     = "OIDC_SIGNING_KEY_ACTIVE_PEM"
	EnvOIDCSigningKeyNext = "OIDC_SIGNING_KEY_NEXT_PEM"
	EnvOIDCSigningKeyPrev = "OIDC_SIGNING_KEY_PREVIOUS_PEM"
)

// defaultDevIssuer is used only in the development environment when
// OIDC_ISSUER is unset.
const defaultDevIssuer = "http://localhost:8080"

// OIDCConfig carries the issuer identity and raw PEM key material for the
// signing keystore. PEM fields hold key content, not file paths.
type OIDCConfig struct {
	// Issuer is the canonical https URL identifying this IdP; it is embedded
	// verbatim in the discovery document and all issued tokens.
	Issuer string
	// ActiveKeyPEM signs new tokens (rotation slot: active).
	ActiveKeyPEM []byte
	// NextKeyPEM is pre-generated and published ahead of use (slot: next).
	NextKeyPEM []byte
	// PreviousKeyPEM verifies outstanding unexpired tokens (slot: previous);
	// empty on a fresh deployment.
	PreviousKeyPEM []byte
}

// HasKeys reports whether externally injected key material is present for the
// two mandatory slots.
func (c OIDCConfig) HasKeys() bool {
	return len(c.ActiveKeyPEM) > 0 && len(c.NextKeyPEM) > 0
}

// LoadOIDC reads OIDC settings from the environment. In non-development
// environments the issuer and both mandatory key slots are required; in
// development a localhost issuer is defaulted and missing keys are tolerated
// (the caller falls back to ephemeral dev keys).
func LoadOIDC(environment string) (OIDCConfig, error) {
	if err := ValidateEnvironment(environment); err != nil {
		return OIDCConfig{}, err
	}
	cfg := OIDCConfig{
		Issuer:         strings.TrimSuffix(os.Getenv(EnvOIDCIssuer), "/"),
		ActiveKeyPEM:   []byte(os.Getenv(EnvOIDCSigningKey)),
		NextKeyPEM:     []byte(os.Getenv(EnvOIDCSigningKeyNext)),
		PreviousKeyPEM: []byte(os.Getenv(EnvOIDCSigningKeyPrev)),
	}

	isDev := environment == "development"

	if cfg.Issuer == "" {
		if !isDev {
			return OIDCConfig{}, fmt.Errorf("config: %s is required outside development", EnvOIDCIssuer)
		}
		cfg.Issuer = defaultDevIssuer
	}
	if _, err := issuerOrigin(cfg.Issuer, environment); err != nil {
		return OIDCConfig{}, err
	}
	if !isDev && (strings.TrimSpace(string(cfg.ActiveKeyPEM)) == "" || strings.TrimSpace(string(cfg.NextKeyPEM)) == "") {
		return OIDCConfig{}, fmt.Errorf(
			"config: %s and %s are required outside development",
			EnvOIDCSigningKey, EnvOIDCSigningKeyNext,
		)
	}

	return cfg, nil
}
