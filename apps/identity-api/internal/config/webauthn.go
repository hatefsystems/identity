// WebAuthn configuration loading covers the Relying Party identity that every
// passkey ceremony is cryptographically bound to. Per docs/architecture.md
// ("Origin & RP ID Binding"), the RP ID is the bare registrable domain and the
// origin allow-list is matched exactly (scheme, host, and port), so both are
// deployment-specific and injected via the environment rather than hardcoded.

package config

import (
	"fmt"
	"strings"
	"time"
)

// Environment variable names for the WebAuthn Relying Party settings. None of
// these are secrets; they are public parameters the browser sees, but a wrong
// value silently breaks every ceremony, so they are validated at startup.
const (
	EnvWebAuthnRPID             = "WEBAUTHN_RP_ID"
	EnvWebAuthnRPDisplayName    = "WEBAUTHN_RP_DISPLAY_NAME"
	EnvWebAuthnRPOrigins        = "WEBAUTHN_RP_ORIGINS"
	EnvWebAuthnChallengeTTL     = "WEBAUTHN_CHALLENGE_TTL"
	EnvWebAuthnUserVerification = "WEBAUTHN_USER_VERIFICATION"
)

// WebAuthn defaults. The RP ID and origin defaults only apply in development
// (plain-HTTP localhost, which browsers exempt from the secure-context rule);
// outside development both must be supplied explicitly.
const (
	defaultDevWebAuthnRPID    = "localhost"
	defaultDevWebAuthnOrigin  = "http://localhost:8080"
	defaultWebAuthnRPName     = "Hatef Identity"
	defaultWebAuthnChallenge  = 5 * time.Minute
	defaultWebAuthnUserVerify = "preferred"

	// maxWebAuthnChallengeTTL bounds the challenge window: a long-lived
	// challenge widens the replay window for a stolen authenticator response,
	// and no legitimate user needs more than a few minutes to touch a key.
	maxWebAuthnChallengeTTL = 15 * time.Minute
)

// WebAuthnConfig carries the Relying Party identity and ceremony policy for the
// passkey flows. It mirrors webauthn.Config but lives here so the webauthn
// package never reads the environment itself.
type WebAuthnConfig struct {
	// RPID is the Relying Party ID: the effective domain with no scheme, port,
	// or path (e.g. "identity.hatef.ir").
	RPID string
	// RPDisplayName is the human-palatable name authenticators display.
	RPDisplayName string
	// RPOrigins is the allow-list of full origins permitted to run a ceremony.
	RPOrigins []string
	// ChallengeTTL bounds how long an issued challenge stays valid.
	ChallengeTTL time.Duration
	// UserVerification is the default userVerification requirement
	// ("required", "preferred", or "discouraged").
	UserVerification string
}

// LoadWebAuthn reads the WebAuthn settings from the environment. In
// non-development environments the RP ID and at least one origin are required
// and every origin must be https; in development a localhost Relying Party is
// defaulted so the service runs with no configuration at all.
//
// It fails fast on an RP ID that carries a scheme/port/path (a common
// misconfiguration that makes browsers reject every ceremony) or a user
// verification value the spec does not define.
func LoadWebAuthn(environment string) (WebAuthnConfig, error) {
	isDev := environment == "development"

	cfg := WebAuthnConfig{
		RPID:             strings.TrimSpace(getEnv(EnvWebAuthnRPID, "")),
		RPDisplayName:    getEnv(EnvWebAuthnRPDisplayName, defaultWebAuthnRPName),
		RPOrigins:        splitOrigins(getEnv(EnvWebAuthnRPOrigins, "")),
		UserVerification: getEnv(EnvWebAuthnUserVerification, defaultWebAuthnUserVerify),
	}

	ttl, err := getEnvDuration(EnvWebAuthnChallengeTTL, defaultWebAuthnChallenge)
	if err != nil {
		return WebAuthnConfig{}, err
	}
	if ttl > maxWebAuthnChallengeTTL {
		return WebAuthnConfig{}, fmt.Errorf(
			"config: %s %v must not exceed %v", EnvWebAuthnChallengeTTL, ttl, maxWebAuthnChallengeTTL)
	}
	cfg.ChallengeTTL = ttl

	if cfg.RPID == "" {
		if !isDev {
			return WebAuthnConfig{}, fmt.Errorf("config: %s is required outside development", EnvWebAuthnRPID)
		}
		cfg.RPID = defaultDevWebAuthnRPID
	}
	if strings.ContainsAny(cfg.RPID, ":/") {
		return WebAuthnConfig{}, fmt.Errorf(
			"config: %s %q must be a bare domain with no scheme, port, or path", EnvWebAuthnRPID, cfg.RPID)
	}

	if len(cfg.RPOrigins) == 0 {
		if !isDev {
			return WebAuthnConfig{}, fmt.Errorf("config: %s is required outside development", EnvWebAuthnRPOrigins)
		}
		cfg.RPOrigins = []string{defaultDevWebAuthnOrigin}
	}
	for _, origin := range cfg.RPOrigins {
		if !isDev && !strings.HasPrefix(origin, "https://") {
			return WebAuthnConfig{}, fmt.Errorf(
				"config: %s entry %q must be an https origin outside development", EnvWebAuthnRPOrigins, origin)
		}
	}

	switch cfg.UserVerification {
	case "required", "preferred", "discouraged":
	default:
		return WebAuthnConfig{}, fmt.Errorf(
			"config: %s %q must be one of required, preferred, discouraged",
			EnvWebAuthnUserVerification, cfg.UserVerification)
	}

	return cfg, nil
}

// splitOrigins parses the comma-separated origin allow-list, trimming spaces
// and dropping empty entries so a trailing comma is harmless.
func splitOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, strings.TrimSuffix(trimmed, "/"))
		}
	}
	return out
}
