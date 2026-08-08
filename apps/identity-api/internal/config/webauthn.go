// WebAuthn configuration loading covers the Relying Party identity that every
// passkey ceremony is cryptographically bound to. Per docs/architecture.md
// ("Origin & RP ID Binding"), the RP ID is the bare registrable domain and the
// origin allow-list is matched exactly (scheme, host, and port), so both are
// deployment-specific and injected via the environment rather than hardcoded.

package config

import (
	"crypto/rand"
	"encoding/base64"
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
	EnvWebAuthnResidentKey      = "WEBAUTHN_RESIDENT_KEY"
	EnvWebAuthnNamedLoginFloor  = "WEBAUTHN_NAMED_LOGIN_FLOOR"
)

// EnvWebAuthnMockChallengeKey names the one WebAuthn setting that *is* a secret:
// the key used to derive the decoy credentials returned for user-named logins
// against identities that cannot log in (Task 4.3). It is injected by the
// KMS/Infisical alongside the other deployment secrets and never committed.
const EnvWebAuthnMockChallengeKey = "WEBAUTHN_MOCK_CHALLENGE_KEY"

// WebAuthn defaults. The RP ID and origin defaults only apply in development
// (plain-HTTP localhost, which browsers exempt from the secure-context rule);
// outside development both must be supplied explicitly.
const (
	defaultDevWebAuthnRPID    = "localhost"
	defaultDevWebAuthnOrigin  = "http://localhost:8080"
	defaultWebAuthnRPName     = "Hatef Identity"
	defaultWebAuthnChallenge  = 5 * time.Minute
	defaultWebAuthnUserVerify = "preferred"

	// defaultWebAuthnResidentKey requires a discoverable credential at
	// registration, because usernameless login — the primary secure path
	// (Task 4.3) — only works with credentials the authenticator can find
	// without being told which account to look for.
	defaultWebAuthnResidentKey = "required"

	// defaultWebAuthnNamedLoginFloor is the constant-time budget for a
	// user-named login options request. It must comfortably exceed the real
	// path's two database round-trips so both the real and the mock branch
	// finish inside it, making the difference unobservable, while staying short
	// enough to be imperceptible to a user.
	defaultWebAuthnNamedLoginFloor = 150 * time.Millisecond

	// maxWebAuthnChallengeTTL bounds the challenge window: a long-lived
	// challenge widens the replay window for a stolen authenticator response,
	// and no legitimate user needs more than a few minutes to touch a key.
	maxWebAuthnChallengeTTL = 15 * time.Minute

	// maxWebAuthnNamedLoginFloor caps the padding: past a second or so the
	// delay stops being a privacy control and becomes a self-inflicted denial
	// of service, since every request holds a goroutine for its duration.
	maxWebAuthnNamedLoginFloor = 2 * time.Second

	// minWebAuthnMockChallengeKeyLen is the shortest accepted mock-derivation
	// key. 32 bytes matches the HMAC-SHA256 block output and puts brute-force
	// recovery of the key out of reach.
	minWebAuthnMockChallengeKeyLen = 32
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
	// ResidentKey is the residentKey requirement applied at registration
	// ("required", "preferred", or "discouraged").
	ResidentKey string
	// MockChallengeKey is the secret behind the decoy credentials returned by
	// the user-named login fallback.
	MockChallengeKey []byte
	// NamedLoginFloor is the constant-time budget for a user-named login
	// options request.
	NamedLoginFloor time.Duration
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
		ResidentKey:      getEnv(EnvWebAuthnResidentKey, defaultWebAuthnResidentKey),
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

	switch cfg.ResidentKey {
	case "required", "preferred", "discouraged":
	default:
		return WebAuthnConfig{}, fmt.Errorf(
			"config: %s %q must be one of required, preferred, discouraged",
			EnvWebAuthnResidentKey, cfg.ResidentKey)
	}

	floor, err := getEnvDuration(EnvWebAuthnNamedLoginFloor, defaultWebAuthnNamedLoginFloor)
	if err != nil {
		return WebAuthnConfig{}, err
	}
	if floor > maxWebAuthnNamedLoginFloor {
		return WebAuthnConfig{}, fmt.Errorf(
			"config: %s %v must not exceed %v", EnvWebAuthnNamedLoginFloor, floor, maxWebAuthnNamedLoginFloor)
	}
	cfg.NamedLoginFloor = floor

	mockKey, err := loadMockChallengeKey(isDev)
	if err != nil {
		return WebAuthnConfig{}, err
	}
	cfg.MockChallengeKey = mockKey

	return cfg, nil
}

// loadMockChallengeKey resolves the secret behind the user-named login decoys.
//
// Outside development it must be supplied (by the KMS/Infisical) and be long
// enough to be unguessable, per the no-hardcoded-secrets rule. In development a
// random per-process key is generated instead, so the service starts with no
// configuration; the trade-off is that decoys change on restart, which is
// harmless locally but would be a (small) enumeration signal in production —
// which is exactly why the variable is mandatory there.
func loadMockChallengeKey(isDev bool) ([]byte, error) {
	raw := strings.TrimSpace(getEnv(EnvWebAuthnMockChallengeKey, ""))
	if raw == "" {
		if !isDev {
			return nil, fmt.Errorf("config: %s is required outside development", EnvWebAuthnMockChallengeKey)
		}
		key := make([]byte, minWebAuthnMockChallengeKeyLen)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("config: generate development %s: %w", EnvWebAuthnMockChallengeKey, err)
		}
		return key, nil
	}

	// The value is accepted either as base64 (how a KMS would hand over raw key
	// bytes) or, failing that, as a literal passphrase.
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || (len(key) < minWebAuthnMockChallengeKeyLen && len([]byte(raw)) >= minWebAuthnMockChallengeKeyLen) {
		key = []byte(raw)
	}
	if len(key) < minWebAuthnMockChallengeKeyLen {
		return nil, fmt.Errorf(
			"config: %s must decode to at least %d bytes, got %d",
			EnvWebAuthnMockChallengeKey, minWebAuthnMockChallengeKeyLen, len(key))
	}
	return key, nil
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
