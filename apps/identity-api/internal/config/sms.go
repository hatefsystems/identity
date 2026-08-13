package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

// SMSConfig holds the SMS OTP workflow policy and gateway credentials (Task
// 4.5). Everything except the gateway secret is a non-sensitive tunable with a
// production-safe default; the gateway API key is a secret injected at runtime
// by the KMS/secrets manager (Infisical) per Definition of Done #3 and is never
// hardcoded.
type SMSConfig struct {
	// GatewayAPIKey authenticates to the upstream SMS gateway. It is required
	// outside development; in development it may be empty (the log-only sender
	// is used, so no real gateway credential is needed).
	GatewayAPIKey string

	// CodeTTL is the pending OTP lifetime (default 3m).
	CodeTTL time.Duration
	// MaxAttempts is the failed-verification budget before lockout (default 3).
	MaxAttempts int
	// LockoutTTL is the brute-force lockout duration (default 15m).
	LockoutTTL time.Duration

	// PerPhonePerMinute / PerPhonePerHour bound sends per phone (defaults 1, 5).
	PerPhonePerMinute int
	PerPhonePerHour   int
	// PerSubnetPerHour bounds sends per IP subnet (default 10).
	PerSubnetPerHour int

	// HashPepper is an optional secret mixed into stored OTP hashes so a Redis
	// snapshot alone cannot be brute-forced offline. Base64-encoded; when set
	// it must decode to at least 16 bytes.
	HashPepper []byte
}

// Environment variable names for the SMS OTP configuration.
const (
	// EnvSMSGatewayAPIKey is the NAME of the environment variable that carries
	// the gateway credential, never the credential itself; the secret is
	// injected at runtime by the KMS/secrets manager (DoD #3).
	EnvSMSGatewayAPIKey = "SMS_GATEWAY_API_KEY" //nolint:gosec // G101: env var name, not a hardcoded secret
	EnvSMSCodeTTL       = "SMS_OTP_CODE_TTL"

	EnvSMSMaxAttempts       = "SMS_OTP_MAX_ATTEMPTS"
	EnvSMSLockoutTTL        = "SMS_OTP_LOCKOUT_TTL"
	EnvSMSPerPhonePerMinute = "SMS_OTP_PER_PHONE_PER_MINUTE"
	EnvSMSPerPhonePerHour   = "SMS_OTP_PER_PHONE_PER_HOUR"
	EnvSMSPerSubnetPerHour  = "SMS_OTP_PER_SUBNET_PER_HOUR"
	EnvSMSHashPepper        = "SMS_OTP_HASH_PEPPER"
)

// SMS OTP default policy values (docs/architecture.md, threat-modeling.md D2).
const (
	defaultSMSCodeTTL           = 3 * time.Minute
	defaultSMSMaxAttempts       = 3
	defaultSMSLockoutTTL        = 15 * time.Minute
	defaultSMSPerPhonePerMinute = 1
	defaultSMSPerPhonePerHour   = 5
	defaultSMSPerSubnetPerHour  = 10
	minSMSHashPepperBytes       = 16
)

// LoadSMS builds an SMSConfig from environment variables, applying the
// documented defaults for every unset tunable and failing fast on a malformed
// value. The gateway API key is required outside development (where a real SMS
// gateway must be configured); in development it may be omitted since the
// log-only sender is used.
func LoadSMS(environment string) (SMSConfig, error) {
	cfg := SMSConfig{
		CodeTTL:           defaultSMSCodeTTL,
		MaxAttempts:       defaultSMSMaxAttempts,
		LockoutTTL:        defaultSMSLockoutTTL,
		PerPhonePerMinute: defaultSMSPerPhonePerMinute,
		PerPhonePerHour:   defaultSMSPerPhonePerHour,
		PerSubnetPerHour:  defaultSMSPerSubnetPerHour,
	}

	cfg.GatewayAPIKey = os.Getenv(EnvSMSGatewayAPIKey)
	if cfg.GatewayAPIKey == "" && environment != "development" {
		return SMSConfig{}, fmt.Errorf("config: %s is required in %q environment", EnvSMSGatewayAPIKey, environment)
	}

	codeTTL, err := getEnvDuration(EnvSMSCodeTTL, defaultSMSCodeTTL)
	if err != nil {
		return SMSConfig{}, err
	}
	cfg.CodeTTL = codeTTL

	lockoutTTL, err := getEnvDuration(EnvSMSLockoutTTL, defaultSMSLockoutTTL)
	if err != nil {
		return SMSConfig{}, err
	}
	cfg.LockoutTTL = lockoutTTL

	if cfg.MaxAttempts, err = getEnvPositiveInt(EnvSMSMaxAttempts, defaultSMSMaxAttempts); err != nil {
		return SMSConfig{}, err
	}
	if cfg.PerPhonePerMinute, err = getEnvPositiveInt(EnvSMSPerPhonePerMinute, defaultSMSPerPhonePerMinute); err != nil {
		return SMSConfig{}, err
	}
	if cfg.PerPhonePerHour, err = getEnvPositiveInt(EnvSMSPerPhonePerHour, defaultSMSPerPhonePerHour); err != nil {
		return SMSConfig{}, err
	}
	if cfg.PerSubnetPerHour, err = getEnvPositiveInt(EnvSMSPerSubnetPerHour, defaultSMSPerSubnetPerHour); err != nil {
		return SMSConfig{}, err
	}

	if raw, ok := os.LookupEnv(EnvSMSHashPepper); ok && raw != "" {
		pepper, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return SMSConfig{}, fmt.Errorf("config: %s must be valid base64: %w", EnvSMSHashPepper, err)
		}
		if len(pepper) < minSMSHashPepperBytes {
			return SMSConfig{}, fmt.Errorf("config: %s must decode to at least %d bytes, got %d", EnvSMSHashPepper, minSMSHashPepperBytes, len(pepper))
		}
		cfg.HashPepper = pepper
	}

	return cfg, nil
}

// getEnvPositiveInt parses a positive integer environment variable, returning
// fallback when unset/empty and an error when the value is unparseable or not
// positive (so a misconfigured limit fails fast rather than silently disabling
// a rate-limit dimension).
func getEnvPositiveInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: invalid %s %q: %w", key, raw, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("config: %s %d must be positive", key, v)
	}
	return v, nil
}
