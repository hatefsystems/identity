package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

// StepUpConfig holds the Step-up Authentication policy (Task 4.7) and the
// secret used to derive opaque distributed replay keys. Policy tunables have
// production-safe defaults; ReplayHMACKey is required runtime key material
// except for the explicit development-only in-memory fallback.
//
// The ACR value itself (stepup.ACRStepUp) is deliberately not configurable: it is
// a protocol identifier shared with clients, and a per-deployment value would
// invalidate in-flight grants during a rolling deploy for no benefit.
type StepUpConfig struct {
	// ReplayHMACKey is a KMS-supplied key used by RedisReplayGuard to derive
	// opaque, cluster-stable Redis keys. It must decode to at least 32 bytes. A
	// nil value is valid only in development when no Redis guard is constructed.
	ReplayHMACKey []byte

	// TokenTTL is the grant lifetime (default 5m). Every document that mentions
	// the window says "3-5 minutes" (docs/architecture.md, docs/api-design.md
	// §1.3, docs/frontend-pages.md §5.3), so a value above the 5-minute ceiling
	// is rejected: configuration may harden the published contract but never
	// weaken it.
	TokenTTL time.Duration

	// PerAccountPerMinute bounds verification attempts for one account within a
	// minute (default 5). This is the window that keeps the 6-digit TOTP space
	// out of brute-force reach.
	PerAccountPerMinute int
	// PerAccountPerHour bounds sustained verification attempts for one account
	// (default 20).
	PerAccountPerHour int
	// PerSubnetPerHour bounds verification attempts from one IP /24 or /48
	// (default 40).
	PerSubnetPerHour int
}

// Environment variable names for the step-up configuration.
const (
	EnvStepUpTokenTTL            = "STEPUP_TOKEN_TTL"       //nolint:gosec // G101: env var name for a TTL, not a credential
	EnvStepUpReplayHMACKey       = "STEPUP_REPLAY_HMAC_KEY" //nolint:gosec // G101: env var name, not hardcoded key material
	EnvStepUpPerAccountPerMinute = "STEPUP_VERIFY_PER_ACCOUNT_PER_MINUTE"
	EnvStepUpPerAccountPerHour   = "STEPUP_VERIFY_PER_ACCOUNT_PER_HOUR"
	EnvStepUpPerSubnetPerHour    = "STEPUP_VERIFY_PER_SUBNET_PER_HOUR"
)

// Step-up default policy values.
const (
	defaultStepUpTokenTTL            = stepup.DefaultTokenTTL
	defaultStepUpPerAccountPerMinute = 5
	defaultStepUpPerAccountPerHour   = 20
	defaultStepUpPerSubnetPerHour    = 40
	// maxStepUpTokenTTL mirrors the ceiling enforced inside stepup.New, checked
	// here as well so a bad value fails during configuration loading with a
	// message naming the environment variable.
	maxStepUpTokenTTL = 5 * time.Minute
)

// LoadStepUp builds a StepUpConfig from environment variables, applying the
// documented defaults for every unset tunable and failing fast on a malformed
// value or a grant lifetime above the published 5-minute ceiling. The replay
// HMAC key may be omitted only when environment is explicitly development.
func LoadStepUp(environment ...string) (StepUpConfig, error) {
	cfg := StepUpConfig{
		TokenTTL:            defaultStepUpTokenTTL,
		PerAccountPerMinute: defaultStepUpPerAccountPerMinute,
		PerAccountPerHour:   defaultStepUpPerAccountPerHour,
		PerSubnetPerHour:    defaultStepUpPerSubnetPerHour,
	}

	rawReplayKey, ok := os.LookupEnv(EnvStepUpReplayHMACKey)
	if !ok || rawReplayKey == "" {
		if len(environment) == 1 && environment[0] == "development" {
			return loadStepUpPolicy(cfg)
		}
		return StepUpConfig{}, fmt.Errorf("config: %s is required", EnvStepUpReplayHMACKey)
	}
	replayKey, err := base64.StdEncoding.DecodeString(rawReplayKey)
	if err != nil {
		return StepUpConfig{}, fmt.Errorf(
			"config: %s must be valid base64: %w", EnvStepUpReplayHMACKey, err)
	}
	if len(replayKey) < stepup.MinReplayHMACKeyBytes {
		return StepUpConfig{}, fmt.Errorf(
			"config: %s must decode to at least %d bytes, got %d",
			EnvStepUpReplayHMACKey, stepup.MinReplayHMACKeyBytes, len(replayKey))
	}
	cfg.ReplayHMACKey = replayKey

	return loadStepUpPolicy(cfg)
}

func loadStepUpPolicy(cfg StepUpConfig) (StepUpConfig, error) {
	var err error
	if cfg.TokenTTL, err = getEnvDuration(EnvStepUpTokenTTL, defaultStepUpTokenTTL); err != nil {
		return StepUpConfig{}, err
	}
	if cfg.TokenTTL > maxStepUpTokenTTL {
		return StepUpConfig{}, fmt.Errorf(
			"config: %s %v exceeds the %v maximum documented for step-up grants",
			EnvStepUpTokenTTL, cfg.TokenTTL, maxStepUpTokenTTL)
	}
	if cfg.PerAccountPerMinute, err = getEnvPositiveInt(
		EnvStepUpPerAccountPerMinute, defaultStepUpPerAccountPerMinute); err != nil {
		return StepUpConfig{}, err
	}
	if cfg.PerAccountPerHour, err = getEnvPositiveInt(
		EnvStepUpPerAccountPerHour, defaultStepUpPerAccountPerHour); err != nil {
		return StepUpConfig{}, err
	}
	if cfg.PerSubnetPerHour, err = getEnvPositiveInt(
		EnvStepUpPerSubnetPerHour, defaultStepUpPerSubnetPerHour); err != nil {
		return StepUpConfig{}, err
	}

	return cfg, nil
}
