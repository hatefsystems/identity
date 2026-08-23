package config

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/hatefsystems/identity/apps/identity-api/internal/recovery"
)

// RecoveryConfig holds the recovery (backup) code policy (Task 4.6). Every
// field is a non-sensitive tunable with a production-safe default except the
// hash pepper, which is an optional secret injected at runtime by the
// KMS/secrets manager (Infisical) per Definition of Done #3 and is never
// hardcoded.
type RecoveryConfig struct {
	// Count is the number of codes minted per batch (default 10).
	Count int
	// EntropyBits is the per-code entropy budget (default 160). Values below
	// recovery.MinEntropyBits (128) are rejected so the mandated floor cannot
	// be weakened by misconfiguration.
	EntropyBits int
	// LowThreshold is the remaining-code count at or below which the status
	// endpoint reports "low" (default 3).
	LowThreshold int

	// PerAccountPerHour / PerSubnetPerHour bound generate/verify attempts
	// (defaults 10, 20).
	PerAccountPerHour int
	PerSubnetPerHour  int

	// HashPepper optionally keys the stored recovery-code hash (HMAC-SHA-256)
	// so a database dump alone cannot be used to test candidate codes offline.
	// Base64-encoded; when set it must decode to at least 16 bytes.
	HashPepper []byte
}

// Environment variable names for the recovery-code configuration.
const (
	EnvRecoveryCount             = "RECOVERY_CODES_COUNT"
	EnvRecoveryEntropyBits       = "RECOVERY_CODE_ENTROPY_BITS"
	EnvRecoveryLowThreshold      = "RECOVERY_CODES_LOW_THRESHOLD"
	EnvRecoveryPerAccountPerHour = "RECOVERY_CODES_PER_ACCOUNT_PER_HOUR"
	EnvRecoveryPerSubnetPerHour  = "RECOVERY_CODES_PER_SUBNET_PER_HOUR"
	// EnvRecoveryHashPepper is the NAME of the environment variable that
	// carries the optional pepper, never the secret itself; the value is
	// injected at runtime by the KMS/secrets manager (DoD #3).
	EnvRecoveryHashPepper = "RECOVERY_CODES_HASH_PEPPER" //nolint:gosec // G101: env var name, not a hardcoded secret
)

// Recovery-code default policy values (docs/data-architecture.md §1.2,
// docs/api-design.md §1.3).
const (
	defaultRecoveryCount             = 10
	defaultRecoveryEntropyBits       = recovery.DefaultEntropyBits
	defaultRecoveryLowThreshold      = 3
	defaultRecoveryPerAccountPerHour = 10
	defaultRecoveryPerSubnetPerHour  = 20
	minRecoveryHashPepperBytes       = 16
)

// LoadRecovery builds a RecoveryConfig from environment variables, applying the
// documented defaults for every unset tunable and failing fast on a malformed
// value or an entropy budget below the mandated 128-bit floor.
func LoadRecovery() (RecoveryConfig, error) {
	cfg := RecoveryConfig{
		Count:             defaultRecoveryCount,
		EntropyBits:       defaultRecoveryEntropyBits,
		LowThreshold:      defaultRecoveryLowThreshold,
		PerAccountPerHour: defaultRecoveryPerAccountPerHour,
		PerSubnetPerHour:  defaultRecoveryPerSubnetPerHour,
	}

	var err error
	if cfg.Count, err = getEnvPositiveInt(EnvRecoveryCount, defaultRecoveryCount); err != nil {
		return RecoveryConfig{}, err
	}
	if cfg.EntropyBits, err = getEnvPositiveInt(EnvRecoveryEntropyBits, defaultRecoveryEntropyBits); err != nil {
		return RecoveryConfig{}, err
	}
	if cfg.EntropyBits < recovery.MinEntropyBits {
		return RecoveryConfig{}, fmt.Errorf("config: %s %d is below the %d-bit minimum", EnvRecoveryEntropyBits, cfg.EntropyBits, recovery.MinEntropyBits)
	}
	if cfg.LowThreshold, err = getEnvPositiveInt(EnvRecoveryLowThreshold, defaultRecoveryLowThreshold); err != nil {
		return RecoveryConfig{}, err
	}
	if cfg.PerAccountPerHour, err = getEnvPositiveInt(EnvRecoveryPerAccountPerHour, defaultRecoveryPerAccountPerHour); err != nil {
		return RecoveryConfig{}, err
	}
	if cfg.PerSubnetPerHour, err = getEnvPositiveInt(EnvRecoveryPerSubnetPerHour, defaultRecoveryPerSubnetPerHour); err != nil {
		return RecoveryConfig{}, err
	}

	if raw, ok := os.LookupEnv(EnvRecoveryHashPepper); ok && raw != "" {
		pepper, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return RecoveryConfig{}, fmt.Errorf("config: %s must be valid base64: %w", EnvRecoveryHashPepper, err)
		}
		if len(pepper) < minRecoveryHashPepperBytes {
			return RecoveryConfig{}, fmt.Errorf("config: %s must decode to at least %d bytes, got %d", EnvRecoveryHashPepper, minRecoveryHashPepperBytes, len(pepper))
		}
		cfg.HashPepper = pepper
	}

	return cfg, nil
}
