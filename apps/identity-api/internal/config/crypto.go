package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
)

// CryptoConfig holds the secret material required by the application-layer
// envelope encryption and blind indexing modules (docs/data-architecture.md
// §2). It is loaded separately from the base HTTP Config so that a service
// which does not touch PII (and therefore does not need these secrets) can
// still start, while any service that constructs the crypto module fails fast
// if the secrets are missing or malformed.
//
// Per Definition of Done #3, no key material is hardcoded: these values are
// injected at runtime by the KMS/secrets manager (Infisical) via the
// ExternalSecret defined in docs/devops-operations.md §2.1.
type CryptoConfig struct {
	// MasterKEK is the 32-byte AES-256 master Key Encryption Key used to wrap
	// per-record DEKs. Sourced from ENVELOPE_MASTER_KEK (base64-encoded).
	MasterKEK []byte
	// MasterKEKVersion is the version byte stamped into every envelope blob so
	// the correct (possibly rotated/retired) KEK can be selected on decrypt.
	// Sourced from ENVELOPE_MASTER_KEK_VERSION (defaults to 1).
	MasterKEKVersion byte
	// BlindIndexPepper is the secret pepper (>=32 bytes) mixed into the
	// SHA-256 blind index. Sourced from ENVELOPE_BLIND_INDEX_PEPPER
	// (base64-encoded).
	BlindIndexPepper []byte
}

// Environment variable names for the crypto secrets. Kept as constants so the
// loader and tests agree on the exact keys (matching devops-operations.md).
const (
	EnvMasterKEK        = "ENVELOPE_MASTER_KEK"
	EnvMasterKEKVersion = "ENVELOPE_MASTER_KEK_VERSION"
	EnvBlindIndexPepper = "ENVELOPE_BLIND_INDEX_PEPPER"
)

// kekSizeBytes is the required decoded length of the master KEK (AES-256).
const kekSizeBytes = 32

// minPepperBytes is the minimum accepted decoded pepper length.
const minPepperBytes = 32

// LoadCrypto builds a CryptoConfig from environment variables, decoding the
// base64-encoded key material and validating its length. It returns an error
// (rather than applying defaults) whenever a required secret is missing or
// malformed, so misconfiguration fails fast at startup.
func LoadCrypto() (CryptoConfig, error) {
	var cfg CryptoConfig

	rawKEK, ok := os.LookupEnv(EnvMasterKEK)
	if !ok || rawKEK == "" {
		return CryptoConfig{}, fmt.Errorf("config: %s is required", EnvMasterKEK)
	}
	kek, err := base64.StdEncoding.DecodeString(rawKEK)
	if err != nil {
		return CryptoConfig{}, fmt.Errorf("config: %s must be valid base64: %w", EnvMasterKEK, err)
	}
	if len(kek) != kekSizeBytes {
		return CryptoConfig{}, fmt.Errorf("config: %s must decode to %d bytes (AES-256), got %d", EnvMasterKEK, kekSizeBytes, len(kek))
	}
	cfg.MasterKEK = kek

	// Version defaults to 1 when unset.
	cfg.MasterKEKVersion = 1
	if raw, ok := os.LookupEnv(EnvMasterKEKVersion); ok && raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return CryptoConfig{}, fmt.Errorf("config: invalid %s %q: %w", EnvMasterKEKVersion, raw, err)
		}
		if v < 0 || v > 255 {
			return CryptoConfig{}, fmt.Errorf("config: %s %d out of range (0-255)", EnvMasterKEKVersion, v)
		}
		cfg.MasterKEKVersion = byte(v)
	}

	rawPepper, ok := os.LookupEnv(EnvBlindIndexPepper)
	if !ok || rawPepper == "" {
		return CryptoConfig{}, fmt.Errorf("config: %s is required", EnvBlindIndexPepper)
	}
	pepper, err := base64.StdEncoding.DecodeString(rawPepper)
	if err != nil {
		return CryptoConfig{}, fmt.Errorf("config: %s must be valid base64: %w", EnvBlindIndexPepper, err)
	}
	if len(pepper) < minPepperBytes {
		return CryptoConfig{}, fmt.Errorf("config: %s must decode to at least %d bytes, got %d", EnvBlindIndexPepper, minPepperBytes, len(pepper))
	}
	cfg.BlindIndexPepper = pepper

	return cfg, nil
}
