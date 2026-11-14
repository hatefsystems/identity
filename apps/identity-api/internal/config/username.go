package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

// Username environment names configure the immutable normalization and lookup authority.
const (
	EnvUsernameEnabled     = "USERNAME_ENABLED"
	EnvUsernameRegex       = "USERNAME_REGEX"
	EnvUsernamePolicyJSON  = "USERNAME_POLICY_JSON"
	EnvUsernameLookupKey   = "USERNAME_LOOKUP_KEY"
	EnvUsernameLookupKeyID = "USERNAME_LOOKUP_KEY_ID"
)

// UsernameConfig admits one immutable core without installing DB authority.
// Composition must refuse enabled registration with username support disabled.
type UsernameConfig struct {
	Enabled    bool
	Normalizer *username.Normalizer
}

// LoadUsername ignores unrelated policy/secrets when disabled. Enabled mode has
// no regex, policy, reserved-list, key or key-ID defaults and no hot reload.
func LoadUsername() (UsernameConfig, error) {
	mode := os.Getenv(EnvUsernameEnabled)
	if mode != "" && mode != "true" && mode != "false" {
		return UsernameConfig{}, fmt.Errorf("config: %s must be true or false", EnvUsernameEnabled)
	}
	if mode != "true" {
		return UsernameConfig{}, nil
	}
	environment, err := LoadEnvironment()
	if err != nil {
		return UsernameConfig{}, err
	}
	for _, name := range []string{EnvUsernameRegex, EnvUsernamePolicyJSON, EnvUsernameLookupKey, EnvUsernameLookupKeyID} {
		if os.Getenv(name) == "" {
			return UsernameConfig{}, fmt.Errorf("config: %s is required", name)
		}
	}
	p, err := username.DecodePolicy([]byte(os.Getenv(EnvUsernamePolicyJSON)))
	if err != nil {
		return UsernameConfig{}, fmt.Errorf("config: invalid %s", EnvUsernamePolicyJSON)
	}
	rawKey := os.Getenv(EnvUsernameLookupKey)
	key, err := base64.StdEncoding.Strict().DecodeString(rawKey)
	if err != nil || len(key) < 32 || base64.StdEncoding.EncodeToString(key) != rawKey {
		return UsernameConfig{}, fmt.Errorf("config: %s requires canonical base64 of at least 32 bytes", EnvUsernameLookupKey)
	}
	if environment == "production" && bytes.Equal(key, make([]byte, len(key))) {
		return UsernameConfig{}, fmt.Errorf("config: %s must not use an all-zero test key in production", EnvUsernameLookupKey)
	}
	// Equality cannot depend on a shared email/phone/ledger pepper.
	if shared, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv(EnvBlindIndexPepper))); err == nil && bytes.Equal(key, shared) {
		return UsernameConfig{}, fmt.Errorf("config: %s must be independent from %s", EnvUsernameLookupKey, EnvBlindIndexPepper)
	}
	n, err := username.New(p, os.Getenv(EnvUsernameRegex), key, os.Getenv(EnvUsernameLookupKeyID))
	if err != nil {
		return UsernameConfig{}, fmt.Errorf("config: invalid username policy, regex or key ID")
	}
	return UsernameConfig{Enabled: true, Normalizer: n}, nil
}
