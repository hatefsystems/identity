package config

import (
	"errors"
	"os"
)

// LoadEnvironment requires an explicit security mode, without defaults or normalization.
func LoadEnvironment() (string, error) {
	raw := os.Getenv("APP_ENV")
	if err := ValidateEnvironment(raw); err != nil {
		return "", err
	}
	return raw, nil
}

// ValidateEnvironment applies the same exact policy to an already-loaded mode.
func ValidateEnvironment(raw string) error {
	switch raw {
	case "development", "test", "production":
		return nil
	default:
		return errors.New("config: APP_ENV must be exactly development, test, or production")
	}
}
