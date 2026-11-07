package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

var testStepUpReplayHMACKey = bytes.Repeat([]byte{0x5a}, stepup.MinReplayHMACKeyBytes)

// clearStepUpEnv unsets every step-up policy variable and supplies the required
// replay secret so each policy test starts from a known environment.
func clearStepUpEnv(t *testing.T) {
	t.Helper()
	t.Setenv("APP_ENV", "test")
	for _, k := range []string{
		EnvStepUpTokenTTL,
		EnvStepUpPerAccountPerMinute,
		EnvStepUpPerAccountPerHour,
		EnvStepUpPerSubnetPerHour,
	} {
		t.Setenv(k, "")
	}
	t.Setenv(EnvStepUpReplayHMACKey, base64.StdEncoding.EncodeToString(testStepUpReplayHMACKey))
}

func TestLoadStepUpDefaults(t *testing.T) {
	clearStepUpEnv(t)

	cfg, err := LoadStepUp()
	if err != nil {
		t.Fatalf("LoadStepUp: %v", err)
	}
	if cfg.TokenTTL != defaultStepUpTokenTTL {
		t.Errorf("TokenTTL = %v, want %v", cfg.TokenTTL, defaultStepUpTokenTTL)
	}
	if !bytes.Equal(cfg.ReplayHMACKey, testStepUpReplayHMACKey) {
		t.Errorf("ReplayHMACKey was not decoded from %s", EnvStepUpReplayHMACKey)
	}
	if cfg.PerAccountPerMinute != defaultStepUpPerAccountPerMinute {
		t.Errorf("PerAccountPerMinute = %d, want %d",
			cfg.PerAccountPerMinute, defaultStepUpPerAccountPerMinute)
	}
	if cfg.PerAccountPerHour != defaultStepUpPerAccountPerHour {
		t.Errorf("PerAccountPerHour = %d, want %d",
			cfg.PerAccountPerHour, defaultStepUpPerAccountPerHour)
	}
	if cfg.PerSubnetPerHour != defaultStepUpPerSubnetPerHour {
		t.Errorf("PerSubnetPerHour = %d, want %d",
			cfg.PerSubnetPerHour, defaultStepUpPerSubnetPerHour)
	}
}

// TestLoadStepUpDefaultMatchesTheService keeps the two default declarations from
// drifting: config re-exports the package's own constant rather than repeating
// the number.
func TestLoadStepUpDefaultMatchesTheService(t *testing.T) {
	if defaultStepUpTokenTTL != stepup.DefaultTokenTTL {
		t.Fatalf("config default %v disagrees with stepup.DefaultTokenTTL %v",
			defaultStepUpTokenTTL, stepup.DefaultTokenTTL)
	}
}

func TestLoadStepUpOverrides(t *testing.T) {
	clearStepUpEnv(t)

	t.Setenv(EnvStepUpTokenTTL, "3m")
	t.Setenv(EnvStepUpPerAccountPerMinute, "2")
	t.Setenv(EnvStepUpPerAccountPerHour, "7")
	t.Setenv(EnvStepUpPerSubnetPerHour, "11")

	cfg, err := LoadStepUp()
	if err != nil {
		t.Fatalf("LoadStepUp: %v", err)
	}
	if cfg.TokenTTL != 3*time.Minute {
		t.Errorf("TokenTTL = %v, want 3m", cfg.TokenTTL)
	}
	if cfg.PerAccountPerMinute != 2 {
		t.Errorf("PerAccountPerMinute = %d, want 2", cfg.PerAccountPerMinute)
	}
	if cfg.PerAccountPerHour != 7 {
		t.Errorf("PerAccountPerHour = %d, want 7", cfg.PerAccountPerHour)
	}
	if cfg.PerSubnetPerHour != 11 {
		t.Errorf("PerSubnetPerHour = %d, want 11", cfg.PerSubnetPerHour)
	}
}

func TestLoadStepUpRequiresValidReplayHMACKey(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "missing", value: ""},
		{name: "malformed base64", value: "not base64!"},
		{
			name:  "decoded key too short",
			value: base64.StdEncoding.EncodeToString(make([]byte, stepup.MinReplayHMACKeyBytes-1)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearStepUpEnv(t)
			t.Setenv(EnvStepUpReplayHMACKey, tc.value)
			if _, err := LoadStepUp(); err == nil {
				t.Fatalf("expected %s=%q to be rejected", EnvStepUpReplayHMACKey, tc.value)
			}
		})
	}
}

func TestLoadStepUpAllowsMissingReplayHMACKeyOnlyInDevelopment(t *testing.T) {
	clearStepUpEnv(t)
	t.Setenv(EnvStepUpReplayHMACKey, "")

	cfg, err := LoadStepUp("development")
	if err != nil {
		t.Fatalf("LoadStepUp(development): %v", err)
	}
	if cfg.ReplayHMACKey != nil {
		t.Fatalf("development fallback key = %x, want nil for in-memory guard", cfg.ReplayHMACKey)
	}

	for _, environment := range []string{"test", "production"} {
		t.Run(environment, func(t *testing.T) {
			if _, err := LoadStepUp(environment); err == nil {
				t.Fatalf("missing %s must fail in %s", EnvStepUpReplayHMACKey, environment)
			}
		})
	}
}

func TestLoadStepUpEnvironmentCannotBeBypassedByKey(t *testing.T) {
	for _, environment := range []string{"unset", "", " ", "\t", "staging", "Development", "development "} {
		t.Run(environment, func(t *testing.T) {
			clearStepUpEnv(t)
			t.Setenv("APP_ENV", environment)
			if environment == "unset" {
				if err := os.Unsetenv("APP_ENV"); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := LoadStepUp()
			if err == nil || !strings.Contains(err.Error(), "APP_ENV") || cfg.ReplayHMACKey != nil || cfg.TokenTTL != 0 {
				t.Fatalf("present key bypassed mode validation: %+v %v", cfg, err)
			}
			cfg, err = LoadStepUp(environment)
			if err == nil || !strings.Contains(err.Error(), "APP_ENV") || cfg.ReplayHMACKey != nil {
				t.Fatalf("supplied invalid mode accepted: %+v %v", cfg, err)
			}
		})
	}
}

func TestLoadStepUpArgumentCardinalityAndDevelopmentFallback(t *testing.T) {
	clearStepUpEnv(t)
	for _, environment := range []string{"development", "test", "production"} {
		if _, err := LoadStepUp(environment); err != nil {
			t.Fatalf("explicit %s rejected: %v", environment, err)
		}
	}
	for _, environments := range [][]string{{"development", "development"}, {"production", "test"}, {"development", "test", "production"}} {
		cfg, err := LoadStepUp(environments...)
		if err == nil || !strings.Contains(err.Error(), "environment argument") || cfg.ReplayHMACKey != nil {
			t.Fatalf("multiple modes accepted: %+v %v", cfg, err)
		}
	}
	t.Setenv(EnvStepUpReplayHMACKey, "")
	t.Setenv("APP_ENV", "development")
	if cfg, err := LoadStepUp(); err != nil || cfg.ReplayHMACKey != nil {
		t.Fatalf("zero-argument explicit development fallback changed: %+v %v", cfg, err)
	}
	for _, environment := range []string{"test", "production"} {
		t.Setenv("APP_ENV", environment)
		if _, err := LoadStepUp(); err == nil || !strings.Contains(err.Error(), EnvStepUpReplayHMACKey) {
			t.Fatalf("zero-argument %s missing key allowed: %v", environment, err)
		}
	}
}

// TestLoadStepUpRejectsAnOverlongTTL enforces the published contract: every
// document describing the grant says "3-5 minutes", so configuration may shorten
// the window but must not widen it.
func TestLoadStepUpRejectsAnOverlongTTL(t *testing.T) {
	clearStepUpEnv(t)

	for _, value := range []string{"6m", "1h", "24h"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(EnvStepUpTokenTTL, value)
			if _, err := LoadStepUp(); err == nil {
				t.Fatalf("expected %s to be rejected as above the 5-minute ceiling", value)
			}
		})
	}

	// The boundary itself is allowed.
	t.Setenv(EnvStepUpTokenTTL, "5m")
	if _, err := LoadStepUp(); err != nil {
		t.Fatalf("5m is the documented maximum and must be accepted: %v", err)
	}
}

// TestLoadStepUpRejectsMalformedValues confirms the loader fails fast rather than
// silently falling back to a default, which would hide a typo that weakens the
// rate limits.
func TestLoadStepUpRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"unparseable duration", EnvStepUpTokenTTL, "five minutes"},
		{"zero duration", EnvStepUpTokenTTL, "0s"},
		{"negative duration", EnvStepUpTokenTTL, "-1m"},
		{"unparseable int", EnvStepUpPerAccountPerMinute, "many"},
		{"zero limit", EnvStepUpPerAccountPerHour, "0"},
		{"negative limit", EnvStepUpPerSubnetPerHour, "-5"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearStepUpEnv(t)
			t.Setenv(tc.key, tc.value)

			if _, err := LoadStepUp(); err == nil {
				t.Fatalf("expected %s=%q to be rejected", tc.key, tc.value)
			}
		})
	}
}

// TestLoadStepUpProducesAUsableServiceConfig closes the loop: the loaded values
// must satisfy stepup.New, so a valid environment cannot yield a configuration
// the service then refuses at startup.
func TestLoadStepUpProducesAUsableServiceConfig(t *testing.T) {
	clearStepUpEnv(t)
	t.Setenv(EnvStepUpTokenTTL, "4m")

	cfg, err := LoadStepUp()
	if err != nil {
		t.Fatalf("LoadStepUp: %v", err)
	}
	if cfg.TokenTTL <= 0 || cfg.TokenTTL > 5*time.Minute {
		t.Fatalf("TokenTTL %v is outside the range stepup.New accepts", cfg.TokenTTL)
	}
}
