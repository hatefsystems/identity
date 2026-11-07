package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadEnvironmentExactModes(t *testing.T) {
	for _, raw := range []string{"development", "test", "production", "", " ", "\t\n", " development", "production ", "TEST", "Development", "staging", "dev"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("APP_ENV", raw)
			got, err := LoadEnvironment()
			valid := raw == "development" || raw == "test" || raw == "production"
			if (err == nil) != valid || valid && got != raw || !valid && got != "" {
				t.Fatalf("environment %q = %q, %v", raw, got, err)
			}
		})
	}
	if err := ValidateEnvironment("test\x00"); err == nil {
		t.Fatal("NUL-bearing mode accepted")
	}
}

func TestEnvironmentRequiredBeforeOwnedLoaderSettings(t *testing.T) {
	loaders := map[string]func() error{
		"HTTP":     func() error { _, err := Load(); return err },
		"session":  func() error { _, err := LoadSession(); return err },
		"crypto":   func() error { _, err := LoadCrypto(); return err },
		"envelope": func() error { _, err := LoadEnvelopeCrypto(); return err },
		"pepper":   func() error { _, err := LoadBlindIndexPepper(); return err },
		"notifier": func() error { _, err := LoadDeletionNotifier(); return err },
	}
	for name, load := range loaders {
		for _, raw := range []string{"missing", "", " ", "staging", "production "} {
			t.Run(name+"/"+raw, func(t *testing.T) {
				t.Setenv("APP_ENV", raw)
				if raw == "missing" {
					if err := os.Unsetenv("APP_ENV"); err != nil {
						t.Fatal(err)
					}
				}
				if err := load(); err == nil || !strings.Contains(err.Error(), "APP_ENV") {
					t.Fatalf("loader did not reject mode first: %v", err)
				}
			})
		}
	}
}

func TestParameterLoadersRequireExactMode(t *testing.T) {
	for _, raw := range []string{"", " ", "development ", "TEST", "staging"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := LoadOIDC(raw); err == nil || !strings.Contains(err.Error(), "APP_ENV") {
				t.Fatalf("OIDC: %v", err)
			}
			if _, err := LoadClients(raw); err == nil || !strings.Contains(err.Error(), "APP_ENV") {
				t.Fatalf("clients: %v", err)
			}
			if _, err := LoadPortal(raw, "http://localhost:8080", nil); err == nil || !strings.Contains(err.Error(), "APP_ENV") {
				t.Fatalf("portal: %v", err)
			}
		})
	}
}
