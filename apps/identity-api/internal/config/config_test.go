package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure no relevant env vars leak in from the host running the tests.
	t.Setenv("HOST", "")
	t.Setenv("PORT", "")
	t.Setenv("APP_ENV", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.Host != defaultHost {
		t.Errorf("Host = %q, want %q", cfg.Host, defaultHost)
	}
	if cfg.Port != defaultPort {
		t.Errorf("Port = %d, want %d", cfg.Port, defaultPort)
	}
	if cfg.Environment != "development" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "development")
	}
	if cfg.ShutdownTimeout != defaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, defaultShutdownTimeout)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HOST", "127.0.0.1")
	t.Setenv("PORT", "9090")
	t.Setenv("APP_ENV", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want %q", cfg.Host, "127.0.0.1")
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want %d", cfg.Port, 9090)
	}
	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "production")
	}
}

func TestLoadInvalidPort(t *testing.T) {
	cases := map[string]string{
		"non-numeric":  "abc",
		"out-of-range": "70000",
		"zero":         "0",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PORT", value)
			if _, err := Load(); err == nil {
				t.Errorf("Load() with PORT=%q: expected error, got nil", value)
			}
		})
	}
}

func TestAddr(t *testing.T) {
	cfg := Config{Host: "0.0.0.0", Port: 8080}
	if got, want := cfg.Addr(), "0.0.0.0:8080"; got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}

func TestDefaultTimeoutsArePositive(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	timeouts := map[string]time.Duration{
		"ReadTimeout":     cfg.ReadTimeout,
		"WriteTimeout":    cfg.WriteTimeout,
		"IdleTimeout":     cfg.IdleTimeout,
		"ShutdownTimeout": cfg.ShutdownTimeout,
	}
	for name, d := range timeouts {
		if d <= 0 {
			t.Errorf("%s = %v, want > 0", name, d)
		}
	}
}
