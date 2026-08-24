package config

import (
	"net/netip"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// Ensure no relevant env vars leak in from the host running the tests.
	t.Setenv("HOST", "")
	t.Setenv("PORT", "")
	t.Setenv("APP_ENV", "")
	t.Setenv(EnvTrustedProxyCIDRs, "")

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
	if len(cfg.TrustedProxyCIDRs) != 0 {
		t.Errorf("TrustedProxyCIDRs = %v, want empty secure default", cfg.TrustedProxyCIDRs)
	}
	if cfg.ShutdownTimeout != defaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, defaultShutdownTimeout)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("HOST", "127.0.0.1")
	t.Setenv("PORT", "9090")
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvTrustedProxyCIDRs, "127.0.0.1/32, 10.23.45.67/8, 2001:db8:abcd::1/48")

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
	wantPrefixes := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8:abcd::/48"),
	}
	if len(cfg.TrustedProxyCIDRs) != len(wantPrefixes) {
		t.Fatalf("TrustedProxyCIDRs = %v, want %v", cfg.TrustedProxyCIDRs, wantPrefixes)
	}
	for i, want := range wantPrefixes {
		if cfg.TrustedProxyCIDRs[i] != want {
			t.Errorf("TrustedProxyCIDRs[%d] = %v, want %v", i, cfg.TrustedProxyCIDRs[i], want)
		}
	}
}

func TestLoadInvalidPort(t *testing.T) {
	t.Setenv(EnvTrustedProxyCIDRs, "")
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

func TestLoadTrustedProxyCIDRsDeduplicatesMaskedPrefixes(t *testing.T) {
	t.Setenv(EnvTrustedProxyCIDRs, "10.1.2.3/8, 10.0.0.0/8, 2001:db8::42/32")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if len(cfg.TrustedProxyCIDRs) != len(want) {
		t.Fatalf("TrustedProxyCIDRs = %v, want %v", cfg.TrustedProxyCIDRs, want)
	}
	for i := range want {
		if cfg.TrustedProxyCIDRs[i] != want[i] {
			t.Errorf("TrustedProxyCIDRs[%d] = %v, want %v", i, cfg.TrustedProxyCIDRs[i], want[i])
		}
	}
}

func TestLoadRejectsInvalidTrustedProxyCIDRs(t *testing.T) {
	tests := map[string]string{
		"malformed":         "not-a-cidr",
		"host without CIDR": "127.0.0.1",
		"empty entry":       "127.0.0.1/32,",
		"IPv4 universal":    "0.0.0.0/0",
		"IPv6 universal":    "::/0",
		"mixed invalid":     "127.0.0.1/32,broken",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(EnvTrustedProxyCIDRs, value)
			if _, err := Load(); err == nil {
				t.Errorf("Load() with %s=%q: expected error, got nil", EnvTrustedProxyCIDRs, value)
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
	t.Setenv(EnvTrustedProxyCIDRs, "")
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
