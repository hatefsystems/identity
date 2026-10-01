package config

import (
	"testing"
	"time"
)

func cleanAdminEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{EnvAdminEnabled, EnvAdminAllowedOrigins, EnvAdminContextRetention, EnvAdminLegalReleasedRetention, EnvAdminPageSizeDefault, EnvAdminPageSizeMax, EnvAdminAuditMaxWindow, EnvAdminChainVerifyMaxLimit, EnvAdminRequestTimeout, EnvAdminPerActorPerMinute, EnvAdminPerSubnetPerMinute} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "development")
}

func TestAdminDefaultsAndLoad(t *testing.T) {
	cleanAdminEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Enabled || cfg.Admin.PageSizeDefault != 50 || cfg.Admin.PageSizeMax != 200 || cfg.Admin.AuditMaxWindow != 744*time.Hour || cfg.Admin.ContextRetention != 0 {
		t.Fatalf("unexpected admin defaults: %+v", cfg.Admin)
	}
}

func TestAdminInvalidBounds(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvAdminPageSizeDefault, "2147483648"}, {EnvAdminPageSizeMax, "201"},
		{EnvAdminPageSizeDefault, "0"}, {EnvAdminPageSizeMax, "-1"},
		{EnvAdminChainVerifyMaxLimit, "5001"}, {EnvAdminAuditMaxWindow, "745h"},
		{EnvAdminRequestTimeout, "11s"}, {EnvAdminPerActorPerMinute, "-1"},
		{EnvAdminContextRetention, "0s"}, {EnvAdminLegalReleasedRetention, "invalid"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			cleanAdminEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestAdminEnableRequiresExplicitPolicy(t *testing.T) {
	cleanAdminEnv(t)
	t.Setenv(EnvAdminEnabled, "true")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("enabled without policy")
	}
	t.Setenv(EnvAdminAllowedOrigins, "https://identity.example")
	t.Setenv(EnvAdminContextRetention, "720h")
	t.Setenv(EnvAdminLegalReleasedRetention, "1440h")
	if _, err := LoadAdmin(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminOrigins(t *testing.T) {
	for _, origin := range []string{"*", "null", "https://example.test/path", "https://example.test/", "https://user:secret@example.test", "https://example.test?key=value", "https://example.test#fragment", "https://example.test,"} {
		t.Run(origin, func(t *testing.T) {
			cleanAdminEnv(t)
			t.Setenv(EnvAdminAllowedOrigins, origin)
			if _, err := LoadAdmin(); err == nil {
				t.Fatal("accepted unsafe origin")
			}
		})
	}
	cleanAdminEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvAdminAllowedOrigins, "http://example.test")
	if _, err := LoadAdmin(); err == nil {
		t.Fatal("accepted cleartext production origin")
	}
}
