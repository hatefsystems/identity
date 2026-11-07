package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func registrationEnvironment(t *testing.T) {
	t.Helper()
	for key, value := range map[string]string{
		"REGISTRATION_ENABLED": "true", "REGISTRATION_PENDING_CAPACITY": "10", "REGISTRATION_GLOBAL_DAILY_LIMIT": "100", "REGISTRATION_EMAIL_HOURLY_LIMIT": "5",
		"SMS_ENABLED": "true", "SMS_PROVIDER": "smsir", "SMS_IR_KEY_MODE": "live", "SMS_GATEWAY_API_KEY": "fixture-api-key-not-a-real-secret",
		"SMS_IR_TEMPLATE_ID": "1", "SMS_IR_CODE_PARAMETER": "CODE", "SMS_OTP_HASH_PEPPER": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		"SMS_OTP_GLOBAL_PER_DAY": "100", "SMS_OTP_MAX_PENDING_SIGNUP": "10", "DATABASE_URL": "postgres://fixture@example.invalid/db", "REDIS_URL": "redis://example.invalid:6379",
		"REGISTRATION_SMTP_HOST": "smtp.example.invalid", "REGISTRATION_SMTP_PORT": "587", "REGISTRATION_SMTP_TLS_MODE": "starttls",
		"REGISTRATION_SMTP_USERNAME": "fixture-user", "REGISTRATION_SMTP_PASSWORD": "fixture-password", "REGISTRATION_SMTP_FROM": "signup@example.invalid",
		"REGISTRATION_SMTP_PUBLIC_ORIGIN": "https://portal.example.invalid", "PORTAL_ORIGIN": "https://portal.example.invalid", "REGISTRATION_SMTP_TIMEOUT": "5s",
	} {
		t.Setenv(key, value)
	}
}

func TestRegistrationDisabledDefaultsAndExactMode(t *testing.T) {
	t.Setenv(EnvRegistrationEnabled, "")
	for _, environment := range []string{"development", "test", "production"} {
		cfg, err := LoadRegistration(environment)
		if err != nil || cfg.Enabled {
			t.Fatal("default disabled registration requires irrelevant secrets")
		}
	}
	for _, environment := range []string{"", " development", "PRODUCTION", "staging"} {
		if _, err := LoadRegistration(environment); err == nil {
			t.Fatal("invalid mode accepted")
		}
	}
	t.Setenv(EnvRegistrationEnabled, " true ")
	if _, err := LoadRegistration("production"); err == nil {
		t.Fatal("nonexact enable flag accepted")
	}
}

func TestRegistrationRequiresFiniteExplicitActivationInputs(t *testing.T) {
	registrationEnvironment(t)
	cfg, err := LoadRegistration("production")
	if err != nil || !cfg.Enabled || cfg.PendingCapacity != 10 || cfg.GlobalDailyLimit != 100 || cfg.EmailHourlyLimit != 5 {
		t.Fatalf("valid explicit fixture config failed: %+v %v", cfg, err)
	}
	for key, value := range map[string]string{
		EnvRegistrationPendingCapacity: "", EnvRegistrationGlobalDailyLimit: "0", EnvRegistrationEmailHourlyLimit: "999999999",
		"SMS_ENABLED": "false", "SMS_IR_KEY_MODE": "sandbox", "SMS_OTP_GLOBAL_PER_DAY": "", "SMS_OTP_MAX_PENDING_SIGNUP": "11",
		"REGISTRATION_SMTP_TLS_MODE": "plaintext", "REGISTRATION_SMTP_PUBLIC_ORIGIN": "https://other.example.invalid",
		"REGISTRATION_SMTP_TIMEOUT": "6s", "REGISTRATION_SMTP_PASSWORD": "", "DATABASE_URL": "", "REDIS_URL": "",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := LoadRegistration("production"); err == nil {
				t.Fatal("missing/unsafe launch prerequisite accepted")
			}
		})
	}
	for _, raw := range []string{"-1", "0", "10001", "+10", "010", " 10", "1e3"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(EnvRegistrationPendingCapacity, raw)
			if _, err := LoadRegistration("production"); err == nil {
				t.Fatal("noncanonical/unbounded capacity accepted")
			}
		})
	}
}

func TestRegistrationCleanupIndependentSecretsAndExactEnvironment(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv(EnvRegistrationCleanupDatabaseURL, "postgres://cleanup@example.invalid/db")
	t.Setenv(EnvRegistrationCleanupBatchSize, "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("OIDC_SIGNING_KEY_PEM", "")
	t.Setenv("ENCRYPTION_MASTER_KEK", "")
	t.Setenv("SMS_ENABLED", "false")
	cfg, err := LoadRegistrationCleanup()
	if err != nil || cfg.BatchSize != 100 {
		t.Fatal("DB-only cleanup loaded unrelated secrets")
	}
	for _, raw := range []string{"", "production ", "unknown"} {
		t.Run("mode"+raw, func(t *testing.T) {
			t.Setenv("APP_ENV", raw)
			if _, err := LoadRegistrationCleanup(); err == nil {
				t.Fatal("cleanup accepted unspecified security mode")
			}
		})
	}
	for _, raw := range []string{"0", "501", " 1", "+1"} {
		t.Run("batch"+raw, func(t *testing.T) {
			t.Setenv(EnvRegistrationCleanupBatchSize, raw)
			if _, err := LoadRegistrationCleanup(); err == nil {
				t.Fatal("unbounded cleanup policy")
			}
		})
	}
	t.Setenv(EnvRegistrationCleanupDatabaseURL, "")
	if _, err := LoadRegistrationCleanup(); err == nil {
		t.Fatal("API DSN fallback allowed")
	}
}
