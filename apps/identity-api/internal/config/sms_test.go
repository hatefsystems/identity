package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func smsEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{EnvSMSEnabled, EnvSMSProvider, EnvSMSKeyMode, EnvSMSGatewayAPIKey, EnvSMSIRTemplateID, EnvSMSIRCodeParameter, EnvSMSCodeTTL, EnvSMSMaxAttempts, EnvSMSLockoutTTL, EnvSMSPerPhonePerMinute, EnvSMSPerPhonePerHour, EnvSMSPerSubnetPerHour, EnvSMSHashPepper, EnvSMSGlobalPerDay, EnvSMSMaxPendingSignup} {
		t.Setenv(key, "")
	}
}
func enabledSMS(t *testing.T) {
	smsEnvironment(t)
	t.Setenv(EnvSMSEnabled, "true")
	t.Setenv(EnvSMSProvider, "smsir")
	t.Setenv(EnvSMSKeyMode, "live")
	t.Setenv(EnvSMSGatewayAPIKey, "unit-test-only-not-a-live-key")
	t.Setenv(EnvSMSIRTemplateID, "42")
	t.Setenv(EnvSMSIRCodeParameter, "Code")
	t.Setenv(EnvSMSHashPepper, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("p", 32))))
}
func TestSMSDisabledNeedsNoDeliverySecrets(t *testing.T) {
	smsEnvironment(t)
	t.Setenv(EnvSMSHashPepper, "invalid")
	for _, env := range []string{"development", "test", "production"} {
		cfg, err := LoadSMS(env)
		if err != nil || cfg.Enabled || cfg.GatewayAPIKey != "" || cfg.HashPepper != nil {
			t.Fatalf("disabled config: %v", err)
		}
	}
	for _, env := range []string{"", " Production", "staging", "production "} {
		if _, err := LoadSMS(env); err == nil {
			t.Fatal("invalid environment accepted")
		}
	}
}
func TestSMSEnabledDefaultsAndExplicitProvider(t *testing.T) {
	enabledSMS(t)
	cfg, err := LoadSMS("production")
	if err != nil || cfg.CodeTTL != 3*time.Minute || cfg.MaxAttempts != 3 || cfg.LockoutTTL != 15*time.Minute || cfg.PerPhonePerMinute != 1 || cfg.PerPhonePerHour != 5 || cfg.PerSubnetPerHour != 10 {
		t.Fatalf("defaults: %v", err)
	}
	t.Setenv(EnvSMSKeyMode, "sandbox")
	if _, err := LoadSMS("production"); err == nil {
		t.Fatal("production accepted sandbox")
	}
	if _, err := LoadSMS("test"); err != nil {
		t.Fatal(err)
	}
}
func TestSMSConfigurationRejectsMissingUnsafeAndHugeValues(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{EnvSMSEnabled, "TRUE"}, {EnvSMSProvider, ""}, {EnvSMSProvider, "log"}, {EnvSMSKeyMode, ""}, {EnvSMSKeyMode, "LIVE"},
		{EnvSMSGatewayAPIKey, ""}, {EnvSMSGatewayAPIKey, "secret\nprivate"}, {EnvSMSGatewayAPIKey, strings.Repeat("a", 513)},
		{EnvSMSIRTemplateID, ""}, {EnvSMSIRTemplateID, "0"}, {EnvSMSIRTemplateID, "-1"}, {EnvSMSIRTemplateID, "1.5"}, {EnvSMSIRTemplateID, "2147483648"},
		{EnvSMSIRCodeParameter, ""}, {EnvSMSIRCodeParameter, "#Code#"}, {EnvSMSIRCodeParameter, " Code"},
		{EnvSMSCodeTTL, "0s"}, {EnvSMSCodeTTL, "4m"}, {EnvSMSLockoutTTL, "1s"}, {EnvSMSLockoutTTL, "25h"},
		{EnvSMSMaxAttempts, "4"}, {EnvSMSPerPhonePerMinute, "6"}, {EnvSMSPerPhonePerHour, "21"}, {EnvSMSPerSubnetPerHour, "101"},
		{EnvSMSHashPepper, ""}, {EnvSMSHashPepper, "private-invalid-base64"}, {EnvSMSHashPepper, base64.StdEncoding.EncodeToString(make([]byte, 65))},
		{EnvSMSHashPepper, base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{EnvSMSGlobalPerDay, "100001"}, {EnvSMSMaxPendingSignup, "10001"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			enabledSMS(t)
			t.Setenv(tc.key, tc.value)
			if _, err := LoadSMS("production"); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}
