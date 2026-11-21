package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func deletionProofEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"ACCOUNT_DELETION_PROOFS_ENABLED", "ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED", "ACCOUNT_DELETION_PROOFS_SMS_ENABLED", "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "LOGIN_ENABLED", "LOGIN_EMAIL_ENABLED", "LOGIN_CODE_HMAC_KEY", "SMS_ENABLED"} {
		t.Setenv(name, "")
	}
}

func TestAccountDeletionProofDefaultOff(t *testing.T) {
	deletionProofEnvironment(t)
	cfg, err := LoadAccountDeletionProofs("production")
	if err != nil || cfg.Enabled || cfg.EmailEnabled || cfg.SMSEnabled || len(cfg.CodeKey) != 0 || len(cfg.BindingKey) != 0 {
		t.Fatal("disabled ceremony acquired delivery or proof authority")
	}
	t.Setenv("ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED", "true")
	if _, err := LoadAccountDeletionProofs("production"); err == nil {
		t.Fatal("delivery enabled without ceremony")
	}
}

func TestAccountDeletionProofIndependentChannelsAndLogin(t *testing.T) {
	deletionProofEnvironment(t)
	t.Setenv("ACCOUNT_DELETION_PROOFS_ENABLED", "true")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("ACCOUNT_DELETION_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if _, err := LoadAccountDeletionProofs("production"); err == nil {
		t.Fatal("ceremony admitted without delivery")
	}
	t.Setenv("ACCOUNT_DELETION_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	cfg, err := LoadAccountDeletionProofs("production")
	if err != nil || !cfg.SMSEnabled || cfg.EmailEnabled || cfg.DeletionTemplateID != 124 {
		t.Fatal("SMS-only ceremony depends on login or email")
	}
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "123")
	if _, err := LoadAccountDeletionProofs("production"); err == nil {
		t.Fatal("sign-in SMS template accepted for deletion")
	}
	t.Setenv("ACCOUNT_DELETION_PROOFS_SMS_ENABLED", "false")
	t.Setenv("SMS_ENABLED", "false")
	t.Setenv("ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED", "true")
	t.Setenv("LOGIN_SMTP_HOST", "smtp.example.test")
	t.Setenv("LOGIN_SMTP_PORT", "465")
	t.Setenv("LOGIN_SMTP_TLS_MODE", "implicit")
	t.Setenv("LOGIN_SMTP_FROM", "identity@example.test")
	t.Setenv("LOGIN_SMTP_USERNAME", "isolated-user")
	t.Setenv("LOGIN_SMTP_PASSWORD", "isolated-password")
	cfg, err = LoadAccountDeletionProofs("production")
	if err != nil || !cfg.EmailEnabled || cfg.SMSEnabled {
		t.Fatalf("email-only ceremony depends on SMS or login: %v", err)
	}
}

func TestAccountDeletionProofProtectionKeysAndSwitches(t *testing.T) {
	deletionProofEnvironment(t)
	t.Setenv("ACCOUNT_DELETION_PROOFS_ENABLED", "true")
	t.Setenv("ACCOUNT_DELETION_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))} {
		t.Setenv("ACCOUNT_DELETION_PROOFS_BINDING_KEY", key)
		if _, err := LoadAccountDeletionProofs("production"); err == nil {
			t.Fatal("invalid or reused proof protection key accepted")
		}
	}
	t.Setenv("ACCOUNT_DELETION_PROOFS_ENABLED", "TRUE")
	if _, err := LoadAccountDeletionProofs("development"); err == nil {
		t.Fatal("noncanonical proof rollout gate accepted")
	}
}
