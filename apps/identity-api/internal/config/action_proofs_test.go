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

func passwordChangeProofEnvironment(t *testing.T) {
	t.Helper()
	deletionProofEnvironment(t)
	for _, key := range []string{"PASSWORD_CHANGE_PROOFS_ENABLED", "PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "PASSWORD_CHANGE_PROOFS_SMS_ENABLED", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID"} {
		t.Setenv(key, "")
	}
}

func TestPasswordChangeProofDefaultOffAndIndependentChannels(t *testing.T) {
	passwordChangeProofEnvironment(t)
	cfg, err := LoadPasswordChangeProofs("production")
	if err != nil || cfg.Enabled || cfg.EmailEnabled || cfg.SMSEnabled || len(cfg.BindingKey) != 0 {
		t.Fatal("default password-change configuration acquired proof authority")
	}
	t.Setenv("PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "true")
	if _, err := LoadPasswordChangeProofs("production"); err == nil {
		t.Fatal("delivery enabled without password-change ceremony")
	}
	t.Setenv("PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "false")
	t.Setenv("PASSWORD_CHANGE_PROOFS_ENABLED", "true")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("PASSWORD_CHANGE_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if _, err := LoadPasswordChangeProofs("production"); err == nil {
		t.Fatal("password change enabled without delivery")
	}
	t.Setenv("PASSWORD_CHANGE_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "125")
	cfg, err = LoadPasswordChangeProofs("production")
	if err != nil || !cfg.SMSEnabled || cfg.EmailEnabled || cfg.ChangeTemplateID != 125 {
		t.Fatal("SMS-only password change requires deletion/login/email", err)
	}
	t.Setenv("PASSWORD_CHANGE_PROOFS_SMS_ENABLED", "false")
	t.Setenv("SMS_ENABLED", "false")
	t.Setenv("PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "true")
	t.Setenv("LOGIN_SMTP_HOST", "smtp.example.test")
	t.Setenv("LOGIN_SMTP_PORT", "465")
	t.Setenv("LOGIN_SMTP_TLS_MODE", "implicit")
	t.Setenv("LOGIN_SMTP_FROM", "identity@example.test")
	t.Setenv("LOGIN_SMTP_USERNAME", "isolated-user")
	t.Setenv("LOGIN_SMTP_PASSWORD", "isolated-password")
	cfg, err = LoadPasswordChangeProofs("production")
	if err != nil || !cfg.EmailEnabled || cfg.SMSEnabled {
		t.Fatal("email-only password change depends on SMS or deletion", err)
	}
}

func TestPasswordChangeProofDistinctTemplatesAndProtection(t *testing.T) {
	passwordChangeProofEnvironment(t)
	t.Setenv("PASSWORD_CHANGE_PROOFS_ENABLED", "true")
	t.Setenv("PASSWORD_CHANGE_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("PASSWORD_CHANGE_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	for _, template := range []string{"", "123", "124", "0", "-1", "invalid"} {
		t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", template)
		if _, err := LoadPasswordChangeProofs("production"); err == nil {
			t.Fatal("password change admitted missing/reused template")
		}
	}
	t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "125")
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))} {
		t.Setenv("PASSWORD_CHANGE_PROOFS_BINDING_KEY", key)
		if _, err := LoadPasswordChangeProofs("production"); err == nil {
			t.Fatal("password change admitted invalid/reused protection key")
		}
	}
	t.Setenv("PASSWORD_CHANGE_PROOFS_ENABLED", "TRUE")
	if _, err := LoadPasswordChangeProofs("development"); err == nil {
		t.Fatal("password change admitted noncanonical switch")
	}
}

func firstPasskeyProofEnvironment(t *testing.T) {
	t.Helper()
	passwordChangeProofEnvironment(t)
	for _, key := range []string{"FIRST_PASSKEY_PROOFS_ENABLED", "FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "FIRST_PASSKEY_PROOFS_SMS_ENABLED", "FIRST_PASSKEY_PROOFS_BINDING_KEY", "FIRST_PASSKEY_SMS_IR_TEMPLATE_ID"} {
		t.Setenv(key, "")
	}
}

func TestFirstPasskeyProofDefaultOffAndSelectedChannels(t *testing.T) {
	firstPasskeyProofEnvironment(t)
	cfg, err := LoadFirstPasskeyProofs("production")
	if err != nil || cfg.Enabled || cfg.EmailEnabled || cfg.SMSEnabled || len(cfg.BindingKey) != 0 {
		t.Fatal("default configuration acquired first-passkey authority")
	}
	t.Setenv("FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "true")
	if _, err := LoadFirstPasskeyProofs("production"); err == nil {
		t.Fatal("delivery enabled without ceremony")
	}
	t.Setenv("FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "false")
	t.Setenv("FIRST_PASSKEY_PROOFS_ENABLED", "true")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("FIRST_PASSKEY_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if _, err := LoadFirstPasskeyProofs("production"); err == nil {
		t.Fatal("proof enabled without channel")
	}
	t.Setenv("FIRST_PASSKEY_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "126")
	cfg, err = LoadFirstPasskeyProofs("production")
	if err != nil || !cfg.SMSEnabled || cfg.EmailEnabled || cfg.FirstTemplateID != 126 {
		t.Fatal("SMS-only first proofs depend on login/SMTP", err)
	}
	t.Setenv("FIRST_PASSKEY_PROOFS_SMS_ENABLED", "false")
	t.Setenv("SMS_ENABLED", "false")
	t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "unused-invalid")
	t.Setenv("FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "true")
	t.Setenv("LOGIN_SMTP_HOST", "smtp.example.test")
	t.Setenv("LOGIN_SMTP_PORT", "465")
	t.Setenv("LOGIN_SMTP_TLS_MODE", "implicit")
	t.Setenv("LOGIN_SMTP_FROM", "identity@example.test")
	t.Setenv("LOGIN_SMTP_USERNAME", "isolated-user")
	t.Setenv("LOGIN_SMTP_PASSWORD", "isolated-password")
	cfg, err = LoadFirstPasskeyProofs("production")
	if err != nil || !cfg.EmailEnabled || cfg.SMSEnabled {
		t.Fatal("email-only first proofs depend on disabled SMS", err)
	}
}

func TestFirstPasskeyDistinctProtectionAndTemplates(t *testing.T) {
	firstPasskeyProofEnvironment(t)
	t.Setenv("FIRST_PASSKEY_PROOFS_ENABLED", "true")
	t.Setenv("FIRST_PASSKEY_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "125")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("ACCOUNT_DELETION_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	t.Setenv("PASSWORD_CHANGE_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32)))
	t.Setenv("FIRST_PASSKEY_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	for _, template := range []string{"", "0", "-1", "invalid", "123", "124", "125"} {
		t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", template)
		if _, err := LoadFirstPasskeyProofs("production"); err == nil {
			t.Fatal("first proofs admitted missing/reused template")
		}
	}
	t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "126")
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))} {
		t.Setenv("FIRST_PASSKEY_PROOFS_BINDING_KEY", key)
		if _, err := LoadFirstPasskeyProofs("production"); err == nil {
			t.Fatal("first proofs admitted invalid/reused binding key")
		}
	}
	t.Setenv("FIRST_PASSKEY_PROOFS_ENABLED", "TRUE")
	if _, err := LoadFirstPasskeyProofs("development"); err == nil {
		t.Fatal("first proofs admitted noncanonical switch")
	}
}
