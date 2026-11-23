package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func mfaProofEnvironment(t *testing.T) {
	t.Helper()
	firstPasskeyProofEnvironment(t)
	for _, name := range []string{"MFA_ENROLLMENT_PROOFS_ENABLED", "MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED", "MFA_ENROLLMENT_PROOFS_SMS_ENABLED", "MFA_ENROLLMENT_PROOFS_BINDING_KEY", "MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID"} {
		t.Setenv(name, "")
	}
}

func TestMFAEnrollmentProofDefaultOffAndDisabledReaderKey(t *testing.T) {
	mfaProofEnvironment(t)
	cfg, err := LoadMFAEnrollmentProofs("production")
	if err != nil || cfg.Enabled || cfg.EmailEnabled || cfg.SMSEnabled || len(cfg.BindingKey) != 0 {
		t.Fatal("default configuration acquired MFA enrollment authority", err)
	}
	key := bytes.Repeat([]byte{11}, 32)
	t.Setenv("MFA_ENROLLMENT_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("LOGIN_CODE_HMAC_KEY", "unused-invalid")
	t.Setenv("LOGIN_SMTP_PORT", "unused-invalid")
	t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", "unused-invalid")
	cfg, err = LoadMFAEnrollmentProofs("production")
	if err != nil || cfg.Enabled || !bytes.Equal(cfg.BindingKey, key) || len(cfg.CodeKey) != 0 {
		t.Fatal("disabled issuance discarded reader protection or required a provider", err)
	}
	for _, name := range []string{"MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED", "MFA_ENROLLMENT_PROOFS_SMS_ENABLED"} {
		t.Setenv(name, "true")
		if _, err := LoadMFAEnrollmentProofs("production"); err == nil {
			t.Fatal("delivery enabled without ceremony")
		}
		t.Setenv(name, "false")
	}
}

func TestMFAEnrollmentProofIndependentEmailAndSMS(t *testing.T) {
	mfaProofEnvironment(t)
	t.Setenv("MFA_ENROLLMENT_PROOFS_ENABLED", "true")
	t.Setenv("MFA_ENROLLMENT_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32)))
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if _, err := LoadMFAEnrollmentProofs("production"); err == nil {
		t.Fatal("issuance admitted without an independently selected channel")
	}
	t.Setenv("MFA_ENROLLMENT_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", "127")
	cfg, err := LoadMFAEnrollmentProofs("production")
	if err != nil || !cfg.SMSEnabled || cfg.EmailEnabled || cfg.EnrollmentTemplateID != 127 {
		t.Fatal("SMS-only ceremony required login/email or another purpose", err)
	}
	t.Setenv("MFA_ENROLLMENT_PROOFS_SMS_ENABLED", "false")
	t.Setenv("SMS_ENABLED", "false")
	t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", "unused-invalid")
	t.Setenv("MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED", "true")
	t.Setenv("LOGIN_SMTP_HOST", "smtp.example.test")
	t.Setenv("LOGIN_SMTP_PORT", "465")
	t.Setenv("LOGIN_SMTP_TLS_MODE", "implicit")
	t.Setenv("LOGIN_SMTP_FROM", "identity@example.test")
	t.Setenv("LOGIN_SMTP_USERNAME", "isolated-user")
	t.Setenv("LOGIN_SMTP_PASSWORD", "isolated-password")
	cfg, err = LoadMFAEnrollmentProofs("production")
	if err != nil || !cfg.EmailEnabled || cfg.SMSEnabled {
		t.Fatal("email-only ceremony required SMS or another purpose", err)
	}
}

func TestMFAEnrollmentProofPurposeSpecificKeysTemplatesAndSwitches(t *testing.T) {
	mfaProofEnvironment(t)
	t.Setenv("MFA_ENROLLMENT_PROOFS_ENABLED", "true")
	t.Setenv("MFA_ENROLLMENT_PROOFS_SMS_ENABLED", "true")
	t.Setenv("SMS_ENABLED", "true")
	t.Setenv("SMS_IR_TEMPLATE_ID", "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "125")
	t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "126")
	for i, name := range []string{"LOGIN_CODE_HMAC_KEY", "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "FIRST_PASSKEY_PROOFS_BINDING_KEY", "MFA_ENROLLMENT_PROOFS_BINDING_KEY"} {
		t.Setenv(name, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(7 + i)}, 32)))
	}
	for _, template := range []string{"", "0", "-1", "invalid", "123", "124", "125", "126", "2147483648"} {
		t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", template)
		if _, err := LoadMFAEnrollmentProofs("production"); err == nil {
			t.Fatal("missing/reused/unbounded MFA template admitted")
		}
	}
	t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", "127")
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))} {
		t.Setenv("MFA_ENROLLMENT_PROOFS_BINDING_KEY", key)
		if _, err := LoadMFAEnrollmentProofs("production"); err == nil {
			t.Fatal("invalid/reused MFA enrollment binding key admitted")
		}
	}
	t.Setenv("MFA_ENROLLMENT_PROOFS_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32)))
	for _, name := range []string{"MFA_ENROLLMENT_PROOFS_ENABLED", "MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED", "MFA_ENROLLMENT_PROOFS_SMS_ENABLED"} {
		previous := "false"
		if name != "MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED" {
			previous = "true"
		}
		t.Setenv(name, "TRUE")
		if _, err := LoadMFAEnrollmentProofs("production"); err == nil {
			t.Fatal("noncanonical MFA switch admitted")
		}
		t.Setenv(name, previous)
	}
}
