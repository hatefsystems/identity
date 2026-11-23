package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func contactConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CONTACT_MANAGEMENT_PROOFS_ENABLED", "CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", "CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", "CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED", "CONTACT_MANAGEMENT_BINDING_KEY", "LOGIN_CODE_HMAC_KEY", "CONTACT_CHANGE_SMS_IR_TEMPLATE_ID", "CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID", "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "FIRST_PASSKEY_PROOFS_BINDING_KEY", "MFA_ENROLLMENT_PROOFS_BINDING_KEY", EnvSMSHashPepper, EnvSMSCodeTTL, EnvSMSMaxAttempts, EnvSMSLockoutTTL} {
		t.Setenv(name, "")
	}
}

func TestContactOwnershipRetainsSMSKeyWhenProviderDisabled(t *testing.T) {
	contactConfigEnvironment(t)
	t.Setenv(EnvSMSEnabled, "false")
	t.Setenv(EnvSMSHashPepper, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{35}, 32)))
	t.Setenv(EnvSMSCodeTTL, "unused-invalid")
	t.Setenv(EnvSMSMaxAttempts, "unused-invalid")
	t.Setenv(EnvSMSLockoutTTL, "unused-invalid")
	disabled, err := LoadContactManagement("production")
	if err != nil || len(disabled.CodeKey) != 32 {
		t.Fatal("disabled delivery lost the SMS ownership reader key")
	}
	t.Setenv(EnvSMSEnabled, "true")
	enabled, err := LoadContactManagement("production")
	if err != nil || !bytes.Equal(enabled.CodeKey, disabled.CodeKey) {
		t.Fatal("provider switch changed the ownership code key")
	}
	t.Setenv("CONTACT_MANAGEMENT_BINDING_KEY", base64.StdEncoding.EncodeToString(disabled.CodeKey))
	if _, err := LoadContactManagement("production"); err == nil {
		t.Fatal("contact proof binding key reused the derived ownership code key")
	}
}

func TestContactManagementDefaultOffAndIndependentReaders(t *testing.T) {
	contactConfigEnvironment(t)
	cfg, err := LoadContactManagement("production")
	if err != nil || cfg.ProofsEnabled || cfg.EmailOwnershipEnabled || len(cfg.CodeKey) != 0 || len(cfg.BindingKey) != 0 {
		t.Fatal("contact issuance must remain default-off without provider prerequisites")
	}
	key := bytes.Repeat([]byte{31}, 32)
	t.Setenv("CONTACT_MANAGEMENT_BINDING_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32)))
	cfg, err = LoadContactManagement("production")
	if err != nil || !bytes.Equal(cfg.BindingKey, key) || len(cfg.CodeKey) != 32 || cfg.ProofsEnabled || cfg.EmailOwnershipEnabled {
		t.Fatal("reader keys must survive issuance shutdown without SMTP or SMS")
	}
}

func TestContactManagementRejectsInvalidSwitchesAndCrossPurposeKeys(t *testing.T) {
	for _, name := range []string{"CONTACT_MANAGEMENT_PROOFS_ENABLED", "CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", "CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", "CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED"} {
		t.Run(name, func(t *testing.T) {
			contactConfigEnvironment(t)
			t.Setenv(name, "yes")
			if _, err := LoadContactManagement("production"); err == nil {
				t.Fatal("invalid switch admitted")
			}
		})
	}
	for _, name := range []string{"LOGIN_CODE_HMAC_KEY", EnvSMSHashPepper, "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "FIRST_PASSKEY_PROOFS_BINDING_KEY", "MFA_ENROLLMENT_PROOFS_BINDING_KEY"} {
		t.Run(name, func(t *testing.T) {
			contactConfigEnvironment(t)
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{33}, 32))
			t.Setenv("CONTACT_MANAGEMENT_BINDING_KEY", key)
			t.Setenv(name, key)
			if _, err := LoadContactManagement("production"); err == nil {
				t.Fatal("cross-purpose binding key admitted")
			}
		})
	}
}

func TestContactManagementRequiresExplicitDelivery(t *testing.T) {
	for _, channel := range []string{"CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", "CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED"} {
		t.Run(channel, func(t *testing.T) {
			contactConfigEnvironment(t)
			t.Setenv(channel, "true")
			if _, err := LoadContactManagement("production"); err == nil {
				t.Fatal("delivery admitted without enabled ceremony")
			}
		})
	}
	contactConfigEnvironment(t)
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_ENABLED", "true")
	if _, err := LoadContactManagement("production"); err == nil {
		t.Fatal("proof issuance admitted without a channel")
	}
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_ENABLED", "false")
	t.Setenv("CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED", "true")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{34}, 32)))
	if _, err := LoadContactManagement("production"); err == nil {
		t.Fatal("email ownership admitted without a TLS relay")
	}
}

func TestContactManagementIndependentEmailAndSMSTemplates(t *testing.T) {
	contactConfigEnvironment(t)
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_ENABLED", "true")
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", "true")
	t.Setenv("CONTACT_MANAGEMENT_BINDING_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{37}, 32)))
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{38}, 32)))
	t.Setenv(EnvSMSEnabled, "true")
	t.Setenv(EnvSMSIRTemplateID, "123")
	t.Setenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "124")
	t.Setenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "125")
	t.Setenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "126")
	t.Setenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID", "127")
	t.Setenv("CONTACT_CHANGE_SMS_IR_TEMPLATE_ID", "128")
	t.Setenv("CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID", "129")
	cfg, err := LoadContactManagement("production")
	if err != nil || !cfg.ProofSMSEnabled || cfg.ProofEmailEnabled || cfg.EmailOwnershipEnabled || cfg.ChangeTemplateID != 128 || cfg.RemovalTemplateID != 129 {
		t.Fatal("explicit SMS proof mode required email or activated new ownership")
	}
	for _, name := range []string{"CONTACT_CHANGE_SMS_IR_TEMPLATE_ID", "CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID"} {
		for _, value := range []string{"", "0", "-1", "invalid", "123", "124", "125", "126", "127", "2147483648"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				t.Setenv(name, value)
				if _, err := LoadContactManagement("production"); err == nil {
					t.Fatal("missing, shared-purpose or unbounded action template admitted")
				}
			})
		}
	}
	t.Setenv("CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID", "128")
	if _, err := LoadContactManagement("production"); err == nil {
		t.Fatal("change and removal reused the same template")
	}
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", "false")
	t.Setenv(EnvSMSEnabled, "false")
	t.Setenv("CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", "true")
	t.Setenv("CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED", "true")
	t.Setenv("LOGIN_SMTP_HOST", "smtp.example.test")
	t.Setenv("LOGIN_SMTP_PORT", "465")
	t.Setenv("LOGIN_SMTP_TLS_MODE", "implicit")
	t.Setenv("LOGIN_SMTP_FROM", "identity@example.test")
	t.Setenv("LOGIN_SMTP_USERNAME", "isolated-user")
	t.Setenv("LOGIN_SMTP_PASSWORD", "isolated-password")
	cfg, err = LoadContactManagement("production")
	if err != nil || cfg.ProofSMSEnabled || !cfg.ProofEmailEnabled || !cfg.EmailOwnershipEnabled {
		t.Fatal("email mode required an enabled alternate provider")
	}
}
