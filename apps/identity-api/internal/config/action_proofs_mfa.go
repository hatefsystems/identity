package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

// MFAEnrollmentProofsConfig separates issuance from bounded pending-state readers.
type MFAEnrollmentProofsConfig struct {
	Enabled              bool
	EmailEnabled         bool
	SMSEnabled           bool
	CodeKey              []byte
	BindingKey           []byte
	SMTP                 smtptransport.Config
	EnrollmentTemplateID int64
}

// LoadMFAEnrollmentProofs retains a configured binding key even with issuance off.
// Disabled readers do not require code keys or available delivery providers.
func LoadMFAEnrollmentProofs(environment string) (MFAEnrollmentProofsConfig, error) {
	var cfg MFAEnrollmentProofsConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, name := range []string{"MFA_ENROLLMENT_PROOFS_ENABLED", "MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED", "MFA_ENROLLMENT_PROOFS_SMS_ENABLED"} {
		if raw := os.Getenv(name); raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: MFA enrollment proof switches must be true or false")
		}
	}
	cfg.Enabled = os.Getenv("MFA_ENROLLMENT_PROOFS_ENABLED") == "true"
	cfg.EmailEnabled = os.Getenv("MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED") == "true"
	cfg.SMSEnabled = os.Getenv("MFA_ENROLLMENT_PROOFS_SMS_ENABLED") == "true"
	var err error
	if cfg.Enabled || os.Getenv("MFA_ENROLLMENT_PROOFS_BINDING_KEY") != "" {
		cfg.BindingKey, err = actionProofKey("MFA_ENROLLMENT_PROOFS_BINDING_KEY")
		if err != nil {
			return cfg, err
		}
		for _, name := range []string{"LOGIN_CODE_HMAC_KEY", "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "FIRST_PASSKEY_PROOFS_BINDING_KEY"} {
			other, decodeErr := base64.StdEncoding.Strict().DecodeString(os.Getenv(name))
			if decodeErr == nil && bytes.Equal(cfg.BindingKey, other) {
				return cfg, errors.New("config: MFA enrollment proof binding key must be purpose-specific")
			}
		}
	}
	if !cfg.Enabled {
		if cfg.EmailEnabled || cfg.SMSEnabled {
			return cfg, errors.New("config: MFA enrollment proof delivery requires enabled ceremony")
		}
		return cfg, nil
	}
	if !cfg.EmailEnabled && !cfg.SMSEnabled {
		return cfg, errors.New("config: MFA enrollment proofs require at least one delivery channel")
	}
	if cfg.CodeKey, err = actionProofKey("LOGIN_CODE_HMAC_KEY"); err != nil {
		return cfg, err
	}
	if cfg.EmailEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid MFA enrollment proof TLS SMTP configuration")
		}
	}
	if cfg.SMSEnabled {
		if os.Getenv(EnvSMSEnabled) != "true" {
			return cfg, errors.New("config: MFA enrollment SMS proofs require enabled SMS delivery")
		}
		cfg.EnrollmentTemplateID, err = strconv.ParseInt(os.Getenv("MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID"), 10, 32)
		if err != nil || cfg.EnrollmentTemplateID <= 0 {
			return cfg, errors.New("config: MFA enrollment SMS requires a distinct explicit template")
		}
		for _, name := range []string{EnvSMSIRTemplateID, "ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "FIRST_PASSKEY_SMS_IR_TEMPLATE_ID"} {
			other, otherErr := strconv.ParseInt(os.Getenv(name), 10, 32)
			if name == EnvSMSIRTemplateID && otherErr != nil || otherErr == nil && cfg.EnrollmentTemplateID == other {
				return cfg, errors.New("config: MFA enrollment SMS requires a distinct explicit template")
			}
		}
	}
	return cfg, nil
}
