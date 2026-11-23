package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smtptransport"
)

// ContactManagementConfig keeps old-contact authorization and new ownership separate.
// Configured reader keys are retained independently of issuance and delivery switches.
type ContactManagementConfig struct {
	ProofsEnabled         bool
	ProofEmailEnabled     bool
	ProofSMSEnabled       bool
	EmailOwnershipEnabled bool
	CodeKey               []byte
	BindingKey            []byte
	SMTP                  smtptransport.Config
	ChangeTemplateID      int64
	RemovalTemplateID     int64
}

// LoadContactManagement never enables contact proofs or email ownership implicitly.
func LoadContactManagement(environment string) (ContactManagementConfig, error) {
	var cfg ContactManagementConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, item := range []struct {
		name string
		out  *bool
	}{
		{"CONTACT_MANAGEMENT_PROOFS_ENABLED", &cfg.ProofsEnabled},
		{"CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED", &cfg.ProofEmailEnabled},
		{"CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED", &cfg.ProofSMSEnabled},
		{"CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED", &cfg.EmailOwnershipEnabled},
	} {
		raw := os.Getenv(item.name)
		if raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: contact management switches must be true or false")
		}
		*item.out = raw == "true"
	}
	if !cfg.ProofsEnabled && (cfg.ProofEmailEnabled || cfg.ProofSMSEnabled) {
		return cfg, errors.New("config: contact proof delivery requires enabled issuance")
	}
	if cfg.ProofsEnabled && !cfg.ProofEmailEnabled && !cfg.ProofSMSEnabled {
		return cfg, errors.New("config: contact proofs require at least one delivery channel")
	}
	var err error
	if cfg.ProofsEnabled || os.Getenv("CONTACT_MANAGEMENT_BINDING_KEY") != "" {
		cfg.BindingKey, err = actionProofKey("CONTACT_MANAGEMENT_BINDING_KEY")
		if err != nil {
			return cfg, err
		}
		for _, name := range []string{"LOGIN_CODE_HMAC_KEY", EnvSMSHashPepper, "ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY", "FIRST_PASSKEY_PROOFS_BINDING_KEY", "MFA_ENROLLMENT_PROOFS_BINDING_KEY"} {
			other, decodeErr := base64.StdEncoding.Strict().DecodeString(os.Getenv(name))
			if decodeErr == nil && bytes.Equal(cfg.BindingKey, other) {
				return cfg, errors.New("config: contact management binding key must be purpose-specific")
			}
		}
	}
	if cfg.ProofsEnabled || cfg.EmailOwnershipEnabled || os.Getenv("LOGIN_CODE_HMAC_KEY") != "" {
		cfg.CodeKey, err = actionProofKey("LOGIN_CODE_HMAC_KEY")
		if err != nil {
			return cfg, err
		}
	}
	// Existing SMS ownership can continue without turning on login or password
	// proofs. Keep its derivation and finite reader policy after sending stops.
	if len(cfg.CodeKey) == 0 && os.Getenv(EnvSMSHashPepper) != "" {
		raw := os.Getenv(EnvSMSHashPepper)
		pepper, decodeErr := base64.StdEncoding.Strict().DecodeString(raw)
		if len(raw) > 88 || decodeErr != nil || len(pepper) < 16 || len(pepper) > 64 || environment == "production" && bytes.Equal(pepper, make([]byte, len(pepper))) {
			return cfg, errors.New("config: invalid retained contact ownership SMS key")
		}
		key := sha256.New()
		_, _ = key.Write([]byte("contactcode:sms:ownership:v1\x00"))
		_, _ = key.Write(pepper)
		cfg.CodeKey = key.Sum(nil)
	}
	if len(cfg.BindingKey) > 0 && bytes.Equal(cfg.BindingKey, cfg.CodeKey) {
		return cfg, errors.New("config: contact management binding and code keys must be independent")
	}
	if cfg.ProofEmailEnabled || cfg.EmailOwnershipEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid contact management TLS SMTP configuration")
		}
	}
	if cfg.ProofSMSEnabled {
		if os.Getenv(EnvSMSEnabled) != "true" {
			return cfg, errors.New("config: contact SMS proofs require enabled SMS delivery")
		}
		for _, item := range []struct {
			name string
			out  *int64
		}{
			{"CONTACT_CHANGE_SMS_IR_TEMPLATE_ID", &cfg.ChangeTemplateID},
			{"CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID", &cfg.RemovalTemplateID},
		} {
			*item.out, err = strconv.ParseInt(os.Getenv(item.name), 10, 32)
			if err != nil || *item.out <= 0 {
				return cfg, errors.New("config: contact SMS proofs require explicit distinct templates")
			}
			for _, name := range []string{EnvSMSIRTemplateID, "ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID", "FIRST_PASSKEY_SMS_IR_TEMPLATE_ID", "MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID"} {
				other, decodeErr := strconv.ParseInt(os.Getenv(name), 10, 32)
				if name == EnvSMSIRTemplateID && decodeErr != nil || decodeErr == nil && *item.out == other {
					return cfg, errors.New("config: contact SMS proofs require explicit distinct templates")
				}
			}
		}
		if cfg.ChangeTemplateID == cfg.RemovalTemplateID {
			return cfg, errors.New("config: contact change and removal SMS templates must differ")
		}
	}
	return cfg, nil
}
