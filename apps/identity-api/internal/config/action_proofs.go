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

// AccountDeletionProofsConfig enables only the T22 ceremony, not live deletion.
type AccountDeletionProofsConfig struct {
	Enabled            bool
	EmailEnabled       bool
	SMSEnabled         bool
	CodeKey            []byte
	BindingKey         []byte
	SMTP               smtptransport.Config
	DeletionTemplateID int64
}

// PasswordChangeProofsConfig enables T24 independently of deletion and login.
type PasswordChangeProofsConfig struct {
	Enabled          bool
	EmailEnabled     bool
	SMSEnabled       bool
	CodeKey          []byte
	BindingKey       []byte
	SMTP             smtptransport.Config
	ChangeTemplateID int64
}

// FirstPasskeyProofsConfig is independent of password login and other proofs.
type FirstPasskeyProofsConfig struct {
	Enabled         bool
	EmailEnabled    bool
	SMSEnabled      bool
	CodeKey         []byte
	BindingKey      []byte
	SMTP            smtptransport.Config
	FirstTemplateID int64
}

// LoadFirstPasskeyProofs keeps all issuance default-off with distinct protection.
func LoadFirstPasskeyProofs(environment string) (FirstPasskeyProofsConfig, error) {
	var cfg FirstPasskeyProofsConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, key := range []string{"FIRST_PASSKEY_PROOFS_ENABLED", "FIRST_PASSKEY_PROOFS_EMAIL_ENABLED", "FIRST_PASSKEY_PROOFS_SMS_ENABLED"} {
		if raw := os.Getenv(key); raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: first passkey proof switches must be true or false")
		}
	}
	cfg.Enabled = os.Getenv("FIRST_PASSKEY_PROOFS_ENABLED") == "true"
	cfg.EmailEnabled = os.Getenv("FIRST_PASSKEY_PROOFS_EMAIL_ENABLED") == "true"
	cfg.SMSEnabled = os.Getenv("FIRST_PASSKEY_PROOFS_SMS_ENABLED") == "true"
	if !cfg.Enabled {
		if cfg.EmailEnabled || cfg.SMSEnabled {
			return cfg, errors.New("config: first passkey proof delivery requires enabled ceremony")
		}
		return cfg, nil
	}
	if !cfg.EmailEnabled && !cfg.SMSEnabled {
		return cfg, errors.New("config: first passkey proofs require at least one delivery channel")
	}
	var err error
	if cfg.CodeKey, err = actionProofKey("LOGIN_CODE_HMAC_KEY"); err != nil {
		return cfg, err
	}
	if cfg.BindingKey, err = actionProofKey("FIRST_PASSKEY_PROOFS_BINDING_KEY"); err != nil {
		return cfg, err
	}
	if bytes.Equal(cfg.CodeKey, cfg.BindingKey) {
		return cfg, errors.New("config: first passkey proof keys must be independent")
	}
	for _, name := range []string{"ACCOUNT_DELETION_PROOFS_BINDING_KEY", "PASSWORD_CHANGE_PROOFS_BINDING_KEY"} {
		other, err := base64.StdEncoding.Strict().DecodeString(os.Getenv(name))
		if err == nil && bytes.Equal(cfg.BindingKey, other) {
			return cfg, errors.New("config: first passkey proof binding key must be purpose-specific")
		}
	}
	if cfg.EmailEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid first passkey proof TLS SMTP configuration")
		}
	}
	if cfg.SMSEnabled {
		if os.Getenv(EnvSMSEnabled) != "true" {
			return cfg, errors.New("config: first passkey SMS proofs require enabled SMS delivery")
		}
		cfg.FirstTemplateID, err = strconv.ParseInt(os.Getenv("FIRST_PASSKEY_SMS_IR_TEMPLATE_ID"), 10, 32)
		if err != nil || cfg.FirstTemplateID <= 0 {
			return cfg, errors.New("config: first passkey SMS requires a distinct explicit template")
		}
		for _, name := range []string{EnvSMSIRTemplateID, "ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID", "PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID"} {
			other, otherErr := strconv.ParseInt(os.Getenv(name), 10, 32)
			if name == EnvSMSIRTemplateID && otherErr != nil || otherErr == nil && cfg.FirstTemplateID == other {
				return cfg, errors.New("config: first passkey SMS requires a distinct explicit template")
			}
		}
	}
	return cfg, nil
}

// LoadPasswordChangeProofs shares contact quotas, never switches or purpose keys.
func LoadPasswordChangeProofs(environment string) (PasswordChangeProofsConfig, error) {
	var cfg PasswordChangeProofsConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, key := range []string{"PASSWORD_CHANGE_PROOFS_ENABLED", "PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED", "PASSWORD_CHANGE_PROOFS_SMS_ENABLED"} {
		if raw := os.Getenv(key); raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: password change proof switches must be true or false")
		}
	}
	cfg.Enabled = os.Getenv("PASSWORD_CHANGE_PROOFS_ENABLED") == "true"
	cfg.EmailEnabled = os.Getenv("PASSWORD_CHANGE_PROOFS_EMAIL_ENABLED") == "true"
	cfg.SMSEnabled = os.Getenv("PASSWORD_CHANGE_PROOFS_SMS_ENABLED") == "true"
	if !cfg.Enabled {
		if cfg.EmailEnabled || cfg.SMSEnabled {
			return cfg, errors.New("config: password change proof delivery requires enabled ceremony")
		}
		return cfg, nil
	}
	if !cfg.EmailEnabled && !cfg.SMSEnabled {
		return cfg, errors.New("config: password change proofs require at least one delivery channel")
	}
	var err error
	if cfg.CodeKey, err = actionProofKey("LOGIN_CODE_HMAC_KEY"); err != nil {
		return cfg, err
	}
	if cfg.BindingKey, err = actionProofKey("PASSWORD_CHANGE_PROOFS_BINDING_KEY"); err != nil {
		return cfg, err
	}
	if bytes.Equal(cfg.CodeKey, cfg.BindingKey) {
		return cfg, errors.New("config: password change proof keys must be independent")
	}
	if cfg.EmailEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid password change proof TLS SMTP configuration")
		}
	}
	if cfg.SMSEnabled {
		if os.Getenv(EnvSMSEnabled) != "true" {
			return cfg, errors.New("config: password change SMS proofs require enabled SMS delivery")
		}
		cfg.ChangeTemplateID, err = strconv.ParseInt(os.Getenv("PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID"), 10, 32)
		loginID, loginErr := strconv.ParseInt(os.Getenv(EnvSMSIRTemplateID), 10, 32)
		deletionID, _ := strconv.ParseInt(os.Getenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID"), 10, 32)
		if err != nil || cfg.ChangeTemplateID <= 0 || loginErr != nil || cfg.ChangeTemplateID == loginID || cfg.ChangeTemplateID == deletionID {
			return cfg, errors.New("config: password change SMS requires a distinct explicit password-change template")
		}
	}
	return cfg, nil
}

// LoadAccountDeletionProofs keeps delivery independent of the login rollout.
// The shared contact-code key preserves cross-purpose quotas and lockouts.
func LoadAccountDeletionProofs(environment string) (AccountDeletionProofsConfig, error) {
	var cfg AccountDeletionProofsConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, key := range []string{"ACCOUNT_DELETION_PROOFS_ENABLED", "ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED", "ACCOUNT_DELETION_PROOFS_SMS_ENABLED"} {
		if raw := os.Getenv(key); raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: account deletion proof switches must be true or false")
		}
	}
	cfg.Enabled = os.Getenv("ACCOUNT_DELETION_PROOFS_ENABLED") == "true"
	cfg.EmailEnabled = os.Getenv("ACCOUNT_DELETION_PROOFS_EMAIL_ENABLED") == "true"
	cfg.SMSEnabled = os.Getenv("ACCOUNT_DELETION_PROOFS_SMS_ENABLED") == "true"
	if !cfg.Enabled {
		if cfg.EmailEnabled || cfg.SMSEnabled {
			return cfg, errors.New("config: account deletion proof delivery requires enabled ceremony")
		}
		return cfg, nil
	}
	if !cfg.EmailEnabled && !cfg.SMSEnabled {
		return cfg, errors.New("config: account deletion proofs require at least one delivery channel")
	}
	var err error
	if cfg.CodeKey, err = actionProofKey("LOGIN_CODE_HMAC_KEY"); err != nil {
		return cfg, err
	}
	if cfg.BindingKey, err = actionProofKey("ACCOUNT_DELETION_PROOFS_BINDING_KEY"); err != nil {
		return cfg, err
	}
	if bytes.Equal(cfg.CodeKey, cfg.BindingKey) {
		return cfg, errors.New("config: account deletion proof keys must be independent")
	}
	if cfg.EmailEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid account deletion proof TLS SMTP configuration")
		}
	}
	if cfg.SMSEnabled {
		if os.Getenv(EnvSMSEnabled) != "true" {
			return cfg, errors.New("config: account deletion SMS proofs require enabled SMS delivery")
		}
		cfg.DeletionTemplateID, err = strconv.ParseInt(os.Getenv("ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID"), 10, 32)
		loginID, loginErr := strconv.ParseInt(os.Getenv(EnvSMSIRTemplateID), 10, 32)
		if err != nil || cfg.DeletionTemplateID <= 0 || loginErr != nil || cfg.DeletionTemplateID == loginID {
			return cfg, errors.New("config: account deletion SMS requires a distinct explicit deletion-request template")
		}
	}
	return cfg, nil
}

func actionProofKey(name string) ([]byte, error) {
	raw := os.Getenv(name)
	if len(raw) > 88 {
		return nil, errors.New("config: invalid action proof protection key")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || len(key) < 32 || len(key) > 64 || bytes.Equal(key, make([]byte, len(key))) {
		return nil, errors.New("config: action proof keys must encode 32..64 nonzero bytes")
	}
	return key, nil
}
