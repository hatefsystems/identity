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

// LoginConfig gates only the new first factors. Passkey MFA and authoritative
// session enforcement remain active independently of these delivery switches.
type LoginConfig struct {
	Enabled      bool
	EmailEnabled bool
	HashKey      []byte
	SMTP         smtptransport.Config
}

// LoadLogin validates independent delivery gates without assuming both channels exist.
func LoadLogin(environment string) (LoginConfig, error) {
	var cfg LoginConfig
	if err := ValidateEnvironment(environment); err != nil {
		return cfg, err
	}
	for _, key := range []string{"LOGIN_ENABLED", "LOGIN_EMAIL_ENABLED"} {
		if raw := os.Getenv(key); raw != "" && raw != "true" && raw != "false" {
			return cfg, errors.New("config: login switches must be true or false")
		}
	}
	cfg.Enabled = os.Getenv("LOGIN_ENABLED") == "true"
	cfg.EmailEnabled = os.Getenv("LOGIN_EMAIL_ENABLED") == "true"
	if !cfg.Enabled {
		if cfg.EmailEnabled {
			return cfg, errors.New("config: email login requires LOGIN_ENABLED")
		}
		return cfg, nil
	}
	key := os.Getenv("LOGIN_CODE_HMAC_KEY")
	if len(key) > 88 {
		return cfg, errors.New("config: invalid login code HMAC key")
	}
	var err error
	cfg.HashKey, err = base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(cfg.HashKey) < 32 || len(cfg.HashKey) > 64 || bytes.Equal(cfg.HashKey, make([]byte, len(cfg.HashKey))) {
		return cfg, errors.New("config: login code HMAC key must encode 32..64 nonzero bytes")
	}
	if cfg.EmailEnabled {
		cfg.SMTP = smtptransport.Config{Host: os.Getenv("LOGIN_SMTP_HOST"), TLSMode: os.Getenv("LOGIN_SMTP_TLS_MODE"), Username: os.Getenv("LOGIN_SMTP_USERNAME"), Password: os.Getenv("LOGIN_SMTP_PASSWORD"), From: os.Getenv("LOGIN_SMTP_FROM"), CABundlePath: os.Getenv("LOGIN_SMTP_CA_BUNDLE"), Timeout: 5 * time.Second}
		cfg.SMTP.Port, err = strconv.Atoi(os.Getenv("LOGIN_SMTP_PORT"))
		if err != nil || cfg.SMTP.Validate() != nil {
			return cfg, errors.New("config: invalid login TLS SMTP configuration")
		}
	}
	return cfg, nil
}
