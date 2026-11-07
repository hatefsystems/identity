package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp/smsir"
)

// SMSConfig defines delivery enablement, provider settings, and bounded OTP policy.
type SMSConfig struct {
	Enabled           bool
	Provider          string
	KeyMode           string
	GatewayAPIKey     string
	TemplateID        int64
	CodeParameter     string
	CodeTTL           time.Duration
	MaxAttempts       int
	LockoutTTL        time.Duration
	PerPhonePerMinute int
	PerPhonePerHour   int
	PerSubnetPerHour  int
	GlobalPerDay      int
	MaxPendingSignup  int
	HashPepper        []byte
}

// EnvSMSEnabled and the other SMS environment keys configure delivery and OTP budgets.
const (
	EnvSMSEnabled           = "SMS_ENABLED"
	EnvSMSProvider          = "SMS_PROVIDER"
	EnvSMSKeyMode           = "SMS_IR_KEY_MODE"
	EnvSMSGatewayAPIKey     = "SMS_GATEWAY_API_KEY" //nolint:gosec // Environment name, not a credential.
	EnvSMSIRTemplateID      = "SMS_IR_TEMPLATE_ID"
	EnvSMSIRCodeParameter   = "SMS_IR_CODE_PARAMETER"
	EnvSMSCodeTTL           = "SMS_OTP_CODE_TTL"
	EnvSMSMaxAttempts       = "SMS_OTP_MAX_ATTEMPTS"
	EnvSMSLockoutTTL        = "SMS_OTP_LOCKOUT_TTL"
	EnvSMSPerPhonePerMinute = "SMS_OTP_PER_PHONE_PER_MINUTE"
	EnvSMSPerPhonePerHour   = "SMS_OTP_PER_PHONE_PER_HOUR"
	EnvSMSPerSubnetPerHour  = "SMS_OTP_PER_SUBNET_PER_HOUR"
	EnvSMSGlobalPerDay      = "SMS_OTP_GLOBAL_PER_DAY"
	EnvSMSMaxPendingSignup  = "SMS_OTP_MAX_PENDING_SIGNUP"
	EnvSMSHashPepper        = "SMS_OTP_HASH_PEPPER"
)

// LoadSMS validates delivery only when enabled. Disabled removal needs no secrets.
func LoadSMS(environment string) (SMSConfig, error) {
	if err := ValidateEnvironment(environment); err != nil {
		return SMSConfig{}, err
	}
	cfg := SMSConfig{}
	raw := os.Getenv(EnvSMSEnabled)
	if raw != "" && raw != "true" && raw != "false" {
		return cfg, fmt.Errorf("config: %s must be true or false", EnvSMSEnabled)
	}
	cfg.Enabled = raw == "true"
	if !cfg.Enabled {
		return cfg, nil
	}
	cfg.Provider = os.Getenv(EnvSMSProvider)
	if cfg.Provider != "smsir" {
		return SMSConfig{}, fmt.Errorf("config: %s must be smsir", EnvSMSProvider)
	}
	cfg.KeyMode = os.Getenv(EnvSMSKeyMode)
	if cfg.KeyMode != "live" && cfg.KeyMode != "sandbox" || environment == "production" && cfg.KeyMode != "live" {
		return SMSConfig{}, fmt.Errorf("config: %s must declare an allowed live or sandbox mode", EnvSMSKeyMode)
	}
	cfg.GatewayAPIKey = os.Getenv(EnvSMSGatewayAPIKey)
	if !smsir.ValidAPIKey(cfg.GatewayAPIKey) {
		return SMSConfig{}, fmt.Errorf("config: invalid or missing %s", EnvSMSGatewayAPIKey)
	}
	id, err := strconv.ParseInt(os.Getenv(EnvSMSIRTemplateID), 10, 32)
	if err != nil || id <= 0 {
		return SMSConfig{}, fmt.Errorf("config: %s must be an explicit positive integer", EnvSMSIRTemplateID)
	}
	cfg.TemplateID = id
	cfg.CodeParameter = os.Getenv(EnvSMSIRCodeParameter)
	if !smsir.ValidParameter(cfg.CodeParameter) {
		return SMSConfig{}, fmt.Errorf("config: invalid or missing %s", EnvSMSIRCodeParameter)
	}
	if cfg.CodeTTL, err = getEnvDuration(EnvSMSCodeTTL, 3*time.Minute); err != nil {
		return SMSConfig{}, err
	}
	if cfg.CodeTTL < time.Second || cfg.CodeTTL > 3*time.Minute {
		return SMSConfig{}, fmt.Errorf("config: %s outside 1s..3m", EnvSMSCodeTTL)
	}
	if cfg.LockoutTTL, err = getEnvDuration(EnvSMSLockoutTTL, 15*time.Minute); err != nil {
		return SMSConfig{}, err
	}
	if cfg.LockoutTTL < 15*time.Minute || cfg.LockoutTTL > 24*time.Hour {
		return SMSConfig{}, fmt.Errorf("config: %s outside 15m..24h", EnvSMSLockoutTTL)
	}
	for _, item := range []struct {
		key           string
		fallback, max int
		out           *int
	}{
		{EnvSMSMaxAttempts, 3, 3, &cfg.MaxAttempts},
		{EnvSMSPerPhonePerMinute, 1, 5, &cfg.PerPhonePerMinute},
		{EnvSMSPerPhonePerHour, 5, 20, &cfg.PerPhonePerHour},
		{EnvSMSPerSubnetPerHour, 10, 100, &cfg.PerSubnetPerHour},
	} {
		if *item.out, err = getEnvPositiveInt(item.key, item.fallback); err != nil {
			return SMSConfig{}, err
		}
		if *item.out > item.max {
			return SMSConfig{}, fmt.Errorf("config: %s exceeds safety ceiling", item.key)
		}
	}
	for _, item := range []struct {
		key string
		max int
		out *int
	}{
		{EnvSMSGlobalPerDay, 100000, &cfg.GlobalPerDay}, {EnvSMSMaxPendingSignup, 10000, &cfg.MaxPendingSignup},
	} {
		if os.Getenv(item.key) == "" {
			continue
		}
		if *item.out, err = getEnvPositiveInt(item.key, 0); err != nil || *item.out > item.max {
			return SMSConfig{}, fmt.Errorf("config: %s must be within its finite safety ceiling", item.key)
		}
	}
	pepperRaw := os.Getenv(EnvSMSHashPepper)
	if len(pepperRaw) > 88 {
		return SMSConfig{}, fmt.Errorf("config: %s is too long", EnvSMSHashPepper)
	}
	cfg.HashPepper, err = base64.StdEncoding.Strict().DecodeString(pepperRaw)
	if err != nil || len(cfg.HashPepper) < 16 || len(cfg.HashPepper) > 64 {
		return SMSConfig{}, fmt.Errorf("config: %s must encode 16..64 bytes", EnvSMSHashPepper)
	}
	if environment == "production" && bytes.Equal(cfg.HashPepper, make([]byte, 32)) {
		return SMSConfig{}, fmt.Errorf("config: %s must not use the public all-zero test pepper", EnvSMSHashPepper)
	}
	return cfg, nil
}

func getEnvPositiveInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 || strings.TrimSpace(raw) != raw {
		return 0, fmt.Errorf("config: %s must be a positive integer", key)
	}
	return v, nil
}
