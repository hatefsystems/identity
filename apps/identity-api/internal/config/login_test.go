package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestLoginDefaultOffAndIndependentChannels(t *testing.T) {
	for _, key := range []string{"LOGIN_ENABLED", "LOGIN_EMAIL_ENABLED", "LOGIN_CODE_HMAC_KEY", "SMS_ENABLED"} {
		t.Setenv(key, "")
	}
	cfg, err := LoadLogin("development")
	if err != nil || cfg.Enabled || cfg.EmailEnabled {
		t.Fatalf("default login gate: %+v %v", cfg, err)
	}
	t.Setenv("LOGIN_ENABLED", "true")
	t.Setenv("LOGIN_CODE_HMAC_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	t.Setenv("SMS_ENABLED", "false")
	cfg, err = LoadLogin("development")
	if err != nil || !cfg.Enabled || cfg.EmailEnabled {
		t.Fatalf("password login without delivery: %+v %v", cfg, err)
	}
	t.Setenv("LOGIN_EMAIL_ENABLED", "true")
	if _, err = LoadLogin("development"); err == nil {
		t.Fatal("enabled email accepted missing SMTP configuration")
	}
	t.Setenv("LOGIN_ENABLED", "false")
	if _, err = LoadLogin("development"); err == nil {
		t.Fatal("email exposed without new-login gate")
	}
}

func TestLoginRejectsUnboundedAndPublicHMACKeys(t *testing.T) {
	t.Setenv("LOGIN_ENABLED", "true")
	t.Setenv("LOGIN_EMAIL_ENABLED", "false")
	for _, key := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 65))} {
		t.Setenv("LOGIN_CODE_HMAC_KEY", key)
		if _, err := LoadLogin("production"); err == nil {
			t.Fatal("invalid login HMAC key accepted")
		}
	}
	t.Setenv("LOGIN_ENABLED", "TRUE")
	if _, err := LoadLogin("development"); err == nil {
		t.Fatal("noncanonical rollout gate accepted")
	}
}
