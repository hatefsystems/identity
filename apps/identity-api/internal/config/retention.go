package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LedgerPurgeConfig deliberately does not load API, cryptographic or broker credentials.
type LedgerPurgeConfig struct {
	DatabaseURL  string
	AuditSubject string
	BatchSize    int
	MaxRows      int
	Timeout      time.Duration
	DryRun       bool
}

// LoadLedgerPurge requires a separate maintenance credential, even in development.
func LoadLedgerPurge() (LedgerPurgeConfig, error) {
	cfg := LedgerPurgeConfig{
		DatabaseURL:  strings.TrimSpace(os.Getenv("SECURITY_LEDGER_PURGE_DATABASE_URL")),
		AuditSubject: getEnv(EnvAuditSubject, defaultAuditSubject),
		BatchSize:    500, MaxRows: 10000, Timeout: 2 * time.Minute, DryRun: true,
	}
	if cfg.DatabaseURL == "" {
		return LedgerPurgeConfig{}, errors.New("config: SECURITY_LEDGER_PURGE_DATABASE_URL is required; API credentials are not a fallback")
	}
	for _, field := range []struct {
		name string
		dst  *int
		max  int
	}{
		{"SECURITY_LEDGER_PURGE_BATCH_SIZE", &cfg.BatchSize, 5000},
		{"SECURITY_LEDGER_PURGE_MAX_ROWS", &cfg.MaxRows, 1000000},
	} {
		if raw, ok := os.LookupEnv(field.name); ok {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > field.max {
				return LedgerPurgeConfig{}, fmt.Errorf("config: %s must be in 1..%d", field.name, field.max)
			}
			*field.dst = value
		}
	}
	if cfg.MaxRows < cfg.BatchSize {
		return LedgerPurgeConfig{}, errors.New("config: SECURITY_LEDGER_PURGE_MAX_ROWS must not be less than batch size")
	}
	if raw, ok := os.LookupEnv("SECURITY_LEDGER_PURGE_TIMEOUT"); ok {
		value, err := time.ParseDuration(raw)
		if err != nil || value < time.Second || value > 30*time.Minute {
			return LedgerPurgeConfig{}, errors.New("config: SECURITY_LEDGER_PURGE_TIMEOUT must be in 1s..30m")
		}
		cfg.Timeout = value
	}
	if raw, ok := os.LookupEnv("SECURITY_LEDGER_PURGE_DRY_RUN"); ok {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return LedgerPurgeConfig{}, errors.New("config: SECURITY_LEDGER_PURGE_DRY_RUN must be a boolean")
		}
		cfg.DryRun = value
	}
	if !strings.HasPrefix(cfg.AuditSubject, auditSubjectPrefix) || len(cfg.AuditSubject) > 100 ||
		strings.ContainsAny(cfg.AuditSubject, "*> \t\r\n") || strings.Contains(cfg.AuditSubject, "..") || strings.HasSuffix(cfg.AuditSubject, ".") {
		return LedgerPurgeConfig{}, errors.New("config: AUDIT_SUBJECT must be a concrete identity.audit subject")
	}
	return cfg, nil
}
