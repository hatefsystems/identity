package config

import (
	"testing"
	"time"
)

func TestLedgerPurgeDefaultsAndIsolation(t *testing.T) {
	t.Setenv("SECURITY_LEDGER_PURGE_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "postgres://api/shared")
	if _, err := LoadLedgerPurge(); err == nil {
		t.Fatal("must not fall back to API credentials")
	}
	t.Setenv("SECURITY_LEDGER_PURGE_DATABASE_URL", "postgres://maintenance/db")
	t.Setenv("AUDIT_SUBJECT", "identity.audit.logs")
	cfg, err := LoadLedgerPurge()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BatchSize != 500 || cfg.MaxRows != 10000 || cfg.Timeout != 2*time.Minute || !cfg.DryRun {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
}

func TestLedgerPurgeInvalidSettings(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"SECURITY_LEDGER_PURGE_BATCH_SIZE", "0"},
		{"SECURITY_LEDGER_PURGE_BATCH_SIZE", "5001"},
		{"SECURITY_LEDGER_PURGE_BATCH_SIZE", ""},
		{"SECURITY_LEDGER_PURGE_MAX_ROWS", "499"},
		{"SECURITY_LEDGER_PURGE_MAX_ROWS", "1000001"},
		{"SECURITY_LEDGER_PURGE_TIMEOUT", "0s"},
		{"SECURITY_LEDGER_PURGE_TIMEOUT", "31m"},
		{"SECURITY_LEDGER_PURGE_TIMEOUT", "forever"},
		{"SECURITY_LEDGER_PURGE_DRY_RUN", "maybe"},
		{"AUDIT_SUBJECT", "identity.user.deleted"},
		{"AUDIT_SUBJECT", "identity.audit.>"},
		{"AUDIT_SUBJECT", "identity.audit..logs"},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			t.Setenv("SECURITY_LEDGER_PURGE_DATABASE_URL", "postgres://maintenance/db")
			t.Setenv(tc.key, tc.value)
			if _, err := LoadLedgerPurge(); err == nil {
				t.Fatal("expected configuration rejection")
			}
		})
	}
}
