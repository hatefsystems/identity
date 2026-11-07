package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func TestRunRequiresDatabaseForPublisherAndCleanup(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("DATABASE_URL", "")
	for _, cleanup := range []bool{false, true} {
		if err := run(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), cleanup); err == nil {
			t.Fatalf("cleanup=%v accepted missing database", cleanup)
		}
	}
}

func TestAuditWorkerRequiresEnvironmentBeforePool(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-owned-worker-dsn")
	for _, raw := range []string{"missing", "", " ", "staging", "development ", "TEST"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("APP_ENV", raw)
			if raw == "missing" {
				if err := os.Unsetenv("APP_ENV"); err != nil {
					t.Fatal(err)
				}
			}
			for _, cleanup := range []bool{false, true} {
				err := run(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), cleanup)
				if err == nil || !strings.Contains(err.Error(), "APP_ENV") {
					t.Fatalf("mode not rejected before pool: %v", err)
				}
			}
		})
	}
}

func TestAuditCleanupIgnoresTransportAndAPISecrets(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-owned-worker-dsn")
	for _, field := range []string{config.EnvMasterKEK, config.EnvBlindIndexPepper, config.EnvOIDCClients, config.EnvOIDCSigningKey, "SMS_GATEWAY_API_KEY", config.EnvAuditBatchSize, config.EnvAuditSubject} {
		t.Setenv(field, "unrelated-invalid-setting")
	}
	t.Setenv(config.EnvNATSURL, "")
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("APP_ENV", environment)
			err := run(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), true)
			if err == nil || !strings.Contains(err.Error(), "invalid-owned-worker-dsn") {
				t.Fatalf("cleanup loaded unrelated settings: %v", err)
			}
		})
	}
}

func TestAuditPublisherRequiresTransportBeforePool(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-owned-worker-dsn")
	t.Setenv(config.EnvNATSURL, "")
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("APP_ENV", environment)
			err := run(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), false)
			if err == nil || !strings.Contains(err.Error(), config.EnvNATSURL) {
				t.Fatalf("publisher reached pool without transport: %v", err)
			}
		})
	}
}

func TestAuditWorkerHelpIndependentOfEnvironmentAndSecrets(t *testing.T) {
	if os.Getenv("AUDIT_HELP_TEST") == "1" {
		flag.CommandLine = flag.NewFlagSet("admin-audit-publisher", flag.ExitOnError)
		os.Args = []string{"admin-audit-publisher", "-h"}
		main()
		return
	}
	t.Setenv("APP_ENV", "")
	t.Setenv("DATABASE_URL", "")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("current test executable is unavailable")
	}
	// #nosec G204 -- Relaunch the system-resolved test binary with a fixed selector.
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestAuditWorkerHelpIndependentOfEnvironmentAndSecrets$")
	cmd.Env = append(os.Environ(), "AUDIT_HELP_TEST=1")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "cleanup-contexts") {
		t.Fatalf("help requires runtime settings: %s, %v", output, err)
	}
}
