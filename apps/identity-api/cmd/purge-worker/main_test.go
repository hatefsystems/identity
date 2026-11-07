package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func purgeStartupEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		config.EnvGDPRDeletionEnabled, config.EnvGDPRGracePeriod, config.EnvGDPRPurgeBatchSize,
		config.EnvGDPRPurgeDryRun, config.EnvGDPRReclaimMaxAttempts, config.EnvGDPRReclaimPerAccountPerHour,
		config.EnvGDPRReclaimPerSubnetPerHour, config.EnvGDPRDeletePerAccountPerDay,
	} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://fixture@localhost/unit")
}

func TestPurgeStartupRejectsInvalidEnvironmentBeforeDial(t *testing.T) {
	for _, environment := range []string{"unset", "", " ", "\t", "staging", "Development", "production "} {
		t.Run(environment, func(t *testing.T) {
			purgeStartupEnvironment(t)
			t.Setenv("APP_ENV", environment)
			if environment == "unset" {
				if err := os.Unsetenv("APP_ENV"); err != nil {
					t.Fatal(err)
				}
			}
			opens := 0
			err := runWithPoolOpener(slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, string) (*pgxpool.Pool, error) {
				opens++
				return nil, errors.New("unexpected database opener")
			})
			if err == nil || !strings.Contains(err.Error(), "APP_ENV") || opens != 0 {
				t.Fatalf("invalid mode reached dial or purge: %v opens=%d", err, opens)
			}
		})
	}
}

func TestPurgeStartupLoadsOnlyWorkerConfiguration(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			purgeStartupEnvironment(t)
			t.Setenv("APP_ENV", environment)
			t.Setenv("PORT", "-1")
			t.Setenv(config.EnvAdminEnabled, "invalid-unrelated-admin")
			t.Setenv("GRPC_ENABLED", "invalid-unrelated-grpc")
			t.Setenv("REDIS_URL", "invalid-unrelated-redis")
			t.Setenv(config.EnvNATSURL, "invalid-unrelated-broker")
			t.Setenv(config.EnvMasterKEK, "invalid-unrelated-key")
			t.Setenv("DATABASE_URL", " postgres://fixture@localhost/unit ")
			stop := errors.New("database opener reached without I/O")
			opens := 0
			err := runWithPoolOpener(slog.New(slog.NewTextHandler(io.Discard, nil)), func(_ context.Context, dsn string) (*pgxpool.Pool, error) {
				opens++
				if dsn != "postgres://fixture@localhost/unit" {
					t.Fatal("database URL not admitted narrowly")
				}
				return nil, stop
			})
			if !errors.Is(err, stop) || opens != 1 {
				t.Fatalf("unrelated configuration blocked DB-only purge: %v opens=%d", err, opens)
			}
		})
	}
}

func TestPurgeStartupPreservesGraceAndDryRunAdmission(t *testing.T) {
	for _, tc := range []struct {
		environment, grace, dryRun string
		allowed                    bool
	}{
		{"production", "720h", "true", true},
		{"production", "24h", "true", false},
		{"test", "24h", "true", true},
		{"development", "24h", "false", true},
		{"production", "720h", "invalid", false},
	} {
		t.Run(tc.environment+"/"+tc.grace+"/"+tc.dryRun, func(t *testing.T) {
			purgeStartupEnvironment(t)
			t.Setenv("APP_ENV", tc.environment)
			t.Setenv(config.EnvGDPRGracePeriod, tc.grace)
			t.Setenv(config.EnvGDPRPurgeDryRun, tc.dryRun)
			stop := errors.New("database opener reached without I/O")
			opens := 0
			err := runWithPoolOpener(slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, string) (*pgxpool.Pool, error) { opens++; return nil, stop })
			if tc.allowed && (!errors.Is(err, stop) || opens != 1) || !tc.allowed && (err == nil || errors.Is(err, stop) || opens != 0) {
				t.Fatalf("grace/dry-run admission changed: %v opens=%d", err, opens)
			}
		})
	}
}

func TestPurgeStartupRequiresDatabaseBeforeDial(t *testing.T) {
	for _, value := range []string{"", " \t"} {
		t.Run(value, func(t *testing.T) {
			purgeStartupEnvironment(t)
			t.Setenv("DATABASE_URL", value)
			opens := 0
			err := runWithPoolOpener(slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, string) (*pgxpool.Pool, error) {
				opens++
				return nil, errors.New("unexpected database opener")
			})
			if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") || opens != 0 {
				t.Fatalf("missing database admitted: %v opens=%d", err, opens)
			}
		})
	}
}
