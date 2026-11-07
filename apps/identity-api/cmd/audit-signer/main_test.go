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

func signerStartupEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		config.EnvAuditStreamName, config.EnvAuditSubject, config.EnvAuditConsumerName,
		config.EnvAuditPublishBuffer, config.EnvAuditSpoolPath, config.EnvAuditSpoolLimitBytes,
		config.EnvAuditBatchSize, config.EnvAuditFlushInterval, config.EnvAuditStreamMaxBytes,
		config.EnvAuditAckWait, config.EnvAuditMaxDeliver, config.EnvSecurityLedgerRetention,
	} {
		t.Setenv(key, "")
	}
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://fixture@localhost/unit")
	t.Setenv(config.EnvNATSURL, "nats://localhost:4222")
}

func TestSignerStartupRejectsInvalidEnvironmentBeforeDial(t *testing.T) {
	for _, environment := range []string{"unset", "", " ", "\t", "staging", "Development", "production "} {
		t.Run(environment, func(t *testing.T) {
			signerStartupEnvironment(t)
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
				t.Fatalf("invalid mode reached dial: %v opens=%d", err, opens)
			}
		})
	}
}

func TestSignerStartupLoadsOnlyWorkerConfiguration(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		t.Run(environment, func(t *testing.T) {
			signerStartupEnvironment(t)
			t.Setenv("APP_ENV", environment)
			t.Setenv("PORT", "-1")
			t.Setenv(config.EnvAdminEnabled, "invalid-unrelated-admin")
			t.Setenv("GRPC_ENABLED", "invalid-unrelated-grpc")
			t.Setenv("REDIS_URL", "invalid-unrelated-redis")
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
				t.Fatalf("unrelated API configuration blocked worker: %v opens=%d", err, opens)
			}
		})
	}
}

func TestSignerStartupStillRequiresDatabaseAndBroker(t *testing.T) {
	for _, environment := range []string{"development", "test", "production"} {
		for _, key := range []string{"DATABASE_URL", config.EnvNATSURL} {
			for _, value := range []string{"", " \t"} {
				t.Run(environment+"/"+key+"/"+value, func(t *testing.T) {
					signerStartupEnvironment(t)
					t.Setenv("APP_ENV", environment)
					t.Setenv(key, value)
					opens := 0
					err := runWithPoolOpener(slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, string) (*pgxpool.Pool, error) {
						opens++
						return nil, errors.New("unexpected dial")
					})
					if err == nil || !strings.Contains(err.Error(), key) || opens != 0 {
						t.Fatalf("missing dependency admitted: %v opens=%d", err, opens)
					}
				})
			}
		}
	}
}
