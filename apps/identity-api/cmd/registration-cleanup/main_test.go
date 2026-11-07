package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
)

type fakeDatabase struct {
	registration.Database
	closed  bool
	pingErr error
}

func (d *fakeDatabase) Ping(context.Context) error { return d.pingErr }
func (d *fakeDatabase) Close()                     { d.closed = true }

func TestHelpAndInvalidConfigurationBeforeDial(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("REGISTRATION_CLEANUP_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "postgres://must-not-be-used")
	called := false
	deps := dependencies{open: func(context.Context, string) (commandDatabase, error) {
		called = true
		return nil, errors.New("unexpected")
	}}
	logger := slog.New(slog.NewTextHandler(new(bytes.Buffer), nil))
	if err := runWithDependencies(context.Background(), logger, []string{"--help"}, deps); err != nil || called {
		t.Fatal("help loaded environment or dialed")
	}
	for _, args := range [][]string{nil, {"unknown"}, {"once", "extra"}} {
		if err := runWithDependencies(context.Background(), logger, args, deps); err != errConfiguration || called {
			t.Fatal("invalid config dialed")
		}
	}
}

func TestCommandDedicatedDSNReadinessBoundsAndFailures(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("REGISTRATION_CLEANUP_DATABASE_URL", "postgres://cleanup@example.invalid/db")
	t.Setenv("DATABASE_URL", "postgres://must-not-use@example.invalid/db")
	t.Setenv("OIDC_ISSUER", "")
	t.Setenv("OIDC_SIGNING_KEY_PEM", "")
	t.Setenv("ENCRYPTION_MASTER_KEK", "")
	t.Setenv("REGISTRATION_CLEANUP_BATCH_SIZE", "7")
	for _, stage := range []string{"once", "check", "open", "ping", "ready", "cleanup", "deadline"} {
		t.Run(stage, func(t *testing.T) {
			database := &fakeDatabase{}
			ready, cleaned := false, false
			private := errors.New("private-dsn-token-email")
			output := new(bytes.Buffer)
			logger := slog.New(slog.NewJSONHandler(output, nil))
			deps := dependencies{
				open: func(ctx context.Context, dsn string) (commandDatabase, error) {
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) > 30*time.Second || dsn != "postgres://cleanup@example.invalid/db" {
						t.Fatal("unbounded or API DSN startup")
					}
					if stage == "open" {
						return database, private
					}
					if stage == "ping" {
						database.pingErr = private
					}
					return database, nil
				},
				ready: func(context.Context, commandDatabase) error {
					ready = true
					if stage == "ready" {
						return private
					}
					return nil
				},
				cleanup: func(_ context.Context, _ registration.Database, batch int32) (registration.CleanupStats, error) {
					cleaned = true
					if batch != 7 {
						t.Fatal("wrong batch")
					}
					if stage == "cleanup" {
						return registration.CleanupStats{Deleted: 1}, private
					}
					if stage == "deadline" {
						return registration.CleanupStats{}, context.DeadlineExceeded
					}
					return registration.CleanupStats{Deleted: 1}, nil
				},
			}
			args := []string{"once"}
			if stage == "check" {
				args = []string{"check"}
			}
			err := runWithDependencies(context.Background(), logger, args, deps)
			if stage == "once" || stage == "check" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("failure succeeded/leaked")
			}
			if !database.closed {
				t.Fatal("database not closed")
			}
			if (stage == "open" || stage == "ping") && ready {
				t.Fatal("readiness after failed dial")
			}
			if stage == "ready" && cleaned || stage == "check" && cleaned {
				t.Fatal("cleanup before readiness or in check mode")
			}
			if strings.Contains(output.String(), "private") || strings.Contains(output.String(), "postgres://") {
				t.Fatal("connection diagnostic leaked")
			}
		})
	}
}
