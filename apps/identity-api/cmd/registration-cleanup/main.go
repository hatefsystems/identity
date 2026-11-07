// Command registration-cleanup performs one bounded transient-state cleanup pass.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/registration"
)

var (
	errConfiguration = errors.New("registration cleanup: invalid configuration")
	errDatabase      = errors.New("registration cleanup: database unavailable")
	errReadiness     = errors.New("registration cleanup: restricted schema and privileges required")
	errCleanup       = errors.New("registration cleanup: pass incomplete")
)

type commandDatabase interface {
	registration.Database
	Ping(context.Context) error
	Close()
}

type dependencies struct {
	open    func(context.Context, string) (commandDatabase, error)
	ready   func(context.Context, commandDatabase) error
	cleanup func(context.Context, registration.Database, int32) (registration.CleanupStats, error)
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, os.Args[1:]); err != nil {
		// Never log raw connection, role, query or provider errors.
		logger.Error("registration cleanup failed", "reason", err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, args []string) error {
	return runWithDependencies(ctx, logger, args, dependencies{
		open: func(ctx context.Context, dsn string) (commandDatabase, error) {
			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				return nil, errDatabase
			}
			cfg.MaxConns = 2
			cfg.ConnConfig.ConnectTimeout = 5 * time.Second
			return pgxpool.NewWithConfig(ctx, cfg)
		},
		ready: func(ctx context.Context, database commandDatabase) error {
			return registration.CheckCleanupReady(ctx, database)
		},
		cleanup: registration.Cleanup,
	})
}

func runWithDependencies(ctx context.Context, logger *slog.Logger, args []string, deps dependencies) error {
	if logger == nil {
		logger = slog.Default()
	}
	mode := "once"
	if len(args) == 1 {
		mode = args[0]
	}
	if len(args) > 1 {
		return errConfiguration
	}
	switch mode {
	case "--help", "-h":
		logger.Info("usage: registration-cleanup [once|check]; dedicated REGISTRATION_CLEANUP_DATABASE_URL and explicit APP_ENV required")
		return nil
	case "once", "check":
	default:
		return errConfiguration
	}
	cfg, err := config.LoadRegistrationCleanup()
	if err != nil {
		return errConfiguration
	}
	// The deadline covers dialing, privilege/schema probes and the entire pass.
	ctx, cancel := context.WithTimeout(ctx, registration.CleanupTimeout)
	defer cancel()
	database, err := deps.open(ctx, cfg.DatabaseURL)
	if database != nil {
		defer database.Close()
	}
	if err != nil || database == nil || database.Ping(ctx) != nil {
		return errDatabase
	}
	if deps.ready(ctx, database) != nil {
		return errReadiness
	}
	if mode == "check" {
		logger.Info("registration cleanup ready")
		return nil
	}
	stats, err := deps.cleanup(ctx, database, cfg.BatchSize)
	logger.Info("registration cleanup outcome", "considered", stats.Considered, "deleted", stats.Deleted,
		"held", stats.Held, "contended", stats.Contended, "complete", err == nil && ctx.Err() == nil)
	if err != nil || ctx.Err() != nil {
		return errCleanup
	}
	return nil
}
