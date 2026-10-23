// Command lifecycle-publisher publishes committed lifecycle intent. Provisioning
// and hold-aware cleanup are explicit, separately credentialed operator modes.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/lifecycle"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, os.Args[1:]); err != nil {
		logFailure(logger, err)
		os.Exit(1)
	}
}

type workerDatabase interface {
	lifecycle.Beginner
	Ping(context.Context) error
	Close()
}

type commandDependencies struct {
	openDatabase func(context.Context, string) (workerDatabase, error)
	connect      func(context.Context, string, *slog.Logger) (jetstream.JetStream, func(), error)
}

func run(ctx context.Context, logger *slog.Logger, args []string) error {
	return runWithDependencies(ctx, logger, args, commandDependencies{
		openDatabase: func(ctx context.Context, dsn string) (workerDatabase, error) { return pgxpool.New(ctx, dsn) },
		connect:      connectNATS,
	})
}

func runWithDependencies(ctx context.Context, logger *slog.Logger, args []string, deps commandDependencies) (result error) {
	if logger == nil {
		logger = slog.Default()
	}
	mode := "publish"
	if len(args) == 1 {
		mode = args[0]
	}
	if len(args) > 1 {
		return errors.New("lifecycle worker: expected one mode")
	}
	switch mode {
	case "-h", "--help":
		logger.Info("usage: lifecycle-publisher [publish|provision|cleanup-published]")
		return nil
	case "publish", "provision", "cleanup-published":
	default:
		return errors.New("lifecycle worker: unsupported mode")
	}
	if ctx.Err() != nil {
		return nil
	}
	// A signal is a graceful stop, including while starting dependencies. Resource
	// cleanup still runs; an independent startup deadline remains a real failure.
	defer func() {
		if ctx.Err() != nil {
			result = nil
		}
	}()
	var cfg config.LifecycleConfig
	var maintenance config.LifecycleCleanupConfig
	var err error
	switch mode {
	case "cleanup-published":
		maintenance, err = config.LoadLifecycleCleanup()
		cfg.DatabaseURL, cfg.StartupTimeout = maintenance.DatabaseURL, maintenance.StartupTimeout
	case "provision":
		cfg, err = config.LoadLifecycleProvision()
	default:
		cfg, err = config.LoadLifecycle()
		if err == nil && cfg.DatabaseURL == "" {
			err = errors.New("lifecycle worker: DATABASE_URL is required for publishing")
		}
	}
	if err != nil {
		return err
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancelStartup()
	var database workerDatabase
	if mode != "provision" {
		database, err = deps.openDatabase(startupCtx, cfg.DatabaseURL)
		if err != nil || database == nil {
			return lifecycle.ErrUnavailable
		}
		defer database.Close()
		if err := database.Ping(startupCtx); err != nil {
			return lifecycle.ErrUnavailable
		}
	}
	if mode == "cleanup-published" {
		cancelStartup()
		count, err := lifecycle.CleanupPublished(ctx, database, maintenance.Retention, maintenance.BatchSize)
		if err == nil {
			logger.Info("lifecycle published cleanup complete", "deleted", count)
		} else if ctx.Err() == nil {
			logger.Error("lifecycle published cleanup incomplete", "deleted", count, "invalid", errors.Is(err, lifecycle.ErrInvalidEvent))
		}
		return err
	}
	js, closeConnection, err := deps.connect(startupCtx, cfg.NATSURL, logger)
	if err != nil || js == nil || closeConnection == nil {
		if closeConnection != nil {
			closeConnection()
		}
		return lifecycle.ErrUnavailable
	}
	// Synchronous publishes are settled before this runs. Close is non-draining:
	// a disconnected broker must not hold process shutdown open indefinitely.
	defer closeConnection()
	opts := lifecycle.StreamOptions{Name: cfg.StreamName, MaxBytes: cfg.StreamMaxBytes, MaxAge: cfg.StreamMaxAge}
	if mode == "provision" {
		if _, err := lifecycle.ProvisionStream(startupCtx, js, opts); err != nil {
			return err
		}
		logger.Info("lifecycle stream provisioned and validated")
		return nil
	}
	if _, err := lifecycle.OpenStream(startupCtx, js, opts); err != nil {
		return err
	}
	cancelStartup()
	worker, err := lifecycle.NewPublisher(database, js, cfg.StreamName, cfg.Publisher)
	if err != nil {
		return err
	}
	return worker.RunUntilDone(ctx, logger)
}

// NATS' synchronous initial dial has a per-server timeout rather than context
// cancellation. Bound the entire startup and close any late connection instead
// of waiting through every URL after shutdown was requested.
func connectNATS(ctx context.Context, url string, logger *slog.Logger) (jetstream.JetStream, func(), error) {
	type connection struct {
		js    jetstream.JetStream
		close func()
		err   error
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	result := make(chan connection)
	go func() {
		nc, js, err := natsjs.Connect(ctx, url, "lifecycle-publisher", logger)
		var closeConnection func()
		if nc != nil {
			closeConnection = nc.Close
		}
		select {
		case result <- connection{js: js, close: closeConnection, err: err}:
		case <-ctx.Done():
			if closeConnection != nil {
				closeConnection()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case c := <-result:
		if c.err != nil {
			if c.close != nil {
				c.close()
			}
			return nil, nil, lifecycle.ErrUnavailable
		}
		return c.js, c.close, nil
	}
}

func logFailure(logger *slog.Logger, err error) {
	reason := "dependency_or_configuration_failure"
	switch {
	case errors.Is(err, lifecycle.ErrStreamMissing):
		reason = "stream_missing"
	case errors.Is(err, lifecycle.ErrStreamMismatch):
		reason = "stream_topology_mismatch"
	case errors.Is(err, lifecycle.ErrInvalidEvent):
		reason = "invalid_envelope"
	}
	logger.Error("lifecycle worker terminated", "reason", reason)
}
