// Command deletion-notifier drains encrypted per-recipient deletion notices.
// The default run mode polls until SIGINT/SIGTERM; once performs one bounded pass.
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

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy/smtp"
)

// A pass can stop before its batch is exhausted. Leases and unclaimed work remain
// durable for the next pass; database/lock waits may not hang a process forever.
const maxPassDuration = 5 * time.Minute

var (
	errConfiguration = errors.New("deletion notifier: invalid configuration")
	errDatabase      = errors.New("deletion notifier: database unavailable")
	errWorker        = errors.New("deletion notifier: worker initialization failed")
	errPass          = errors.New("deletion notifier: pass incomplete")
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
	db.DBTX
	privacy.Transacter
	Ping(context.Context) error
	Close()
}

type notificationWorker interface {
	RunOnce(context.Context) (privacy.NotificationStats, error)
}

type commandDependencies struct {
	openDatabase func(context.Context, string) (workerDatabase, error)
	newWorker    func(privacy.NotificationConfig, workerDatabase, privacy.Cipher, privacy.Notifier, *slog.Logger) (notificationWorker, error)
}

func run(ctx context.Context, logger *slog.Logger, args []string) error {
	return runWithDependencies(ctx, logger, args, commandDependencies{
		openDatabase: func(ctx context.Context, dsn string) (workerDatabase, error) { return pgxpool.New(ctx, dsn) },
		newWorker:    newWorker,
	})
}

func newWorker(cfg privacy.NotificationConfig, database workerDatabase, cipher privacy.Cipher, notifier privacy.Notifier, logger *slog.Logger) (notificationWorker, error) {
	return privacy.NewNotificationWorker(cfg, db.New(database), database, cipher, notifier, audit.NewLogRecorder(logger),
		privacy.WithNotificationLogger(logger))
}

func runWithDependencies(ctx context.Context, logger *slog.Logger, args []string, deps commandDependencies) (result error) {
	if logger == nil {
		logger = slog.Default()
	}
	mode := "run"
	if len(args) == 1 {
		mode = args[0]
	}
	if len(args) > 1 {
		return errors.New("deletion notifier: expected one mode")
	}
	switch mode {
	case "-h", "--help":
		logger.Info("usage: deletion-notifier [run|once]")
		return nil
	case "run", "once":
	default:
		return errors.New("deletion notifier: unsupported mode")
	}
	if ctx.Err() != nil {
		return nil
	}
	// Signals are graceful shutdown, including startup cancellation. Independent
	// startup/pass deadlines remain failures, not successful deliveries.
	defer func() {
		if ctx.Err() != nil {
			result = nil
		}
	}()
	cfg, err := config.LoadDeletionNotifier()
	if err != nil {
		return errConfiguration
	}
	cryptoCfg, err := config.LoadEnvelopeCrypto()
	if err != nil {
		return errConfiguration
	}
	provider, err := kms.NewMockProvider(cryptoCfg.MasterKEK, cryptoCfg.MasterKEKVersion)
	clear(cryptoCfg.MasterKEK)
	if err != nil {
		return errConfiguration
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		return errConfiguration
	}
	notifier, err := smtp.New(cfg.SMTP)
	if err != nil {
		return errConfiguration
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancelStartup()
	database, err := deps.openDatabase(startupCtx, cfg.DatabaseURL)
	if database != nil {
		defer database.Close()
	}
	if err != nil || database == nil {
		return errDatabase
	}
	if err := database.Ping(startupCtx); err != nil {
		return errDatabase
	}
	cancelStartup()
	if ctx.Err() != nil {
		return nil
	}
	worker, err := deps.newWorker(privacy.NotificationConfig{
		BatchSize: cfg.BatchSize, Concurrency: cfg.Concurrency, LeaseDuration: cfg.LeaseDuration,
		SendTimeout: cfg.SMTP.Timeout, RetryBase: cfg.RetryBase, RetryMax: cfg.RetryMax,
		GracePeriod: cfg.GracePeriod, ReclaimMaxAttempts: cfg.ReclaimMaxAttempts,
	}, database, cipher, notifier, logger)
	if err != nil || worker == nil {
		return errWorker
	}
	logger.Info("deletion notifier starting", "mode", mode, "batch_size", cfg.BatchSize, "concurrency", cfg.Concurrency)
	for ctx.Err() == nil {
		passCtx, cancelPass := context.WithTimeout(ctx, maxPassDuration)
		stats, err := worker.RunOnce(passCtx)
		if err == nil && passCtx.Err() != nil {
			err = passCtx.Err()
		}
		cancelPass()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			logger.Error("deletion notifier pass incomplete", "reason", "dependency_failure")
			if mode == "once" {
				return errPass
			}
		} else {
			level := slog.LevelInfo
			if stats.Failed > 0 {
				level = slog.LevelWarn
			}
			logger.Log(ctx, level, "deletion notifier pass complete",
				"considered", stats.Considered, "claimed", stats.Claimed, "relay_accepted", stats.Accepted,
				"retried", stats.Retried, "failed", stats.Failed, "payloads_cleaned", stats.Cleaned,
				"skipped_legal_hold", stats.SkippedLegalHold)
			if mode == "once" {
				return nil
			}
		}
		timer := time.NewTimer(cfg.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func logFailure(logger *slog.Logger, err error) {
	reason := "dependency_or_configuration_failure"
	switch {
	case errors.Is(err, errConfiguration):
		reason = "invalid_configuration"
	case errors.Is(err, errDatabase):
		reason = "database_unavailable"
	case errors.Is(err, errWorker):
		reason = "worker_initialization_failed"
	case errors.Is(err, errPass):
		reason = "pass_incomplete"
	}
	logger.Error("deletion notifier terminated", "reason", reason)
}
