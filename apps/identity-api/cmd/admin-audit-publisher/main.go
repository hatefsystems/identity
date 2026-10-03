// Command admin-audit-publisher drains only marked administrative audit envelopes
// on AUDIT_SUBJECT. The signer owns JetStream topology and cryptographic chains.
// --cleanup-contexts performs a bounded hold-aware narrative-retention sweep with
// a separately privileged DATABASE_URL; it requires no NATS or decryption key.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
)

func main() {
	cleanup := flag.Bool("cleanup-contexts", false, "remove one bounded batch of expired, unheld action contexts")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, *cleanup); err != nil {
		// Connection errors can include DSNs; do not log their text.
		logger.Error("admin audit worker terminated", "reason", "dependency_or_configuration_failure")
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, cleanup bool) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(startupCtx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(startupCtx); err != nil {
		return err
	}
	if cleanup {
		environment := os.Getenv("APP_ENV")
		if environment == "" {
			environment = "development"
		}
		if _, err := legalpolicy.LoadBaseline(startupCtx, pool, uuid.Nil, environment); err != nil {
			return err
		}
		count, err := adminaction.CleanupExpired(ctx, pool, 500)
		if err == nil {
			logger.Info("admin action context cleanup complete", "deleted", count)
		}
		return err
	}
	environment := os.Getenv("APP_ENV")
	if environment == "" {
		environment = "development"
	}
	cfg, err := config.LoadAudit(environment)
	if err != nil {
		return err
	}
	if !cfg.HasNATS() {
		return errors.New("NATS_URL is required")
	}
	nc, js, err := natsjs.Connect(startupCtx, cfg.NATSURL, "admin-audit-publisher", logger)
	if err != nil {
		return err
	}
	defer nc.Close()
	worker, err := adminaction.NewPublisher(pool, js, cfg.Subject, adminaction.PublisherConfig{})
	if err != nil {
		return err
	}
	return worker.RunUntilDone(ctx, logger)
}
