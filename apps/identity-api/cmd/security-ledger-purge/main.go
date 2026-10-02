// Command security-ledger-purge performs one bounded Class B expiry pass.
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

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/retention"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("security ledger purge failed", "reason", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.LoadLedgerPurge()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return errors.New("security-ledger-purge: invalid dedicated database configuration")
	}
	poolCfg.MaxConns = 3
	poolCfg.ConnConfig.ConnectTimeout = 10 * time.Second
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "security-ledger-purge"
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	poolCfg.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	pool, err := pgxpool.NewWithConfig(connectCtx, poolCfg)
	if err != nil {
		return retention.ErrDatabase
	}
	defer pool.Close()
	store, err := retention.NewPgStore(pool, cfg.AuditSubject)
	if err != nil {
		return err
	}
	locker, err := pglock.NewPgAdvisoryLocker(pool, pglock.SecurityLedgerPurgeKey)
	if err != nil {
		return retention.ErrDatabase
	}
	worker, err := retention.New(retention.Config{BatchSize: cfg.BatchSize, MaxRows: cfg.MaxRows,
		Timeout: cfg.Timeout, DryRun: cfg.DryRun}, store, locker, logger)
	if err != nil {
		return err
	}
	_, err = worker.RunOnce(ctx)
	return err
}
