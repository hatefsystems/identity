// Command purge-worker performs one bounded GDPR hard-delete pass over accounts
// whose 30-day grace window has expired, then exits (Task 5.1).
//
// It is a one-shot binary, matching cmd/migrate, and is intended to be driven by a
// Kubernetes CronJob rather than by an internal scheduler: the platform already
// owns retries, concurrency policy, and alerting for CronJobs, and a long-lived
// ticker inside the process would duplicate all three while adding a resident
// memory cost the MVP explicitly avoids. Overlapping invocations are made safe by a
// PostgreSQL advisory lock, so a slow run plus the next schedule tick is a no-op
// rather than a double walk.
//
// Usage:
//
//	purge-worker        run one pass and exit
//
// It deletes only Class A data in PostgreSQL. Every Redis and in-process artifact
// belonging to a deleted subject either has a TTL far shorter than the grace window
// or lives in the API process's own heap, where a separate worker cannot reach it —
// which is why sessions and refresh tokens are revoked synchronously at soft-delete
// instead of here. The security_event_ledger is untouched, and that is enforced by
// the schema (it has no foreign key to users), not by this program.
//
// Environment:
//
//	DATABASE_URL                        required; PostgreSQL DSN
//	APP_ENV                             deployment environment label
//	GDPR_GRACE_PERIOD                   recovery window (default 720h)
//	GDPR_PURGE_BATCH_SIZE               subjects considered per run (default 100)
//	GDPR_PURGE_DRY_RUN                  decide and log without deleting (default false)
//
// Credentials are never hardcoded (DoD #3). Exit status is non-zero only for an
// infrastructural failure: a per-subject skip — including a legal-hold check that
// could not be answered — is counted and logged, never fatal, because failing the
// run for one undecidable subject would alert on a condition the next run may
// clear by itself.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
)

// dbConnectTimeout bounds the startup connectivity probe so an unreachable
// database fails the run quickly instead of hanging a CronJob pod.
const dbConnectTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("purge worker terminated with error", slog.String("error", err.Error()))

		os.Exit(1)
	}
}

// run wires the worker and performs exactly one pass. It is separated from main so
// it can return errors instead of calling os.Exit directly.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("purge-worker: load config: %w", err)
	}

	privacyCfg, err := config.LoadPrivacy(cfg.Environment)
	if err != nil {
		return fmt.Errorf("purge-worker: load privacy config: %w", err)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("purge-worker: DATABASE_URL is required")
	}

	// SIGTERM must stop the walk between subjects rather than abort a subject
	// mid-transaction: a CronJob pod being evicted should leave the remaining
	// subjects for the next run, not half-purge one.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, dbConnectTimeout)
	defer cancel()

	pool, err := pgxpool.New(connectCtx, dsn)
	if err != nil {
		return fmt.Errorf("purge-worker: open database pool: %w", err)
	}
	defer pool.Close()
	// Probe once: a misconfigured DSN should fail the run immediately rather than
	// surface as a per-subject failure that looks like a data problem.
	if err := pool.Ping(connectCtx); err != nil {
		return fmt.Errorf("purge-worker: ping database: %w", err)
	}

	queries := db.New(pool)

	opener, err := privacy.NewPgSubjectTxOpener(pool)
	if err != nil {
		return fmt.Errorf("purge-worker: build subject transaction opener: %w", err)
	}
	locker, err := privacy.NewPgAdvisoryLocker(pool, privacy.PurgeAdvisoryLockKey)
	if err != nil {
		return fmt.Errorf("purge-worker: build advisory locker: %w", err)
	}

	// No Notifier and no session/refresh-token revokers are wired: this worker
	// touches PostgreSQL only. Notification belongs to the soft-delete request,
	// and revocation happened there too — by the time a subject reaches this
	// worker, its sessions have been gone for the whole grace window.
	purger, err := privacy.NewPurger(privacy.PurgeConfig{
		GracePeriod: privacyCfg.GracePeriod,
		BatchSize:   privacyCfg.PurgeBatchSize,
		DryRun:      privacyCfg.PurgeDryRun,
	}, queries, opener, audit.NewLogRecorder(logger),
		privacy.WithAdvisoryLocker(locker),
		privacy.WithPurgeLogger(logger),
	)
	if err != nil {
		return fmt.Errorf("purge-worker: build purger: %w", err)
	}

	logger.Info("purge worker starting",
		slog.String("env", cfg.Environment),
		slog.Duration("grace_period", privacyCfg.GracePeriod),
		slog.Int("batch_size", privacyCfg.PurgeBatchSize),
		slog.Bool("dry_run", privacyCfg.PurgeDryRun),
	)

	stats, err := purger.RunOnce(ctx)
	if err != nil {
		return fmt.Errorf("purge-worker: run purge pass: %w", err)
	}

	logger.Info("purge worker finished",
		slog.Int("considered", stats.Considered),
		slog.Int("purged", stats.Purged),
		slog.Int("skipped_legal_hold", stats.SkippedLegalHold),
		slog.Int("failed", stats.Failed),
	)
	return nil
}
