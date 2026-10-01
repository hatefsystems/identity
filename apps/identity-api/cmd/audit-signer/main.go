// Command audit-signer is the single-threaded worker that turns queued audit
// envelopes into the two cryptographic hash chains (Task 5.2).
//
// It drains the NATS JetStream audit subject and, for each batch, computes
//
//	chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N)))
//
// then writes mvp_audit_logs (Class C) and security_event_ledger (Class B) in one
// transaction. It is the sole writer of both chains.
//
// # Why this is a long-running process and not a CronJob
//
// cmd/purge-worker is one-shot because its work is a scheduled sweep. This worker is
// the opposite: it is a queue consumer whose backlog grows continuously, and its
// durable JetStream consumer plus in-memory chain tip make process restarts the
// expensive part of its cycle. It therefore runs until signalled and lets the
// orchestrator restart it.
//
// # Exactly one instance
//
// A second concurrent signer would read the same chain tip, extend it independently,
// and produce rows in both tables claiming the same predecessor. Because UPDATE and
// DELETE are revoked on both tables, that fork is permanent and unrepairable. A
// PostgreSQL advisory lock enforces the single writer, and failing to acquire it is
// fatal: this process exits non-zero rather than idling, so the deployment surfaces
// the misconfiguration instead of quietly running two signers. Scale this Deployment
// to replicas: 1.
//
// Usage:
//
//	audit-signer        drain until SIGINT/SIGTERM
//
// Environment:
//
//	DATABASE_URL                required; PostgreSQL DSN
//	NATS_URL                    required; NATS server URL
//	APP_ENV                     deployment environment label
//	AUDIT_STREAM_NAME           JetStream stream (default IDENTITY_AUDIT)
//	AUDIT_SUBJECT               subject consumed (default identity.audit.logs)
//	AUDIT_CONSUMER_NAME         durable consumer (default audit-signer)
//	AUDIT_BATCH_SIZE            messages per batch (default 1000)
//	AUDIT_FLUSH_INTERVAL        partial-batch flush wait (default 5s)
//	AUDIT_STREAM_MAX_BYTES      stream size cap (default 536870912)
//	AUDIT_ACK_WAIT              redelivery timeout (default 60s)
//	AUDIT_MAX_DELIVER           redelivery attempts (default 5)
//	SECURITY_LEDGER_RETENTION   ledger retain_until offset (default 8760h)
//	ENVELOPE_BLIND_INDEX_PEPPER shared producer/lookup key for legacy index capture
//
// Credentials are never hardcoded (DoD #3).
//
// This is the one process that declares the JetStream topology. The API only
// publishes: CreateOrUpdateStream is authoritative, so letting API replicas declare
// it would let a stale rollout rewrite the stream's limits underneath this worker.
// See internal/natsjs.
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

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// dbConnectTimeout bounds the startup connectivity probe so an unreachable database
// fails the process quickly instead of hanging a pod in a crash-loop with no
// diagnostic.
const dbConnectTimeout = 10 * time.Second

// natsConnectTimeout bounds only the initial dial. After it succeeds the client
// reconnects forever (see natsjs.Connect), because a NATS blip must not stop a worker
// whose backlog is durable on the server.
const natsConnectTimeout = 15 * time.Second

// exitLockUnavailable is the exit status used when another signer already holds the
// advisory lock. It is distinct from the generic failure status so an orchestrator or
// alert rule can tell "misconfigured to run twice" apart from "cannot reach its
// dependencies", which need different responses.
const exitLockUnavailable = 2

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		if errors.Is(err, signer.ErrLockUnavailable) {
			// Not an error condition to retry into: a second signer is either a
			// deployment scaled past one replica or a leftover pod. Exiting with a
			// distinct status makes that visible.
			logger.Error("audit signer refusing to start; another signer holds the advisory lock",
				slog.String("error", err.Error()))
			os.Exit(exitLockUnavailable)
		}
		logger.Error("audit signer terminated with error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// run wires the worker and drains until signalled. It is separated from main so it
// can return errors instead of calling os.Exit directly.
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	auditCfg, err := config.LoadAudit(cfg.Environment)
	if err != nil {
		return err
	}
	if !auditCfg.HasNATS() {
		// LoadAudit only permits a missing NATS_URL in development, where it means
		// "the API logs unchained events". For this process there is no degraded mode:
		// with no stream there is nothing to sign.
		return errors.New("audit-signer: NATS_URL is required")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("audit-signer: DATABASE_URL is required")
	}

	// SIGTERM stops the loop between batches. The in-flight batch finishes on a
	// context detached from this one (see signer.RunUntilDone), because aborting
	// mid-commit only costs a redelivery.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := openPool(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	connectCtx, cancelConnect := context.WithTimeout(ctx, natsConnectTimeout)
	defer cancelConnect()

	nc, js, err := natsjs.Connect(connectCtx, auditCfg.NATSURL, "audit-signer", logger)
	if err != nil {
		return err
	}
	// Drain rather than Close: it lets the client finish settling messages it has
	// already acknowledged locally before the connection goes away.
	defer func() {
		if drainErr := nc.Drain(); drainErr != nil {
			logger.Warn("audit-signer: drain NATS connection", slog.String("error", drainErr.Error()))
		}
	}()

	// This process is the single declarer of the topology; see the package doc.
	if _, err := natsjs.EnsureStream(connectCtx, js, natsjs.StreamOptions{
		Name:       auditCfg.StreamName,
		Subjects:   auditCfg.StreamSubjects(),
		MaxBytes:   auditCfg.StreamMaxBytes,
		Duplicates: auditCfg.DuplicateWindow,
	}); err != nil {
		return err
	}

	consumer, err := natsjs.EnsureConsumer(connectCtx, js, auditCfg.StreamName, natsjs.ConsumerOptions{
		Durable:       auditCfg.ConsumerName,
		FilterSubject: auditCfg.Subject,
		AckWait:       auditCfg.AckWait,
		MaxAckPending: auditCfg.MaxAckPending(),
		MaxDeliver:    auditCfg.MaxDeliver,
	})
	if err != nil {
		return err
	}

	store, err := signer.NewPoolStore(pool)
	if err != nil {
		return err
	}
	opener, err := signer.NewPgBatchTxOpener(pool)
	if err != nil {
		return err
	}
	locker, err := pglock.NewPgAdvisoryLocker(pool, pglock.AuditSignerKey)
	if err != nil {
		return err
	}

	opts := []signer.Option{
		signer.WithLogger(logger),
		signer.WithAdvisoryLocker(locker),
	}
	if indexer, ok := buildBlindIndexer(cfg.Environment, logger); ok {
		opts = append(opts, signer.WithBlindIndexer(indexer))
	}

	worker, err := signer.New(signer.Config{
		BatchSize:       auditCfg.BatchSize,
		FlushInterval:   auditCfg.FlushInterval,
		LedgerRetention: auditCfg.LedgerRetention,
	}, store, opener, consumer, opts...)
	if err != nil {
		return err
	}

	logger.Info("audit signer starting",
		slog.String("env", cfg.Environment),
		slog.String("stream", auditCfg.StreamName),
		slog.String("subject", auditCfg.Subject),
		slog.String("consumer", auditCfg.ConsumerName),
		slog.Int("batch_size", auditCfg.BatchSize),
		slog.Duration("flush_interval", auditCfg.FlushInterval),
		slog.Duration("ack_wait", auditCfg.AckWait),
		slog.Duration("ledger_retention", auditCfg.LedgerRetention),
	)

	if err := worker.RunUntilDone(ctx); err != nil {
		return err
	}

	logger.Info("audit signer stopped")
	return nil
}

// openPool opens and probes the database pool.
//
// The probe is deliberate: without it a bad DSN would first surface as a failed
// chain-tip read inside RunUntilDone, which reads like a data-integrity problem
// rather than a connectivity one.
func openPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	connectCtx, cancel := context.WithTimeout(ctx, dbConnectTimeout)
	defer cancel()

	pool, err := pgxpool.New(connectCtx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// buildBlindIndexer constructs the identity_blind_index derivation.
//
// A missing pepper is not fatal. identity_blind_index is nullable by design, so the
// worst case is a ledger row that cannot be found by a blind-index lookup — whereas
// refusing to start would stop both chains entirely and lose the events themselves.
// The degradation is logged loudly because it is silent in the data: a NULL index is
// indistinguishable from a purged subject's NULL.
//
// The signer only needs the shared pepper, not legal narrative encryption keys.
// The caller enforces the non-development failure policy.
func buildBlindIndexer(environment string, logger *slog.Logger) (*blindindex.Indexer, bool) {
	pepper, err := config.LoadBlindIndexPepper()
	if err != nil {
		logger.Error("audit-signer: crypto config unavailable; ledger rows will have a NULL identity_blind_index",
			slog.String("environment", environment),
			slog.String("error", err.Error()))
		return nil, false
	}
	indexer, err := blindindex.New(pepper)
	if err != nil {
		logger.Error("audit-signer: blind indexer unavailable; ledger rows will have a NULL identity_blind_index",
			slog.String("environment", environment),
			slog.String("error", err.Error()))
		return nil, false
	}
	return indexer, true
}
