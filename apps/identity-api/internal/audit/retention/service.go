// Package retention implements bounded, separately credentialed Class B expiry.
package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// Errors contain only bounded operational classifications, never database details.
var (
	ErrIntegrity = errors.New("retention: ledger proof is invalid")
	ErrPrivilege = errors.New("retention: restricted maintenance provisioning required")
	ErrDatabase  = errors.New("retention: database operation failed")
	ErrDeferred  = errors.New("retention: bounded lock or statement wait exhausted")
	ErrUncertain = errors.New("retention: commit outcome is uncertain; inspect durable state before retry")
)

// Config bounds work and keeps initial deployments nondestructive.
type Config struct {
	BatchSize int
	MaxRows   int
	Timeout   time.Duration
	DryRun    bool
}

// Boundary fixes the expiration cutoff and logical high water for an entire run.
type Boundary struct {
	Cutoff     time.Time
	ThroughSeq int64
}

// Candidate contains only the keys needed for ordered traversal and account locking.
type Candidate struct {
	Seq         int64
	AccountRef  uuid.UUID
	RetainUntil time.Time
}

// BatchResult reports only a known commit (or a successful dry-run rollback).
type BatchResult struct {
	Deleted int
	Held    int
}

// Backlog is a bounded lower-bound diagnostic, not an unbounded table count.
type Backlog struct {
	Count  int
	Capped bool
	Oldest time.Time
}

// Store keeps the security boundary in PostgreSQL as well as in the worker.
type Store interface {
	Probe(context.Context) error
	Capture(context.Context) (Boundary, error)
	Candidates(context.Context, Boundary, Candidate, int) ([]Candidate, error)
	Purge(context.Context, Boundary, []Candidate, bool) (BatchResult, error)
	Backlog(context.Context, Boundary, int) (Backlog, error)
}

// Stats never attributes rows excluded by the candidate prefilter to inspected holds.
type Stats struct {
	Considered  int
	Deleted     int
	WouldDelete int
	Held        int
	Deferred    int
	Failed      int
	Uncertain   int
	Overlap     bool
	Boundary    Boundary
	Backlog     Backlog
}

// Service performs one run; the session lock only suppresses overlapping schedules.
type Service struct {
	cfg    Config
	store  Store
	locker pglock.AdvisoryLocker
	logger *slog.Logger
}

// New validates bounds independently of environment loading.
func New(cfg Config, store Store, locker pglock.AdvisoryLocker, logger *slog.Logger) (*Service, error) {
	if store == nil || locker == nil || cfg.BatchSize < 1 || cfg.BatchSize > 5000 ||
		cfg.MaxRows < cfg.BatchSize || cfg.MaxRows > 1000000 || cfg.Timeout < time.Second || cfg.Timeout > 30*time.Minute {
		return nil, errors.New("retention: invalid bounded worker configuration")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{cfg: cfg, store: store, locker: locker, logger: logger}, nil
}

// RunOnce stops on integrity, authority and uncertain-commit errors without retries.
func (s *Service) RunOnce(ctx context.Context) (stats Stats, err error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	defer func() {
		s.logger.Info("security ledger retention outcome",
			"considered", stats.Considered, "deleted", stats.Deleted, "would_delete", stats.WouldDelete,
			"held", stats.Held, "deferred", stats.Deferred, "failed", stats.Failed, "uncertain", stats.Uncertain,
			"overlap", stats.Overlap, "dry_run", s.cfg.DryRun, "cutoff", stats.Boundary.Cutoff,
			"runtime", time.Since(started), "backlog_count", stats.Backlog.Count, "backlog_capped", stats.Backlog.Capped,
			"backlog_oldest_expiry", stats.Backlog.Oldest, "success", err == nil)
	}()
	if err = s.store.Probe(ctx); err != nil {
		return stats, err
	}
	acquired, release, lockErr := s.locker.TryLock(ctx)
	if lockErr != nil {
		return stats, ErrDatabase
	}
	if !acquired {
		stats.Overlap = true
		return stats, nil
	}
	defer release()
	stats.Boundary, err = s.store.Capture(ctx)
	if err != nil {
		return stats, err
	}
	var cursor Candidate
	for stats.Considered < s.cfg.MaxRows {
		if err = ctx.Err(); err != nil {
			return stats, err
		}
		limit := min(s.cfg.BatchSize, s.cfg.MaxRows-stats.Considered)
		var candidates []Candidate
		candidates, err = s.store.Candidates(ctx, stats.Boundary, cursor, limit)
		if err != nil {
			return stats, err
		}
		if len(candidates) == 0 {
			break
		}
		if len(candidates) > limit {
			return stats, ErrIntegrity
		}
		// Move past even a deferred batch. Contention cannot consume the entire run.
		cursor = candidates[len(candidates)-1]
		stats.Considered += len(candidates)
		var result BatchResult
		result, err = s.store.Purge(ctx, stats.Boundary, candidates, s.cfg.DryRun)
		if err != nil {
			if errors.Is(err, ErrDeferred) && ctx.Err() == nil {
				stats.Deferred += len(candidates)
				err = nil
				continue
			}
			if errors.Is(err, ErrUncertain) {
				stats.Uncertain += len(candidates)
			} else {
				stats.Failed += len(candidates)
			}
			return stats, err
		}
		stats.Held += result.Held
		if s.cfg.DryRun {
			stats.WouldDelete += result.Deleted
		} else {
			stats.Deleted += result.Deleted
		}
	}
	stats.Backlog, err = s.store.Backlog(ctx, stats.Boundary, s.cfg.MaxRows)
	return stats, err
}
