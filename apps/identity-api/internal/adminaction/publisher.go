package adminaction

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ErrPublish leaves unacknowledged messages available for a later retry.
var ErrPublish = errors.New("adminaction: publication not acknowledged; retained for retry")

// JetStreamPublisher is the synchronous, server-acknowledged API. PublishAsync
// and the best-effort audit.Recorder intentionally cannot satisfy this contract.
type JetStreamPublisher interface {
	Publish(context.Context, string, []byte, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// PublisherConfig bounds batch size, retries and polling.
type PublisherConfig struct {
	BatchSize      int32
	PublishTimeout time.Duration
	BatchTimeout   time.Duration
	PollInterval   time.Duration
}

// Publisher delivers committed admin audit intent using JetStream acknowledgements.
type Publisher struct {
	beginner Beginner
	js       JetStreamPublisher
	subject  string
	cfg      PublisherConfig
}

// NewPublisher constructs a subject-scoped outbox worker.
func NewPublisher(beginner Beginner, js JetStreamPublisher, subject string, cfg PublisherConfig) (*Publisher, error) {
	if beginner == nil || js == nil || !validSubject(subject) {
		return nil, ErrUnavailable
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 50
	}
	if cfg.PublishTimeout == 0 {
		cfg.PublishTimeout = 5 * time.Second
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 30 * time.Second
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.BatchSize < 1 || cfg.BatchSize > 200 || cfg.PublishTimeout < time.Millisecond ||
		cfg.PublishTimeout > time.Minute || cfg.BatchTimeout < cfg.PublishTimeout || cfg.BatchTimeout > 5*time.Minute ||
		cfg.PollInterval < time.Millisecond || cfg.PollInterval > time.Minute {
		return nil, errors.New("adminaction: invalid bounded publisher configuration")
	}
	return &Publisher{beginner: beginner, js: js, subject: subject, cfg: cfg}, nil
}

// RunOnce locks a bounded batch, waits for a real JetStream PubAck, and only then
// marks a row delivered. A crash after publish but before PostgreSQL commit
// replays the same EventID/Nats-Msg-Id. Signer dedup remains authoritative after
// JetStream's finite duplicate window expires.
func (p *Publisher) RunOnce(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.BatchTimeout)
	defer cancel()
	tx, err := beginReadCommitted(ctx, p.beginner)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer rollback(ctx, tx)
	q := db.New(tx)
	rows, err := q.ClaimAdminActionOutbox(ctx, db.ClaimAdminActionOutboxParams{Subject: p.subject, BatchSize: p.cfg.BatchSize})
	if err != nil {
		return 0, ErrUnavailable
	}
	published := 0
	failed := false
	for _, row := range rows {
		// Protect the signer against accidentally misrouted or corrupted rows.
		// Never include the payload or broker error text in last_error/logs.
		var env audit.Envelope
		retryCode := "invalid_envelope"
		var ack *jetstream.PubAck
		if json.Unmarshal([]byte(row.Payload), &env) == nil && env.EventID == row.ID &&
			env.SchemaVersion == audit.EnvelopeSchemaVersion && env.Security == nil && eventName.MatchString(env.EventType) {
			publishCtx, cancelPublish := context.WithTimeout(ctx, p.cfg.PublishTimeout)
			ack, err = p.js.Publish(publishCtx, p.subject, []byte(row.Payload), jetstream.WithMsgID(row.ID.String()))
			cancelPublish()
			retryCode = "publish_unacknowledged"
		} else {
			err = ErrInvalidEvent
		}
		var affected int64
		if err != nil || ack == nil || ack.Stream == "" || ack.Sequence == 0 {
			failed = true
			affected, err = q.RetryAdminActionOutbox(ctx, db.RetryAdminActionOutboxParams{
				ID: row.ID, Subject: p.subject, LastError: &retryCode,
				NextAttemptAt: timestamp(time.Now().Add(retryDelay(row.Attempts))),
			})
		} else {
			affected, err = q.MarkAdminActionPublished(ctx, db.MarkAdminActionPublishedParams{ID: row.ID, Subject: p.subject})
			published++
		}
		if err != nil || affected != 1 {
			return 0, ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, ErrUnavailable
	}
	if failed {
		return published, ErrPublish
	}
	return published, nil
}

func retryDelay(attempts int32) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 8 {
		attempts = 8
	}
	return time.Second * time.Duration(1<<attempts)
}

// Backlog reports pending count and oldest undelivered age.
type Backlog struct {
	Pending   int64
	Attempts  int64
	OldestAge time.Duration
}

// Backlog reads operational delivery health without claiming messages.
func (p *Publisher) Backlog(ctx context.Context) (Backlog, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginReadCommitted(ctx, p.beginner)
	if err != nil {
		return Backlog{}, ErrUnavailable
	}
	defer rollback(ctx, tx)
	row, err := db.New(tx).AdminActionBacklog(ctx, p.subject)
	if err != nil {
		return Backlog{}, ErrUnavailable
	}
	b := Backlog{Pending: row.Pending, Attempts: row.Attempts}
	if row.OldestAt.Valid {
		b.OldestAge = max(0, time.Since(row.OldestAt.Time))
	}
	return b, nil
}

// RunUntilDone retries indefinitely without acknowledging unpersisted work.
// Structured backlog/retry diagnostics intentionally contain no payload/error
// values from PostgreSQL or NATS.
func (p *Publisher) RunUntilDone(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()
	nextReport := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		count, err := p.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Error("admin audit outbox delivery deferred", "published", count, "retry", true)
		}
		if time.Now().After(nextReport) {
			if b, err := p.Backlog(ctx); err == nil {
				logger.Info("admin audit outbox backlog", "pending", b.Pending, "attempts", b.Attempts, "oldest_age_seconds", b.OldestAge.Seconds())
			}
			nextReport = time.Now().Add(time.Minute)
		}
		if count == int(p.cfg.BatchSize) && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
