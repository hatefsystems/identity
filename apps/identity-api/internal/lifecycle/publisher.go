package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	identityv1 "github.com/hatefsystems/identity/libs/schemas/gen/go/hatef/identity/v1"
)

// Delivery errors omit database, broker and event contents.
var (
	ErrUnavailable = errors.New("lifecycle: dependency unavailable")
	ErrPublish     = errors.New("lifecycle: publication deferred; intent retained for retry")
)

// Beginner is also satisfied by transaction wrappers used for fault injection.
type Beginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// JetStreamPublisher requires a synchronous server acknowledgement, not an
// asynchronous enqueue or the best-effort audit recorder.
type JetStreamPublisher interface {
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// PublisherConfig bounds claims, synchronous publication and polling.
type PublisherConfig struct {
	BatchSize      int32
	PublishTimeout time.Duration
	BatchTimeout   time.Duration
	PollInterval   time.Duration
}

// DefaultPublisherConfig supplies resource bounds, not retention policy.
func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{BatchSize: 50, PublishTimeout: 5 * time.Second, BatchTimeout: 30 * time.Second, PollInterval: time.Second}
}

// Validate rejects unsafe resource bounds without supplying defaults.
func (c PublisherConfig) Validate() error {
	if c.BatchSize < 1 || c.BatchSize > 200 || c.PublishTimeout < time.Millisecond || c.PublishTimeout > time.Minute ||
		c.BatchTimeout < c.PublishTimeout || c.BatchTimeout > 5*time.Minute || c.PollInterval < time.Millisecond || c.PollInterval > time.Minute {
		return errors.New("lifecycle: invalid bounded publisher configuration")
	}
	return nil
}

// Publisher delivers committed intent while preserving revisioned account heads.
type Publisher struct {
	beginner  Beginner
	js        JetStreamPublisher
	stream    string
	cfg       PublisherConfig
	claimTurn atomic.Uint32
}

// NewPublisher requires an acknowledged transport and a separately validated stream.
func NewPublisher(beginner Beginner, js JetStreamPublisher, streamName string, cfg PublisherConfig) (*Publisher, error) {
	if beginner == nil || js == nil || !validStreamName(streamName) {
		return nil, ErrUnavailable
	}
	defaults := DefaultPublisherConfig()
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaults.BatchSize
	}
	if cfg.PublishTimeout == 0 {
		cfg.PublishTimeout = defaults.PublishTimeout
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = defaults.BatchTimeout
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Publisher{beginner: beginner, js: js, stream: streamName, cfg: cfg}, nil
}

// RunOnce holds each head lock through PubAck and bookkeeping commit. An
// uncertain commit replays the same stored ID/time; consumers still need durable
// deduplication beyond JetStream's finite duplicate window.
func (p *Publisher) RunOnce(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.BatchTimeout)
	defer cancel()
	tx, err := beginReadCommitted(ctx, p.beginner)
	if err != nil {
		return 0, dependencyError(ctx)
	}
	defer rollback(ctx, tx)
	q := db.New(tx)
	claims := []func(context.Context, int32) ([]db.EventOutbox, error){q.ClaimLifecycleEvents, q.ClaimLegacyLifecycleEvents}
	// Alternate priority rather than starving legacy tombstones under a busy new
	// stream. Both lanes share the same total bound, including at batch size one.
	if p.claimTurn.Add(1)%2 == 0 {
		claims[0], claims[1] = claims[1], claims[0]
	}
	rows := make([]db.EventOutbox, 0, p.cfg.BatchSize)
	remaining := p.cfg.BatchSize
	for _, claim := range claims {
		if remaining == 0 {
			break
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		batch, err := claim(ctx, remaining)
		if err != nil || len(batch) > int(remaining) {
			return 0, dependencyError(ctx)
		}
		for _, row := range batch {
			rows = append(rows, row)
			remaining--
		}
	}
	published, failed := 0, false
	deadline, _ := ctx.Deadline()
	commitReserve := min(time.Second, p.cfg.BatchTimeout/10)
	for index, row := range rows {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		// Preserve completed retries instead of timing out a whole batch during
		// a broker outage. Unattempted claimed rows are simply unlocked at commit.
		if index > 0 && time.Until(deadline) <= p.cfg.PublishTimeout+commitReserve {
			break
		}
		if row.AdminAction || row.PublishedAt.Valid {
			return 0, ErrUnavailable
		}
		payload, _, decodeErr := decodeOutboxEvent(row)
		retryCode := "invalid_envelope"
		var ack *jetstream.PubAck
		publishErr := decodeErr
		if decodeErr == nil {
			msg := &nats.Msg{Subject: row.Subject, Data: payload, Header: nats.Header{}}
			msg.Header.Set(jetstream.MsgIDHeader, row.ID.String())
			msg.Header.Set(jetstream.ExpectedStreamHeader, p.stream)
			publishCtx, cancelPublish := context.WithTimeout(ctx, p.cfg.PublishTimeout)
			ack, publishErr = p.js.PublishMsg(publishCtx, msg)
			cancelPublish()
			retryCode = "publish_unacknowledged"
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		var affected int64
		if publishErr != nil || ack == nil || ack.Stream != p.stream || ack.Sequence == 0 {
			failed = true
			affected, err = q.RetryLifecycleEvent(ctx, db.RetryLifecycleEventParams{
				ID: row.ID, LastError: &retryCode,
				NextAttemptAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(retryDelay(row.Attempts)).Truncate(time.Microsecond), Valid: true},
			})
		} else {
			affected, err = q.MarkLifecyclePublished(ctx, row.ID)
			published++
		}
		if err != nil || affected != 1 {
			return 0, dependencyError(ctx)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, dependencyError(ctx)
	}
	if failed {
		return published, ErrPublish
	}
	return published, nil
}

// decodeOutboxEvent is shared by publication and cleanup: invalid metadata must
// neither escape to the broker nor select an account lock for deletion.
func decodeOutboxEvent(row db.EventOutbox) ([]byte, uuid.UUID, error) {
	if row.AdminAction || row.ID == uuid.Nil || !row.CreatedAt.Valid || row.CreatedAt.InfinityModifier != pgtype.Finite ||
		row.CreatedAt.Time.IsZero() || len(row.Payload) == 0 || len(row.Payload) > MaxMessageBytes {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	occurredAt := row.CreatedAt.Time.UTC().Truncate(time.Microsecond)
	if row.LifecycleUserID.Valid || row.LifecycleRevision != nil {
		if !row.LifecycleUserID.Valid || row.LifecycleUserID.UUID == uuid.Nil || row.LifecycleRevision == nil || *row.LifecycleRevision <= 0 {
			return nil, uuid.Nil, ErrInvalidEvent
		}
		// The dual-version reader validates persisted v1/v2 in place. Preserve
		// the original bytes on publication; rollout never rewrites old intent.
		event, err := UnmarshalEvent([]byte(row.Payload))
		if err != nil || event.EventType != row.Subject || event.EventId != row.ID.String() ||
			event.UserId != row.LifecycleUserID.UUID.String() || event.Revision == nil ||
			event.GetRevision() != uint64(*row.LifecycleRevision) || !event.OccurredAt.AsTime().Equal(occurredAt) {
			return nil, uuid.Nil, ErrInvalidEvent
		}
		return []byte(row.Payload), row.LifecycleUserID.UUID, nil
	}
	if row.Subject != SubjectDeleted {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	decoder := json.NewDecoder(strings.NewReader(row.Payload))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	if token, err := decoder.Token(); err != nil || token != "user_id" {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	var rawID string
	if err := decoder.Decode(&rawID); err != nil || decoder.More() {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	userID, err := uuid.Parse(rawID)
	if err != nil || userID == uuid.Nil || rawID != userID.String() {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	// Revision-less historical tombstones remain v1, never inferred as v2.
	payload, err := MarshalEvent(&identityv1.UserLifecycleEvent{
		SchemaVersion: SchemaVersion, EventId: row.ID.String(), EventType: SubjectDeleted,
		UserId: userID.String(), OccurredAt: timestamppb.New(occurredAt),
	})
	if err != nil {
		return nil, uuid.Nil, ErrInvalidEvent
	}
	return payload, userID, nil
}

func retryDelay(attempts int32) time.Duration {
	return time.Second * time.Duration(1<<min(8, max(0, attempts)))
}

// Backlog contains aggregate delivery health without account or event identifiers.
type Backlog struct {
	Pending   int64
	Attempts  int64
	Invalid   int64
	OldestAge time.Duration
}

// Backlog reads pending health without claiming or mutating events.
func (p *Publisher) Backlog(ctx context.Context) (Backlog, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginReadCommitted(ctx, p.beginner)
	if err != nil {
		return Backlog{}, dependencyError(ctx)
	}
	defer rollback(ctx, tx)
	row, err := db.New(tx).LifecycleBacklog(ctx)
	if err != nil {
		return Backlog{}, dependencyError(ctx)
	}
	b := Backlog{Pending: row.Pending, Attempts: row.Attempts, Invalid: row.Invalid}
	if row.OldestAt.Valid && row.OldestAt.InfinityModifier == pgtype.Finite {
		b.OldestAge = max(0, time.Since(row.OldestAt.Time))
	}
	return b, nil
}

// RunUntilDone runs until cancellation, reporting aggregates and fixed reason
// codes only. Poison intent is retained indefinitely for operator repair.
func (p *Publisher) RunUntilDone(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()
	nextReport := time.Time{}
	for ctx.Err() == nil {
		count, err := p.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			logger.Error("lifecycle outbox delivery deferred", "published", count, "failed_batches", 1, "reason", "delivery_deferred")
		}
		if time.Now().After(nextReport) {
			if b, err := p.Backlog(ctx); err == nil {
				logger.Info("lifecycle outbox backlog", "pending", b.Pending, "attempts", b.Attempts,
					"invalid", b.Invalid, "oldest_age_seconds", b.OldestAge.Seconds())
				if b.Invalid > 0 {
					logger.Error("lifecycle invalid intent retained", "invalid", b.Invalid, "reason", "invalid_envelope")
				}
			} else if ctx.Err() == nil {
				logger.Error("lifecycle backlog unavailable", "reason", "dependency_unavailable")
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
	return nil
}

func dependencyError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

func beginReadCommitted(ctx context.Context, beginner Beginner) (pgx.Tx, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if b, ok := beginner.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	}); ok {
		return b.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"); err != nil {
		rollback(ctx, tx)
		return nil, err
	}
	return tx, nil
}

func rollback(ctx context.Context, tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
