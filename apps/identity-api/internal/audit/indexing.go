package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// IdentitySource is the narrow live-account lookup used before asynchronous
// signing. *db.Queries implements it. No identity text leaves this call.
type IdentitySource interface {
	GetUserEmailForBlindIndex(context.Context, uuid.UUID) (string, error)
}

// IdentityIndexer computes the shared email blind index.
type IdentityIndexer interface {
	Compute(string) string
}

// IndexingRecorder captures available Class B attribution before enqueueing an
// event. It preserves the ordinary recorder's best-effort transport semantics;
// privileged Class C operations use the separate transactional admin outbox.
type IndexingRecorder struct {
	next    Recorder
	source  IdentitySource
	indexer IdentityIndexer
	logger  *slog.Logger
}

// NewIndexingRecorder captures attribution before asynchronous publication.
func NewIndexingRecorder(next Recorder, source IdentitySource, indexer IdentityIndexer, logger *slog.Logger) (*IndexingRecorder, error) {
	if next == nil || source == nil || indexer == nil {
		return nil, errors.New("audit: recorder, identity source and indexer are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &IndexingRecorder{next: next, source: source, indexer: indexer, logger: logger}, nil
}

// Record captures Class B identity material and forwards the event.
func (r *IndexingRecorder) Record(ctx context.Context, e Event) error {
	if !IsLedgerEventType(e.EventType) {
		e.Security = nil
		return r.next.Record(ctx, e)
	}
	if e.Security == nil || e.Security.AccountRef == uuid.Nil {
		return r.next.Record(ctx, e)
	}
	// Do not mutate the caller's shared context or leave mutable index pointers
	// crossing the asynchronous boundary.
	security := *e.Security
	e.Security = &security
	if security.IdentityBlindIndex == nil {
		captureCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		email, err := r.source.GetUserEmailForBlindIndex(captureCtx, security.AccountRef)
		if err != nil || email == "" {
			// Database error text can contain identifiers; log only bounded metadata.
			r.logger.Warn("audit: identity capture unavailable; signer fallback required",
				slog.String("marker", "audit_index_capture_missing"), slog.String("event_type", e.EventType))
		} else {
			digest := r.indexer.Compute(email)
			security.IdentityBlindIndex = &digest
		}
	} else {
		digest := *security.IdentityBlindIndex
		security.IdentityBlindIndex = &digest
	}
	return r.next.Record(ctx, e)
}
