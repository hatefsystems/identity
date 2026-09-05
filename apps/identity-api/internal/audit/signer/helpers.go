package signer

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nats-io/nats.go/jetstream"
)

// drain collects a fetched batch into a slice.
//
// The whole channel is consumed before any processing starts because a Fetch is a
// single server response: leaving messages in the channel would leave them un-acked
// with no owner, and the next Fetch would not return them until AckWait expired.
func drain(batch jetstream.MessageBatch) []jetstream.Msg {
	msgs := make([]jetstream.Msg, 0, 16)
	for msg := range batch.Messages() {
		msgs = append(msgs, msg)
	}
	return msgs
}

// pendingFromLast reads consumer lag off the last message's metadata.
//
// The last message is used because NumPending is relative to the message's own
// position, so the newest one gives the smallest — and therefore truthful — remaining
// backlog. Metadata is best-effort: it is observability, and a missing value must not
// fail a batch.
func pendingFromLast(msgs []jetstream.Msg) uint64 {
	for i := len(msgs) - 1; i >= 0; i-- {
		if md, err := msgs[i].Metadata(); err == nil {
			return md.NumPending
		}
	}
	return 0
}

// sleepCtx waits for d or until ctx is done. It reports false when the wait was cut
// short by cancellation, so callers can distinguish "backed off" from "shutting
// down".
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// marshalPayload renders a signer-authored payload as JSONB text.
//
// The signer only ever passes scalars, so the error path is unreachable; it degrades
// to a valid JSON object carrying the failure rather than returning invalid text,
// because the payload column is NOT NULL and a malformed value would abort the whole
// COPY — losing a real batch over a diagnostic field.
func marshalPayload(payload map[string]any) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		slog.Default().Error("signer: marshal synthesized payload", slog.String("error", err.Error()))
		return `{"error":"payload_not_serializable"}`
	}
	return string(encoded)
}

// optional maps "" to a NULL column value.
//
// The distinction is load-bearing for the ledger chain: NULL and "" hash differently
// (see audit.SerializeLedger), so "this attribute did not apply to this event" stays
// distinguishable from "it applied and was empty".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// timestamptz converts a Go time into the pgx wrapper the generated params use.
func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}
