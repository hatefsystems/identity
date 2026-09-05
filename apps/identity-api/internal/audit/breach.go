package audit

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
)

// BreachRecorderAdapter turns the token service's RTR breach notification into an
// audit event. It satisfies token.BreachRecorder without package audit importing
// package token (or vice versa), which is why the interface is declared there and
// implemented here.
//
// A refresh-token replay means a token leaked, so this is one of the highest-value
// records in the ledger: it must remain attributable after the account is erased,
// because "when did this account's session material leak" is a question that gets
// asked long after a deletion request.
type BreachRecorderAdapter struct {
	recorder Recorder
	logger   *slog.Logger
}

// NewBreachRecorderAdapter wraps a Recorder. A nil recorder yields nil so the
// caller can pass the result straight into token.NewService, whose breach hook is
// optional.
func NewBreachRecorderAdapter(recorder Recorder, logger *slog.Logger) *BreachRecorderAdapter {
	if recorder == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &BreachRecorderAdapter{recorder: recorder, logger: logger}
}

// RecordRTRBreach implements token.BreachRecorder.
//
// userID arrives as a string because the token service stores refresh-token
// metadata in Redis, where everything is text. A value that does not parse as a
// UUID cannot be attributed, so the event is still recorded — losing the breach
// signal would be far worse than losing its subject — but without a ledger row,
// since account_ref is NOT NULL and must be a real users.id.
//
// user_agent is unavailable at this layer: the breach is detected inside the grant
// logic, which is deliberately given a context and a form rather than the
// *http.Request. It is left empty rather than guessed.
func (a *BreachRecorderAdapter) RecordRTRBreach(ctx context.Context, userID, clientID string) {
	clientIP := ""
	if addr, ok := clientip.FromContext(ctx); ok {
		clientIP = addr.String()
	}

	event := Event{
		EventType:     EventRTRBreach,
		ActionStatus:  StatusFailure,
		ActorSPIFFEID: APIActorSPIFFEID,
		ClientIP:      clientIP,
		Payload: map[string]any{
			"client_id": clientID,
			"reason":    "refresh_token_reuse",
			// The response is part of the record: the ledger must show that every
			// session was killed, not merely that a replay was seen.
			"all_user_refresh_tokens_revoked": true,
		},
	}

	accountRef, err := uuid.Parse(userID)
	switch {
	case err != nil || accountRef == uuid.Nil:
		// Record the breach anyway; flag that attribution is impossible so the gap
		// is visible in the audit row instead of being inferred from a missing
		// ledger row.
		event.Payload["account_ref_unresolvable"] = true
		a.logger.Error("audit: RTR breach has no parseable user id; recording without ledger attribution",
			slog.String("client_id", clientID))
	default:
		event.ActorID = accountRef
		event.SubjectID = &accountRef
		event.Security = &SecurityContext{
			AccountRef: accountRef,
			ClientID:   clientID,
		}
	}

	if err := a.recorder.Record(ctx, event); err != nil {
		a.logger.Error("audit: record RTR breach event",
			slog.String("event_type", EventRTRBreach),
			slog.String("error", err.Error()))
	}
}
