package audit

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/clientip"
)

// captureRecorder records the events handed to it so the adapter's decisions are
// inspectable without a transport.
type captureRecorder struct {
	events []Event
	err    error
}

func (c *captureRecorder) Record(_ context.Context, e Event) error {
	c.events = append(c.events, e)
	return c.err
}

// discardLogger returns a logger writing into a buffer the caller can read.
func discardLogger() (*slog.Logger, *strings.Builder) {
	var sb strings.Builder
	return slog.New(slog.NewJSONHandler(&sb, &slog.HandlerOptions{Level: slog.LevelDebug})), &sb
}

// TestNewBreachRecorderAdapterNilRecorderYieldsNil keeps the constructor safe to feed
// straight into token.NewService, whose breach hook is optional.
func TestNewBreachRecorderAdapterNilRecorderYieldsNil(t *testing.T) {
	t.Parallel()

	if adapter := NewBreachRecorderAdapter(nil, nil); adapter != nil {
		t.Errorf("NewBreachRecorderAdapter(nil) = %v, want nil", adapter)
	}
}

// TestRecordRTRBreachAttributesToAccount covers the happy path: a refresh-token replay
// is the highest-value ledger record there is, so it must carry a security context
// that survives the account's erasure.
func TestRecordRTRBreachAttributesToAccount(t *testing.T) {
	t.Parallel()

	rec := &captureRecorder{}
	logger, _ := discardLogger()
	adapter := NewBreachRecorderAdapter(rec, logger)
	account := uuid.New()

	adapter.RecordRTRBreach(context.Background(), account.String(), "search-engine")

	if len(rec.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(rec.events))
	}
	e := rec.events[0]

	if e.EventType != EventRTRBreach {
		t.Errorf("EventType = %q, want %q", e.EventType, EventRTRBreach)
	}
	if e.ActionStatus != StatusFailure {
		t.Errorf("ActionStatus = %q, want %q", e.ActionStatus, StatusFailure)
	}
	if e.ActorSPIFFEID != APIActorSPIFFEID {
		t.Errorf("ActorSPIFFEID = %q, want %q", e.ActorSPIFFEID, APIActorSPIFFEID)
	}
	if e.ActorID != account {
		t.Errorf("ActorID = %s, want %s", e.ActorID, account)
	}
	if e.SubjectID == nil || *e.SubjectID != account {
		t.Errorf("SubjectID = %v, want %s", e.SubjectID, account)
	}
	if e.Security == nil {
		t.Fatal("Security is nil; the breach would not reach security_event_ledger and would vanish with the account")
	}
	if e.Security.AccountRef != account {
		t.Errorf("AccountRef = %s, want %s", e.Security.AccountRef, account)
	}
	if e.Security.ClientID != "search-engine" {
		t.Errorf("Security.ClientID = %q, want %q", e.Security.ClientID, "search-engine")
	}
	// The response is part of the record: the ledger must show that every session was
	// killed, not merely that a replay was observed.
	if e.Payload["all_user_refresh_tokens_revoked"] != true {
		t.Errorf("payload = %v, want all_user_refresh_tokens_revoked=true", e.Payload)
	}
	if e.Payload["reason"] != "refresh_token_reuse" {
		t.Errorf("payload reason = %v, want refresh_token_reuse", e.Payload["reason"])
	}
	if _, flagged := e.Payload["account_ref_unresolvable"]; flagged {
		t.Error("payload flags the account as unresolvable even though it parsed")
	}
}

// TestRecordRTRBreachRecordsUnattributableBreach is the deliberate trade-off in the
// adapter: losing the breach signal would be far worse than losing its subject, so an
// unparseable user id still produces an audit row — just no ledger row, because
// account_ref is NOT NULL and inventing one would fabricate attribution evidence.
func TestRecordRTRBreachRecordsUnattributableBreach(t *testing.T) {
	t.Parallel()

	for name, userID := range map[string]string{
		"not a uuid": "session-42",
		"empty":      "",
		"nil uuid":   uuid.Nil.String(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &captureRecorder{}
			logger, logs := discardLogger()
			NewBreachRecorderAdapter(rec, logger).RecordRTRBreach(context.Background(), userID, "email-service")

			if len(rec.events) != 1 {
				t.Fatalf("recorded %d events, want 1 (the breach must be logged even without a subject)", len(rec.events))
			}
			e := rec.events[0]
			if e.Security != nil {
				t.Errorf("Security = %+v, want nil; a fabricated account_ref would be false attribution evidence", e.Security)
			}
			if e.Payload["account_ref_unresolvable"] != true {
				t.Errorf("payload = %v, want account_ref_unresolvable=true so the gap is explicit rather than inferred", e.Payload)
			}
			if e.SubjectID != nil {
				t.Errorf("SubjectID = %v, want nil", e.SubjectID)
			}
			if !strings.Contains(logs.String(), "no parseable user id") {
				t.Errorf("log %s does not report the unattributable breach", logs.String())
			}
		})
	}
}

// TestRecordRTRBreachTakesClientIPFromContext covers the one request-scoped field this
// layer can still recover: the breach is detected inside the grant logic, which gets a
// context rather than an *http.Request.
func TestRecordRTRBreachTakesClientIPFromContext(t *testing.T) {
	t.Parallel()

	// Route a request through the real middleware rather than faking the context key,
	// so this test breaks if the storage contract changes.
	var ctx context.Context
	handler := clientip.Middleware(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
	}))
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := &captureRecorder{}
	logger, _ := discardLogger()
	NewBreachRecorderAdapter(rec, logger).RecordRTRBreach(ctx, uuid.New().String(), "search-engine")

	if len(rec.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(rec.events))
	}
	if got := rec.events[0].ClientIP; got != "203.0.113.5" {
		t.Errorf("ClientIP = %q, want %q", got, "203.0.113.5")
	}
}

// TestRecordRTRBreachWithoutContextIPLeavesItEmpty pins that a missing address is left
// empty rather than guessed: "" and a wrong address hash differently, and a fabricated
// one would be misleading evidence.
func TestRecordRTRBreachWithoutContextIPLeavesItEmpty(t *testing.T) {
	t.Parallel()

	rec := &captureRecorder{}
	logger, _ := discardLogger()
	NewBreachRecorderAdapter(rec, logger).RecordRTRBreach(context.Background(), uuid.New().String(), "search-engine")

	if len(rec.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(rec.events))
	}
	if got := rec.events[0].ClientIP; got != "" {
		t.Errorf("ClientIP = %q, want empty", got)
	}
	if got := rec.events[0].UserAgent; got != "" {
		t.Errorf("UserAgent = %q, want empty; it is unavailable at this layer and must not be invented", got)
	}
}

// TestRecordRTRBreachLogsRecorderFailure keeps a transport failure visible. The
// adapter cannot fail the caller's operation, so the log line is the only trace.
func TestRecordRTRBreachLogsRecorderFailure(t *testing.T) {
	t.Parallel()

	rec := &captureRecorder{err: context.DeadlineExceeded}
	logger, logs := discardLogger()

	NewBreachRecorderAdapter(rec, logger).RecordRTRBreach(context.Background(), uuid.New().String(), "search-engine")

	if !strings.Contains(logs.String(), EventRTRBreach) {
		t.Errorf("log %s does not name the event type that failed to record", logs.String())
	}
}
