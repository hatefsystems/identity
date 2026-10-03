package audit

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// newTestRecorder returns a LogRecorder writing into a buffer the caller can
// inspect.
func newTestRecorder() (*LogRecorder, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return NewLogRecorder(logger), &buf
}

func TestLogRecorderEmitsEventShape(t *testing.T) {
	rec, buf := newTestRecorder()
	subject := uuid.New()
	actor := uuid.New()

	err := rec.Record(context.Background(), Event{
		EventType:     EventDeletionPurged,
		ActionStatus:  StatusSuccess,
		ActorID:       actor,
		ActorSPIFFEID: SystemActorSPIFFEID,
		SubjectID:     &subject,
		Payload:       map[string]any{"cutoff": "2026-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		EventDeletionPurged,
		StatusSuccess,
		SystemActorSPIFFEID,
		actor.String(),
		subject.String(),
		"cutoff",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log line %q does not contain %q", out, want)
		}
	}
}

// TestLogRecorderRedactsPayloadValues is the load-bearing property: the recorder
// reports which context an event carried, never the context itself. A caller that
// violates the Event.Payload contract by attaching a token, a passcode, or an email
// address must not be able to leak it through the process log.
func TestLogRecorderRedactsPayloadValues(t *testing.T) {
	rec, buf := newTestRecorder()
	subject := uuid.New()

	const (
		secretToken = "gCcXQ9x1sWkTgV2gPPQnnnXtqDcvhpLTe1I0ycn5Fyw" //nolint:gosec // G101: a synthetic value this test asserts is NOT logged
		secretCode  = "482913"
		secretEmail = "victim@example.test"
	)

	if err := rec.Record(context.Background(), Event{
		EventType:    EventDeletionReclaimFailed,
		ActionStatus: StatusFailure,
		SubjectID:    &subject,
		// Deliberately hostile input: none of these belong in a payload.
		ClientIP:  "203.0.113.7",
		UserAgent: "Mozilla/5.0 (probe)",
		Payload: map[string]any{
			"reclaim_token": secretToken,
			"passcode":      secretCode,
			"email":         secretEmail,
		},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	out := buf.String()
	for _, leaked := range []string{secretToken, secretCode, secretEmail} {
		if strings.Contains(out, leaked) {
			t.Errorf("log line leaked a payload value %q: %s", leaked, out)
		}
	}
	// Request-linkable context is omitted entirely; its home is the ledger, not
	// the process log.
	if strings.Contains(out, "203.0.113.7") {
		t.Errorf("log line leaked the client IP: %s", out)
	}
	if strings.Contains(out, "Mozilla") {
		t.Errorf("log line leaked the user agent: %s", out)
	}
	// The field names must survive, or the line carries no diagnostic value.
	for _, key := range []string{"reclaim_token", "passcode", "email"} {
		if !strings.Contains(out, key) {
			t.Errorf("log line dropped payload field name %q: %s", key, out)
		}
	}
}

// TestLogRecorderOmitsNilIdentifiers checks that a worker-raised event (no actor,
// system SPIFFE ID) does not emit a nil UUID, which would be indistinguishable from
// a real account in a log search.
func TestLogRecorderOmitsNilIdentifiers(t *testing.T) {
	rec, buf := newTestRecorder()

	if err := rec.Record(context.Background(), Event{
		EventType:     EventDeletionSkippedLegalHold,
		ActionStatus:  StatusSuccess,
		ActorSPIFFEID: SystemActorSPIFFEID,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, uuid.Nil.String()) {
		t.Errorf("log line emitted the nil UUID: %s", out)
	}
	if strings.Contains(out, "subject_id") {
		t.Errorf("log line emitted subject_id for an event without a subject: %s", out)
	}
}

// TestLogRecorderNilLoggerFallback confirms the constructor tolerates a nil logger
// rather than panicking at the first event, matching smsotp.NewLogSender.
func TestLogRecorderNilLoggerFallback(t *testing.T) {
	rec := NewLogRecorder(nil)
	if err := rec.Record(context.Background(), Event{EventType: EventDeletionRequested}); err != nil {
		t.Fatalf("Record with a nil logger: %v", err)
	}
}

// TestPayloadFieldsSorted pins the deterministic field ordering so log-based
// assertions and diffing stay stable across Go's randomised map iteration.
func TestPayloadFieldsSorted(t *testing.T) {
	got := payloadFields(map[string]any{"zeta": 1, "alpha": 2, "mid": 3, "beta": 4})
	want := []string{"alpha", "beta", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("payloadFields = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("payloadFields = %v, want %v", got, want)
		}
	}
}

// TestRecorderInterfaceIsSatisfied documents that LogRecorder is the Task 5.1
// implementation of the seam Task 5.2 replaces.
func TestRecorderInterfaceIsSatisfied(_ *testing.T) {
	var _ Recorder = NewLogRecorder(nil)
}

func TestGRPCAccessDeniedIsAuditOnly(t *testing.T) {
	t.Parallel()
	if IsLedgerEventType(EventGRPCAccessDenied) {
		t.Fatal("workload denials must not fabricate account attribution in the security ledger")
	}
}
