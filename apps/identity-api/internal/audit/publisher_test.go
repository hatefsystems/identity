package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type publishAttempt struct {
	subject string
	data    []byte
	opts    []jetstream.PublishOpt
}

type fakePubAckFuture struct {
	ok  chan *jetstream.PubAck
	err chan error
	msg *nats.Msg
}

func (f *fakePubAckFuture) Ok() <-chan *jetstream.PubAck { return f.ok }
func (f *fakePubAckFuture) Err() <-chan error            { return f.err }
func (f *fakePubAckFuture) Msg() *nats.Msg               { return f.msg }

func newSuccessFuture() *fakePubAckFuture {
	f := &fakePubAckFuture{
		ok:  make(chan *jetstream.PubAck, 1),
		err: make(chan error, 1),
	}
	f.ok <- &jetstream.PubAck{Stream: "IDENTITY_AUDIT", Sequence: 1}
	return f
}

func newErrorFuture(err error) *fakePubAckFuture {
	f := &fakePubAckFuture{
		ok:  make(chan *jetstream.PubAck, 1),
		err: make(chan error, 1),
	}
	f.err <- err
	return f
}

type fakeJetStream struct {
	jetstream.JetStream
	mu         sync.Mutex
	attempts   []publishAttempt
	entered    chan struct{}
	gate       chan struct{}
	publishErr error
	ackErr     error
	pending    int
}

func (f *fakeJetStream) PublishAsync(subject string, data []byte, opts ...jetstream.PublishOpt) (jetstream.PubAckFuture, error) {
	f.mu.Lock()
	f.attempts = append(f.attempts, publishAttempt{subject: subject, data: data, opts: opts})
	pErr := f.publishErr
	aErr := f.ackErr
	f.mu.Unlock()

	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}

	if f.gate != nil {
		<-f.gate
	}

	if pErr != nil {
		return nil, pErr
	}
	if aErr != nil {
		return newErrorFuture(aErr), nil
	}
	return newSuccessFuture(), nil
}

func (f *fakeJetStream) PublishAsyncComplete() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (f *fakeJetStream) PublishAsyncPending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending
}

func (f *fakeJetStream) getAttempts() []publishAttempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]publishAttempt, len(f.attempts))
	copy(copied, f.attempts)
	return copied
}

func newTestJSONLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return l, &buf
}

// 1. Validating dependencies.
func TestNewJetStreamRecorderValidation(t *testing.T) {
	fake := &fakeJetStream{}
	logger, _ := newTestJSONLogger()

	if _, err := NewJetStreamRecorder(nil, "identity.audit.logs", 10, logger); err == nil {
		t.Error("expected error for nil JetStream")
	}
	if _, err := NewJetStreamRecorder(fake, "", 10, logger); err == nil {
		t.Error("expected error for empty subject")
	}
	if _, err := NewJetStreamRecorder(fake, "identity.audit.logs", 0, logger); err == nil {
		t.Error("expected error for zero bufferSize")
	}
	if _, err := NewJetStreamRecorder(fake, "identity.audit.logs", -5, logger); err == nil {
		t.Error("expected error for negative bufferSize")
	}

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 10, nil)
	if err != nil {
		t.Fatalf("unexpected error with nil logger: %v", err)
	}
	defer rec.Close(context.Background())
	if rec.logger == nil {
		t.Error("expected default logger when nil provided")
	}
}

// 2. Asserting the envelope gets published to the right subject.
func TestJetStreamRecorderPublishesEnvelope(t *testing.T) {
	fake := &fakeJetStream{}
	logger, _ := newTestJSONLogger()
	fixedID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	tFixed := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	rec, err := NewJetStreamRecorder(
		fake,
		"identity.audit.logs",
		10,
		logger,
		WithRecorderClock(func() time.Time { return tFixed }),
		WithRecorderIDs(func() uuid.UUID { return fixedID }),
		WithPublishStallWait(500*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	subjectID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	actorID := uuid.MustParse("99999999-8888-7777-6666-555555555555")
	event := Event{
		EventType:     EventLoginSucceeded,
		ActionStatus:  StatusSuccess,
		ActorID:       actorID,
		ActorSPIFFEID: APIActorSPIFFEID,
		SubjectID:     &subjectID,
		ClientIP:      "192.0.2.1",
		UserAgent:     "TestBrowser/1.0",
		Payload:       map[string]any{"method": "webauthn"},
		Security: &SecurityContext{
			AccountRef: subjectID,
			ClientID:   "test-client",
		},
	}

	if err := rec.Record(context.Background(), event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	attempts := fake.getAttempts()
	if len(attempts) != 1 {
		t.Fatalf("expected 1 publish attempt, got %d", len(attempts))
	}

	att := attempts[0]
	if att.subject != "identity.audit.logs" {
		t.Errorf("subject = %q, want %q", att.subject, "identity.audit.logs")
	}

	var env Envelope
	if err := json.Unmarshal(att.data, &env); err != nil {
		t.Fatalf("Unmarshal published envelope: %v", err)
	}

	if env.EventID != fixedID {
		t.Errorf("EventID = %v, want %v", env.EventID, fixedID)
	}
	if env.SchemaVersion != EnvelopeSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", env.SchemaVersion, EnvelopeSchemaVersion)
	}
	if !env.OccurredAt.Equal(tFixed) {
		t.Errorf("OccurredAt = %v, want %v", env.OccurredAt, tFixed)
	}
	if env.EventType != EventLoginSucceeded {
		t.Errorf("EventType = %q, want %q", env.EventType, EventLoginSucceeded)
	}
	if env.ActionStatus != StatusSuccess {
		t.Errorf("ActionStatus = %q, want %q", env.ActionStatus, StatusSuccess)
	}
	if env.ActorID != actorID.String() {
		t.Errorf("ActorID = %q, want %q", env.ActorID, actorID.String())
	}
	if env.SubjectID != subjectID.String() {
		t.Errorf("SubjectID = %q, want %q", env.SubjectID, subjectID.String())
	}
	if env.ClientIP != "192.0.2.1" {
		t.Errorf("ClientIP = %q, want 192.0.2.1", env.ClientIP)
	}
	if env.Security == nil || env.Security.AccountRef != subjectID.String() {
		t.Errorf("Security AccountRef = %v, want %v", env.Security, subjectID.String())
	}
}

// 3. Checking that a full buffer triggers the fallback and increments the drop counter.
func TestJetStreamRecorderFullBufferFallback(t *testing.T) {
	fake := &fakeJetStream{
		entered: make(chan struct{}, 8),
		gate:    make(chan struct{}),
	}
	logger, logBuf := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 1, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	t.Cleanup(func() {
		close(fake.gate)
		_ = rec.Close(context.Background())
	})

	// First event enters buf, gets picked up by run(), calls PublishAsync and blocks on gate.
	if err := rec.Record(context.Background(), Event{EventType: "event.one"}); err != nil {
		t.Fatalf("Record 1: %v", err)
	}

	// Wait until PublishAsync is entered for event 1.
	select {
	case <-fake.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event 1 to enter PublishAsync")
	}

	// Now buf is empty again, so event 2 fills buf (size 1).
	if err := rec.Record(context.Background(), Event{EventType: "event.two"}); err != nil {
		t.Fatalf("Record 2: %v", err)
	}

	// Now buf is full. Event 3 must hit default case and trigger fallback.
	if err := rec.Record(context.Background(), Event{EventType: "event.three"}); err != nil {
		t.Fatalf("Record 3: %v", err)
	}

	if dropped := rec.Dropped(); dropped != 1 {
		t.Errorf("Dropped() = %d, want 1", dropped)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, AuditTransportFailureMarker) {
		t.Errorf("expected log to contain marker %q, got: %s", AuditTransportFailureMarker, logs)
	}
	if !strings.Contains(logs, "publish_buffer_full") {
		t.Errorf("expected log to contain 'publish_buffer_full', got: %s", logs)
	}
}

// 4. Verifying unserializable payloads log an error and count as dropped.
func TestJetStreamRecorderUnserializablePayload(t *testing.T) {
	fake := &fakeJetStream{}
	logger, logBuf := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 10, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}
	defer rec.Close(context.Background())

	unserializable := map[string]any{
		"ch": make(chan int),
	}
	err = rec.Record(context.Background(), Event{
		EventType: "event.bad.payload",
		Payload:   unserializable,
	})
	if err == nil {
		t.Fatal("expected error for unserializable payload, got nil")
	}

	if dropped := rec.Dropped(); dropped != 1 {
		t.Errorf("Dropped() = %d, want 1", dropped)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, AuditTransportFailureMarker) {
		t.Errorf("expected marker %q in logs: %s", AuditTransportFailureMarker, logs)
	}
	if !strings.Contains(logs, "payload_not_serializable") {
		t.Errorf("expected 'payload_not_serializable' in logs: %s", logs)
	}
}

// 5. Testing that publish rejections fall back to the logger.
func TestJetStreamRecorderPublishRejectionFallback(t *testing.T) {
	fake := &fakeJetStream{
		publishErr: errors.New("simulated publish rejection"),
	}
	logger, logBuf := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 10, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	if err := rec.Record(context.Background(), Event{EventType: "event.rejected"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if dropped := rec.Dropped(); dropped != 1 {
		t.Errorf("Dropped() = %d, want 1", dropped)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, AuditTransportFailureMarker) {
		t.Errorf("expected marker in logs: %s", logs)
	}
	if !strings.Contains(logs, "publish_rejected") {
		t.Errorf("expected 'publish_rejected' in logs: %s", logs)
	}
}

// 6. Testing unacknowledged publishes falling back.
func TestJetStreamRecorderPublishNotAcknowledgedFallback(t *testing.T) {
	fake := &fakeJetStream{
		ackErr: errors.New("simulated nack error"),
	}
	logger, logBuf := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 10, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	if err := rec.Record(context.Background(), Event{EventType: "event.nack"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if dropped := rec.Dropped(); dropped != 1 {
		t.Errorf("Dropped() = %d, want 1", dropped)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, AuditTransportFailureMarker) {
		t.Errorf("expected marker in logs: %s", logs)
	}
	if !strings.Contains(logs, "publish_not_acknowledged") {
		t.Errorf("expected 'publish_not_acknowledged' in logs: %s", logs)
	}
}

// 7. Ensuring the fallback log preserves the full envelope for recovery.
func TestJetStreamRecorderFallbackPreservesEnvelope(t *testing.T) {
	fake := &fakeJetStream{
		publishErr: errors.New("nack"),
	}
	logger, logBuf := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 10, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	subjectID := uuid.New()
	event := Event{
		EventType:    EventTokenIssued,
		ActionStatus: StatusSuccess,
		SubjectID:    &subjectID,
		ClientIP:     "198.51.100.2",
		UserAgent:    "OAuthClient/2.0",
		Payload:      map[string]any{"client_id": "app-1", "scope": "openid"},
		Security: &SecurityContext{
			AccountRef: subjectID,
			ClientID:   "app-1",
			Scope:      "openid",
		},
	}

	if err := rec.Record(context.Background(), event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	type logLine struct {
		Marker    string `json:"marker"`
		Reason    string `json:"reason"`
		EventID   string `json:"event_id"`
		EventType string `json:"event_type"`
		Subject   string `json:"subject"`
		Envelope  string `json:"envelope"`
	}

	found := false
	for _, line := range strings.Split(logBuf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, AuditTransportFailureMarker) {
			continue
		}
		var parsed logLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			continue
		}
		if parsed.Reason == "publish_rejected" {
			found = true
			if parsed.EventType != EventTokenIssued {
				t.Errorf("logged event_type = %q, want %q", parsed.EventType, EventTokenIssued)
			}
			if parsed.Envelope == "" {
				t.Fatal("envelope attribute in log line is empty")
			}
			var reconstructed Envelope
			if err := json.Unmarshal([]byte(parsed.Envelope), &reconstructed); err != nil {
				t.Fatalf("Unmarshal reconstructed envelope: %v", err)
			}
			if reconstructed.EventType != EventTokenIssued {
				t.Errorf("reconstructed EventType = %q, want %q", reconstructed.EventType, EventTokenIssued)
			}
			if reconstructed.Security == nil || reconstructed.Security.AccountRef != subjectID.String() {
				t.Errorf("reconstructed Security = %v, want AccountRef %v", reconstructed.Security, subjectID)
			}
		}
	}
	if !found {
		t.Fatalf("could not find fallback log line in: %s", logBuf.String())
	}
}

// 8. Draining buffered events on close.
func TestJetStreamRecorderCloseDrainsBufferedEvents(t *testing.T) {
	fake := &fakeJetStream{}
	logger, _ := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 20, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := rec.Record(context.Background(), Event{
			EventType:    EventMFATOTPEnabled,
			ActionStatus: StatusSuccess,
		}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	attempts := fake.getAttempts()
	if len(attempts) != 5 {
		t.Errorf("expected 5 published attempts on drain, got %d", len(attempts))
	}
	if dropped := rec.Dropped(); dropped != 0 {
		t.Errorf("expected 0 dropped events, got %d", dropped)
	}
}

// 9. Making close idempotent.
func TestJetStreamRecorderCloseIdempotent(t *testing.T) {
	fake := &fakeJetStream{}
	logger, _ := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 5, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rec.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// 10. Handling timeouts during close when the gate is blocked.
func TestJetStreamRecorderCloseTimeout(t *testing.T) {
	fake := &fakeJetStream{
		entered: make(chan struct{}, 8),
		gate:    make(chan struct{}),
	}
	logger, _ := newTestJSONLogger()

	rec, err := NewJetStreamRecorder(fake, "identity.audit.logs", 5, logger)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	t.Cleanup(func() {
		close(fake.gate)
		_ = rec.Close(context.Background())
	})

	// Put event 1 into recorder; it enters publish and blocks on gate.
	if err := rec.Record(context.Background(), Event{EventType: "blocking.event"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	select {
	case <-fake.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event to enter publish")
	}

	// Buffer another event so len(buf) > 0.
	if err := rec.Record(context.Background(), Event{EventType: "buffered.event"}); err != nil {
		t.Fatalf("Record buffered: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	err = rec.Close(ctx)
	if err == nil {
		t.Fatal("expected Close to return timeout/cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if !strings.Contains(err.Error(), "envelopes still buffered") {
		t.Errorf("expected error message to mention 'envelopes still buffered', got %q", err.Error())
	}
}
