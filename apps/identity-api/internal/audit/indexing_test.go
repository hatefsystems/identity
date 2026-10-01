package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
)

type capturedRecorder struct{ event Event }

func (r *capturedRecorder) Record(_ context.Context, e Event) error { r.event = e; return nil }

type identitySourceFunc func(context.Context, uuid.UUID) (string, error)

func (f identitySourceFunc) GetUserEmailForBlindIndex(ctx context.Context, id uuid.UUID) (string, error) {
	return f(ctx, id)
}

func TestIndexingRecorderCapturesBeforeAsyncBoundary(t *testing.T) {
	next := &capturedRecorder{}
	indexer, err := blindindex.New([]byte(strings.Repeat("p", 32)))
	if err != nil {
		t.Fatal(err)
	}
	e, _, account := envelopeTestEvent()
	email := " Alice@Example.test "
	source := identitySourceFunc(func(_ context.Context, id uuid.UUID) (string, error) {
		if id != account {
			t.Fatal("wrong account")
		}
		return email, nil
	})
	r, err := NewIndexingRecorder(next, source, indexer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if e.Security.IdentityBlindIndex != nil {
		t.Fatal("mutated caller context")
	}
	if got := next.event.Security.IdentityBlindIndex; got == nil || *got != indexer.Compute(email) {
		t.Fatal("index was not captured synchronously")
	}
	env, err := NewEnvelope(next.event, uuid.New(), fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "alice") {
		t.Fatal("raw identity crossed wire")
	}
	if strings.Contains(env.Payload, *env.Security.IdentityBlindIndex) {
		t.Fatal("index leaked into audit payload")
	}
	*next.event.Security.IdentityBlindIndex = "changed"
	if *env.Security.IdentityBlindIndex != indexer.Compute(email) {
		t.Fatal("envelope retained mutable pointer")
	}
}

func TestIndexingRecorderClassCRejectsInjectedSecurity(t *testing.T) {
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)))
	next := &capturedRecorder{}
	r, err := NewIndexingRecorder(next, identitySourceFunc(func(context.Context, uuid.UUID) (string, error) {
		t.Fatal("Class C queried identity source")
		return "", nil
	}), indexer, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{EventAdminChainVerified, EventLegalHoldApplied, EventLegalInquiryLookup, "legal.future.action"} {
		e, _, _ := envelopeTestEvent()
		e.EventType = eventType
		if err := r.Record(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		if next.event.Security != nil {
			t.Fatal("Class C retained security context")
		}
		env, err := NewEnvelope(e, uuid.New(), fixedTime)
		if err != nil {
			t.Fatal(err)
		}
		if env.Security != nil {
			t.Fatal("producer permitted injected Class C security context")
		}
	}
}

func TestIndexingRecorderCaptureFailureDoesNotLeakError(t *testing.T) {
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)))
	next := &capturedRecorder{}
	var logs bytes.Buffer
	r, err := NewIndexingRecorder(next, identitySourceFunc(func(context.Context, uuid.UUID) (string, error) {
		return "", errors.New("sensitive@example.test")
	}), indexer, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := envelopeTestEvent()
	if err := r.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if next.event.Security.IdentityBlindIndex != nil {
		t.Fatal("invented index after failed capture")
	}
	if strings.Contains(logs.String(), "sensitive") || !strings.Contains(logs.String(), "audit_index_capture_missing") {
		t.Fatalf("unsafe or missing diagnostic: %s", logs.String())
	}
}
