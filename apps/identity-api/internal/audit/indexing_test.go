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
	indexer, err := blindindex.New([]byte(strings.Repeat("p", 32)), 7)
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
	if next.event.Security.BlindIndexVersion != 7 || e.Security.BlindIndexVersion != 0 {
		t.Fatal("captured generation missing or caller mutated")
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
	var decoded Envelope
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Security.BlindIndexVersion != 7 {
		t.Fatal("captured generation lost across envelope roundtrip")
	}
	*next.event.Security.IdentityBlindIndex = "changed"
	if *env.Security.IdentityBlindIndex != indexer.Compute(email) {
		t.Fatal("envelope retained mutable pointer")
	}
}

func TestIndexingRecorderClassCRejectsInjectedSecurity(t *testing.T) {
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)), 0)
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
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)), 0)
	next := &capturedRecorder{}
	var logs bytes.Buffer
	r, err := NewIndexingRecorder(next, identitySourceFunc(func(context.Context, uuid.UUID) (string, error) {
		return "", errors.New("sensitive@example.test")
	}), indexer, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := envelopeTestEvent()
	e.Security.BlindIndexVersion = 9
	if err := r.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if next.event.Security.IdentityBlindIndex != nil {
		t.Fatal("invented index after failed capture")
	}
	if next.event.Security.BlindIndexVersion != 9 {
		t.Fatal("missing-capture fallback generation changed")
	}
	if strings.Contains(logs.String(), "sensitive") || !strings.Contains(logs.String(), "audit_index_capture_missing") {
		t.Fatalf("unsafe or missing diagnostic: %s", logs.String())
	}
}

func TestIndexingRecorderPreservesCapturedPair(t *testing.T) {
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)), 7)
	next := &capturedRecorder{}
	r, err := NewIndexingRecorder(next, identitySourceFunc(func(context.Context, uuid.UUID) (string, error) {
		t.Fatal("already captured pair queried live identity")
		return "", nil
	}), indexer, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, _, _ := envelopeTestEvent()
	digest := strings.Repeat("a", 64)
	e.Security.IdentityBlindIndex = &digest
	e.Security.BlindIndexVersion = 3
	if err := r.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if next.event.Security.BlindIndexVersion != 3 || *next.event.Security.IdentityBlindIndex != digest {
		t.Fatal("existing capture pair replaced")
	}
	*next.event.Security.IdentityBlindIndex = "changed"
	if digest != strings.Repeat("a", 64) {
		t.Fatal("retained caller's mutable index pointer")
	}
}

func TestIndexingRecorderEmailSpecificCapture(t *testing.T) {
	indexer, _ := blindindex.New([]byte(strings.Repeat("p", 32)), 7)
	for _, email := range []string{"\u062d\u0627\u062a\u0641@\u0645\u062b\u0627\u0644.ir", "\ufb00@example.test", "f\u0066@example.test", "bad\x00@example.test"} {
		t.Run(email, func(t *testing.T) {
			next := &capturedRecorder{}
			var logs bytes.Buffer
			r, err := NewIndexingRecorder(next, identitySourceFunc(func(context.Context, uuid.UUID) (string, error) { return email, nil }), indexer, slog.New(slog.NewTextHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			e, _, _ := envelopeTestEvent()
			e.Security.BlindIndexVersion = 3
			if err := r.Record(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			want, err := indexer.ComputeEmail(email)
			if err != nil {
				if next.event.Security.IdentityBlindIndex != nil || next.event.Security.BlindIndexVersion != 3 || strings.Contains(logs.String(), "bad") {
					t.Fatal("invalid email captured or leaked")
				}
				return
			}
			if next.event.Security.IdentityBlindIndex == nil || *next.event.Security.IdentityBlindIndex != want || next.event.Security.BlindIndexVersion != 7 {
				t.Fatal("email-specific capture pair mismatch")
			}
			if email == "\ufb00@example.test" && want == indexer.Compute(email) {
				t.Fatal("capture used generic NFKC index")
			}
		})
	}
}
