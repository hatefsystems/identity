package contactcode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
)

func ownershipFixture(t *testing.T, channel string) (fixture, OwnershipBinding, *captureSender) {
	t.Helper()
	sender := &captureSender{}
	cfg := Config{ContactOwnershipEmail: sender}
	var sms *smsotp.Config
	if channel == ChannelSMS {
		sms = &smsotp.Config{GlobalPerDay: 20, CodeTTL: time.Minute, MaxAttempts: 2}
	}
	f := newFixture(t, cfg, sms, false)
	b := OwnershipBinding{DeletionBinding: DeletionBinding{f.id, 9, "earning-session", f.jkt}, Target: "email", Destination: "new@example.test"}
	if channel == ChannelSMS {
		b.Target, b.Destination, sender = "phone", "+989123456789", f.sms
	}
	return f, b, sender
}

func TestPreparedOwnershipIsPrivateFrozenAndOneShot(t *testing.T) {
	for _, channel := range []string{ChannelEmail, ChannelSMS} {
		t.Run(channel, func(t *testing.T) {
			f, binding, sender := ownershipFixture(t, channel)
			handle := capability(20)
			deadline := time.Now().UTC().Add(30 * time.Second).Truncate(time.Millisecond)
			p, err := f.svc.PrepareOwnership(t.Context(), binding, handle, deadline, "203.0.113.8")
			if err != nil || p.Handle() != handle || !p.ExpiresAt().Equal(deadline) || sender.calls() != 0 || len(f.mr.Keys()) != 0 {
				t.Fatal("preparation performed I/O or replaced handle/deadline", err)
			}
			secret := p.code
			if output := fmt.Sprintf("%+v %#v", p, p); strings.Contains(output, binding.Destination) || strings.Contains(output, string(secret)) {
				t.Fatal("prepared diagnostics exposed private material")
			}
			admissions := 0
			if err := f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error {
				admissions++
				if sender.calls() != 0 || f.mr.HGet(challengePrefix+handle, "active") != "0" || len(f.mr.Keys()) < 5 {
					t.Fatal("admission ran before quota or after submission")
				}
				return nil
			}); err != nil || admissions != 1 || sender.calls() != 1 {
				t.Fatal("one-shot dispatch did not submit/activate", err)
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) || p.service != nil || p.destination != "" || len(p.code) != 0 {
				t.Fatal("prepared secrets retained after dispatch")
			}
			payload := f.mr.HGet(challengePrefix+handle, "payload")
			if strings.Contains(payload, binding.Destination) || strings.Contains(payload, sender.last().code) {
				t.Fatal("pending destination or plaintext OTP persisted")
			}
			rec, err := f.store.Get(t.Context(), handle)
			if err != nil || rec.Destination != "" || len(rec.DestinationMAC) != 64 || !rec.ExpiresAt.Equal(deadline) {
				t.Fatal("exact private activated record lost", err)
			}
			if _, err := f.svc.Verify(t.Context(), handle, binding.JKT, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("ownership became login authority", err)
			}
			if err := f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error { return nil }); err != ErrNoActiveCode || sender.calls() != 1 {
				t.Fatal("preparation submitted twice", err)
			}
			// No transport/service policy is needed by a finite ownership reader.
			reader, err := New(Config{HashKey: f.svc.cfg.HashKey}, f.store, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.VerifyOwnership(t.Context(), binding, handle, sender.last().code); err != nil {
				t.Fatal("sending-off reader rejected frozen ownership", err)
			}
			if _, err := reader.VerifyOwnership(t.Context(), binding, handle, sender.last().code); err != ErrNoActiveCode {
				t.Fatal("ownership replay accepted", err)
			}
		})
	}
}

func TestOwnershipForeignBindingsDoNotSpendAttempts(t *testing.T) {
	f, binding, sender := ownershipFixture(t, ChannelEmail)
	handle := capability(21)
	p, err := f.svc.PrepareOwnership(t.Context(), binding, handle, time.Now().Add(time.Minute), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"account", "session", "version", "jkt", "target", "destination", "handle", "code"} {
		other, id, code := binding, handle, sender.last().code
		switch field {
		case "account":
			other.AccountID = uuid.New()
		case "session":
			other.SessionID = "foreign-session"
		case "version":
			other.AuthVersion++
		case "jkt":
			other.JKT = capability(2)
		case "target":
			other.Target, other.Destination = "phone", "+989123456789"
		case "destination":
			other.Destination = "foreign@example.test"
		case "handle":
			id = capability(22)
		case "code":
			code = "12 456"
		}
		if _, err := f.svc.VerifyOwnership(t.Context(), other, id, code); err != ErrNoActiveCode && err != ErrInvalid {
			t.Fatal("foreign input became ownership", field, err)
		}
		if f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
			t.Fatal("foreign input burned legitimate attempts", field)
		}
	}
	if _, err := f.svc.VerifyContactAction(t.Context(), binding.DeletionBinding, handle, sender.last().code, PurposeContactChange); err != ErrNoActiveCode {
		t.Fatal("ownership became action authority", err)
	}
	if _, err := f.svc.VerifyOwnership(t.Context(), binding, handle, sender.last().code); err != nil {
		t.Fatal(err)
	}
}

type admissionStore struct {
	Store
	afterReserve func()
	activateErr  error
}

func (s admissionStore) Reserve(ctx context.Context, rec Record, budgets []Budget, key string, capacity int) error {
	if err := s.Store.Reserve(ctx, rec, budgets, key, capacity); err != nil {
		return err
	}
	if s.afterReserve != nil {
		s.afterReserve()
	}
	return nil
}

func (s admissionStore) Activate(ctx context.Context, rec Record) error {
	if s.activateErr != nil {
		return s.activateErr
	}
	return s.Store.Activate(ctx, rec)
}

func TestPreparedOwnershipFinalAdmissionAndUnknownOutcomes(t *testing.T) {
	for _, failure := range []string{"replacement", "expiry", "provider-unknown", "activation-unknown", "quota"} {
		t.Run(failure, func(t *testing.T) {
			f, binding, sender := ownershipFixture(t, ChannelEmail)
			handle := capability(23)
			deadline := time.Now().Add(time.Minute)
			if failure == "expiry" {
				deadline = time.Now().Add(100 * time.Millisecond)
			}
			stateLive := true
			store := admissionStore{Store: f.store}
			if failure == "replacement" {
				store.afterReserve = func() { stateLive = false }
			}
			if failure == "provider-unknown" {
				sender.err = errPrivate
			}
			if failure == "activation-unknown" {
				store.activateErr = ErrOutcomeUnknown
			}
			f.svc.store = store
			p, err := f.svc.PrepareOwnership(t.Context(), binding, handle, deadline, "203.0.113.8")
			if err != nil {
				t.Fatal(err)
			}
			if failure == "quota" {
				f.svc.cfg.MaxPending = 1
				if _, err := f.mr.ZAdd(capacityKey, float64(time.Now().Add(time.Minute).UnixMilli()), "other"); err != nil {
					t.Fatal(err)
				}
			}
			admitted := 0
			err = f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error {
				admitted++
				if !stateLive {
					return ErrNoActiveCode
				}
				if failure == "expiry" {
					time.Sleep(time.Until(p.ExpiresAt()) + time.Millisecond)
				}
				return nil
			})
			if failure == "provider-unknown" || failure == "activation-unknown" {
				if err != ErrOutcomeUnknown || sender.calls() != 1 {
					t.Fatal("uncertain acceptance retried or misclassified", err)
				}
			} else if sender.calls() != 0 || err == nil {
				t.Fatal("stale/expired/quota-denied state submitted", err)
			}
			if failure == "quota" && admitted != 0 || failure != "quota" && admitted != 1 {
				t.Fatal("final check was not after successful quota reservation")
			}
			if _, err := f.store.Get(t.Context(), handle); err != ErrNoActiveCode {
				t.Fatal("failed dispatch activated a code", err)
			}
			if p.service != nil || len(p.code) != 0 || p.destination != "" {
				t.Fatal("failed dispatch retained private preparation")
			}
		})
	}
}

func TestContactActionCodesFreezeTargetsAndHaveFiniteDisabledReaders(t *testing.T) {
	for _, action := range []string{PurposeContactChange, PurposeContactRemove} {
		for _, target := range []string{"email", "phone"} {
			t.Run(action+"/"+target, func(t *testing.T) {
				sender := &captureSender{}
				f := newFixture(t, Config{ContactChangeEmail: sender, ContactRemovalEmail: sender}, nil, false)
				binding := DeletionBinding{f.id, 9, "earning-session", f.jkt}
				deadline := time.Now().Add(30 * time.Second).UTC().Truncate(time.Millisecond)
				handle, expires, err := f.svc.RequestContactAction(t.Context(), binding, action, target, ChannelEmail, "owner@example.test", strings.Repeat("ab", 32), deadline, "203.0.113.8", func(context.Context) error { return nil })
				if err != nil || !expires.Equal(deadline) || sender.calls() != 1 {
					t.Fatal("contact authorization deadline restamped", err)
				}
				otherAction := PurposeContactChange
				if action == otherAction {
					otherAction = PurposeContactRemove
				}
				if _, err := f.svc.VerifyContactAction(t.Context(), binding, handle, sender.last().code, otherAction); err != ErrNoActiveCode || f.mr.HGet(challengePrefix+handle, "attempts") != "0" {
					t.Fatal("cross-action OTP burned or authorized", err)
				}
				reader, err := New(Config{HashKey: f.svc.cfg.HashKey}, f.store, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				rec, err := reader.VerifyContactAction(t.Context(), binding, handle, sender.last().code, action)
				if err != nil || rec.Target != target || rec.Action != action || !rec.ExpiresAt.Equal(deadline) {
					t.Fatal("reader lost frozen action/target", err)
				}
			})
		}
	}
}

func TestOwnershipSharesQuotasAndPreservesCapturedAttemptPolicy(t *testing.T) {
	f, binding, sender := ownershipFixture(t, ChannelSMS)
	handle := capability(24)
	p, err := f.svc.PrepareOwnership(t.Context(), binding, handle, time.Now().Add(3*time.Minute), "203.0.113.8")
	if err != nil || time.Until(p.ExpiresAt()) > time.Minute || p.record.MaxAttempts != 2 {
		t.Fatal("stricter SMS code policy lost", err)
	}
	if err := f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Request(t.Context(), f.id, 9, f.jkt, ChannelSMS, binding.Destination, "203.0.113.8"); err != ErrRateLimited {
		t.Fatal("ownership bypassed shared login/SMS spend", err)
	}
	reader, err := New(Config{HashKey: f.svc.cfg.HashKey, MaxAttempts: 3}, f.store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if wrong == sender.last().code {
		wrong = "000001"
	}
	if _, err := reader.VerifyOwnership(t.Context(), binding, handle, wrong); err != ErrInvalidCode {
		t.Fatal(err)
	}
	if _, err := reader.VerifyOwnership(t.Context(), binding, handle, wrong); err != ErrLockedOut {
		t.Fatal("reader widened captured attempt bound", err)
	}
}

func TestConcurrentPreparedDispatchSubmitsOnlyOnce(t *testing.T) {
	f, binding, sender := ownershipFixture(t, ChannelEmail)
	p, err := f.svc.PrepareOwnership(t.Context(), binding, capability(25), time.Now().Add(time.Minute), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Go(func() { results <- f.svc.DispatchOwnership(t.Context(), p, func(context.Context) error { return nil }) })
	}
	workers.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrNoActiveCode) {
			t.Fatal(err)
		}
	}
	if winners != 1 || sender.calls() != 1 {
		t.Fatal("prepared dispatch admitted more than once")
	}
}

func TestT27RecordExtensionsKeepExistingEncoding(t *testing.T) {
	f := newFixture(t, Config{}, nil, true)
	handle, _ := f.request(t, ChannelEmail, "owner@example.test")
	rec, err := f.store.Get(t.Context(), handle)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(rec)
	if err != nil || strings.Contains(string(encoded), "Action") || strings.Contains(string(encoded), "Target") || strings.Contains(string(encoded), "DestinationMAC") {
		t.Fatal("new zero fields changed existing canonical payload/HMAC")
	}
	if _, err := f.svc.Verify(t.Context(), handle, f.jkt, f.email.last().code); err != nil {
		t.Fatal("existing login path changed", err)
	}
	for _, phone := range []string{"+442071234567", "+98912345678", "+9891234567890", "09123456789", "+98912345678x"} {
		if OwnershipDestinationSupported("phone", phone) {
			t.Fatal("unsupported provider recipient admitted before authority")
		}
	}
}

func TestPreparedOwnershipAbortAndBindingHMAC(t *testing.T) {
	f, binding, _ := ownershipFixture(t, ChannelEmail)
	for _, mode := range []string{"sql-rollback", "missing-admission"} {
		p, err := f.svc.PrepareOwnership(t.Context(), binding, capability(26), time.Now().Add(time.Minute), "203.0.113.8")
		if err != nil {
			t.Fatal(err)
		}
		secret := p.code
		if mode == "sql-rollback" {
			p.Clear()
		} else if err := f.svc.DispatchOwnership(t.Context(), p, nil); err != ErrInvalid {
			t.Fatal("missing final admission accepted", err)
		}
		if p.service != nil || p.destination != "" || !bytes.Equal(secret, make([]byte, len(secret))) || len(f.mr.Keys()) != 0 {
			t.Fatal("precommit abort retained code or reserved quota")
		}
	}
	p, err := f.svc.PrepareOwnership(t.Context(), binding, capability(27), time.Now().Add(time.Minute), "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	for _, field := range []string{"action", "target", "destination-mac", "purpose"} {
		rec := p.record
		switch field {
		case "action":
			rec.Action = PurposeContactRemove
		case "target":
			rec.Target = "phone"
		case "destination-mac":
			rec.DestinationMAC = strings.Repeat("ab", 32)
		case "purpose":
			rec.Purpose = PurposeContactChange
		}
		if f.svc.hashCode(rec, string(p.code)) == p.record.CodeHash {
			t.Fatal("ownership HMAC omitted frozen binding", field)
		}
	}
	if _, err := f.svc.PrepareOwnership(t.Context(), binding, capability(28), time.Now().Add(-time.Second), "203.0.113.8"); err != ErrNoActiveCode {
		t.Fatal("expired deadline renewed", err)
	}
}

func TestContactSMSActionTemplatesNeverFallBackToOwnership(t *testing.T) {
	for _, action := range []string{PurposeContactChange, PurposeContactRemove} {
		t.Run(action, func(t *testing.T) {
			change, removal := &captureSender{}, &captureSender{}
			f := newFixture(t, Config{}, &smsotp.Config{ContactChangeSender: smsSender{change}, ContactRemovalSender: smsSender{removal}}, false)
			binding := DeletionBinding{f.id, 9, "earning-session", f.jkt}
			handle, _, err := f.svc.RequestContactAction(t.Context(), binding, action, "phone", ChannelSMS, "+989123456789", strings.Repeat("ab", 32), time.Now().Add(time.Minute), "203.0.113.8", func(context.Context) error { return nil })
			if err != nil || f.sms.calls() != 0 || change.calls()+removal.calls() != 1 {
				t.Fatal("SMS action reused ownership sender or dispatched more than once", err)
			}
			sender := change
			if action == PurposeContactRemove {
				sender = removal
			}
			if sender.calls() != 1 {
				t.Fatal("SMS action used wrong action template")
			}
			reader, err := New(Config{HashKey: f.svc.cfg.HashKey}, f.store, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.VerifyContactAction(t.Context(), binding, handle, sender.last().code, action); err != nil {
				t.Fatal("SMS action reader required provider enablement", err)
			}
		})
	}
}
