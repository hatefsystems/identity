package signer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

func integrityMessage(t *testing.T, env audit.Envelope) *fakeMsg {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeMsg{data: raw}
}

func TestSignerNormalizesLegacyAndSyntheticTimestamps(t *testing.T) {
	now := time.Date(2026, 9, 18, 1, 2, 3, 123456789, time.FixedZone("offset", 12600))
	id := uuid.New()
	index := strings.Repeat("a", 64)
	store := &fakeStore{userEmails: map[uuid.UUID]string{id: "alice@example.test"}}
	tx := &fakeBatchTx{store: store}
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: time.Hour + 987*time.Nanosecond}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithClock(func() time.Time { return now }), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	env := audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), ActorID: id.String(), SubjectID: id.String(), OccurredAt: now, EventType: audit.EventLoginSucceeded, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: id.String(), IdentityBlindIndex: &index}}
	if err := s.processBatch(context.Background(), []jetstream.Msg{integrityMessage(t, env), &fakeMsg{data: []byte("not json")}}); err != nil {
		t.Fatal(err)
	}
	prev := audit.GenesisChainHash
	for _, row := range store.insertedAuditLogs {
		if row.Timestamp.Time.Nanosecond()%1000 != 0 {
			t.Fatal("audit timestamp is not microsecond aligned")
		}
		record := audit.AuditRecord{ID: row.ID.String(), ActorID: row.ActorID.String(), ActorSPIFFEID: row.ActorSpiffeID, EventType: row.EventType, ActionStatus: row.ActionStatus, ClientIP: row.ClientIp, UserAgent: row.UserAgent, Payload: row.Payload, Timestamp: row.Timestamp.Time.Truncate(time.Microsecond)}
		if row.ChainHash != audit.ChainHash(prev, audit.SerializeAudit(record)) {
			t.Fatal("audit hash differs after PostgreSQL precision roundtrip")
		}
		prev, _ = audit.DecodeChainHash(row.ChainHash)
	}
	row := store.insertedSecurityEvents[0]
	if row.Timestamp.Time.Nanosecond()%1000 != 0 || row.RetainUntil.Time.Nanosecond()%1000 != 0 {
		t.Fatal("ledger timestamps not microsecond aligned")
	}
	record := audit.LedgerRecord{ID: row.ID.String(), AccountRef: row.AccountRef.String(), IdentityBlindIndex: row.IdentityBlindIndex, EventType: row.EventType, ClientIP: row.ClientIp, IPSubnet: row.IpSubnet, UserAgent: row.UserAgent, DeviceFingerprint: row.DeviceFingerprint, ClientID: row.ClientID, Scope: row.Scope, Timestamp: row.Timestamp.Time.Truncate(time.Microsecond), RetainUntil: row.RetainUntil.Time.Truncate(time.Microsecond)}
	if row.ChainHash != audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(record)) {
		t.Fatal("ledger hash differs after PostgreSQL precision roundtrip")
	}
}

func TestSignerLateSubjectsAndClassC(t *testing.T) {
	live, deleted := uuid.New(), uuid.New()
	index := strings.Repeat("a", 64)
	store := &fakeStore{userEmails: map[uuid.UUID]string{live: "live@example.test"}, userEmailErrs: map[uuid.UUID]error{deleted: errors.New("must not query identity after capture")}}
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}, &fakeFetcher{}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	var msgs []jetstream.Msg
	for _, subject := range []uuid.UUID{live, deleted} {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), ActorID: live.String(), SubjectID: subject.String(), OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: subject.String(), IdentityBlindIndex: &index}}))
	}
	for _, eventType := range []string{audit.EventAdminChainVerified, audit.EventLegalHoldApplied, audit.EventLegalInquiryLookup, "legal.future.action"} {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), ActorID: live.String(), SubjectID: deleted.String(), OccurredAt: time.Now(), EventType: eventType, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: deleted.String(), IdentityBlindIndex: &index}}))
	}
	if err := s.processBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if len(store.insertedSecurityEvents) != 2 {
		t.Fatal("Class C injected context produced ledger records")
	}
	if !store.insertedAuditLogs[0].UserID.Valid {
		t.Fatal("live subject attachment lost")
	}
	for _, row := range store.insertedAuditLogs[1:] {
		if row.UserID.Valid {
			t.Fatal("absent subject retained invalid FK")
		}
		if strings.Contains(row.Payload, index) {
			t.Fatal("index leaked to audit payload")
		}
	}
	if *store.insertedSecurityEvents[1].IdentityBlindIndex != index {
		t.Fatal("captured index lost after deletion")
	}
}

func TestSignerSubjectLockFailureAbortsBatch(t *testing.T) {
	store := &fakeStore{subjectLockErr: errors.New("lock unavailable")}
	tx := &fakeBatchTx{store: store}
	s, err := New(Config{BatchSize: 1, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), SubjectID: uuid.NewString(), EventType: audit.EventLegalHoldApplied})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil {
		t.Fatal("lock failure accepted")
	}
	if tx.committed || !tx.rolledBack || !msg.naked || len(store.insertedAuditLogs) != 0 {
		t.Fatal("failed subject lock did not abort batch safely")
	}
}

func TestSignerFailedReseedStopsBeforeNextFetch(t *testing.T) {
	store := &fakeStore{latestAuditErr: pgx.ErrNoRows, latestLedgerErr: pgx.ErrNoRows}
	tx := &fakeBatchTx{store: store, commitErr: errors.New("commit outcome uncertain")}
	tx.onCommit = func() { store.latestAuditErr = errors.New("database unreachable") }
	ch := make(chan jetstream.Msg, 1)
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), ActorID: uuid.Nil.String(), OccurredAt: time.Now(), EventType: audit.EventSessionLoggedOut, Payload: "{}"})
	ch <- msg
	close(ch)
	fetcher := &fakeFetcher{batches: []jetstream.MessageBatch{&fakeMessageBatch{msgs: ch}}}
	locker := &fakeAdvisoryLocker{acquired: true}
	s, err := New(Config{BatchSize: 1, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: tx}, fetcher, WithLogger(discardLogger()), WithAdvisoryLocker(locker))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.RunUntilDone(ctx); !errors.Is(err, ErrChainTipsUnknown) {
		t.Fatalf("got %v, want fatal unknown-tip error", err)
	}
	if fetcher.calls != 1 || !msg.naked || !locker.released {
		t.Fatal("signer continued or failed to release lock")
	}
	before := len(store.insertedAuditLogs)
	if err := s.processBatch(ctx, []jetstream.Msg{msg}); !errors.Is(err, ErrChainTipsUnknown) {
		t.Fatal("invalid cached tips reused")
	}
	if len(store.insertedAuditLogs) != before {
		t.Fatal("new write with invalid tips")
	}
}
