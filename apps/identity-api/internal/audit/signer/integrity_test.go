package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
	store := &fakeStore{head: genesisLedgerHead(), userEmails: map[uuid.UUID]string{id: "alice@example.test"}}
	tx := &fakeBatchTx{store: store}
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: time.Hour + 987*time.Nanosecond}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithClock(func() time.Time { return now }), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	env := audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: id.String(), SubjectID: id.String(), OccurredAt: now, EventType: audit.EventLoginSucceeded, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: id.String(), IdentityBlindIndex: &index}}
	if err := s.processBatch(context.Background(), []jetstream.Msg{integrityMessage(t, env), &fakeMsg{data: []byte("not json")}}); err != nil {
		t.Fatal(err)
	}
	prev := audit.Genesis()
	for i, row := range store.insertedAuditLogs {
		if row.Timestamp.Time.Nanosecond()%1000 != 0 {
			t.Fatal("audit timestamp is not microsecond aligned")
		}
		node := store.insertedAuditChain[i]
		record := audit.AuditRecord{ID: node.EventID.String(), ActorID: row.ActorID.String(), ActorSPIFFEID: row.ActorSpiffeID, EventType: row.EventType, ActionStatus: row.ActionStatus, ClientIP: row.ClientIp, UserAgent: row.UserAgent, Payload: row.Payload, Timestamp: row.Timestamp.Time.Truncate(time.Microsecond)}
		leafHash, err := audit.LeafAudit(record)
		if err != nil {
			t.Fatal(err)
		}
		if stored, _ := audit.DecodeDigest(node.LeafHash); stored != leafHash {
			t.Fatal("audit leaf differs after PostgreSQL precision roundtrip")
		}
		prev = audit.ChainAudit(prev, leafHash)
		if stored, _ := audit.DecodeDigest(node.ChainHash); stored != prev {
			t.Fatal("audit chain digest differs after PostgreSQL precision roundtrip")
		}
	}
	row := store.insertedSecurityEvents[0]
	if row.Timestamp.Time.Nanosecond()%1000 != 0 || row.RetainUntil.Time.Nanosecond()%1000 != 0 {
		t.Fatal("ledger timestamps not microsecond aligned")
	}
	node := store.insertedLedgerChain[0]
	record := audit.LedgerRecord{ID: node.EventID.String(), AccountRef: row.AccountRef.String(), IdentityBlindIndex: row.IdentityBlindIndex, BlindIndexVersion: row.BlindIndexVersion, EventType: row.EventType, ClientIP: row.ClientIp, IPSubnet: row.IpSubnet, UserAgent: row.UserAgent, DeviceFingerprint: row.DeviceFingerprint, ClientID: row.ClientID, Scope: row.Scope, Timestamp: row.Timestamp.Time.Truncate(time.Microsecond), RetainUntil: row.RetainUntil.Time.Truncate(time.Microsecond)}
	leafHash, err := audit.LeafLedger(record)
	if err != nil {
		t.Fatal(err)
	}
	if stored, _ := audit.DecodeDigest(node.LeafHash); stored != leafHash {
		t.Fatal("ledger leaf differs after PostgreSQL precision roundtrip")
	}
	if stored, _ := audit.DecodeDigest(node.ChainHash); stored != audit.ChainLedger(audit.LedgerGenesis(), leafHash) {
		t.Fatal("ledger chain digest differs after PostgreSQL precision roundtrip")
	}
}

func TestSignerLateSubjectsAndClassC(t *testing.T) {
	live, deleted := uuid.New(), uuid.New()
	index := strings.Repeat("a", 64)
	store := &fakeStore{head: genesisLedgerHead(), userEmails: map[uuid.UUID]string{live: "live@example.test"}, userEmailErrs: map[uuid.UUID]error{deleted: errors.New("must not query identity after capture")}}
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}, &fakeFetcher{}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	var msgs []jetstream.Msg
	for _, subject := range []uuid.UUID{live, deleted} {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: live.String(), SubjectID: subject.String(), OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: subject.String(), IdentityBlindIndex: &index}}))
	}
	for _, eventType := range []string{audit.EventAdminChainVerified, audit.EventLegalHoldApplied, audit.EventLegalInquiryLookup, "legal.future.action"} {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: live.String(), SubjectID: deleted.String(), OccurredAt: time.Now(), EventType: eventType, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: deleted.String(), IdentityBlindIndex: &index}}))
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
	store := &fakeStore{head: genesisLedgerHead(), subjectLockErr: errors.New("lock unavailable")}
	tx := &fakeBatchTx{store: store}
	s, err := New(Config{BatchSize: 1, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.Nil.String(), OccurredAt: time.Now(), SubjectID: uuid.NewString(), EventType: audit.EventLegalHoldApplied})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil {
		t.Fatal("lock failure accepted")
	}
	if tx.committed || !tx.rolledBack || !msg.naked || len(store.insertedAuditLogs) != 0 {
		t.Fatal("failed subject lock did not abort batch safely")
	}
}

func TestSignerQuarantineReasonsRedactAndRetainEvidence(t *testing.T) {
	sentinel := "sensitive@example.test-secret-token"
	base := audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.NewString(), OccurredAt: time.Now(), EventType: audit.EventSessionLoggedOut, Payload: "{}"}
	marshal := func(change func(*audit.Envelope)) []byte {
		env := base
		change(&env)
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name, reason string
		raw          []byte
	}{
		{"timestamp_parse", "invalid_json", []byte(`{"occurred_at":"` + sentinel + `"}`)},
		{"uuid_parse", "invalid_json", []byte(`{"event_id":"` + sentinel + `"}`)},
		{"generation_overflow", "invalid_json", []byte(`{"security":{"blind_index_version":32768},"payload":"` + sentinel + `"}`)},
		{"syntax", "invalid_json", []byte(`{"` + sentinel + `":`)},
		{"invalid_utf8", "invalid_json", []byte{0xff}},
		{"oversize", "envelope_too_large", []byte(strings.Repeat(sentinel, audit.MaxEnvelopeBytes/len(sentinel)+1))},
		{"actor", "invalid_actor_id", marshal(func(e *audit.Envelope) { e.ActorID = sentinel })},
		{"actor_missing", "invalid_actor_id", marshal(func(e *audit.Envelope) { e.ActorID = "" })},
		{"actor_omitted", "invalid_actor_id", []byte(strings.ReplaceAll(string(marshal(func(*audit.Envelope) {})), `"actor_id":"`+base.ActorID+`",`, ""))},
		{"missing_timestamp", "invalid_timestamp", marshal(func(e *audit.Envelope) { e.OccurredAt = time.Time{} })},
		{"schema", "unsupported_schema", marshal(func(e *audit.Envelope) { e.SchemaVersion = 1 })},
		{"event_id", "invalid_event_id", marshal(func(e *audit.Envelope) { e.EventID = uuid.Nil })},
		{"actor_uppercase", "invalid_actor_id", marshal(func(e *audit.Envelope) { e.ActorID = strings.ToUpper("abcdefab-1234-4321-8123-123456789012") })},
		{"nul", "invalid_text", marshal(func(e *audit.Envelope) { e.Payload = sentinel + "\x00" })},
		{"agent_oversize", "invalid_text", marshal(func(e *audit.Envelope) { e.UserAgent = strings.Repeat("a", 8193) + sentinel })},
		{"generation", "invalid_blind_index", marshal(func(e *audit.Envelope) {
			e.Security = &audit.EnvelopeSecurity{AccountRef: uuid.NewString(), BlindIndexVersion: -1}
		})},
		{"retention_overflow", "invalid_retention_timestamp", marshal(func(e *audit.Envelope) {
			e.EventType = audit.EventLoginSucceeded
			e.OccurredAt = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
		})},
		{"subnet_storage", "invalid_subnet", marshal(func(e *audit.Envelope) { e.EventType = audit.EventLoginSucceeded; e.ClientIP = strings.Repeat("x", 50) })},
		{"subnet_utf8", "invalid_subnet", marshal(func(e *audit.Envelope) {
			e.EventType = audit.EventLoginSucceeded
			e.ClientIP = strings.Repeat("\u0800", 50)
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			store := &fakeStore{head: genesisLedgerHead()}
			tx := &fakeBatchTx{store: store}
			s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			if err != nil {
				t.Fatal(err)
			}
			bad := &fakeMsg{data: tc.raw, metadata: &jetstream.MsgMetadata{Stream: "AUDIT", Sequence: jetstream.SequencePair{Stream: 42}}}
			valid := integrityMessage(t, base)
			if err := s.processBatch(context.Background(), []jetstream.Msg{bad, bad, valid}); err != nil {
				t.Fatal(err)
			}
			if !tx.committed || !bad.termed || bad.acked || !valid.acked || len(store.insertedAuditLogs) != 2 {
				t.Fatal("quarantine blocked valid progress or duplicate quarantine was written")
			}
			row := store.insertedAuditLogs[0]
			var payload struct {
				Reason, Stream string
				RawBytes       int    `json:"raw_bytes"`
				Digest         string `json:"raw_sha256"`
				Sequence       uint64 `json:"stream_sequence"`
			}
			if err := json.Unmarshal([]byte(row.Payload), &payload); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(tc.raw)
			if payload.Reason != tc.reason || payload.Stream != "AUDIT" || payload.Sequence != 42 || payload.RawBytes != len(tc.raw) || payload.Digest != hex.EncodeToString(digest[:]) {
				t.Fatalf("wrong retained evidence: %+v", payload)
			}
			if strings.Contains(logs.String(), sentinel) || strings.Contains(row.Payload, sentinel) || len(payload.Reason) > 32 {
				t.Fatal("quarantine leaked raw parser/input content")
			}
			wantID := uuid.NewSHA1(quarantineNamespace, []byte("AUDIT/42"))
			if store.insertedAuditChain[0].EventID != wantID {
				t.Fatal("stream-position dedup identity changed")
			}
			store.existingAuditIDs = []uuid.UUID{wantID}
			if err := s.processBatch(context.Background(), []jetstream.Msg{bad}); err != nil {
				t.Fatal(err)
			}
			if len(store.insertedAuditLogs) != 2 {
				t.Fatal("redelivery appended duplicate quarantine")
			}
			noMetadata := &fakeMsg{data: tc.raw}
			if got := s.decode([]jetstream.Msg{noMetadata})[0].record.envelope.EventID; got != uuid.NewSHA1(quarantineNamespace, []byte(hex.EncodeToString(digest[:]))) {
				t.Fatal("digest fallback dedup identity changed")
			}
		})
	}
}

func TestSignerCapturedAndFallbackGeneration(t *testing.T) {
	account := uuid.New()
	indexer := &fakeBlindIndexer{pepper: "test", version: 7}
	captured := strings.Repeat("a", 64)
	store := &fakeStore{head: genesisLedgerHead(), userEmails: map[uuid.UUID]string{account: "email@example.test"}}
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}, &fakeFetcher{}, WithBlindIndexer(indexer), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	var msgs []jetstream.Msg
	for _, pair := range []struct {
		digest  *string
		version int16
	}{{&captured, 3}, {nil, 0}} {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.Nil.String(), OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: account.String(), IdentityBlindIndex: pair.digest, BlindIndexVersion: pair.version}}))
	}
	if err := s.processBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	rows := store.insertedSecurityEvents
	if len(rows) != 2 || rows[0].BlindIndexVersion != 3 || *rows[0].IdentityBlindIndex != captured || rows[1].BlindIndexVersion != 7 || *rows[1].IdentityBlindIndex != indexer.Compute("email@example.test") {
		t.Fatal("captured or fallback digest/generation pair lost")
	}
}

func TestSignerInvalidFallbackEmailFailsClosedAndRedacted(t *testing.T) {
	account := uuid.New()
	sentinel := "sensitive@example.test-secret-token"
	store := &fakeStore{head: genesisLedgerHead(), userEmails: map[uuid.UUID]string{account: sentinel}}
	tx := &fakeBatchTx{store: store}
	s, err := New(Config{BatchSize: 1, FlushInterval: time.Second, LedgerRetention: time.Hour}, store, &fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithBlindIndexer(&fakeBlindIndexer{emailErr: errors.New(sentinel)}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.Nil.String(), OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: account.String()}})
	err = s.processBatch(context.Background(), []jetstream.Msg{msg})
	if err == nil || strings.Contains(err.Error(), sentinel) || tx.committed || !msg.naked || msg.acked || len(store.insertedAuditLogs) != 0 {
		t.Fatal("invalid email fallback was signed, lost or leaked")
	}
}

func TestSignerFailedReseedStopsBeforeNextFetch(t *testing.T) {
	store := &fakeStore{head: genesisLedgerHead()}
	tx := &fakeBatchTx{store: store, commitErr: errors.New("commit outcome uncertain")}
	tx.onCommit = func() { store.auditHeadErr = errors.New("database unreachable") }
	ch := make(chan jetstream.Msg, 1)
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), ActorID: uuid.Nil.String(), OccurredAt: time.Now(), EventType: audit.EventSessionLoggedOut, Payload: "{}"})
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
