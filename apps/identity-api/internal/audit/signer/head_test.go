package signer

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/ledgerproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func newHeadTestSigner(t *testing.T, store *fakeStore, tx *fakeBatchTx) *Signer {
	t.Helper()
	s, err := New(Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 365 * 24 * time.Hour}, store,
		&fakeBatchTxOpener{tx: tx}, &fakeFetcher{}, WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerHeadFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		head db.GetSignerLedgerHeadRow
		err  error
	}{
		{"missing", genesisLedgerHead(), pgx.ErrNoRows},
		{"malformed", db.GetSignerLedgerHeadRow{Seq: 10, ChainHash: "bad", StateValid: true}, nil},
		{"inconsistent terminal", db.GetSignerLedgerHeadRow{Seq: 10, ChainHash: strings.Repeat("a", 64)}, nil},
		{"negative sequence", db.GetSignerLedgerHeadRow{Seq: -1, ChainHash: strings.Repeat("0", 64), StateValid: true}, nil},
		{"false genesis", db.GetSignerLedgerHeadRow{Seq: 0, ChainHash: strings.Repeat("a", 64), StateValid: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{head: tc.head, headErr: tc.err, latestAuditErr: pgx.ErrNoRows}
			tx := &fakeBatchTx{store: store}
			s := newHeadTestSigner(t, store, tx)
			if err := s.seedChainTips(context.Background()); !errors.Is(err, ErrLedgerStateInvalid) {
				t.Fatalf("startup accepted bad state: %v", err)
			}
			msg := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
			if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); !errors.Is(err, ErrLedgerStateInvalid) {
				t.Fatalf("batch accepted bad state: %v", err)
			}
			if !tx.rolledBack || tx.committed || !msg.naked || msg.acked || len(store.insertedAuditLogs) != 0 {
				t.Fatal("bad state allowed writes or acknowledgement")
			}
		})
	}
}

func TestSignerStartupValidatesEntireProof(t *testing.T) {
	store := &fakeStore{head: db.GetSignerLedgerHeadRow{Seq: 71, ChainHash: strings.Repeat("b", 64), StateValid: true}, latestAuditErr: pgx.ErrNoRows}
	tx := &fakeBatchTx{store: store, validationErr: ErrLedgerStateInvalid}
	s := newHeadTestSigner(t, store, tx)
	if err := s.seedChainTips(context.Background()); !errors.Is(err, ErrLedgerStateInvalid) {
		t.Fatalf("invalid interior proof accepted: %v", err)
	}
	if !slices.Equal(tx.validatedThrough, []int64{71}) {
		t.Fatalf("validation highwater = %v", tx.validatedThrough)
	}
	tx.validationErr = nil
	if err := s.seedChainTips(context.Background()); err != nil {
		t.Fatal(err)
	}
	want, _ := audit.DecodeChainHash(store.head.ChainHash)
	if s.ledgerTip != want {
		t.Fatal("did not seed the initialized logical head")
	}
}

func TestSignerBatchUsesFreshHeadAndActualTerminalID(t *testing.T) {
	store := &fakeStore{head: db.GetSignerLedgerHeadRow{Seq: 41, ChainHash: strings.Repeat("b", 64), StateValid: true}}
	var order []string
	store.onHeadRead = func() { order = append(order, "head") }
	store.onSubjectLock = func() { order = append(order, "subjects") }
	account, subject := uuid.New(), uuid.New()
	tx := &fakeBatchTx{store: store, onAccounts: func(ids []uuid.UUID) error {
		order = append(order, "accounts")
		if !slices.Contains(ids, account) || !slices.Contains(ids, subject) {
			t.Fatal("account lock set omitted security attribution or subject")
		}
		return nil
	}}
	s := newHeadTestSigner(t, store, tx)
	s.ledgerTip, _ = audit.DecodeChainHash(strings.Repeat("c", 64))
	var msgs []jetstream.Msg
	for range 2 {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), SubjectID: subject.String(),
			OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: account.String()}}))
	}
	msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut}))
	if err := s.processBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []string{"head", "accounts", "subjects"}) {
		t.Fatalf("lock/read ordering = %v", order)
	}
	if len(store.advancedHeads) != 1 || store.advancedHeads[0].ExpectedSeq != 41 || store.advancedHeads[0].TerminalID != store.insertedSecurityEvents[1].ID {
		t.Fatalf("head advance must use old durable seq and actual last ledger UUID: %v", store.advancedHeads)
	}
	row := store.insertedSecurityEvents[0]
	record := audit.LedgerRecord{ID: row.ID.String(), AccountRef: row.AccountRef.String(), IdentityBlindIndex: row.IdentityBlindIndex,
		EventType: row.EventType, ClientIP: row.ClientIp, IPSubnet: row.IpSubnet, UserAgent: row.UserAgent,
		DeviceFingerprint: row.DeviceFingerprint, ClientID: row.ClientID, Scope: row.Scope, Timestamp: row.Timestamp.Time, RetainUntil: row.RetainUntil.Time}
	if _, err := ledgerproof.VerifyRecord(store.head.ChainHash, record, row.ChainHash); err != nil {
		t.Fatalf("batch used stale cached ledger hash: %v", err)
	}
}

func TestSignerAuditOnlyAndPurgedDuplicateDoNotAdvanceHead(t *testing.T) {
	id := uuid.New()
	store := &fakeStore{head: db.GetSignerLedgerHeadRow{Seq: 91, ChainHash: strings.Repeat("b", 64), StateValid: true}, existingAuditIDs: []uuid.UUID{id}}
	tx := &fakeBatchTx{store: store}
	s := newHeadTestSigner(t, store, tx)
	duplicate := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: id, EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}})
	fresh := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
	if err := s.processBatch(context.Background(), []jetstream.Msg{duplicate, fresh}); err != nil {
		t.Fatal(err)
	}
	if len(store.advancedHeads) != 0 || len(store.insertedSecurityEvents) != 0 || len(store.insertedAuditLogs) != 1 || !duplicate.acked || !fresh.acked {
		t.Fatal("audit-only/retained Class C duplicate changed ledger state")
	}
}

func TestSignerHeadAdvanceFailureRollsBackBeforeAck(t *testing.T) {
	store := &fakeStore{head: genesisLedgerHead(), advanceErr: errors.New("terminal sequence reset")}
	tx := &fakeBatchTx{store: store}
	s := newHeadTestSigner(t, store, tx)
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil {
		t.Fatal("head advancement failure accepted")
	}
	if tx.committed || !tx.rolledBack || msg.acked || !msg.naked || s.auditTip != audit.GenesisChainHash || s.ledgerTip != audit.GenesisChainHash {
		t.Fatal("failed atomic advance changed tips or acknowledged the message")
	}
}

func TestSignerUncertainCommitReseedsDurableHead(t *testing.T) {
	store := &fakeStore{head: genesisLedgerHead(), latestAuditErr: pgx.ErrNoRows}
	tx := &fakeBatchTx{store: store, commitErr: errors.New("commit outcome unknown")}
	tx.onCommit = func() {
		store.head = db.GetSignerLedgerHeadRow{Seq: 107, ChainHash: strings.Repeat("d", 64), StateValid: true}
	}
	s := newHeadTestSigner(t, store, tx)
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: 1, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil || errors.Is(err, ErrChainTipsUnknown) {
		t.Fatalf("expected recoverable commit failure after successful reseed, got %v", err)
	}
	want, _ := audit.DecodeChainHash(store.head.ChainHash)
	if s.tipsUnknown || s.ledgerTip != want || !slices.Equal(tx.validatedThrough, []int64{107}) || !msg.naked || msg.acked {
		t.Fatal("uncertain commit did not use validated durable state")
	}
	tx.onCommit = func() { store.headErr = pgx.ErrNoRows }
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); !errors.Is(err, ErrChainTipsUnknown) {
		t.Fatalf("missing recovery head did not stop signer: %v", err)
	}
}
