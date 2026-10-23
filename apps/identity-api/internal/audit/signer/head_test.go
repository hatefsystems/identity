package signer

import (
	"context"
	"errors"
	"slices"
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
		head db.GetSecurityLedgerHeadRow
		err  error
	}{
		{"missing", genesisLedgerHead(), pgx.ErrNoRows},
		{"malformed", db.GetSecurityLedgerHeadRow{Seq: 10, ChainHash: []byte("bad"), StateValid: true}, nil},
		{"inconsistent terminal", db.GetSecurityLedgerHeadRow{Seq: 10, ChainHash: audit.LedgerGenesis().Bytes()}, nil},
		{"negative sequence", db.GetSecurityLedgerHeadRow{Seq: -1, ChainHash: audit.LedgerGenesis().Bytes(), StateValid: true}, nil},
		// seq 0 must pair with the derived genesis seed. v1 used 32 zero bytes, so a
		// blanked column was indistinguishable from a real genesis.
		{"false genesis", db.GetSecurityLedgerHeadRow{Seq: 0, ChainHash: audit.Genesis().Bytes(), StateValid: true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{head: tc.head, headErr: tc.err}
			tx := &fakeBatchTx{store: store}
			s := newHeadTestSigner(t, store, tx)
			if err := s.seedChainTips(context.Background()); !errors.Is(err, ErrLedgerStateInvalid) {
				t.Fatalf("startup accepted bad state: %v", err)
			}
			msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
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
	store := &fakeStore{head: db.GetSecurityLedgerHeadRow{Seq: 71, ChainHash: fakeDigest(0xbb), StateValid: true}}
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
	want, _ := audit.DecodeDigest(store.head.ChainHash)
	if s.ledgerTip != want {
		t.Fatal("did not seed the initialized logical head")
	}
}

func TestSignerBatchUsesFreshHeadAndActualTerminalID(t *testing.T) {
	store := &fakeStore{head: db.GetSecurityLedgerHeadRow{Seq: 41, ChainHash: fakeDigest(0xbb), StateValid: true}}
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
	// Deliberately poison the cached tip: the batch must re-read the durable head
	// rather than trust it.
	s.ledgerTip, _ = audit.DecodeDigest(fakeDigest(0xcc))
	var msgs []jetstream.Msg
	for range 2 {
		msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), SubjectID: subject.String(),
			OccurredAt: time.Now(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: account.String()}}))
	}
	msgs = append(msgs, integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut}))
	if err := s.processBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []string{"head", "accounts", "subjects"}) {
		t.Fatalf("lock/read ordering = %v", order)
	}
	// The ledger head advance must declare the span it actually wrote, seeded from
	// the durable seq rather than a cached one.
	var ledgerAdvance *db.AdvanceChainHeadParams
	for i := range store.advancedHeads {
		if store.advancedHeads[i].Which == "ledger" {
			ledgerAdvance = &store.advancedHeads[i]
		}
	}
	if ledgerAdvance == nil || ledgerAdvance.ExpectedSeq != 41 {
		t.Fatalf("ledger head advance must use the durable seq: %v", store.advancedHeads)
	}
	last := store.insertedLedgerChain[len(store.insertedLedgerChain)-1]
	if ledgerAdvance.LastSeq != last.Seq || ledgerAdvance.NodeCount != int64(len(store.insertedLedgerChain)) {
		t.Fatalf("advance span does not describe the written nodes: %+v", *ledgerAdvance)
	}

	// The first ledger node must chain off the freshly read durable head, not the
	// poisoned cached tip.
	row := store.insertedSecurityEvents[0]
	node := store.insertedLedgerChain[0]
	record := audit.LedgerRecord{ID: node.EventID.String(), AccountRef: row.AccountRef.String(),
		IdentityBlindIndex: row.IdentityBlindIndex, BlindIndexVersion: row.BlindIndexVersion,
		EventType: row.EventType, ClientIP: row.ClientIp, IPSubnet: row.IpSubnet, UserAgent: row.UserAgent,
		DeviceFingerprint: row.DeviceFingerprint, ClientID: row.ClientID, Scope: row.Scope,
		Timestamp: row.Timestamp.Time, RetainUntil: row.RetainUntil.Time}
	if _, err := ledgerproof.VerifyRecord(record, node.LeafHash); err != nil {
		t.Fatalf("stored leaf does not match the written payload: %v", err)
	}
	durable, _ := audit.DecodeDigest(store.head.ChainHash)
	leafHash, _ := audit.DecodeDigest(node.LeafHash)
	expected := audit.ChainLedger(durable, leafHash)
	if stored, _ := audit.DecodeDigest(node.ChainHash); stored != expected {
		t.Fatal("batch chained off a stale cached ledger tip")
	}
}

// fakeDigest builds a syntactically valid 32-byte digest for head fixtures.
func fakeDigest(b byte) []byte {
	out := make([]byte, audit.DigestSize)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSignerAuditOnlyAndPurgedDuplicateDoNotAdvanceHead(t *testing.T) {
	id := uuid.New()
	store := &fakeStore{head: db.GetSecurityLedgerHeadRow{Seq: 91, ChainHash: fakeDigest(0xbb), StateValid: true}, existingAuditIDs: []uuid.UUID{id}}
	tx := &fakeBatchTx{store: store}
	s := newHeadTestSigner(t, store, tx)
	duplicate := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: id, EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}})
	fresh := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
	if err := s.processBatch(context.Background(), []jetstream.Msg{duplicate, fresh}); err != nil {
		t.Fatal(err)
	}
	// The audit head does advance: one fresh audit-only event was written. What
	// must not happen is any *ledger* state change, because the only Class B event
	// in the batch was a duplicate whose chain node already exists.
	var ledgerAdvances int
	for _, adv := range store.advancedHeads {
		if adv.Which == "ledger" {
			ledgerAdvances++
		}
	}
	if ledgerAdvances != 0 || len(store.insertedLedgerChain) != 0 || len(store.insertedSecurityEvents) != 0 ||
		len(store.insertedAuditLogs) != 1 || !duplicate.acked || !fresh.acked {
		t.Fatalf("audit-only/retained duplicate changed ledger state: ledger advances=%d ledger rows=%d audit rows=%d",
			ledgerAdvances, len(store.insertedSecurityEvents), len(store.insertedAuditLogs))
	}
}

func TestSignerHeadAdvanceFailureRollsBackBeforeAck(t *testing.T) {
	store := &fakeStore{head: genesisLedgerHead(), advanceErr: errors.New("terminal sequence reset")}
	tx := &fakeBatchTx{store: store}
	s := newHeadTestSigner(t, store, tx)
	// Seed first, so "the cached tips did not move" is a meaningful assertion
	// rather than a comparison against the zero value.
	if err := s.seedChainTips(context.Background()); err != nil {
		t.Fatal(err)
	}
	auditBefore, ledgerBefore := s.auditTip, s.ledgerTip

	msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), EventType: audit.EventLoginSucceeded, Security: &audit.EnvelopeSecurity{AccountRef: uuid.NewString()}})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil {
		t.Fatal("head advancement failure accepted")
	}
	if tx.committed || !tx.rolledBack || msg.acked || !msg.naked {
		t.Fatal("failed atomic advance committed or acknowledged the message")
	}
	// The tips are only adopted after a successful commit, so a failed head
	// advance must leave the signer chaining from exactly where it was.
	if s.auditTip != auditBefore || s.ledgerTip != ledgerBefore {
		t.Fatalf("failed atomic advance moved the cached tips: audit %s->%s ledger %s->%s",
			auditBefore.Hex(), s.auditTip.Hex(), ledgerBefore.Hex(), s.ledgerTip.Hex())
	}
}

func TestSignerUncertainCommitReseedsDurableHead(t *testing.T) {
	store := &fakeStore{head: genesisLedgerHead()}
	tx := &fakeBatchTx{store: store, commitErr: errors.New("commit outcome unknown")}
	tx.onCommit = func() {
		store.head = db.GetSecurityLedgerHeadRow{Seq: 107, ChainHash: fakeDigest(0xdd), StateValid: true}
	}
	s := newHeadTestSigner(t, store, tx)
	msg := integrityMessage(t, audit.Envelope{SchemaVersion: audit.EnvelopeSchemaVersion, EventID: uuid.New(), EventType: audit.EventSessionLoggedOut})
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); err == nil || errors.Is(err, ErrChainTipsUnknown) {
		t.Fatalf("expected recoverable commit failure after successful reseed, got %v", err)
	}
	want, _ := audit.DecodeDigest(store.head.ChainHash)
	if s.tipsUnknown || s.ledgerTip != want || !slices.Equal(tx.validatedThrough, []int64{107}) || !msg.naked || msg.acked {
		t.Fatal("uncertain commit did not use validated durable state")
	}
	tx.onCommit = func() { store.headErr = pgx.ErrNoRows }
	if err := s.processBatch(context.Background(), []jetstream.Msg{msg}); !errors.Is(err, ErrChainTipsUnknown) {
		t.Fatalf("missing recovery head did not stop signer: %v", err)
	}
}
