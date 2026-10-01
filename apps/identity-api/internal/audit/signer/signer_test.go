package signer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type fakeAdvisoryLocker struct {
	acquired bool
	released bool
	err      error
}

func (l *fakeAdvisoryLocker) TryLock(_ context.Context) (bool, func(), error) {
	if l.err != nil {
		return false, nil, l.err
	}
	if !l.acquired {
		return false, nil, nil
	}
	return true, func() { l.released = true }, nil
}

type fakeStore struct {
	mu                     sync.Mutex
	latestAuditHash        string
	latestAuditErr         error
	latestLedgerHash       string
	latestLedgerErr        error
	existingAuditIDs       []uuid.UUID
	existingLedgerIDs      []uuid.UUID
	userEmails             map[uuid.UUID]string
	userEmailErrs          map[uuid.UUID]error
	subjectLockErr         error
	insertedAuditLogs      []db.InsertAuditLogsParams
	insertedSecurityEvents []db.InsertSecurityEventsParams
}

func (s *fakeStore) GetLatestAuditLogChainHash(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latestAuditErr != nil {
		return "", s.latestAuditErr
	}
	return s.latestAuditHash, nil
}

func (s *fakeStore) GetLatestSecurityEventChainHash(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.latestLedgerErr != nil {
		return "", s.latestLedgerErr
	}
	return s.latestLedgerHash, nil
}

func (s *fakeStore) FilterExistingAuditLogIDs(_ context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existingSet := make(map[uuid.UUID]struct{}, len(s.existingAuditIDs))
	for _, id := range s.existingAuditIDs {
		existingSet[id] = struct{}{}
	}
	var res []uuid.UUID
	for _, id := range ids {
		if _, ok := existingSet[id]; ok {
			res = append(res, id)
		}
	}
	return res, nil
}

func (s *fakeStore) FilterExistingSecurityEventIDs(_ context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existingSet := make(map[uuid.UUID]struct{}, len(s.existingLedgerIDs))
	for _, id := range s.existingLedgerIDs {
		existingSet[id] = struct{}{}
	}
	var res []uuid.UUID
	for _, id := range ids {
		if _, ok := existingSet[id]; ok {
			res = append(res, id)
		}
	}
	return res, nil
}

func (s *fakeStore) GetUserEmailForBlindIndex(_ context.Context, id uuid.UUID) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.userEmailErrs[id]; ok {
		return "", err
	}
	if email, ok := s.userEmails[id]; ok {
		return email, nil
	}
	return "", pgx.ErrNoRows
}

func (s *fakeStore) LockAuditSubjects(_ context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	if s.subjectLockErr != nil {
		return nil, s.subjectLockErr
	}
	var live []uuid.UUID
	for _, id := range ids {
		if _, ok := s.userEmails[id]; ok {
			live = append(live, id)
		}
	}
	return live, nil
}

func (s *fakeStore) InsertAuditLogs(_ context.Context, arg []db.InsertAuditLogsParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertedAuditLogs = append(s.insertedAuditLogs, arg...)
	return int64(len(arg)), nil
}

func (s *fakeStore) InsertSecurityEvents(_ context.Context, arg []db.InsertSecurityEventsParams) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertedSecurityEvents = append(s.insertedSecurityEvents, arg...)
	return int64(len(arg)), nil
}

type fakeBatchTx struct {
	store      *fakeStore
	committed  bool
	rolledBack bool
	commitErr  error
	onCommit   func()
}

func (t *fakeBatchTx) Store() Store { return t.store }

func (t *fakeBatchTx) Commit(_ context.Context) error {
	if t.onCommit != nil {
		t.onCommit()
	}
	if t.commitErr != nil {
		return t.commitErr
	}
	t.committed = true
	return nil
}

func (t *fakeBatchTx) Rollback(_ context.Context) error {
	t.rolledBack = true
	return nil
}

type fakeBatchTxOpener struct {
	tx  *fakeBatchTx
	err error
}

func (o *fakeBatchTxOpener) BeginBatch(_ context.Context) (BatchTx, error) {
	if o.err != nil {
		return nil, o.err
	}
	return o.tx, nil
}

type fakeMsg struct {
	jetstream.Msg
	data       []byte
	metadata   *jetstream.MsgMetadata
	acked      bool
	naked      bool
	nakDelay   time.Duration
	termed     bool
	termReason string
}

func (m *fakeMsg) Data() []byte { return m.data }

func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	if m.metadata != nil {
		return m.metadata, nil
	}
	return nil, errors.New("no metadata")
}

func (m *fakeMsg) Ack() error {
	m.acked = true
	return nil
}

func (m *fakeMsg) NakWithDelay(d time.Duration) error {
	m.naked = true
	m.nakDelay = d
	return nil
}

func (m *fakeMsg) TermWithReason(reason string) error {
	m.termed = true
	m.termReason = reason
	return nil
}

type fakeMessageBatch struct {
	msgs <-chan jetstream.Msg
	err  error
}

func (b *fakeMessageBatch) Messages() <-chan jetstream.Msg { return b.msgs }
func (b *fakeMessageBatch) Error() error                   { return b.err }

type fakeFetcher struct {
	batches []jetstream.MessageBatch
	err     error
	calls   int
}

func (f *fakeFetcher) Fetch(_ int, _ ...jetstream.FetchOpt) (jetstream.MessageBatch, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if len(f.batches) == 0 {
		ch := make(chan jetstream.Msg)
		close(ch)
		return &fakeMessageBatch{msgs: ch}, nil
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

type fakeBlindIndexer struct {
	pepper string
}

func (b *fakeBlindIndexer) Compute(pii string) string {
	sum := sha256.Sum256([]byte(pii + b.pepper))
	return hex.EncodeToString(sum[:])
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// 1. Validating constructor arguments.
func TestNewSignerValidation(t *testing.T) {
	validCfg := Config{
		BatchSize:       100,
		FlushInterval:   time.Second,
		LedgerRetention: 365 * 24 * time.Hour,
	}
	store := &fakeStore{}
	opener := &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}
	fetcher := &fakeFetcher{}

	if _, err := New(validCfg, nil, opener, fetcher); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := New(validCfg, store, nil, fetcher); err == nil {
		t.Error("expected error for nil opener")
	}
	if _, err := New(validCfg, store, opener, nil); err == nil {
		t.Error("expected error for nil fetcher")
	}

	badCfg := validCfg
	badCfg.BatchSize = 0
	if _, err := New(badCfg, store, opener, fetcher); err == nil {
		t.Error("expected error for zero batch size")
	}

	badCfg = validCfg
	badCfg.FlushInterval = 0
	if _, err := New(badCfg, store, opener, fetcher); err == nil {
		t.Error("expected error for zero flush interval")
	}

	badCfg = validCfg
	badCfg.LedgerRetention = 0
	if _, err := New(badCfg, store, opener, fetcher); err == nil {
		t.Error("expected error for zero ledger retention")
	}

	s, err := New(validCfg, store, opener, fetcher,
		WithLogger(discardLogger()),
		WithClock(time.Now),
		WithBlindIndexer(&fakeBlindIndexer{pepper: "test"}),
		WithAdvisoryLocker(&fakeAdvisoryLocker{acquired: true}),
	)
	if err != nil {
		t.Fatalf("unexpected New error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil signer")
	}
}

// 2. Signer requires an advisory locker before running.
func TestSignerRequiresAdvisoryLocker(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	store := &fakeStore{}
	opener := &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}
	fetcher := &fakeFetcher{}

	s, err := New(cfg, store, opener, fetcher, WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = s.RunUntilDone(context.Background())
	if err == nil || !strings.Contains(err.Error(), "advisory locker is required") {
		t.Fatalf("expected advisory locker required error, got %v", err)
	}
}

// 3. Signer fails closed when another signer holds the advisory lock.
func TestSignerFailsClosedOnLockContention(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	store := &fakeStore{}
	opener := &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}
	fetcher := &fakeFetcher{}
	locker := &fakeAdvisoryLocker{acquired: false}

	s, err := New(cfg, store, opener, fetcher,
		WithLogger(discardLogger()),
		WithAdvisoryLocker(locker),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = s.RunUntilDone(context.Background())
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("expected ErrLockUnavailable, got %v", err)
	}
}

// 4. Seeding chain tips from genesis when tables are empty.
func TestSignerGenesisChainTips(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	store := &fakeStore{
		latestAuditErr:  pgx.ErrNoRows,
		latestLedgerErr: pgx.ErrNoRows,
	}
	opener := &fakeBatchTxOpener{tx: &fakeBatchTx{store: store}}
	fetcher := &fakeFetcher{}
	locker := &fakeAdvisoryLocker{acquired: true}

	s, err := New(cfg, store, opener, fetcher,
		WithLogger(discardLogger()),
		WithAdvisoryLocker(locker),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.seedChainTips(context.Background()); err != nil {
		t.Fatalf("seedChainTips: %v", err)
	}

	if s.auditTip != audit.GenesisChainHash {
		t.Errorf("auditTip = %x, want genesis %x", s.auditTip, audit.GenesisChainHash)
	}
	if s.ledgerTip != audit.GenesisChainHash {
		t.Errorf("ledgerTip = %x, want genesis %x", s.ledgerTip, audit.GenesisChainHash)
	}
}

// 5. Complete batch processing: decoding, chaining, batch COPY, blind index, retention, and acking.
func TestSignerProcessBatchChainingAndPersistence(t *testing.T) {
	fixedTime := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		BatchSize:       10,
		FlushInterval:   time.Second,
		LedgerRetention: 180 * 24 * time.Hour, // ~6 months
	}

	accountRef := uuid.MustParse("22222222-3333-4444-5555-666666666666")
	userEmail := "alice@example.test"

	store := &fakeStore{
		latestAuditErr:  pgx.ErrNoRows,
		latestLedgerErr: pgx.ErrNoRows,
		userEmails:      map[uuid.UUID]string{accountRef: userEmail},
	}
	batchTx := &fakeBatchTx{store: store}
	opener := &fakeBatchTxOpener{tx: batchTx}
	locker := &fakeAdvisoryLocker{acquired: true}
	indexer := &fakeBlindIndexer{pepper: "test-pepper"}

	s, err := New(cfg, store, opener, &fakeFetcher{},
		WithLogger(discardLogger()),
		WithClock(func() time.Time { return fixedTime }),
		WithAdvisoryLocker(locker),
		WithBlindIndexer(indexer),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.seedChainTips(context.Background()); err != nil {
		t.Fatalf("seedChainTips: %v", err)
	}

	// Prepare 3 messages:
	// Msg 1: Audit-only event (e.g. session logged out)
	env1 := audit.Envelope{
		EventID:       uuid.MustParse("11111111-0000-0000-0000-000000000001"),
		SchemaVersion: audit.EnvelopeSchemaVersion,
		OccurredAt:    fixedTime,
		EventType:     audit.EventSessionLoggedOut,
		ActionStatus:  audit.StatusSuccess,
		ActorID:       accountRef.String(),
		ActorSPIFFEID: audit.APIActorSPIFFEID,
		Payload:       "{}",
	}
	data1, _ := json.Marshal(env1)
	m1 := &fakeMsg{data: data1}

	// Msg 2: Security event (LoginSucceeded) with SecurityContext
	env2 := audit.Envelope{
		EventID:       uuid.MustParse("11111111-0000-0000-0000-000000000002"),
		SchemaVersion: audit.EnvelopeSchemaVersion,
		OccurredAt:    fixedTime,
		EventType:     audit.EventLoginSucceeded,
		ActionStatus:  audit.StatusSuccess,
		ActorID:       accountRef.String(),
		ActorSPIFFEID: audit.APIActorSPIFFEID,
		SubjectID:     accountRef.String(),
		ClientIP:      "203.0.113.10",
		UserAgent:     "TestBrowser",
		Payload:       `{"method":"passkey"}`,
		Security: &audit.EnvelopeSecurity{
			AccountRef:        accountRef.String(),
			ClientID:          "portal",
			Scope:             "openid",
			DeviceFingerprint: "fp-123",
		},
	}
	data2, _ := json.Marshal(env2)
	m2 := &fakeMsg{data: data2}

	// Msg 3: Undecodable message (malformed JSON)
	m3 := &fakeMsg{
		data: []byte("invalid json"),
		metadata: &jetstream.MsgMetadata{
			Stream: "IDENTITY_AUDIT",
			Sequence: jetstream.SequencePair{
				Stream: 42,
			},
		},
	}

	msgs := []jetstream.Msg{m1, m2, m3}

	err = s.processBatch(context.Background(), msgs)
	if err != nil {
		t.Fatalf("processBatch: %v", err)
	}

	// Verify transaction commit.
	if !batchTx.committed {
		t.Fatal("expected batchTx to be committed")
	}

	// Verify settlement:
	// m1 and m2 should be Acked.
	if !m1.acked {
		t.Error("m1 was not acked")
	}
	if !m2.acked {
		t.Error("m2 was not acked")
	}
	// m3 was undecodable: it should be Termed with reason, NOT Acked.
	if m3.acked {
		t.Error("m3 was acked, want Term")
	}
	if !m3.termed {
		t.Error("m3 was not termed")
	}
	if !strings.Contains(m3.termReason, "undecodable audit envelope") {
		t.Errorf("m3 termReason = %q, want quarantine reason", m3.termReason)
	}

	// Verify audit logs written:
	// Order: Quarantine records are chained FIRST, then decoded records (m1, then m2).
	// Total 3 audit rows: 1 quarantine + 2 normal.
	if len(store.insertedAuditLogs) != 3 {
		t.Fatalf("insertedAuditLogs count = %d, want 3", len(store.insertedAuditLogs))
	}

	// Row 0: Quarantine record for m3
	qRow := store.insertedAuditLogs[0]
	if qRow.EventType != audit.EventPipelineUndecodable {
		t.Errorf("row 0 EventType = %q, want %q", qRow.EventType, audit.EventPipelineUndecodable)
	}
	if qRow.ActorSpiffeID != audit.SignerActorSPIFFEID {
		t.Errorf("row 0 ActorSpiffeID = %q, want %q", qRow.ActorSpiffeID, audit.SignerActorSPIFFEID)
	}

	// Row 1: m1
	if store.insertedAuditLogs[1].EventType != audit.EventSessionLoggedOut {
		t.Errorf("row 1 EventType = %q, want %q", store.insertedAuditLogs[1].EventType, audit.EventSessionLoggedOut)
	}

	// Row 2: m2
	if store.insertedAuditLogs[2].EventType != audit.EventLoginSucceeded {
		t.Errorf("row 2 EventType = %q, want %q", store.insertedAuditLogs[2].EventType, audit.EventLoginSucceeded)
	}

	// Verify cryptographic chaining for audit logs:
	tip := audit.GenesisChainHash
	for i, row := range store.insertedAuditLogs {
		rec := audit.AuditRecord{
			ID:            row.ID.String(),
			ActorID:       row.ActorID.String(),
			ActorSPIFFEID: row.ActorSpiffeID,
			EventType:     row.EventType,
			ActionStatus:  row.ActionStatus,
			ClientIP:      row.ClientIp,
			UserAgent:     row.UserAgent,
			Payload:       row.Payload,
			Timestamp:     row.Timestamp.Time,
		}
		expectedHash := audit.ChainHash(tip, audit.SerializeAudit(rec))
		if row.ChainHash != expectedHash {
			t.Errorf("row %d chain hash = %q, want %q", i, row.ChainHash, expectedHash)
		}
		tip, _ = audit.DecodeChainHash(row.ChainHash)
	}

	// Verify ledger rows written:
	// Only m2 was a ledger event. Total 1 ledger row.
	if len(store.insertedSecurityEvents) != 1 {
		t.Fatalf("insertedSecurityEvents count = %d, want 1", len(store.insertedSecurityEvents))
	}

	lRow := store.insertedSecurityEvents[0]
	if lRow.AccountRef != accountRef {
		t.Errorf("ledger AccountRef = %v, want %v", lRow.AccountRef, accountRef)
	}
	expectedBlindIndex := indexer.Compute(userEmail)
	if lRow.IdentityBlindIndex == nil || *lRow.IdentityBlindIndex != expectedBlindIndex {
		t.Errorf("ledger IdentityBlindIndex = %v, want %q", lRow.IdentityBlindIndex, expectedBlindIndex)
	}
	expectedRetainUntil := fixedTime.Add(cfg.LedgerRetention)
	if !lRow.RetainUntil.Time.Equal(expectedRetainUntil) {
		t.Errorf("ledger RetainUntil = %v, want %v", lRow.RetainUntil.Time, expectedRetainUntil)
	}
	if lRow.ClientID == nil || *lRow.ClientID != "portal" {
		t.Errorf("ledger ClientID = %v, want portal", lRow.ClientID)
	}
	if lRow.DeviceFingerprint == nil || *lRow.DeviceFingerprint != "fp-123" {
		t.Errorf("ledger DeviceFingerprint = %v, want fp-123", lRow.DeviceFingerprint)
	}

	// Verify cryptographic chaining for ledger:
	lRec := audit.LedgerRecord{
		ID:                 lRow.ID.String(),
		AccountRef:         lRow.AccountRef.String(),
		IdentityBlindIndex: lRow.IdentityBlindIndex,
		EventType:          lRow.EventType,
		ClientIP:           lRow.ClientIp,
		IPSubnet:           lRow.IpSubnet,
		UserAgent:          lRow.UserAgent,
		DeviceFingerprint:  lRow.DeviceFingerprint,
		ClientID:           lRow.ClientID,
		Scope:              lRow.Scope,
		Timestamp:          lRow.Timestamp.Time,
		RetainUntil:        lRow.RetainUntil.Time,
	}
	expectedLedgerHash := audit.ChainHash(audit.GenesisChainHash, audit.SerializeLedger(lRec))
	if lRow.ChainHash != expectedLedgerHash {
		t.Errorf("ledger chain hash = %q, want %q", lRow.ChainHash, expectedLedgerHash)
	}
}

// 6. Duplicate filtering suppresses already-persisted events and batch-internal duplicates.
func TestSignerDuplicateFiltering(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	dupID := uuid.MustParse("33333333-0000-0000-0000-000000000001")
	newID := uuid.MustParse("33333333-0000-0000-0000-000000000002")

	store := &fakeStore{
		latestAuditErr:   pgx.ErrNoRows,
		latestLedgerErr:  pgx.ErrNoRows,
		existingAuditIDs: []uuid.UUID{dupID},
	}
	batchTx := &fakeBatchTx{store: store}
	opener := &fakeBatchTxOpener{tx: batchTx}

	s, err := New(cfg, store, opener, &fakeFetcher{},
		WithLogger(discardLogger()),
		WithAdvisoryLocker(&fakeAdvisoryLocker{acquired: true}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.seedChainTips(context.Background())

	envDup := audit.Envelope{
		EventID:       dupID,
		SchemaVersion: audit.EnvelopeSchemaVersion,
		EventType:     audit.EventSessionLoggedOut,
	}
	dataDup, _ := json.Marshal(envDup)

	envNew := audit.Envelope{
		EventID:       newID,
		SchemaVersion: audit.EnvelopeSchemaVersion,
		EventType:     audit.EventSessionLoggedOut,
	}
	dataNew, _ := json.Marshal(envNew)

	// Provide: 1 already stored, 1 new, and another copy of the new one (batch-internal duplicate).
	msgs := []jetstream.Msg{
		&fakeMsg{data: dataDup},
		&fakeMsg{data: dataNew},
		&fakeMsg{data: dataNew},
	}

	if err := s.processBatch(context.Background(), msgs); err != nil {
		t.Fatalf("processBatch: %v", err)
	}

	// Only 1 row should be inserted (newID once).
	if len(store.insertedAuditLogs) != 1 {
		t.Fatalf("insertedAuditLogs len = %d, want 1", len(store.insertedAuditLogs))
	}
	if store.insertedAuditLogs[0].ID != newID {
		t.Errorf("inserted ID = %v, want %v", store.insertedAuditLogs[0].ID, newID)
	}
}

// 7. Commit failure causes rollback, nakAll, and re-seeding of chain tips.
func TestSignerCommitFailureRollsBackAndNaks(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	store := &fakeStore{
		latestAuditHash:  strings.Repeat("a", 64),
		latestLedgerHash: strings.Repeat("b", 64),
	}
	batchTx := &fakeBatchTx{
		store:     store,
		commitErr: errors.New("simulated database failure"),
	}
	opener := &fakeBatchTxOpener{tx: batchTx}

	s, err := New(cfg, store, opener, &fakeFetcher{},
		WithLogger(discardLogger()),
		WithAdvisoryLocker(&fakeAdvisoryLocker{acquired: true}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = s.seedChainTips(context.Background())

	env := audit.Envelope{
		EventID:       uuid.New(),
		SchemaVersion: audit.EnvelopeSchemaVersion,
		EventType:     audit.EventSessionLoggedOut,
	}
	data, _ := json.Marshal(env)
	msg := &fakeMsg{data: data}

	err = s.processBatch(context.Background(), []jetstream.Msg{msg})
	if err == nil {
		t.Fatal("expected processBatch error, got nil")
	}

	// Rollback must have been called.
	if !batchTx.rolledBack {
		t.Error("expected batchTx.Rollback to be called")
	}

	// Message must have been Naked.
	if !msg.naked {
		t.Error("expected msg to be Naked")
	}
	if msg.nakDelay != commitFailureBackoff {
		t.Errorf("nakDelay = %v, want %v", msg.nakDelay, commitFailureBackoff)
	}
}

// 8. Graceful shutdown exits cleanly when context is done.
func TestSignerGracefulShutdown(t *testing.T) {
	cfg := Config{BatchSize: 10, FlushInterval: time.Second, LedgerRetention: 24 * time.Hour}
	store := &fakeStore{
		latestAuditErr:  pgx.ErrNoRows,
		latestLedgerErr: pgx.ErrNoRows,
	}
	batchTx := &fakeBatchTx{store: store}
	opener := &fakeBatchTxOpener{tx: batchTx}
	fetcher := &fakeFetcher{}
	locker := &fakeAdvisoryLocker{acquired: true}

	s, err := New(cfg, store, opener, fetcher,
		WithLogger(discardLogger()),
		WithAdvisoryLocker(locker),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately

	err = s.RunUntilDone(ctx)
	if err != nil {
		t.Errorf("expected clean shutdown nil, got %v", err)
	}
	if !locker.released {
		t.Error("expected advisory lock to be released on shutdown")
	}
}
