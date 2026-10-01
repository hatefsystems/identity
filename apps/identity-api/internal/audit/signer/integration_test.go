//go:build integration

package signer_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/blindindex"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

func TestAuditSignerEndToEndIntegration(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL is required")
		}
		t.Skip("DATABASE_URL is not set; skipping integration test")
	}
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("NATS_URL is required")
		}
		natsURL = "nats://127.0.0.1:4222"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ensure DB migrations are applied.
	sqldb, err := migrate.Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("migrate.Open: %v", err)
	}
	defer sqldb.Close()
	if err := migrate.Up(ctx, sqldb); err != nil {
		t.Fatalf("migrate.Up: %v", err)
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	// Connect to NATS.
	nc, js, err := natsjs.Connect(ctx, natsURL, "audit-e2e-test", nil)
	if err != nil {
		if os.Getenv("NATS_URL") != "" || os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatalf("required NATS unavailable: %v", err)
		}
		t.Skipf("cannot connect to NATS at %s: %v; skipping", natsURL, err)
	}
	defer nc.Close()

	// Unique stream and subject names for isolation.
	uid := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	streamName := fmt.Sprintf("TEST_STREAM_%s", uid)
	subject := fmt.Sprintf("test.audit.%s", uid)
	consumerName := fmt.Sprintf("signer-%s", uid)

	_, err = natsjs.EnsureStream(ctx, js, natsjs.StreamOptions{
		Name:     streamName,
		Subjects: []string{subject},
		MaxBytes: 10 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("EnsureStream: %v", err)
	}
	t.Cleanup(func() {
		_ = js.DeleteStream(context.Background(), streamName)
	})

	consumer, err := natsjs.EnsureConsumer(ctx, js, streamName, natsjs.ConsumerOptions{
		Durable:       consumerName,
		FilterSubject: subject,
		AckWait:       10 * time.Second,
		MaxAckPending: 100,
		MaxDeliver:    5,
	})
	if err != nil {
		t.Fatalf("EnsureConsumer: %v", err)
	}

	// Create a test user in DB for blind index resolution.
	queries := db.New(pool)
	auditAfter, err := queries.GetAuditLogHighWaterSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ledgerAfter, err := queries.GetSecurityEventHighWaterSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	readTip := func(get func(context.Context) (string, error)) [32]byte {
		hash, err := get(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return audit.GenesisChainHash
		}
		if err != nil {
			t.Fatal(err)
		}
		tip, err := audit.DecodeChainHash(hash)
		if err != nil {
			t.Fatal(err)
		}
		return tip
	}
	auditTip := readTip(queries.GetLatestAuditLogChainHash)
	ledgerTip := readTip(queries.GetLatestSecurityEventChainHash)
	// Allocate unused sequence values. Hash linkage, not numeric contiguity,
	// must remain sufficient to verify the new segment.
	if _, err := pool.Exec(ctx, "SELECT nextval(pg_get_serial_sequence('mvp_audit_logs', 'seq')), nextval(pg_get_serial_sequence('security_event_ledger', 'seq'))"); err != nil {
		t.Fatal(err)
	}
	testEmail := fmt.Sprintf("audit-user-%s@test.local", uid)
	testUser, err := queries.CreateUser(ctx, db.CreateUserParams{
		Email:  testEmail,
		Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	pepper := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	indexer, err := blindindex.New(pepper)
	if err != nil {
		t.Fatalf("blindindex.New: %v", err)
	}

	store, err := signer.NewPoolStore(pool)
	if err != nil {
		t.Fatalf("NewPoolStore: %v", err)
	}
	opener, err := signer.NewPgBatchTxOpener(pool)
	if err != nil {
		t.Fatalf("NewPgBatchTxOpener: %v", err)
	}
	locker, err := pglock.NewPgAdvisoryLocker(pool, pglock.AuditSignerKey)
	if err != nil {
		t.Fatalf("NewPgAdvisoryLocker: %v", err)
	}

	cfg := signer.Config{
		BatchSize:       10,
		FlushInterval:   100 * time.Millisecond,
		LedgerRetention: 180*24*time.Hour + 789*time.Nanosecond,
	}

	signingWorker, err := signer.New(cfg, store, opener, consumer,
		signer.WithAdvisoryLocker(locker),
		signer.WithBlindIndexer(indexer),
		signer.WithClock(func() time.Time { return time.Now().Truncate(time.Second).Add(123456789 * time.Nanosecond) }),
	)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}

	// 1. Publish events using JetStreamRecorder.
	recorder, err := audit.NewJetStreamRecorder(js, subject, 10, nil)
	if err != nil {
		t.Fatalf("NewJetStreamRecorder: %v", err)
	}

	event1ID := uuid.New()
	event1 := audit.Event{
		EventType:     audit.EventSessionLoggedOut,
		ActionStatus:  audit.StatusSuccess,
		ActorID:       testUser.ID,
		ActorSPIFFEID: audit.APIActorSPIFFEID,
		ClientIP:      "192.0.2.55",
		UserAgent:     "Go-Test-Agent",
		Payload:       map[string]any{"reason": "user_action"},
	}

	event2ID := uuid.New()
	event2 := audit.Event{
		EventType:     audit.EventLoginSucceeded,
		ActionStatus:  audit.StatusSuccess,
		ActorID:       testUser.ID,
		ActorSPIFFEID: audit.APIActorSPIFFEID,
		SubjectID:     &testUser.ID,
		ClientIP:      "192.0.2.55",
		UserAgent:     "Go-Test-Agent",
		Payload:       map[string]any{"method": "webauthn"},
		Security: &audit.SecurityContext{
			AccountRef:        testUser.ID,
			ClientID:          "test-client-e2e",
			Scope:             "openid profile",
			DeviceFingerprint: "device-xyz",
		},
	}

	// Helper recorder that assigns predictable IDs
	rec1, err := audit.NewJetStreamRecorder(js, subject, 10, nil,
		audit.WithRecorderIDs(func() uuid.UUID { return event1ID }),
		audit.WithRecorderClock(func() time.Time { return time.Now().Truncate(time.Second).Add(987654321 * time.Nanosecond) }),
	)
	if err != nil {
		t.Fatalf("rec1: %v", err)
	}
	if err := rec1.Record(ctx, event1); err != nil {
		t.Fatalf("rec1.Record: %v", err)
	}
	if err := rec1.Close(ctx); err != nil {
		t.Fatalf("rec1.Close: %v", err)
	}

	rec2, err := audit.NewJetStreamRecorder(js, subject, 10, nil,
		audit.WithRecorderIDs(func() uuid.UUID { return event2ID }),
		audit.WithRecorderClock(func() time.Time { return time.Now().Truncate(time.Second).Add(123456789 * time.Nanosecond) }),
	)
	if err != nil {
		t.Fatalf("rec2: %v", err)
	}
	capturingRecorder, err := audit.NewIndexingRecorder(rec2, queries, indexer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := capturingRecorder.Record(ctx, event2); err != nil {
		t.Fatalf("rec2.Record: %v", err)
	}
	if err := rec2.Close(ctx); err != nil {
		t.Fatalf("rec2.Close: %v", err)
	}
	// Simulate the producer/signing race: identity and its FK disappear after
	// publish but before the signer resolves the event.
	if _, err := pool.Exec(ctx, "DELETE FROM users WHERE id=$1", testUser.ID); err != nil {
		t.Fatal(err)
	}
	event3ID := uuid.New()
	index := indexer.Compute(testEmail)
	injected := audit.Envelope{SchemaVersion: 1, EventID: event3ID, ActorID: uuid.Nil.String(), SubjectID: testUser.ID.String(), OccurredAt: time.Now().Truncate(time.Second).Add(456789123 * time.Nanosecond), EventType: audit.EventLegalHoldApplied, Payload: "{}", Security: &audit.EnvelopeSecurity{AccountRef: testUser.ID.String(), IdentityBlindIndex: &index}}
	raw, err := json.Marshal(injected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, subject, raw, jetstream.WithMsgID(event3ID.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, subject, []byte("malformed envelope")); err != nil {
		t.Fatal(err)
	}

	// Clean up recorder
	_ = recorder.Close(ctx)

	// Run signing worker in background and cancel context after processing.
	workerCtx, cancelWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- signingWorker.RunUntilDone(workerCtx)
	}()

	// Wait until the events are processed and written to the database.
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		existing, filterErr := store.FilterExistingAuditLogIDs(ctx, []uuid.UUID{event1ID, event2ID, event3ID})
		if filterErr == nil && len(existing) == 3 {
			break
		}
	}

	// Stop the worker cleanly.
	cancelWorker()
	if err := <-workerDone; err != nil {
		t.Fatalf("signing worker error: %v", err)
	}

	// Verify records in mvp_audit_logs.
	existingAudit, err := store.FilterExistingAuditLogIDs(ctx, []uuid.UUID{event1ID, event2ID, event3ID})
	if err != nil {
		t.Fatalf("FilterExistingAuditLogIDs: %v", err)
	}
	if len(existingAudit) != 3 {
		t.Fatalf("expected 3 published audit records persisted, got %d", len(existingAudit))
	}

	// Verify records in security_event_ledger.
	// Only event2 is a ledger event.
	existingLedger, err := store.FilterExistingSecurityEventIDs(ctx, []uuid.UUID{event1ID, event2ID, event3ID})
	if err != nil {
		t.Fatalf("FilterExistingSecurityEventIDs: %v", err)
	}
	if len(existingLedger) != 1 {
		t.Fatalf("expected 1 security event persisted, got %d", len(existingLedger))
	}
	if existingLedger[0] != event2ID {
		t.Fatal("injected Class C context produced ledger row")
	}

	auditThrough, err := queries.GetAuditLogHighWaterSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	persistedAudit, err := queries.ListAuditLogsForChainVerification(ctx, db.ListAuditLogsForChainVerificationParams{AfterSeq: auditAfter, ThroughSeq: auditThrough, PageLimit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(persistedAudit) != 4 {
		t.Fatalf("got %d audit rows, want three events and quarantine", len(persistedAudit))
	}
	for _, row := range persistedAudit {
		record := audit.AuditRecord{ID: row.ID.String(), ActorID: row.ActorID.String(), ActorSPIFFEID: row.ActorSpiffeID, EventType: row.EventType, ActionStatus: row.ActionStatus, ClientIP: row.ClientIp, UserAgent: row.UserAgent, Payload: row.Payload, Timestamp: row.Timestamp.Time}
		if got := audit.ChainHash(auditTip, audit.SerializeAudit(record)); got != row.ChainHash {
			t.Fatalf("persisted audit seq %d mismatch: got %s stored %s", row.Seq, got, row.ChainHash)
		}
		auditTip, _ = audit.DecodeChainHash(row.ChainHash)
		if row.UserID.Valid {
			t.Fatal("late subject attached a missing FK")
		}
		if strings.Contains(row.Payload, testEmail) || strings.Contains(row.Payload, index) {
			t.Fatal("raw identity/index leaked to Class C payload")
		}
	}
	if persistedAudit[0].Seq <= auditAfter+1 {
		t.Fatal("sequence-hole fixture was not exercised")
	}
	ledgerThrough, err := queries.GetSecurityEventHighWaterSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	persistedLedger, err := queries.ListSecurityEventsForChainVerification(ctx, db.ListSecurityEventsForChainVerificationParams{AfterSeq: ledgerAfter, ThroughSeq: ledgerThrough, PageLimit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range persistedLedger {
		record := audit.LedgerRecord{ID: row.ID.String(), AccountRef: row.AccountRef.String(), IdentityBlindIndex: row.IdentityBlindIndex, EventType: row.EventType, ClientIP: row.ClientIp, IPSubnet: row.IpSubnet, UserAgent: row.UserAgent, DeviceFingerprint: row.DeviceFingerprint, ClientID: row.ClientID, Scope: row.Scope, Timestamp: row.Timestamp.Time, RetainUntil: row.RetainUntil.Time}
		if got := audit.ChainHash(ledgerTip, audit.SerializeLedger(record)); got != row.ChainHash {
			t.Fatalf("persisted ledger seq %d mismatch: got %s stored %s", row.Seq, got, row.ChainHash)
		}
		ledgerTip, _ = audit.DecodeChainHash(row.ChainHash)
	}

	// Verify blind index attribution lookup.
	expectedBlindIndex := indexer.Compute(testEmail)
	ledgerRows, err := queries.FindSecurityEventsByBlindIndex(ctx, db.FindSecurityEventsByBlindIndexParams{
		IdentityBlindIndex: &expectedBlindIndex,
		PageLimit:          10,
		PageOffset:         0,
	})
	if err != nil {
		t.Fatalf("FindSecurityEventsByBlindIndex: %v", err)
	}
	if len(ledgerRows) == 0 {
		t.Fatal("expected to find security event by blind index")
	}

	row := ledgerRows[0]
	if row.AccountRef != testUser.ID {
		t.Errorf("ledger row AccountRef = %v, want %v", row.AccountRef, testUser.ID)
	}
	if row.EventType != audit.EventLoginSucceeded {
		t.Errorf("ledger row EventType = %q, want %q", row.EventType, audit.EventLoginSucceeded)
	}
	if row.ClientID == nil || *row.ClientID != "test-client-e2e" {
		t.Errorf("ledger row ClientID = %v, want test-client-e2e", row.ClientID)
	}
	if row.Scope == nil || *row.Scope != "openid profile" {
		t.Errorf("ledger row Scope = %v, want 'openid profile'", row.Scope)
	}
	if row.DeviceFingerprint == nil || *row.DeviceFingerprint != "device-xyz" {
		t.Errorf("ledger row DeviceFingerprint = %v, want 'device-xyz'", row.DeviceFingerprint)
	}
	if len(row.ChainHash) != audit.ChainHashHexLen {
		t.Errorf("ledger row ChainHash length = %d, want %d", len(row.ChainHash), audit.ChainHashHexLen)
	}

	// Verify retain_until is ~180 days in future relative to timestamp.
	expectedRetain := row.Timestamp.Time.Add(cfg.LedgerRetention)
	diff := row.RetainUntil.Time.Sub(expectedRetain)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ledger retain_until %v differs from expected %v by %v", row.RetainUntil.Time, expectedRetain, diff)
	}
}
