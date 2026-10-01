//go:build integration

package adminaction

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/natsjs"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// REQUIRE_ADMIN_AUDIT_INTEGRATION=1 turns absent DB/NATS configuration into a
// failure. Once configured, unavailable services always fail, never skip.
func integrationPool(t *testing.T) (*pgxpool.Pool, *envelope.Encryptor) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("DATABASE_URL required by mandatory admin audit integration gate")
		}
		t.Skip("DATABASE_URL not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sqldb, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatal(err)
	}
	_ = sqldb.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	key := make([]byte, kms.KEKSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewMockProvider(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	return pool, enc
}

func integrationJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	url := os.Getenv("NATS_URL")
	if url == "" {
		if os.Getenv("REQUIRE_ADMIN_AUDIT_INTEGRATION") == "1" {
			t.Fatal("NATS_URL required by mandatory admin audit integration gate")
		}
		t.Skip("NATS_URL not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, js, err := natsjs.Connect(ctx, url, "admin-action-integration", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return js
}

func integrationStream(t *testing.T, js jetstream.JetStream, subject string) jetstream.Stream {
	t.Helper()
	name := "ADMIN_TEST_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	stream, err := natsjs.EnsureStream(context.Background(), js, natsjs.StreamOptions{Name: name, Subjects: []string{subject}, MaxBytes: 1024 * 1024, Duplicates: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), name) })
	return stream
}

func integrationOperation(t *testing.T, pool *pgxpool.Pool, enc Encryptor, subject string) *Operation {
	t.Helper()
	s, err := New(pool, enc, subject, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	op.Event = testEvent()
	t.Cleanup(func() {
		_ = op.Rollback(context.Background())
		_, _ = pool.Exec(context.Background(), "DELETE FROM admin_action_contexts WHERE action_id=$1", op.ID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM event_outbox WHERE id=$1", op.ID)
	})
	return op
}

func TestAdminActionAtomicityAndPrivacyIntegration(t *testing.T) {
	pool, enc := integrationPool(t)
	ctx := context.Background()
	op := integrationOperation(t, pool, enc, "identity.audit.test."+uuid.NewString())
	absentSubject := uuid.New()
	op.Event.SubjectID = &absentSubject
	op.Event.Security = &audit.SecurityContext{AccountRef: absentSubject}
	op.Event.Payload = map[string]any{"reason": "restricted narrative", "identifier": "private@example.test", "blind_index": strings.Repeat("a", 64), "result_count": 1}
	if err := SetDetails(WithContext(ctx, op), map[string]string{"reason": "restricted narrative"}); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var payload string
	var cipher []byte
	var storedSubject uuid.UUID
	if err := pool.QueryRow(ctx, "SELECT o.payload,c.details_encrypted,c.account_ref FROM event_outbox o JOIN admin_action_contexts c ON c.action_id=o.id WHERE o.id=$1", op.ID).Scan(&payload, &cipher, &storedSubject); err != nil {
		t.Fatal(err)
	}
	if storedSubject != absentSubject {
		t.Fatal("absent account reference not retained")
	}
	for _, forbidden := range []string{"restricted narrative", "private@example.test", "blind_index", absentSubject.String()} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("forbidden data escaped into envelope: %s", forbidden)
		}
	}
	if bytes.Contains(cipher, []byte("restricted narrative")) {
		t.Fatal("narrative persisted in plaintext")
	}
	plain, err := enc.Decrypt(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(op.ID.String())) || !bytes.Contains(plain, []byte("restricted narrative")) {
		t.Fatal("encrypted binding/content missing")
	}
	var env audit.Envelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatal(err)
	}
	if env.EventID != op.ID || env.Security != nil || env.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatal("envelope invariants violated")
	}

	// Force outbox insertion failure after an actual business INSERT and encrypted
	// context INSERT. All business/context state must disappear on rollback.
	failed := integrationOperation(t, pool, enc, "identity.audit.test."+uuid.NewString())
	if _, err := pool.Exec(ctx, "INSERT INTO event_outbox(id,subject,payload) VALUES($1,'fixture','{}')", failed.ID); err != nil {
		t.Fatal(err)
	}
	user, err := failed.Queries.CreateUser(ctx, db.CreateUserParams{Email: "rollback-" + uuid.NewString() + "@example.test", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetDetails(WithContext(ctx, failed), map[string]string{"reason": "must roll back"}); err != nil {
		t.Fatal(err)
	}
	if err := failed.Commit(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outbox failure did not fail closed: %v", err)
	}
	var userCount, contextCount int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM users WHERE id=$1),(SELECT count(*) FROM admin_action_contexts WHERE action_id=$2)", user.ID, failed.ID).Scan(&userCount, &contextCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 0 || contextCount != 0 {
		t.Fatal("business/context change escaped failed audit transaction")
	}
}

type failDeliveryBeginner struct{ pool *pgxpool.Pool }

func (b failDeliveryBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &failDeliveryTx{Tx: tx}, nil
}

type failDeliveryTx struct{ pgx.Tx }

func (tx *failDeliveryTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "MarkAdminActionPublished") {
		return pgconn.CommandTag{}, errors.New("simulated crash after broker acknowledgement")
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func TestAdminActionJetStreamCrashDedupAndSubjectScopeIntegration(t *testing.T) {
	pool, enc := integrationPool(t)
	js := integrationJetStream(t)
	subject := "identity.audit.test." + uuid.NewString()
	stream := integrationStream(t, js, subject)
	op := integrationOperation(t, pool, enc, subject)
	if err := op.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Even an unrelated deletion-shaped event on the same subject is ineligible.
	deletionID := uuid.New()
	if _, err := pool.Exec(context.Background(), "INSERT INTO event_outbox(id,subject,payload) VALUES($1,$2,'{\"user_id\":\"deleted-subject\"}')", deletionID, subject); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM event_outbox WHERE id=$1", deletionID) })
	other := integrationOperation(t, pool, enc, subject+".other")
	if err := other.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	crashing, err := NewPublisher(failDeliveryBeginner{pool}, js, subject, PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := crashing.RunOnce(context.Background()); n != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("crash seam: n=%d err=%v", n, err)
	}
	var published bool
	if err := pool.QueryRow(context.Background(), "SELECT published_at IS NOT NULL FROM event_outbox WHERE id=$1", op.ID).Scan(&published); err != nil || published {
		t.Fatalf("crashed delivery marked published: %v", err)
	}
	worker, err := NewPublisher(pool, js, subject, PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("restart did not recover: n=%d err=%v", n, err)
	}
	info, err := stream.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("JetStream did not deduplicate stable ID: msgs=%d", info.State.Msgs)
	}
	message, err := stream.GetMsg(context.Background(), info.State.FirstSeq)
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Get("Nats-Msg-Id") != op.ID.String() {
		t.Fatal("stable Nats-Msg-Id missing")
	}
	var untouched int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM event_outbox WHERE id=ANY($1::uuid[]) AND published_at IS NULL", []uuid.UUID{deletionID, other.ID}).Scan(&untouched); err != nil {
		t.Fatal(err)
	}
	if untouched != 2 {
		t.Fatal("publisher touched unmarked/wrong-subject event")
	}
	backlog, err := worker.Backlog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if backlog.Pending != 0 {
		t.Fatalf("delivered outbox still pending: %#v", backlog)
	}
}

type blockedPublisher struct {
	inner   JetStreamPublisher
	entered chan struct{}
	release chan struct{}
}

func (p *blockedPublisher) Publish(ctx context.Context, subject string, data []byte, options ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	close(p.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.release:
	}
	return p.inner.Publish(ctx, subject, data, options...)
}

func TestAdminActionConcurrentClaimsAndRetryIntegration(t *testing.T) {
	pool, enc := integrationPool(t)
	js := integrationJetStream(t)
	subject := "identity.audit.test." + uuid.NewString()
	op := integrationOperation(t, pool, enc, subject)
	if err := op.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	// No stream: a real JetStream publish cannot be acknowledged. The durable row
	// remains with bounded retry metadata instead of being dropped into memory.
	worker, err := NewPublisher(pool, js, subject, PublisherConfig{PublishTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := worker.RunOnce(context.Background()); n != 0 || !errors.Is(err, ErrPublish) {
		t.Fatalf("no-stream publish: n=%d err=%v", n, err)
	}
	var attempts int
	var scheduled bool
	if err := pool.QueryRow(context.Background(), "SELECT attempts,next_attempt_at>created_at FROM event_outbox WHERE id=$1 AND published_at IS NULL", op.ID).Scan(&attempts, &scheduled); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || !scheduled {
		t.Fatal("retry schedule missing")
	}
	integrationStream(t, js, subject)
	if _, err := pool.Exec(context.Background(), "UPDATE event_outbox SET next_attempt_at=CURRENT_TIMESTAMP WHERE id=$1", op.ID); err != nil {
		t.Fatal(err)
	}
	blocked := &blockedPublisher{inner: js, entered: make(chan struct{}), release: make(chan struct{})}
	first, err := NewPublisher(pool, blocked, subject, PublisherConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := first.RunOnce(ctx); result <- err }()
	select {
	case <-blocked.entered:
	case <-ctx.Done():
		t.Fatal("first publisher never claimed")
	}
	if n, err := worker.RunOnce(ctx); n != 0 || err != nil {
		t.Fatalf("second publisher did not skip locked claim: n=%d err=%v", n, err)
	}
	close(blocked.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func expiredContext(t *testing.T, pool *pgxpool.Pool, enc Encryptor, account uuid.UUID) *Operation {
	t.Helper()
	op := integrationOperation(t, pool, enc, "identity.audit.test."+uuid.NewString())
	op.occurredAt = time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Microsecond)
	op.Event.SubjectID = &account
	if err := SetDetails(WithContext(context.Background(), op), map[string]string{"reason": "expired protected narrative"}); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestAdminActionCleanupHoldPrecedenceIntegration(t *testing.T) {
	pool, enc := integrationPool(t)
	ctx := context.Background()
	account := uuid.New()
	op := expiredContext(t, pool, enc, account)
	hold := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO legal_holds(id,account_ref,applied_by,idempotency_key,details_encrypted,review_at) VALUES($1,$2,$3,$4,$5,NOW()-INTERVAL '1 day')", hold, account, uuid.New(), uuid.New(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM legal_holds WHERE id=$1", hold) })
	if n, err := CleanupExpired(ctx, pool, 500); err != nil || n != 0 {
		t.Fatalf("active hold ignored past advisory review date: n=%d err=%v", n, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE legal_holds SET is_active=FALSE,released_at=NOW(),details_encrypted=NULL,details_purged_at=NOW() WHERE id=$1", hold); err != nil {
		t.Fatal(err)
	}
	if n, err := CleanupExpired(ctx, pool, 500); err != nil || n != 1 {
		t.Fatalf("released context not removed on original clock: n=%d err=%v", n, err)
	}
	var tombstones, outbox int
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM legal_holds WHERE id=$1),(SELECT count(*) FROM event_outbox WHERE id=$2)", hold, op.ID).Scan(&tombstones, &outbox); err != nil {
		t.Fatal(err)
	}
	if tombstones != 1 || outbox != 1 {
		t.Fatal("cleanup removed opaque tombstone or audit intent")
	}
}

type cleanupBarrier struct {
	pool     *pgxpool.Pool
	calls    int
	selected chan struct{}
	resume   chan struct{}
}

func (b *cleanupBarrier) Begin(ctx context.Context) (pgx.Tx, error) {
	b.calls++
	if b.calls == 2 {
		close(b.selected)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-b.resume:
		}
	}
	return b.pool.Begin(ctx)
}

func TestAdminActionCleanupRechecksHoldAfterSharedLockIntegration(t *testing.T) {
	pool, enc := integrationPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	account := uuid.New()
	op := expiredContext(t, pool, enc, account)
	barrier := &cleanupBarrier{pool: pool, selected: make(chan struct{}), resume: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		n, err := CleanupExpired(ctx, barrier, 500)
		if err == nil && n != 0 {
			err = errors.New("racing hold failed to protect context")
		}
		result <- err
	}()
	select {
	case <-barrier.selected:
	case <-ctx.Done():
		t.Fatal("cleanup did not select candidate")
	}
	holdTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(ctx, holdTx)
	if err := pglock.LockAccount(ctx, holdTx, account); err != nil {
		t.Fatal(err)
	}
	hold := uuid.New()
	if _, err := holdTx.Exec(ctx, "INSERT INTO legal_holds(id,account_ref,applied_by,reason,requesting_authority,legal_basis) VALUES($1,$2,$3,'fixture','fixture','fixture')", hold, account, uuid.New()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM legal_holds WHERE id=$1", hold) })
	close(barrier.resume)
	if err := holdTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	var survives bool
	if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM admin_action_contexts WHERE action_id=$1)", op.ID).Scan(&survives); err != nil || !survives {
		t.Fatalf("context lost to hold/cleanup race: %v", err)
	}
}
