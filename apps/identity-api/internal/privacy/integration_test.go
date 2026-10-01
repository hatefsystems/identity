//go:build integration

// Integration tests for Task 5.1, exercising the GDPR deletion lifecycle against
// real PostgreSQL.
//
// The unit tests run without a Transacter, so every atomicity and schema claim the
// design rests on is unverified there: the FOR UPDATE lock ordering, the FK cascades,
// the ON DELETE SET NULL that preserves audit rows, the widened partial unique
// indexes that reserve identifiers during the grace window, and — most importantly —
// that hard-delete leaves security_event_ledger untouched. Those are properties of
// the schema, not of the Go code, so only a migrated database can confirm them.
//
// They require a reachable PostgreSQL instance addressed by DATABASE_URL (see
// .env.example / docker-compose.dev.yml). The mandatory Nx security-DB target checks
// the variable before invoking this integration-tagged package.
//
// With DATABASE_URL set, run the DB-backed packages serially:
//
//	go test -tags=integration -p 1 ./...
//
// `go test` runs packages in parallel, and internal/migrate, internal/dbintegration,
// internal/recovery and this package all drive goose against the one shared schema,
// so a parallel run has them tearing down each other's tables.
//
// Coverage:
//   - End-to-end soft-delete -> past cutoff -> purge, asserting exactly which rows
//     disappear, which survive with user_id nulled, and that the ledger is unchanged.
//   - Active Legal Hold blocks the purge; releasing it lets the next run through.
//   - Reclaim inside the window restores the account; past the window is refused.
//   - A third party cannot squat a pending_deletion account's email, so the reclaim
//     cannot be starved by a unique violation.
//   - Concurrent reclaim vs purge on one subject: exactly one wins, no partial state.
//   - Schema-drift guard over every FK referencing users(id).
package privacy

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
)

// integrationTimeout bounds the whole lifecycle per test run.
const integrationTimeout = 2 * time.Minute

// testGracePeriod is short enough that a test can place a subject on either side of
// the cutoff by choosing deleted_at, without waiting.
const testGracePeriod = time.Hour

func legalFixtureString(value string) *string { return &value }

// openTestPool applies the embedded migrations and returns a connection pool.
//
// MaxConns is raised because the concurrency test needs several simultaneous
// transactions: with a single connection the racing reclaim and purge would
// serialize at the pool rather than at the users-row lock, and the test would pass
// without ever exercising FOR UPDATE.
func openTestPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Fatal("DATABASE_URL is required for integration-tag privacy tests")
	}

	sqldb, err := migrate.Open(ctx, url)
	if err != nil {
		t.Fatalf("open privacy integration database: %v", err)
	}
	if err := migrate.Up(ctx, sqldb); err != nil {
		_ = sqldb.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	_ = sqldb.Close()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	cfg.MinConns = 2
	if cfg.MaxConns < 8 {
		cfg.MaxConns = 8
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open privacy integration pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping privacy integration database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// integrationEnv bundles the real service, the real purger, and the fakes whose
// recorded calls the assertions read.
type integrationEnv struct {
	pool     *pgxpool.Pool
	queries  *db.Queries
	svc      *Service
	purger   *Purger
	notifier *fakeNotifier
	recorder *fakeRecorder
	sessions *fakeRevoker
	tokens   *fakeRevoker
	passkeys *fakePasskeys
}

// newIntegrationEnv wires the service and purger exactly as cmd/server and
// cmd/purge-worker do: sqlc queries over the pool, transactions opened on the pool
// itself.
func newIntegrationEnv(t *testing.T, pool *pgxpool.Pool) *integrationEnv {
	t.Helper()

	env := &integrationEnv{
		pool:     pool,
		queries:  db.New(pool),
		notifier: &fakeNotifier{},
		recorder: &fakeRecorder{},
		sessions: &fakeRevoker{},
		tokens:   &fakeRevoker{},
		passkeys: &fakePasskeys{},
	}

	svc, err := New(Config{GracePeriod: testGracePeriod}, env.queries, env.notifier, env.recorder,
		WithTransacter(pool),
		WithSessionRevoker(env.sessions),
		WithTokenRevoker(env.tokens),
		WithPasskeyReclaimer(env.passkeys),
		WithLogger(discardLogger()),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	env.svc = svc

	opener, err := NewPgSubjectTxOpener(pool)
	if err != nil {
		t.Fatalf("NewPgSubjectTxOpener: %v", err)
	}
	locker, err := NewPgAdvisoryLocker(pool, PurgeAdvisoryLockKey)
	if err != nil {
		t.Fatalf("NewPgAdvisoryLocker: %v", err)
	}
	purger, err := NewPurger(PurgeConfig{GracePeriod: testGracePeriod, BatchSize: 50},
		env.queries, opener, env.recorder,
		WithAdvisoryLocker(locker),
		WithPurgeLogger(discardLogger()),
	)
	if err != nil {
		t.Fatalf("NewPurger: %v", err)
	}
	env.purger = purger
	return env
}

// createTestUser inserts an active account with a full set of child rows, so a purge
// has something to cascade through, and registers a physical cleanup.
func createTestUser(ctx context.Context, t *testing.T, pool *pgxpool.Pool, email string) db.User {
	t.Helper()

	q := db.New(pool)
	// A previous aborted run may have left this fixture behind. The widened index
	// now also covers pending_deletion rows, so clear by email regardless of state.
	if _, err := pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email); err != nil {
		t.Fatalf("clear fixture %q: %v", email, err)
	}

	user, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Status: "active"})
	if err != nil {
		t.Fatalf("CreateUser %q: %v", email, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID)
	})
	return user
}

// addChildRows gives the subject one row in each ON DELETE CASCADE table plus one
// audit row, so the purge assertions cover the whole blast radius rather than just
// the users row.
func addChildRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) {
	t.Helper()
	q := db.New(pool)

	if _, err := q.CreateWebauthnCredential(ctx, db.CreateWebauthnCredentialParams{
		ID:              append([]byte("cred-"), userID[:]...),
		UserID:          userID,
		PublicKey:       []byte("cose-key"),
		AttestationType: "none",
		Aaguid:          uuid.Nil,
	}); err != nil {
		t.Fatalf("CreateWebauthnCredential: %v", err)
	}

	if _, err := q.CreateRecoveryCodes(ctx, []db.CreateRecoveryCodesParams{
		{UserID: userID, CodeHash: HashReclaimToken("code-" + userID.String())},
	}); err != nil {
		t.Fatalf("CreateRecoveryCodes: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO roles (id, description) VALUES ('purge-test-role', 'fixture')
		 ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := q.AssignRoleToUser(ctx, db.AssignRoleToUserParams{
		UserID: userID, RoleID: "purge-test-role",
	}); err != nil {
		t.Fatalf("AssignRoleToUser: %v", err)
	}

	if _, err := q.CreateMfaTotpEnrollment(ctx, db.CreateMfaTotpEnrollmentParams{
		UserID:          userID,
		SessionID:       uuid.New(),
		Purpose:         "maintenance",
		SecretEncrypted: []byte("enc"),
		ExpiresAt:       pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("CreateMfaTotpEnrollment: %v", err)
	}
}

// insertAuditRow writes one mvp_audit_logs row attributed to userID. The table is
// append-only, so it is never cleaned up; the assertions locate it by id.
func insertAuditRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID) uuid.UUID {
	t.Helper()

	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO mvp_audit_logs (
			user_id, actor_id, actor_spiffe_id, event_type, action_status,
			client_ip, user_agent, payload, chain_hash
		) VALUES ($1, $1, 'test://privacy', 'privacy.test', 'success', '127.0.0.1', 'test', '{}', $2)
		RETURNING id`,
		userID, HashReclaimToken("chain-"+userID.String())).Scan(&id)
	if err != nil {
		t.Fatalf("insert audit row: %v", err)
	}
	return id
}

// insertLedgerRow writes one security_event_ledger row for the subject. It has no FK
// to users by design, so it must survive the purge untouched.
func insertLedgerRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, accountRef uuid.UUID) {
	t.Helper()

	if _, err := db.New(pool).InsertSecurityEvent(ctx, db.InsertSecurityEventParams{
		AccountRef:  accountRef,
		EventType:   "privacy.test",
		RetainUntil: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
		ChainHash:   HashReclaimToken("ledger-" + accountRef.String()),
	}); err != nil {
		t.Fatalf("InsertSecurityEvent: %v", err)
	}
}

// countRows runs a scalar COUNT(*) query.
func countRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

// backdateDeletion moves a soft-deleted subject's deleted_at (and its reclaim
// token's expiry, which is derived from it) into the past, so the purge cutoff is
// crossed without waiting out a real grace period.
func backdateDeletion(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, age time.Duration) {
	t.Helper()

	if _, err := pool.Exec(ctx,
		"UPDATE users SET deleted_at = NOW() - $2::interval WHERE id = $1",
		userID, age.String()); err != nil {
		t.Fatalf("backdate deleted_at: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE deletion_requests SET expires_at = NOW() - $2::interval WHERE user_id = $1",
		userID, (age - testGracePeriod).String()); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}
}

// ---------------------------------------------------------------------------
// End-to-end purge
// ---------------------------------------------------------------------------

// TestIntegrationSoftDeleteThenPurge is the whole-lifecycle assertion, and the only
// place the schema's blast radius is actually verified.
func TestIntegrationSoftDeleteThenPurge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)

	user := createTestUser(ctx, t, pool, "purge-e2e@privacy.test")
	addChildRows(ctx, t, pool, user.ID)
	auditID := insertAuditRow(ctx, t, pool, user.ID)
	insertLedgerRow(ctx, t, pool, user.ID)

	ledgerBefore := countRows(ctx, t, pool, "SELECT COUNT(*) FROM security_event_ledger")
	outboxBefore := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())

	result, err := env.svc.RequestDeletion(ctx, user.ID, "203.0.113.10")
	if err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	if !result.TokenMinted || !result.Notified {
		t.Fatalf("RequestDeletion result = %+v, want a minted and delivered token", result)
	}

	stored, err := env.queries.GetUserByIDForAdmin(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByIDForAdmin: %v", err)
	}
	if stored.Status != "pending_deletion" || !stored.DeletedAt.Valid {
		t.Fatalf("after RequestDeletion: status=%q deleted_at.Valid=%v", stored.Status, stored.DeletedAt.Valid)
	}
	if env.sessions.count() != 1 || env.tokens.count() != 1 {
		t.Errorf("revocations = %d sessions / %d tokens, want 1 each",
			env.sessions.count(), env.tokens.count())
	}
	if got := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM deletion_requests WHERE user_id = $1", user.ID); got != 1 {
		t.Fatalf("deletion_requests = %d, want 1", got)
	}

	// A subject still inside the window must not be purged.
	//
	// The assertion is deliberately about *this* subject rather than the run's
	// aggregate counts: the suites share one schema, so another fixture's expired
	// row may legitimately be purged by the same run.
	if _, err := env.purger.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce inside the window: %v", err)
	}
	if _, err := env.queries.GetUserByIDForAdmin(ctx, user.ID); err != nil {
		t.Fatalf("the subject was purged while still inside the grace window: %v", err)
	}

	backdateDeletion(ctx, t, pool, user.ID, 2*testGracePeriod)

	stats, err := env.purger.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce past the cutoff: %v", err)
	}
	if stats.Purged < 1 {
		t.Fatalf("stats = %+v, want at least one purge", stats)
	}

	// The users row and every ON DELETE CASCADE child must be gone.
	if _, err := env.queries.GetUserByIDForAdmin(ctx, user.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("the users row survived the purge: %v", err)
	}
	for _, tc := range []struct {
		table string
		query string
	}{
		{"webauthn_credentials", "SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = $1"},
		{"recovery_codes", "SELECT COUNT(*) FROM recovery_codes WHERE user_id = $1"},
		{"user_roles", "SELECT COUNT(*) FROM user_roles WHERE user_id = $1"},
		{"mfa_totp_enrollments", "SELECT COUNT(*) FROM mfa_totp_enrollments WHERE user_id = $1"},
		{"deletion_requests", "SELECT COUNT(*) FROM deletion_requests WHERE user_id = $1"},
	} {
		if got := countRows(ctx, t, pool, tc.query, user.ID); got != 0 {
			t.Errorf("%s rows = %d after purge, want 0 (the FK cascade did not fire)", tc.table, got)
		}
	}

	// The audit row survives with user_id nulled, which is what makes the ledger
	// still verifiable after an erasure — and the reason Task 5.2's canonical
	// serialization must exclude user_id.
	var auditUserID *uuid.UUID
	var auditChainHash string
	if err := pool.QueryRow(ctx,
		"SELECT user_id, chain_hash FROM mvp_audit_logs WHERE id = $1", auditID).
		Scan(&auditUserID, &auditChainHash); err != nil {
		t.Fatalf("the audit row did not survive the purge: %v", err)
	}
	if auditUserID != nil {
		t.Errorf("mvp_audit_logs.user_id = %v after purge, want NULL", *auditUserID)
	}
	if auditChainHash == "" {
		t.Error("the audit row's chain_hash was cleared by the purge")
	}

	// The ledger must be byte-for-byte unchanged. This is enforced by the schema
	// (no FK to users), but asserted here rather than assumed, because it is the
	// single control that keeps a post-deletion lawful inquiry answerable.
	if got := countRows(ctx, t, pool, "SELECT COUNT(*) FROM security_event_ledger"); got != ledgerBefore {
		t.Errorf("security_event_ledger count = %d after purge, want %d (unchanged)", got, ledgerBefore)
	}
	if got := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM security_event_ledger WHERE account_ref = $1", user.ID); got != 1 {
		t.Errorf("the subject's ledger row count = %d, want 1", got)
	}

	// Exactly one outbox event, carrying only the user id.
	outboxAfter := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())
	if outboxAfter-outboxBefore != 1 {
		t.Fatalf("outbox rows for the subject = %d, want exactly 1", outboxAfter-outboxBefore)
	}
	var subject string
	var payloadKeys int
	if err := pool.QueryRow(ctx, `
		SELECT subject, (SELECT COUNT(*) FROM jsonb_object_keys(payload::jsonb))
		FROM event_outbox
		WHERE payload::jsonb ->> 'user_id' = $1`, user.ID.String()).Scan(&subject, &payloadKeys); err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	if subject != SubjectDeletedEvent {
		t.Errorf("outbox subject = %q, want %q", subject, SubjectDeletedEvent)
	}
	if payloadKeys != 1 {
		t.Errorf("outbox payload has %d keys, want exactly 1 (user_id only; anything else escapes the erasure)", payloadKeys)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())
	})

	if got := env.recorder.countOf(audit.EventDeletionPurged, audit.StatusSuccess); got < 1 {
		t.Errorf("%s events = %d, want at least 1", audit.EventDeletionPurged, got)
	}
}

// ---------------------------------------------------------------------------
// Legal Hold
// ---------------------------------------------------------------------------

// TestIntegrationLegalHoldBlocksPurge covers both directions of "holds outrank
// retention, but cannot resurrect data": while a hold is active nothing is deleted,
// and once it is released the next run purges normally.
func TestIntegrationLegalHoldBlocksPurge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)

	user := createTestUser(ctx, t, pool, "purge-hold@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	backdateDeletion(ctx, t, pool, user.ID, 2*testGracePeriod)

	hold, err := env.queries.ApplyLegalHold(ctx, db.ApplyLegalHoldParams{
		AccountRef:          user.ID,
		Reason:              legalFixtureString("integration test"),
		RequestingAuthority: legalFixtureString("test-court"),
		LegalBasis:          legalFixtureString("legal obligation"),
		AppliedBy:           uuid.New(),
	})
	if err != nil {
		t.Fatalf("ApplyLegalHold: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM legal_holds WHERE id = $1", hold.ID)
	})

	stats, err := env.purger.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce under hold: %v", err)
	}
	if stats.SkippedLegalHold < 1 {
		t.Errorf("SkippedLegalHold = %d, want at least 1", stats.SkippedLegalHold)
	}
	if _, err := env.queries.GetUserByIDForAdmin(ctx, user.ID); err != nil {
		t.Fatalf("a subject under an active legal hold was purged: %v", err)
	}
	if got := env.recorder.countOf(audit.EventDeletionSkippedLegalHold, audit.StatusSuccess); got < 1 {
		t.Errorf("%s events = %d, want at least 1", audit.EventDeletionSkippedLegalHold, got)
	}
	if got := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String()); got != 0 {
		t.Errorf("a held subject enqueued %d outbox rows, want 0", got)
	}

	if _, err := env.queries.ReleaseLegalHold(ctx, db.ReleaseLegalHoldParams{
		ID:         hold.ID,
		ReleasedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true},
	}); err != nil {
		t.Fatalf("ReleaseLegalHold: %v", err)
	}

	if _, err := env.purger.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after release: %v", err)
	}
	if _, err := env.queries.GetUserByIDForAdmin(ctx, user.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("the subject was not purged after the hold was released: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())
	})
}

// TestIntegrationHardDeleteQueryRefusesHeldSubject exercises the NOT EXISTS predicate
// inside HardDeleteUser directly, which is the half of the legal-hold defence that
// survives a hold applied *after* the Go-side check.
func TestIntegrationHardDeleteQueryRefusesHeldSubject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	q := db.New(pool)

	user := createTestUser(ctx, t, pool, "purge-toctou@privacy.test")
	if _, err := q.SoftDeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("SoftDeleteUser: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE users SET deleted_at = NOW() - INTERVAL '2 hours' WHERE id = $1", user.ID); err != nil {
		t.Fatalf("backdate deleted_at: %v", err)
	}

	hold, err := q.ApplyLegalHold(ctx, db.ApplyLegalHoldParams{
		AccountRef:          user.ID,
		Reason:              legalFixtureString("toctou test"),
		RequestingAuthority: legalFixtureString("test-court"),
		LegalBasis:          legalFixtureString("legal obligation"),
		AppliedBy:           uuid.New(),
	})
	if err != nil {
		t.Fatalf("ApplyLegalHold: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM legal_holds WHERE id = $1", hold.ID)
	})

	cutoff := pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true}
	affected, err := q.HardDeleteUser(ctx, db.HardDeleteUserParams{ID: user.ID, DeletedAt: cutoff})
	if err != nil {
		t.Fatalf("HardDeleteUser: %v", err)
	}
	if affected != 0 {
		t.Fatalf("HardDeleteUser affected %d rows for a held subject, want 0", affected)
	}
	if _, err := q.GetUserByIDForAdmin(ctx, user.ID); err != nil {
		t.Fatalf("the held subject was deleted by the query: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Reclaim
// ---------------------------------------------------------------------------

func TestIntegrationReclaimInsideWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)

	user := createTestUser(ctx, t, pool, "reclaim-inside@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, ok := env.notifier.last()
	if !ok {
		t.Fatal("no notice delivered")
	}

	if err := env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}

	restored, err := env.queries.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("the reclaimed account is not visible to the soft-delete-filtered lookup: %v", err)
	}
	if restored.Status != "active" {
		t.Errorf("status = %q, want active", restored.Status)
	}
	if restored.DeletedAt.Valid {
		t.Error("deleted_at was not cleared")
	}
	// Every outstanding token must be retired, so a second reclaim is impossible.
	if got := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM deletion_requests WHERE user_id = $1 AND consumed_at IS NULL",
		user.ID); got != 0 {
		t.Errorf("active deletion requests after reclaim = %d, want 0", got)
	}
	if err := env.svc.Reclaim(ctx, notice.ReclaimToken,
		ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("second Reclaim = %v, want ErrInvalidToken", err)
	}

	// A reclaimed account must drop straight out of the purge batch.
	stats, err := env.purger.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if _, err := env.queries.GetUserByID(ctx, user.ID); err != nil {
		t.Fatalf("a reclaimed account was purged (stats %+v): %v", stats, err)
	}
}

func TestIntegrationReclaimPastWindowIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)

	user := createTestUser(ctx, t, pool, "reclaim-expired@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := env.notifier.last()

	backdateDeletion(ctx, t, pool, user.ID, 2*testGracePeriod)

	if err := env.svc.Reclaim(ctx, notice.ReclaimToken,
		ReclaimAttempt{Method: FactorWebAuthn}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Reclaim past the window = %v, want ErrInvalidToken", err)
	}
	if _, err := env.svc.ReclaimOptions(ctx, notice.ReclaimToken, ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ReclaimOptions past the window = %v, want ErrInvalidToken", err)
	}
	stored, err := env.queries.GetUserByIDForAdmin(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByIDForAdmin: %v", err)
	}
	if stored.Status != "pending_deletion" {
		t.Errorf("status = %q, want the account to stay pending_deletion", stored.Status)
	}
}

// TestIntegrationIdentifierIsReservedDuringGraceWindow is the migration's whole
// point. Without the widened partial unique indexes a third party could claim the
// email during the window, and the reclaim — which clears deleted_at and so re-arms
// those indexes — would fail with a unique violation, leaving the subject
// permanently unrecoverable.
func TestIntegrationIdentifierIsReservedDuringGraceWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	q := db.New(pool)

	const email = "squatted@privacy.test"
	user := createTestUser(ctx, t, pool, email)
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := env.notifier.last()

	// The squatter's registration attempt must be rejected by the index, and this is
	// exactly the 23505 a registration endpoint has to render as a clean 409.
	_, err := q.CreateUser(ctx, db.CreateUserParams{Email: email, Status: "active"})
	if err == nil {
		t.Fatal("a third party claimed a reserved pending_deletion email")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("CreateUser error = %v, want a 23505 unique violation", err)
	}

	// The application-level "is it taken?" lookup deliberately cannot see the
	// reservation, which is why the 23505 above must be mapped rather than
	// pre-empted.
	if _, err := q.GetUserByEmail(ctx, email); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("GetUserByEmail sees the reserved identifier (%v); the mapping note is stale", err)
	}

	// And the legitimate reclaim still succeeds.
	if err := env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatalf("Reclaim after a squat attempt: %v", err)
	}
	restored, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail after reclaim: %v", err)
	}
	if restored.ID != user.ID {
		t.Errorf("the email resolves to %s, want the original owner %s", restored.ID, user.ID)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestIntegrationConcurrentReclaimVersusPurge: exactly one of the two wins the
// users-row lock, and neither leaves partial state — no purged subject without its
// outbox event, and no reclaimed subject with one.
func TestIntegrationConcurrentReclaimVersusPurge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)

	user := createTestUser(ctx, t, pool, "race@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, user.ID, ""); err != nil {
		t.Fatalf("RequestDeletion: %v", err)
	}
	notice, _ := env.notifier.last()

	// Place the subject just past the cutoff while leaving the reclaim token live, so
	// both operations are simultaneously eligible. This is the genuine race: the
	// token expires exactly at the cutoff, so a user reclaiming at the last second
	// contends with the worker.
	if _, err := pool.Exec(ctx,
		"UPDATE users SET deleted_at = NOW() - INTERVAL '2 hours' WHERE id = $1", user.ID); err != nil {
		t.Fatalf("backdate deleted_at: %v", err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE deletion_requests SET expires_at = NOW() + INTERVAL '1 hour' WHERE user_id = $1",
		user.ID); err != nil {
		t.Fatalf("extend expires_at: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			"DELETE FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())
	})

	var (
		wg         sync.WaitGroup
		reclaimErr error
		purgeStats PurgeStats
		purgeErr   error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		reclaimErr = env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn})
	}()
	go func() {
		defer wg.Done()
		purgeStats, purgeErr = env.purger.RunOnce(ctx)
	}()
	wg.Wait()

	if purgeErr != nil {
		t.Fatalf("RunOnce: %v", purgeErr)
	}

	_, lookupErr := env.queries.GetUserByIDForAdmin(ctx, user.ID)
	purged := errors.Is(lookupErr, pgx.ErrNoRows)
	if lookupErr != nil && !purged {
		t.Fatalf("GetUserByIDForAdmin: %v", lookupErr)
	}

	outbox := countRows(ctx, t, pool,
		"SELECT COUNT(*) FROM event_outbox WHERE payload::jsonb ->> 'user_id' = $1", user.ID.String())

	switch {
	case purged:
		// The purge won. The reclaim must have failed, and the event must exist.
		if reclaimErr == nil {
			t.Error("both the purge and the reclaim reported success")
		}
		if outbox != 1 {
			t.Errorf("outbox rows = %d for a purged subject, want exactly 1", outbox)
		}
	default:
		// The reclaim won (or the purge deferred). The account must be coherent and
		// no event may exist for a subject that is still present.
		stored, err := env.queries.GetUserByIDForAdmin(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetUserByIDForAdmin: %v", err)
		}
		if reclaimErr == nil {
			if stored.Status != "active" || stored.DeletedAt.Valid {
				t.Errorf("a successful reclaim left status=%q deleted_at.Valid=%v",
					stored.Status, stored.DeletedAt.Valid)
			}
		}
		if outbox != 0 {
			t.Errorf("outbox rows = %d for a surviving subject, want 0 (downstream would scrub live data)", outbox)
		}
		if purgeStats.Purged != 0 {
			t.Errorf("stats report %d purged but the subject is still present", purgeStats.Purged)
		}
	}
}

// TestIntegrationAdvisoryLockSerializesRuns confirms the real
// pg_try_advisory_lock guard: while one run holds it, a second observes contention
// and exits cleanly rather than walking the same batch.
func TestIntegrationAdvisoryLockSerializesRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)
	locker, err := NewPgAdvisoryLocker(pool, PurgeAdvisoryLockKey)
	if err != nil {
		t.Fatalf("NewPgAdvisoryLocker: %v", err)
	}

	acquired, release, err := locker.TryLock(ctx)
	if err != nil {
		t.Fatalf("first TryLock: %v", err)
	}
	if !acquired {
		t.Fatal("first TryLock did not acquire an uncontended lock")
	}

	second, secondRelease, err := locker.TryLock(ctx)
	if err != nil {
		release()
		t.Fatalf("second TryLock: %v", err)
	}
	if second {
		secondRelease()
		release()
		t.Fatal("second TryLock acquired a lock already held; two runs could purge the same batch")
	}

	release()

	// Once released the lock must be re-acquirable, or a crashed run would wedge the
	// schedule permanently.
	third, thirdRelease, err := locker.TryLock(ctx)
	if err != nil {
		t.Fatalf("third TryLock: %v", err)
	}
	if !third {
		t.Fatal("the advisory lock was not released")
	}
	thirdRelease()
}

// ---------------------------------------------------------------------------
// Schema-drift guard
// ---------------------------------------------------------------------------

// usersFKAllowlist names every foreign key referencing users(id) whose referential
// action is deliberately neither CASCADE nor SET NULL.
//
// It is empty today, and adding an entry must be a conscious act: any other action
// (NO ACTION / RESTRICT) makes the hard delete fail outright, silently converting a
// GDPR erasure into a permanent per-subject purge failure.
var usersFKAllowlist = map[string]struct{}{}

// TestIntegrationUsersForeignKeysStayPurgeSafe is what keeps hard-delete honest as
// the schema grows.
//
// Every table added later that references users(id) must declare what happens to its
// rows on erasure. Without this guard, a new table with the PostgreSQL default (NO
// ACTION) would make every purge fail on a foreign-key violation — and the failure
// would be counted as a per-subject skip, so nothing would alert until a compliance
// audit asked why nothing had been deleted for months.
func TestIntegrationUsersForeignKeysStayPurgeSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)

	rows, err := pool.Query(ctx, `
		SELECT
			con.conname,
			src.relname AS referencing_table,
			CASE con.confdeltype
				WHEN 'a' THEN 'NO ACTION'
				WHEN 'r' THEN 'RESTRICT'
				WHEN 'c' THEN 'CASCADE'
				WHEN 'n' THEN 'SET NULL'
				WHEN 'd' THEN 'SET DEFAULT'
			END AS on_delete
		FROM pg_constraint con
		JOIN pg_class src ON src.oid = con.conrelid
		JOIN pg_class tgt ON tgt.oid = con.confrelid
		WHERE con.contype = 'f'
		  AND tgt.relname = 'users'
		ORDER BY src.relname, con.conname`)
	if err != nil {
		t.Fatalf("query users foreign keys: %v", err)
	}
	defer rows.Close()

	found := 0
	for rows.Next() {
		var name, table, onDelete string
		if err := rows.Scan(&name, &table, &onDelete); err != nil {
			t.Fatalf("scan foreign key: %v", err)
		}
		found++

		if _, allowed := usersFKAllowlist[name]; allowed {
			continue
		}
		if onDelete != "CASCADE" && onDelete != "SET NULL" {
			t.Errorf("foreign key %s on %s references users(id) with ON DELETE %s; "+
				"hard-delete requires CASCADE or SET NULL, or an explicit entry in usersFKAllowlist",
				name, table, onDelete)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign keys: %v", err)
	}
	if found == 0 {
		t.Fatal("no foreign keys referencing users(id) were found; the drift guard is not actually checking anything")
	}
}

// TestIntegrationLedgerHasNoUsersForeignKey pins the structural guarantee behind
// "hard-delete MUST NOT touch security_event_ledger": it is the absence of a foreign
// key, not worker discipline, that makes the ledger survive.
func TestIntegrationLedgerHasNoUsersForeignKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)

	n := countRows(ctx, t, pool, `
		SELECT COUNT(*)
		FROM pg_constraint con
		JOIN pg_class src ON src.oid = con.conrelid
		JOIN pg_class tgt ON tgt.oid = con.confrelid
		WHERE con.contype = 'f'
		  AND src.relname = 'security_event_ledger'
		  AND tgt.relname = 'users'`)
	if n != 0 {
		t.Fatalf("security_event_ledger has %d foreign keys to users; a cascade would erase "+
			"the attribution record that outlives the account", n)
	}
}

// TestIntegrationOutboxHasNoUsersForeignKey pins the same property for the outbox:
// the subject row is deleted in the same transaction that inserts the event, so any
// FK would either block the delete or cascade the event away.
func TestIntegrationOutboxHasNoUsersForeignKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	pool := openTestPool(ctx, t)

	n := countRows(ctx, t, pool, `
		SELECT COUNT(*)
		FROM pg_constraint con
		JOIN pg_class src ON src.oid = con.conrelid
		JOIN pg_class tgt ON tgt.oid = con.confrelid
		WHERE con.contype = 'f'
		  AND src.relname = 'event_outbox'
		  AND tgt.relname = 'users'`)
	if n != 0 {
		t.Fatalf("event_outbox has %d foreign keys to users; the delete and the event cannot then share a transaction", n)
	}
}
