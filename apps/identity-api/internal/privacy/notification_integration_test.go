//go:build integration

package privacy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

type notificationFaultBeginner struct {
	pool    *pgxpool.Pool
	started chan struct{}
	query   string
}

func (b notificationFaultBeginner) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if b.started != nil {
		select {
		case b.started <- struct{}{}:
		default:
		}
	}
	return notificationFaultTx{Tx: tx, reject: b.query}, nil
}

type notificationFaultTx struct {
	pgx.Tx
	reject string
}

func (t notificationFaultTx) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if t.reject != "" && strings.Contains(query, t.reject) {
		return pgconn.CommandTag{}, errBoom
	}
	return t.Tx.Exec(ctx, query, args...)
}

func (t notificationFaultTx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if t.reject != "" && strings.Contains(query, t.reject) {
		return notificationErrorRow{}
	}
	return t.Tx.QueryRow(ctx, query, args...)
}

type notificationErrorRow struct{}

func (notificationErrorRow) Scan(...any) error { return errBoom }

type oversizedNotificationCipher struct{ Cipher }

func (oversizedNotificationCipher) Encrypt(context.Context, []byte) ([]byte, error) {
	return make([]byte, maxNotificationCiphertext+1), nil
}

func integrationNotification(ctx context.Context, t *testing.T, env *integrationEnv, userID uuid.UUID, role string) db.DeletionNotification {
	t.Helper()
	var id uuid.UUID
	if err := env.pool.QueryRow(ctx, "SELECT id FROM deletion_notifications WHERE user_id=$1 AND recipient_role=$2 ORDER BY created_at DESC LIMIT 1", userID, role).Scan(&id); err != nil {
		t.Fatal(err)
	}
	row, err := env.queries.GetDeletionNotificationForUpdate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func integrationQueuedNotice(ctx context.Context, t *testing.T, env *integrationEnv, userID uuid.UUID) DeletionNotice {
	t.Helper()
	row := integrationNotification(ctx, t, env, userID, "primary")
	request, err := env.queries.GetDeletionRequestForUpdate(ctx, row.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := env.cipher.Decrypt(ctx, row.PayloadEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	notice, err := decodeNotificationPayload(plaintext, row, request)
	if err != nil {
		t.Fatal(err)
	}
	return notice
}

func TestPrivacyNotificationPersistenceRollbackIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	for _, fault := range []string{"encrypt", "oversized", "insert", "backup"} {
		t.Run(fault, func(t *testing.T) {
			env := newIntegrationEnv(t, pool)
			u := createTestUser(ctx, t, pool, "notification-rollback-"+fault+"@privacy.test")
			switch fault {
			case "encrypt":
				env.svc.cipher = failingCipher{Cipher: env.cipher, encryptErr: errBoom}
			case "oversized":
				env.svc.cipher = oversizedNotificationCipher{Cipher: env.cipher}
			case "insert":
				env.svc.tx = notificationFaultBeginner{pool: pool, query: "-- name: CreateDeletionNotification"}
			case "backup":
				if _, err := pool.Exec(ctx, "UPDATE users SET backup_email_encrypted=$2 WHERE id=$1", u.ID, []byte("unavailable")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err == nil {
				t.Fatal("notification persistence failure accepted")
			}
			stored, err := env.queries.GetUserByIDForAdmin(ctx, u.ID)
			if err != nil || stored.Status != "active" || stored.DeletedAt.Valid || stored.AuthVersion != u.AuthVersion || stored.LifecycleRevision != u.LifecycleRevision {
				t.Fatal("deletion/version/lifecycle state escaped rollback", err)
			}
			for _, query := range []string{"SELECT count(*) FROM deletion_requests WHERE user_id=$1", "SELECT count(*) FROM deletion_notifications WHERE user_id=$1", "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1"} {
				if countRows(ctx, t, pool, query, u.ID) != 0 {
					t.Fatal("failed transaction persisted partial intent")
				}
			}
			if env.notifier.count()+env.sessions.count()+env.tokens.count() != 0 {
				t.Fatal("rollback caused postcommit side effects")
			}
		})
	}
}

func TestPrivacyConcurrentDeletionCoalescesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "notification-coalesce@privacy.test")
	backup, err := env.cipher.Encrypt(ctx, []byte("coalesce-backup@privacy.test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE users SET backup_email_encrypted=$2 WHERE id=$1", u.ID, backup); err != nil {
		t.Fatal(err)
	}
	const callers = 12
	results := make(chan DeletionResult, callers)
	errorsOut := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			result, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, "")
			results <- result
			errorsOut <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expiry time.Time
	minted := 0
	for result := range results {
		if result.TokenMinted {
			minted++
		}
		if expiry.IsZero() {
			expiry = result.ExpiresAt
		}
		if !result.NotificationQueued || !result.ExpiresAt.Equal(expiry) {
			t.Fatal("concurrent admitted requests moved the deadline")
		}
	}
	stored, err := env.queries.GetUserByIDForAdmin(ctx, u.ID)
	if err != nil || minted != 1 || stored.AuthVersion != u.AuthVersion+1 || stored.LifecycleRevision != 1 ||
		countRows(ctx, t, pool, "SELECT count(*) FROM deletion_requests WHERE user_id=$1", u.ID) != 1 ||
		countRows(ctx, t, pool, "SELECT count(*) FROM deletion_notifications WHERE user_id=$1", u.ID) != 2 ||
		countRows(ctx, t, pool, "SELECT count(*) FROM event_outbox WHERE lifecycle_user_id=$1", u.ID) != 1 {
		t.Fatal("concurrent deletion failed to coalesce atomically", err)
	}
}

func TestPrivacyDeletionRechecksAuthorityAfterSubjectLockIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "notification-authority@privacy.test")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := pglock.LockAccount(ctx, tx, u.ID); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	env.svc.tx = notificationFaultBeginner{pool: pool, started: started}
	done := make(chan error, 1)
	go func() {
		_, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, "")
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := db.New(tx).ModerateUserStatus(ctx, db.ModerateUserStatusParams{ID: u.ID, Status: "suspended"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrStaleAuthority) {
		t.Fatal("admitted deletion overwrote moderation", err)
	}
	stored, err := env.queries.GetUserByIDForAdmin(ctx, u.ID)
	if err != nil || stored.Status != "suspended" || stored.DeletedAt.Valid || countRows(ctx, t, pool, "SELECT count(*) FROM deletion_requests WHERE user_id=$1", u.ID) != 0 {
		t.Fatal("stale delete persisted state", err)
	}
}

func TestPrivacyReclaimRetirementRacesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	for _, retirement := range []string{"consumed", "replaced", "attempt_cap"} {
		t.Run(retirement, func(t *testing.T) {
			env := newIntegrationEnv(t, pool)
			u := createTestUser(ctx, t, pool, "reclaim-retirement-"+retirement+"@privacy.test")
			if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err != nil {
				t.Fatal(err)
			}
			notice := integrationQueuedNotice(ctx, t, env, u.ID)
			request, err := env.queries.GetActiveDeletionRequestForUser(ctx, u.ID)
			if err != nil {
				t.Fatal(err)
			}
			started, proceed := make(chan struct{}), make(chan struct{})
			env.passkeys.onFinish = func() {
				close(started)
				select {
				case <-proceed:
				case <-ctx.Done():
				}
			}
			done := make(chan error, 1)
			go func() { done <- env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}) }()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if retirement == "attempt_cap" {
				// Assert the UPDATE itself is atomic even with callers that do not
				// serialize on the subject lock. Production still takes that lock.
				var wg sync.WaitGroup
				counts := make(chan int32, 16)
				for range 16 {
					wg.Go(func() {
						updated, err := env.queries.RecordDeletionRequestFailure(ctx, db.RecordDeletionRequestFailureParams{
							ID: request.ID, UserID: u.ID, TokenHash: request.TokenHash, MaxAttempts: defaultReclaimMaxAttempts,
						})
						if err == nil {
							counts <- updated.FailedAttempts
						} else if !errors.Is(err, pgx.ErrNoRows) {
							t.Error(err)
						}
					})
				}
				wg.Wait()
				close(counts)
				seen := make(map[int32]bool)
				for count := range counts {
					if seen[count] {
						t.Error("duplicate attempt count returned")
					}
					seen[count] = true
				}
				if len(seen) != defaultReclaimMaxAttempts {
					t.Errorf("atomic failure counts = %d", len(seen))
				}
			} else {
				if _, err := env.queries.ConsumeDeletionRequest(ctx, request.ID); err != nil {
					t.Error(err)
				}
				if retirement == "replaced" {
					_, hash, _ := NewReclaimToken()
					if _, err := env.queries.CreateDeletionRequest(ctx, db.CreateDeletionRequestParams{UserID: u.ID, TokenHash: hash, ExpiresAt: request.ExpiresAt, RequestedAuthVersion: request.RequestedAuthVersion}); err != nil {
						t.Error(err)
					}
				}
			}
			close(proceed)
			if err := <-done; !errors.Is(err, ErrInvalidToken) {
				t.Fatal("in-flight completion survived exact request retirement", err)
			}
			stored, err := env.queries.GetUserByIDForAdmin(ctx, u.ID)
			if err != nil || stored.Status != statusPendingDeletion || stored.AuthVersion != u.AuthVersion+1 {
				t.Fatal("retired request restored authority", err)
			}
		})
	}
}

func TestPrivacyReclaimDeadlineEvaluatedAfterLockWaitIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "reclaim-lock-deadline@privacy.test")
	result, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, "")
	if err != nil {
		t.Fatal(err)
	}
	notice := integrationQueuedNotice(ctx, t, env, u.ID)
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	env.svc.now = func() time.Time { return time.Unix(0, now.Load()) }
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := pglock.LockAccount(ctx, tx, u.ID); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	env.svc.tx = notificationFaultBeginner{pool: pool, started: started}
	done := make(chan error, 1)
	go func() { done <- env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	now.Store(result.ExpiresAt.UnixNano())
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrInvalidToken) {
		t.Fatal("pre-lock time extended the recovery deadline", err)
	}
}

func TestPrivacyNotificationRestartAndRecipientRetryIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "restart-primary@privacy.test")
	backup, err := env.cipher.Encrypt(ctx, []byte("restart-backup@privacy.test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE users SET backup_email_encrypted=$2 WHERE id=$1", u.ID, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	before := integrationNotification(ctx, t, env, u.ID, "backup")
	if affected, err := env.queries.CreateDeletionNotification(ctx, db.CreateDeletionNotificationParams{
		ID: uuid.New(), UserID: u.ID, RequestID: before.RequestID, RecipientRole: "backup",
		PayloadEncrypted: before.PayloadEncrypted, ExpiresAt: before.ExpiresAt,
	}); err != nil || affected != 0 {
		t.Fatal("duplicate enqueue was not harmless", err)
	}
	firstToken := integrationQueuedNotice(ctx, t, env, u.ID).ReclaimToken
	if bytes.Contains(before.PayloadEncrypted, []byte(firstToken)) || bytes.Contains(before.PayloadEncrypted, []byte(u.Email)) || env.notifier.count() != 0 {
		t.Fatal("API sent synchronously or persisted plaintext delivery material")
	}
	var attempts []DeletionNotice
	fail := true
	sender := notifierFunc(func(_ context.Context, n DeletionNotice) error {
		attempts = append(attempts, n)
		if n.PrimaryEmail == "restart-backup@privacy.test" && fail {
			return errBoom
		}
		return nil
	})
	// A fresh worker/cipher instance has only committed database intent, modeling
	// loss of the API process immediately after the transaction committed.
	w, err := NewNotificationWorker(NotificationConfig{GracePeriod: testGracePeriod, Concurrency: 1}, env.queries, pool, newTestCipher(t), sender, env.recorder, WithNotificationLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	primary := integrationNotification(ctx, t, env, u.ID, "primary")
	after := integrationNotification(ctx, t, env, u.ID, "backup")
	if !primary.AcceptedAt.Valid || len(primary.PayloadEncrypted) != 0 || after.AcceptedAt.Valid || after.Attempts != 1 ||
		!bytes.Equal(before.PayloadEncrypted, after.PayloadEncrypted) || len(attempts) != 2 {
		t.Fatal("recipient failure affected accepted recipient or replaced retry material")
	}
	fail = false
	if _, err := pool.Exec(ctx, "UPDATE deletion_notifications SET next_attempt_at=clock_timestamp() WHERE id=$1", after.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 3 || attempts[2].DeliveryID != after.ID || attempts[2].ReclaimToken != firstToken || !attempts[2].ExpiresAt.Equal(before.ExpiresAt.Time) {
		t.Fatal("retry did not retain original recipient identity, token, and deadline")
	}
}

func TestPrivacyNotifierRoleCannotReadContactsOrChangeAuthorityIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "notifier-privileges@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	role := "privacy_notice_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{role}.Sanitize()
	password := uuid.NewString()
	if _, err := pool.Exec(ctx, "CREATE ROLE "+identifier+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '"+password+"'"); err != nil {
		t.Fatal("create isolated notifier role", err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = pool.Exec(cleanupCtx, "DROP OWNED BY "+identifier)
		_, _ = pool.Exec(cleanupCtx, "DROP ROLE "+identifier)
	})
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA public TO ",
		"GRANT SELECT (id, status, auth_version, deleted_at) ON users TO ",
		"GRANT SELECT (id, user_id, token_hash, expires_at, consumed_at, failed_attempts, requested_auth_version) ON deletion_requests TO ",
		"GRANT SELECT (account_ref, is_active) ON legal_holds TO ",
		"GRANT SELECT ON deletion_notifications TO ",
		"GRANT UPDATE (payload_encrypted, lease_token, lease_until, attempts, next_attempt_at, accepted_at, failed_at, last_error_code) ON deletion_notifications TO ",
	} {
		if _, err := pool.Exec(ctx, grant+identifier); err != nil {
			t.Fatal("grant isolated delivery privileges", err)
		}
	}
	cfg := pool.Config().Copy()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, password
	cfg.MinConns, cfg.MaxConns = 0, 2
	workerPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open restricted notifier pool", err)
	}
	t.Cleanup(workerPool.Close)
	for _, forbidden := range []string{
		"SELECT email FROM users LIMIT 0",
		"SELECT requested_ip FROM deletion_requests LIMIT 0",
		"UPDATE users SET id=id WHERE FALSE",
		"UPDATE users SET status='active' WHERE FALSE",
		"UPDATE deletion_requests SET id=id WHERE FALSE",
		"DELETE FROM deletion_requests WHERE FALSE",
		"DELETE FROM event_outbox WHERE FALSE",
	} {
		_, err := workerPool.Exec(ctx, forbidden)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("notifier capability boundary failed for %q: %v", forbidden, err)
		}
	}
	w, err := NewNotificationWorker(NotificationConfig{GracePeriod: testGracePeriod, Concurrency: 1},
		db.New(workerPool), workerPool, env.cipher, env.notifier, env.recorder, WithNotificationLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := w.RunOnce(ctx)
	if err != nil || stats.Accepted != 1 || stats.Cleaned != 1 || env.notifier.count() != 1 {
		t.Fatalf("read-only authority role could not deliver and clean: %+v, %v", stats, err)
	}
	stored, err := env.queries.GetUserByIDForAdmin(ctx, u.ID)
	if err != nil || stored.Status != statusPendingDeletion || stored.AuthVersion != u.AuthVersion+1 {
		t.Fatal("notification processing changed account authority", err)
	}
}

func TestPrivacyNotificationLeasesFenceConcurrentWorkersIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "concurrent-workers@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	started, proceed := make(chan struct{}), make(chan struct{})
	env.worker.notifier = notifierFunc(func(ctx context.Context, _ DeletionNotice) error {
		close(started)
		select {
		case <-proceed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	done := make(chan error, 1)
	go func() { _, err := env.worker.RunOnce(ctx); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second := newIntegrationEnv(t, pool)
	if _, err := second.worker.RunOnce(ctx); err != nil {
		t.Error(err)
	}
	if second.notifier.count() != 0 {
		t.Error("second worker stole an active lease")
	}
	row := integrationNotification(ctx, t, env, u.ID, "primary")
	replacement := uuid.New()
	if _, err := pool.Exec(ctx, "UPDATE deletion_notifications SET lease_token=$2 WHERE id=$1", row.ID, replacement); err != nil {
		t.Error(err)
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	row = integrationNotification(ctx, t, env, u.ID, "primary")
	if row.AcceptedAt.Valid || row.LeaseToken.UUID != replacement {
		t.Fatal("stale worker acknowledgement overwrote the replacement lease")
	}
	if _, err := pool.Exec(ctx, "UPDATE deletion_notifications SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE id=$1", row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := second.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if row = integrationNotification(ctx, t, env, u.ID, "primary"); !row.AcceptedAt.Valid || second.notifier.count() != 1 {
		t.Fatal("crash-expired lease did not recover")
	}
}

func TestPrivacyNotificationCleanupHoldLockAndFailureIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	pool := openTestPool(ctx, t)
	env := newIntegrationEnv(t, pool)
	u := createTestUser(ctx, t, pool, "notification-held-cleanup@privacy.test")
	if _, err := env.svc.RequestDeletion(ctx, u.ID, u.AuthVersion, ""); err != nil {
		t.Fatal(err)
	}
	notice := integrationQueuedNotice(ctx, t, env, u.ID)
	if err := env.svc.Reclaim(ctx, notice.ReclaimToken, ReclaimAttempt{Method: FactorWebAuthn}); err != nil {
		t.Fatal(err)
	}
	before := integrationNotification(ctx, t, env, u.ID, "primary")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := pglock.LockAccount(ctx, tx, u.ID); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	env.worker.tx = notificationFaultBeginner{pool: pool, started: started}
	done := make(chan error, 1)
	go func() { _, err := env.worker.RunOnce(ctx); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	hold, err := db.New(tx).ApplyLegalHold(ctx, db.ApplyLegalHoldParams{AccountRef: u.ID, Reason: legalFixtureString("payload preservation fixture"), RequestingAuthority: legalFixtureString("test-court"), LegalBasis: legalFixtureString("legal obligation"), AppliedBy: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM legal_holds WHERE id=$1", hold.ID) })
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if after := integrationNotification(ctx, t, env, u.ID, "primary"); !bytes.Equal(before.PayloadEncrypted, after.PayloadEncrypted) || env.notifier.count() != 0 {
		t.Fatal("hold created during lock wait did not preserve non-deliverable ciphertext")
	}
	if _, err := env.queries.ReleaseLegalHold(ctx, db.ReleaseLegalHoldParams{ID: hold.ID, ReleasedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	env.worker.tx = notificationFaultBeginner{pool: pool, query: "-- name: HasActiveLegalHold"}
	if _, err := env.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(integrationNotification(ctx, t, env, u.ID, "primary").PayloadEncrypted) == 0 {
		t.Fatal("unknown hold answer erased ciphertext")
	}
	env.worker.tx = pool
	if _, err := env.worker.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(integrationNotification(ctx, t, env, u.ID, "primary").PayloadEncrypted) != 0 || env.notifier.count() != 0 {
		t.Fatal("released canceled notice was not cleaned, or was delivered")
	}
}
