//go:build integration

package legalhold

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/privacy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type legalIntegration struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	svc     *Service
	actions *adminaction.Service
	actors  [2]db.User
}

func newLegalIntegration(t *testing.T) *legalIntegration {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for integration-tag legal tests; use a disposable database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	migrations, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = migrate.Up(ctx, migrations)
	_ = migrations.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 8 // Two contenders plus a separate lock observer must run concurrently.
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	svc, _ := testService(t)
	svc.store = db.New(pool)
	actions, err := adminaction.New(pool, svc.encryptor, "identity.audit.legal-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := &legalIntegration{ctx: ctx, pool: pool, svc: svc, actions: actions}
	for i := range f.actors {
		f.actors[i] = f.user(t)
		if err := db.New(pool).AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: f.actors[i].ID, RoleID: "dpo"}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *legalIntegration) user(t *testing.T) db.User {
	t.Helper()
	u, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: uuid.NewString() + "@legal.test", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), "DELETE FROM users WHERE id=$1", u.ID) })
	return u
}

func (f *legalIntegration) operation(t *testing.T, actor int) (context.Context, *adminaction.Operation) {
	t.Helper()
	op, err := f.actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{EventType: audit.EventLegalHoldApplied, ActionStatus: audit.StatusSuccess, ActorID: f.actors[actor].ID}
	t.Cleanup(func() {
		_ = op.Rollback(context.Background())
		_, _ = f.pool.Exec(context.Background(), "DELETE FROM event_outbox WHERE id=$1", op.ID)
	})
	ctx := session.WithSession(f.ctx, session.Session{UserID: f.actors[actor].ID.String(), Kind: session.KindAuthenticated,
		AuthVersion: f.actors[actor].AuthVersion, AuthVersionSet: true})
	return adminaction.WithContext(ctx, op), op
}

func (f *legalIntegration) request(t *testing.T, account uuid.UUID) ApplyRequest {
	t.Helper()
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), "DELETE FROM legal_holds WHERE account_ref=$1", account)
	})
	return ApplyRequest{AccountRef: account, AppliedBy: f.actors[0].ID, IdempotencyKey: uuid.New(), Reason: "sealed investigation",
		RequestingAuthority: "test court", LegalBasis: "test order", ReviewAt: f.svc.now().Add(-time.Hour)}
}

// Observe an actual PostgreSQL advisory-lock wait, not a scheduling delay. Using
// distinct actors prevents their actor lock from masking a missing subject lock.
func (f *legalIntegration) waitBlocked(t *testing.T, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("contender did not block on the shared account advisory lock")
		case <-ticker.C:
		}
	}
}

func applyKind(ctx context.Context, svc *Service, req ApplyRequest, preservation bool) (ApplyResult, error) {
	if !preservation {
		return svc.Apply(ctx, req)
	}
	r, err := svc.Preserve(ctx, PreserveRequest{AccountRef: req.AccountRef, AppliedBy: req.AppliedBy, IdempotencyKey: req.IdempotencyKey,
		Reason: req.Reason, RequestingAuthority: req.RequestingAuthority, ExpiresAt: req.ReviewAt})
	return r.ApplyResult, err
}

func TestLegalConcurrentRequestsIntegration(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		firstPreserve, secondPreserve bool
		newKey, changedBody           bool
	}{
		{name: "hold replay"},
		{name: "preservation replay", firstPreserve: true, secondPreserve: true},
		{name: "conflicting preservation", firstPreserve: true, secondPreserve: true, changedBody: true},
		{name: "independent key", newKey: true},
		{name: "independent request kind", secondPreserve: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLegalIntegration(t)
			req := f.request(t, uuid.New())
			ctx1, op1 := f.operation(t, 0)
			first, err := applyKind(ctx1, f.svc, req, tc.firstPreserve)
			if err != nil {
				t.Fatal(err)
			}
			secondReq := req
			secondReq.AppliedBy = f.actors[1].ID
			if tc.newKey {
				secondReq.IdempotencyKey = uuid.New()
			}
			if tc.changedBody {
				secondReq.Reason = "different case"
			}
			ctx2, op2 := f.operation(t, 1)
			pid := op2.Tx.Conn().PgConn().PID()
			type outcome struct {
				result ApplyResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				r, err := applyKind(ctx2, f.svc, secondReq, tc.secondPreserve)
				if err == nil {
					err = op2.Commit(ctx2)
				} else {
					_ = op2.Rollback(ctx2)
				}
				done <- outcome{r, err}
			}()
			f.waitBlocked(t, pid)
			if err := op1.Commit(ctx1); err != nil {
				t.Fatal(err)
			}
			got := <-done
			independent := tc.newKey || tc.firstPreserve != tc.secondPreserve
			switch {
			case tc.changedBody:
				if !errors.Is(got.err, ErrIdempotencyConflict) {
					t.Fatalf("changed request: %v", got.err)
				}
			case independent:
				if got.err != nil || got.result.Replayed || got.result.Hold.Record.ID == first.Hold.Record.ID {
					t.Fatalf("independent request collapsed: %+v %v", got.result, got.err)
				}
			default:
				if got.err != nil || !got.result.Replayed || got.result.Hold.Record.ID != first.Hold.Record.ID {
					t.Fatalf("retry not replayed: %+v %v", got.result, got.err)
				}
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM legal_holds WHERE account_ref=$1 AND is_active", req.AccountRef).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 1
			if independent {
				want = 2
			}
			if count != want {
				t.Fatalf("active requests=%d, want %d", count, want)
			}
		})
	}
}

func TestLegalReleaseSerializesReplayIntegration(t *testing.T) {
	for _, replayRelease := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply replay", true: "release retry"}[replayRelease], func(t *testing.T) {
			f := newLegalIntegration(t)
			req := f.request(t, uuid.New())
			ctx, op := f.operation(t, 0)
			first, err := f.svc.Apply(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if err := op.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			ctx1, op1 := f.operation(t, 0)
			released, err := f.svc.Release(ctx1, first.Hold.Record.ID, f.actors[0].ID)
			if err != nil || released.Replayed {
				t.Fatalf("initial release: %v", err)
			}
			ctx2, op2 := f.operation(t, 1)
			pid := op2.Tx.Conn().PgConn().PID()
			done := make(chan error, 1)
			go func() {
				var h Hold
				var replayed bool
				var err error
				if replayRelease {
					var r ReleaseResult
					r, err = f.svc.Release(ctx2, first.Hold.Record.ID, f.actors[1].ID)
					h, replayed = r.Hold, r.Replayed
				} else {
					req.AppliedBy = f.actors[1].ID
					var r ApplyResult
					r, err = f.svc.Apply(ctx2, req)
					h, replayed = r.Hold, r.Replayed
				}
				if err == nil && (!replayed || h.Record.IsActive || h.Record.ReleasedBy != released.Hold.Record.ReleasedBy ||
					!h.Record.ReleasedAt.Time.Equal(released.Hold.Record.ReleasedAt.Time)) {
					err = errors.New("retry resurrected hold or replaced first release attribution")
				}
				if err == nil {
					err = op2.Commit(ctx2)
				}
				done <- err
			}()
			f.waitBlocked(t, pid)
			if err := op1.Commit(ctx1); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type legalPurgeBeginner struct{ tx pgx.Tx }

func (b legalPurgeBeginner) Begin(context.Context) (pgx.Tx, error) { return b.tx, nil }

func TestLegalPurgeBothLockOrdersIntegration(t *testing.T) {
	for _, preservation := range []bool{false, true} {
		for _, purgeFirst := range []bool{false, true} {
			name := map[bool]string{false: "apply", true: "preserve"}[preservation] + "/" + map[bool]string{false: "hold first", true: "purge first"}[purgeFirst]
			t.Run(name, func(t *testing.T) {
				f := newLegalIntegration(t)
				user := f.user(t)
				req := f.request(t, user.ID)
				f.ledger(t, user.ID, nil, f.svc.now().Add(time.Hour))
				if _, err := f.pool.Exec(f.ctx, "UPDATE users SET status='pending_deletion',deleted_at=NOW()-INTERVAL '2 hours' WHERE id=$1", user.ID); err != nil {
					t.Fatal(err)
				}
				purgeTx, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = purgeTx.Rollback(context.Background()) }()
				opener, err := privacy.NewPgSubjectTxOpener(legalPurgeBeginner{purgeTx})
				if err != nil {
					t.Fatal(err)
				}
				purge, err := opener.BeginSubject(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				ctx, op := f.operation(t, 0)
				cutoff := db.HardDeleteUserParams{ID: user.ID, DeletedAt: timestamptz(time.Now().Add(-time.Hour))}
				if purgeFirst {
					if err := purge.LockAccount(f.ctx, user.ID); err != nil {
						t.Fatal(err)
					}
					if n, err := purge.Store().HardDeleteUser(f.ctx, cutoff); err != nil || n != 1 {
						t.Fatalf("delete before hold: %d %v", n, err)
					}
					done := make(chan error, 1)
					pid := op.Tx.Conn().PgConn().PID()
					go func() {
						_, err := applyKind(ctx, f.svc, req, preservation)
						done <- err
					}()
					f.waitBlocked(t, pid)
					if err := purge.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := applyKind(ctx, f.svc, req, preservation); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					pid := purgeTx.Conn().PgConn().PID()
					go func() { done <- purge.LockAccount(f.ctx, user.ID) }()
					f.waitBlocked(t, pid)
					if err := op.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					if n, err := purge.Store().HardDeleteUser(f.ctx, cutoff); err != nil || n != 0 {
						t.Fatalf("fresh purge statement ignored committed hold: %d %v", n, err)
					}
					if err := purge.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
				}
				if purgeFirst {
					observed, err := op.Queries.ObserveLegalSubject(ctx, user.ID)
					if err != nil || observed.AccountPresent || !observed.LedgerEvidencePresent {
						t.Fatalf("post-purge snapshot: %+v %v", observed, err)
					}
					if err := op.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func (f *legalIntegration) ledger(t *testing.T, account uuid.UUID, index *string, retain time.Time) db.SecurityEventLedger {
	t.Helper()
	id := uuid.New()
	_, err := db.New(f.pool).InsertSecurityEvents(f.ctx, []db.InsertSecurityEventsParams{{ID: id, AccountRef: account,
		IdentityBlindIndex: index, EventType: audit.EventLoginSucceeded, Timestamp: timestamptz(f.svc.now().Add(-time.Minute)),
		// A syntactically valid fixture digest, not a signed integrity proof.
		RetainUntil: timestamptz(retain), ChainHash: "0000000000000000000000000000000000000000000000000000000000000000"}})
	if err != nil {
		t.Fatal(err)
	}
	var seq int64
	if err := f.pool.QueryRow(f.ctx, "SELECT seq FROM security_event_ledger WHERE id=$1", id).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	return db.SecurityEventLedger{ID: id, Seq: seq, AccountRef: account}
}

func TestLegalPostDeletionRetentionCursorIntegration(t *testing.T) {
	f := newLegalIntegration(t)
	u := f.user(t)
	index := f.svc.indexer.Compute(u.Email)
	now := f.svc.now()
	f.ledger(t, uuid.New(), &index, now.Add(-time.Microsecond))
	boundary := f.ledger(t, u.ID, &index, now)
	heldAccount := uuid.New()
	held := f.ledger(t, heldAccount, &index, now.Add(-time.Hour))
	reused := f.ledger(t, uuid.New(), &index, now.Add(time.Hour))
	f.ledger(t, u.ID, nil, now.Add(time.Hour))
	ctx, op := f.operation(t, 0)
	hold, err := f.svc.Apply(ctx, f.request(t, heldAccount))
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "DELETE FROM users WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.operation(t, 0)
	req := LookupRequest{IdentifierType: IdentifierTypeEmail, Identifier: " " + u.Email + " ", ActorID: f.actors[0].ID,
		RequestingAuthority: "court", CaseReference: "case", Purpose: "investigation", StartTime: now.Add(-time.Hour), EndTime: now, Limit: 1}
	allReq := req
	allReq.Limit = 200
	all, err := f.svc.Lookup(ctx, allReq)
	if err != nil || len(all.Events) != 3 || all.Events[0].ID != boundary.ID || all.Events[1].ID != held.ID || all.Events[2].ID != reused.ID {
		t.Fatalf("expired-held/expired-unheld eligibility: %+v %v", all, err)
	}
	first, err := f.svc.Lookup(ctx, req)
	if err != nil || len(first.Events) != 1 || first.Events[0].ID != boundary.ID || first.NextCursor == "" {
		t.Fatalf("exact retention boundary/post-deletion lookup: %+v %v", first, err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.operation(t, 1)
	if _, err := f.svc.Release(ctx, hold.Hold.Record.ID, f.actors[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.ledger(t, uuid.New(), &index, now.Add(time.Hour)) // Beyond the original high-water mark.
	ctx, op = f.operation(t, 0)
	req.Cursor = first.NextCursor
	second, err := f.svc.Lookup(ctx, req)
	if err != nil || len(second.Events) != 1 || second.Events[0].ID != reused.ID || second.NextCursor != "" ||
		second.Coverage.ThroughSeq != first.Coverage.ThroughSeq || !second.Coverage.ObservedAt.Equal(first.Coverage.ObservedAt) {
		t.Fatalf("continuation disclosed released/new/unindexed evidence: %+v %v", second, err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.operation(t, 0)
	preserve := f.request(t, u.ID)
	observed, err := f.svc.Preserve(ctx, PreserveRequest{AccountRef: u.ID, AppliedBy: preserve.AppliedBy, IdempotencyKey: preserve.IdempotencyKey,
		Reason: preserve.Reason, RequestingAuthority: preserve.RequestingAuthority, ExpiresAt: now.Add(-time.Hour)})
	if err != nil || observed.AccountPresent || !observed.LedgerEvidencePresent || observed.ObservedAt.IsZero() || !observed.Hold.Record.IsActive {
		t.Fatalf("preservation after deletion with surviving evidence: %+v %v", observed, err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLegalMaintenanceHoldPrecedenceAndTombstoneIntegration(t *testing.T) {
	f := newLegalIntegration(t)
	account := uuid.New()
	req := f.request(t, account)
	f.ledger(t, account, nil, f.svc.now().Add(-time.Hour))
	ctx, op := f.operation(t, 0)
	first, err := f.svc.Apply(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	otherReq := req
	otherReq.IdempotencyKey = uuid.New()
	other, err := f.svc.Apply(ctx, otherReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Release(ctx, first.Hold.Record.ID, req.AppliedBy); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.operation(t, 0)
	for _, offset := range []int32{0, 100} {
		page, err := f.svc.List(ctx, ListRequest{AccountRef: uuid.NullUUID{UUID: account, Valid: true}, Status: "all", Limit: 1, Offset: offset})
		if err != nil || page.Total != 2 || (offset == 0 && (len(page.Holds) != 1 || page.Holds[0].Details.Reason != req.Reason)) ||
			(offset == 100 && len(page.Holds) != 0) {
			t.Fatalf("encrypted page/count snapshot at offset %d: %+v %v", offset, page, err)
		}
	}
	if err := op.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if n, err := f.svc.CleanupReleased(f.ctx, f.pool, 1000); err != nil || n != 0 {
		t.Fatalf("independent active hold must preserve released narrative: %d %v", n, err)
	}
	for _, released := range []bool{false, true} {
		if released {
			ctx, op = f.operation(t, 0)
			if _, err := f.svc.Release(ctx, other.Hold.Record.ID, req.AppliedBy); err != nil {
				t.Fatal(err)
			}
			if err := op.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
		// Hold release changes eligibility, never the signed expiration. Actual
		// erasure and real-role enforcement are covered by retentiondbintegration.
		tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := pglock.LockAccount(f.ctx, tx, account); err != nil {
			t.Fatal(err)
		}
		var eligible bool
		if err := tx.QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM security_event_ledger l
WHERE l.account_ref=$1 AND l.retain_until < now()
AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.account_ref=l.account_ref AND h.is_active))`, account).Scan(&eligible); err != nil {
			t.Fatal(err)
		}
		if eligible != released {
			t.Fatal("ledger eligibility ignored active hold or restarted retention after release")
		}
		if err := tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.svc.CleanupReleased(f.ctx, f.pool, 1000); err != nil || n != 2 {
		t.Fatalf("cleanup after all releases: %d %v", n, err)
	}
	ctx, op = f.operation(t, 0)
	if _, err := f.svc.Apply(ctx, req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("cleaned-up request recreated protection: %v", err)
	}
	list, err := f.svc.List(ctx, ListRequest{AccountRef: uuid.NullUUID{UUID: account, Valid: true}, Status: "released", Limit: 1})
	if err != nil || list.Total != 2 || len(list.Holds) != 1 || !list.Holds[0].DetailsPurged {
		t.Fatalf("tombstone list: %+v %v", list, err)
	}
	if err := op.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}
