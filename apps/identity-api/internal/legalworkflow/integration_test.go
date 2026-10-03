//go:build integration

package legalworkflow

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type integration struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	actions *adminaction.Service
	service *Service
	actors  [3]Actor
	policy  legalpolicy.Policy
	dsn     string
}

func integrationFixture(t *testing.T) *integration {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL required for integration legal workflow tests; use disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	// Public-qualified ledger functions require a private database, not just a
	// search_path schema. Never reset or rewrite the caller's database.
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "legal_workflow_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(context.Background(), `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`)
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		t.Fatal("DATABASE_URL must be a PostgreSQL URL")
	}
	parsed.Path = "/" + name
	dsn = parsed.String()
	migrationDB, err := migrate.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	err = migrate.Up(ctx, migrationDB)
	_ = migrationDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 12
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	enc := testEncryptor(t)
	actions, err := adminaction.New(pool, enc, "identity.audit.workflow-fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "fixture-workflow-not-production", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600, ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry, LegacyInventoryReference: "fixture-legacy-inventory",
		Workflow: &legalpolicy.WorkflowPolicy{MaxCaseAgeSeconds: 86400, ClosedCaseRetentionSeconds: 1800, CaseClock: legalpolicy.ClockCaseExpiry, ReplayFields: legalpolicy.WorkflowReplayFields(), ReplayLifetime: legalpolicy.LifetimeNoExpiry}}
	if baseline, err := legalpolicy.LoadBaseline(ctx, pool, uuid.Nil, "test"); err == nil {
		p.ContextRetentionSeconds = baseline.ContextRetentionSeconds
		p.ReleasedHoldRetentionSeconds = baseline.ReleasedHoldRetentionSeconds
	}
	op, err := actions.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/workflow-fixture"}
	if err = legalpolicy.Install(ctx, op, p, "test"); err != nil {
		_ = op.Rollback(ctx)
		t.Fatal(err)
	}
	if err = op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	svc, err := New(enc, Config{Enabled: true, PolicyID: p.ID, Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	f := &integration{ctx: ctx, pool: pool, actions: actions, service: svc, policy: p, dsn: dsn}
	for i := range f.actors {
		u, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Email: uuid.NewString() + "@workflow.test", Status: "active"})
		if err != nil {
			t.Fatal(err)
		}
		if err = db.New(pool).AssignRoleToUser(ctx, db.AssignRoleToUserParams{UserID: u.ID, RoleID: "dpo"}); err != nil {
			t.Fatal(err)
		}
		f.actors[i] = Actor{ID: u.ID, AuthVersion: u.AuthVersion}
	}
	return f
}
func (f *integration) op(t *testing.T, index int) (context.Context, *adminaction.Operation) {
	t.Helper()
	op, err := f.actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{ActorID: f.actors[index].ID, EventType: "legal.case.fixture", ActionStatus: audit.StatusSuccess}
	t.Cleanup(func() { _ = op.Rollback(context.Background()) })
	ctx := session.WithSession(f.ctx, session.Session{UserID: f.actors[index].ID.String(), Kind: session.KindAuthenticated, AuthVersion: f.actors[index].AuthVersion, AuthVersionSet: true})
	return adminaction.WithContext(ctx, op), op
}
func commit(ctx context.Context, t *testing.T, op *adminaction.Operation) {
	t.Helper()
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
func (f *integration) create(t *testing.T, subjects ...uuid.UUID) (MutationResult, CreateRequest) {
	t.Helper()
	r := CreateRequest{Key: uuid.New(), ReceivedAt: time.Now().UTC().Add(-time.Minute), Content: fixtureContent(), SubjectIDs: subjects}
	ctx, op := f.op(t, 0)
	result, err := f.service.Create(ctx, f.actors[0], r)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	return result, r
}
func (f *integration) review(t *testing.T, c MutationResult, decision string) MutationResult {
	t.Helper()
	ctx, op := f.op(t, 0)
	r, err := f.service.Review(ctx, f.actors[0], ReviewRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: c.ContentRevision, Decision: decision, Rationale: "fixture review"})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	return r
}
func (f *integration) prepared(t *testing.T) (MutationResult, ResponseRequest) {
	t.Helper()
	subject := uuid.New()
	c, _ := f.create(t, subject)
	c = f.review(t, c, "accepted")
	r := fixtureResponse(c.ID, subject)
	r.ExpectedVersion = c.Version
	ctx, op := f.op(t, 0)
	c, err := f.service.PrepareResponse(ctx, f.actors[0], r)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	return c, r
}
func (f *integration) approve(t *testing.T, c MutationResult) MutationResult {
	t.Helper()
	ctx, op := f.op(t, 1)
	r, err := f.service.ApproveResponse(ctx, f.actors[1], ApprovalRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: c.ContentRevision, ProposalRevision: c.ProposalRevision})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	return r
}
func (f *integration) counters(t *testing.T) (int64, int64) {
	t.Helper()
	var received, answered int64
	if err := f.pool.QueryRow(f.ctx, `SELECT COALESCE(sum(received),0)::bigint,COALESCE(sum(answered),0)::bigint FROM legal_transparency_months`).Scan(&received, &answered); err != nil {
		t.Fatal(err)
	}
	return received, answered
}

func TestWorkflowFinalDeliveryAndExactReplayIntegration(t *testing.T) {
	f := integrationFixture(t)
	received, answered := f.counters(t)
	c, proposal := f.prepared(t)
	ctx, self := f.op(t, 0)
	if _, err := f.service.ApproveResponse(ctx, f.actors[0], ApprovalRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: c.ContentRevision, ProposalRevision: c.ProposalRevision}); err == nil {
		t.Fatal("self approval allowed")
	}
	_ = self.Rollback(ctx)
	c = f.approve(t, c)
	// Content and proposal revisions survive review/approval bookkeeping.
	if c.ContentRevision != 1 || c.ProposalRevision != 1 || c.Version != 4 {
		t.Fatalf("revisions=%+v", c)
	}
	req := DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: time.Now().UTC(), ReceiptReference: "fixture-receipt"}
	ctx, op := f.op(t, 2)
	delivered, err := f.service.DeliverResponse(ctx, f.actors[2], req)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 2)
	replayed, err := f.service.DeliverResponse(ctx, f.actors[2], req)
	if err != nil || !replayed.Replayed || replayed.Version != delivered.Version {
		t.Fatalf("replay=%+v error=%v", replayed, err)
	}
	commit(ctx, t, op)
	req.ReceiptReference = "different receipt"
	ctx, op = f.op(t, 2)
	if _, err = f.service.DeliverResponse(ctx, f.actors[2], req); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay=%v", err)
	}
	_ = op.Rollback(ctx)
	r, a := f.counters(t)
	if r != received+1 || a != answered+1 {
		t.Fatalf("counters received=%d answered=%d", r-received, a-answered)
	}
	ctx, op = f.op(t, 0)
	detail, err := f.service.Get(ctx, f.actors[0], c.ID)
	if err != nil || detail.Status != "closed" || detail.Response.Manifest.Artifacts[0].Digest != proposal.Manifest.Artifacts[0].Digest || len(detail.History) != 5 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 0)
	_, err = f.service.Close(ctx, f.actors[0], CloseRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: delivered.Version, Reason: "withdrawn", Rationale: "no reopening"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("closed transition=%v", err)
	}
	_ = op.Rollback(ctx)
}

func TestWorkflowAmendmentReviewAndNoAnswerIntegration(t *testing.T) {
	f := integrationFixture(t)
	_, before := f.counters(t)
	c, _ := f.create(t) // rejected and unmatched requests need no surviving account
	c = f.review(t, c, "rejected")
	ctx, op := f.op(t, 0)
	r, err := f.service.Close(ctx, f.actors[0], CloseRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Reason: "no_response_required", Rationale: "withdrawn fixture"})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	if r.Status != "closed" {
		t.Fatal(r)
	}
	_, after := f.counters(t)
	if after != before {
		t.Fatal("closure counted an answer")
	}
	c, proposal := f.prepared(t)
	c = f.approve(t, c)
	ctx, op = f.op(t, 0)
	c, err = f.service.Revise(ctx, f.actors[0], RevisionRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Content: fixtureContent(), SubjectIDs: proposal.Manifest.SubjectIDs})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	if c.Decision != "pending" || c.ContentRevision != 2 {
		t.Fatal(c)
	}
	proposal.Key = uuid.New()
	proposal.ExpectedVersion = c.Version
	proposal.ContentRevision = c.ContentRevision
	ctx, op = f.op(t, 0)
	if _, err = f.service.PrepareResponse(ctx, f.actors[0], proposal); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreviewed amendment=%v", err)
	}
	_ = op.Rollback(ctx)
	c = f.review(t, c, "needs_information")
	proposal.ExpectedVersion = c.Version
	ctx, op = f.op(t, 0)
	if _, err = f.service.PrepareResponse(ctx, f.actors[0], proposal); !errors.Is(err, ErrConflict) {
		t.Fatalf("needs information disclosure=%v", err)
	}
	_ = op.Rollback(ctx)
	c = f.review(t, c, "accepted")
	proposal.ExpectedVersion = c.Version
	ctx, op = f.op(t, 0)
	c, err = f.service.PrepareResponse(ctx, f.actors[0], proposal)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	if c.ProposalRevision != 2 {
		t.Fatal("proposal overwritten")
	}
}

func TestWorkflowAuditRollbackAndCreateIdempotencyIntegration(t *testing.T) {
	f := integrationFixture(t)
	before, _ := f.counters(t)
	c, r := f.create(t)
	ctx, op := f.op(t, 1)
	same, err := f.service.Create(ctx, f.actors[1], r)
	if err != nil || !same.Replayed || same.ID != c.ID {
		t.Fatalf("replay=%+v %v", same, err)
	}
	commit(ctx, t, op)
	r.Content.RequestReference = "changed"
	ctx, op = f.op(t, 1)
	if _, err = f.service.Create(ctx, f.actors[1], r); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed body=%v", err)
	}
	_ = op.Rollback(ctx)
	r.Key = uuid.New()
	ctx, op = f.op(t, 0)
	// This real outbox insertion failure must roll back counters and case alike.
	_, err = op.Tx.Exec(ctx, `CREATE FUNCTION pg_temp.workflow_reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = op.Tx.Exec(ctx, `CREATE TRIGGER workflow_fixture_reject BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.workflow_reject_outbox()`)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := f.service.Create(ctx, f.actors[0], r)
	if err != nil {
		t.Fatal(err)
	}
	if err = op.Commit(ctx); !errors.Is(err, adminaction.ErrUnavailable) {
		t.Fatalf("commit=%v", err)
	}
	var exists bool
	if err = f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM legal_cases WHERE id=$1)`, failed.ID).Scan(&exists); err != nil || exists {
		t.Fatalf("case survived audit failure: %v %v", exists, err)
	}
	after, _ := f.counters(t)
	if after != before+1 {
		t.Fatalf("counter audit rollback delta=%d", after-before)
	}
}

func (f *integration) waitBlocked(t *testing.T, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		var waiting bool
		err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, pid).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("no observed advisory lock wait")
		case <-timer.C:
		}
	}
}
func TestWorkflowCompetingReviewsIntegration(t *testing.T) {
	f := integrationFixture(t)
	c, _ := f.create(t, uuid.New())
	r := ReviewRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, Decision: "accepted", Rationale: "first review"}
	ctx1, op1 := f.op(t, 0)
	if _, err := f.service.Review(ctx1, f.actors[0], r); err != nil {
		t.Fatal(err)
	}
	r.Key = uuid.New()
	r.Decision = "rejected"
	ctx2, op2 := f.op(t, 1)
	done := make(chan error, 1)
	go func() { _, err := f.service.Review(ctx2, f.actors[1], r); done <- err }()
	f.waitBlocked(t, op2.Tx.Conn().PgConn().PID())
	commit(ctx1, t, op1)
	if err := <-done; !errors.Is(err, ErrConflict) {
		t.Fatalf("stale review=%v", err)
	}
	_ = op2.Rollback(ctx2)
}

func TestWorkflowStoredApproverRevocationLockOrdersIntegration(t *testing.T) {
	for _, releaseFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(releaseFirst), func(t *testing.T) {
			f := integrationFixture(t)
			c, _ := f.prepared(t)
			c = f.approve(t, c)
			r := DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: time.Now().UTC(), ReceiptReference: "fixture-release"}
			ctx, delivery := f.op(t, 2)
			revoke, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = revoke.Rollback(context.Background()) }()
			if releaseFirst {
				if _, err = f.service.DeliverResponse(ctx, f.actors[2], r); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					err := pglock.LockAccount(f.ctx, revoke, f.actors[1].ID)
					if err == nil {
						_, err = revoke.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id='dpo'`, f.actors[1].ID)
					}
					done <- err
				}()
				f.waitBlocked(t, revoke.Conn().PgConn().PID())
				commit(ctx, t, delivery)
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				if err = revoke.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = pglock.LockAccount(f.ctx, revoke, f.actors[1].ID); err != nil {
					t.Fatal(err)
				}
				if _, err = revoke.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id='dpo'`, f.actors[1].ID); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := f.service.DeliverResponse(ctx, f.actors[2], r); done <- err }()
				f.waitBlocked(t, delivery.Tx.Conn().PgConn().PID())
				if err = revoke.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err == nil {
					t.Fatal("revoked approver released response")
				}
				_ = delivery.Rollback(ctx)
			}
		})
	}
}
func TestWorkflowAuthVersionAndCryptoImmutabilityIntegration(t *testing.T) {
	f := integrationFixture(t)
	c, _ := f.prepared(t)
	c = f.approve(t, c)
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, f.actors[1].ID); err != nil {
		t.Fatal(err)
	}
	ctx, op := f.op(t, 2)
	_, err := f.service.DeliverResponse(ctx, f.actors[2], DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: time.Now().UTC(), ReceiptReference: "fixture"})
	if err == nil {
		t.Fatal("stale approver auth version accepted")
	}
	_ = op.Rollback(ctx)
	if _, err = f.pool.Exec(f.ctx, `UPDATE legal_workflow_events SET body_encrypted=body_encrypted WHERE scope=$1`, c.ID); err == nil {
		t.Fatal("history update allowed")
	}
	other, _ := f.create(t)
	if _, err = f.pool.Exec(f.ctx, `UPDATE legal_cases SET content_event=(SELECT content_event FROM legal_cases WHERE id=$2) WHERE id=$1`, c.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 0)
	if _, err = f.service.Get(ctx, f.actors[0], c.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cipher transplant=%v", err)
	}
	_ = op.Rollback(ctx)
}

// Each login is real, not SET ROLE. Provisioning uses only the disposable owner.
func (f *integration) maintenance(t *testing.T) (*pgxpool.Pool, *adminaction.Service) {
	t.Helper()
	name := "wf_maintenance_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := uuid.NewString()
	_, err := f.pool.Exec(f.ctx, `CREATE ROLE `+pgx.Identifier{name}.Sanitize()+` LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`)
	if err != nil {
		t.Fatal(err)
	}
	grants := []string{
		`GRANT USAGE ON SCHEMA public TO ` + pgx.Identifier{name}.Sanitize(),
		`GRANT SELECT,UPDATE ON legal_cases TO ` + pgx.Identifier{name}.Sanitize(),
		`GRANT SELECT,UPDATE(erased,event_id) ON legal_workflow_replays TO ` + pgx.Identifier{name}.Sanitize(),
		`GRANT SELECT,DELETE ON legal_workflow_events,legal_case_subjects,legal_case_holds,legal_hold_reviews TO ` + pgx.Identifier{name}.Sanitize(),
		`GRANT SELECT ON legal_holds,legal_governance_policies,legal_governance_baseline TO ` + pgx.Identifier{name}.Sanitize(),
		`GRANT INSERT ON event_outbox TO ` + pgx.Identifier{name}.Sanitize(),
	}
	for _, sql := range grants {
		if _, err = f.pool.Exec(f.ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = name
	cfg.ConnConfig.Password = password
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = f.pool.Exec(context.Background(), `DROP OWNED BY `+pgx.Identifier{name}.Sanitize())
		_, _ = f.pool.Exec(context.Background(), `DROP ROLE `+pgx.Identifier{name}.Sanitize())
	})
	actions, err := adminaction.New(pool, f.service.encryptor, "identity.audit.workflow-maintenance", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = ProbeMaintenance(f.ctx, tx)
	_ = tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal("maintenance grant probe:", err)
	}
	return pool, actions
}

func (f *integration) applyHold(t *testing.T, subject uuid.UUID) (*legalhold.Service, legalhold.ApplyRequest, uuid.UUID) {
	t.Helper()
	svc, err := legalhold.New(db.New(f.pool), f.service.encryptor, legalhold.WithReleasedMetadataRetention(f.policy.ReleasedHoldRetention()))
	if err != nil {
		t.Fatal(err)
	}
	req := legalhold.ApplyRequest{AccountRef: subject, AppliedBy: f.actors[0].ID, IdempotencyKey: uuid.New(), Reason: "fixture hold", RequestingAuthority: "fixture authority", LegalBasis: "fixture law", ReviewAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)}
	ctx, op := f.op(t, 0)
	r, err := svc.Apply(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	return svc, req, r.Hold.Record.ID
}
func TestWorkflowHistoricalHoldsExpiryAndCleanupIntegration(t *testing.T) {
	f := integrationFixture(t)
	subject := uuid.New()
	holdSvc, _, holdID := f.applyHold(t, subject)
	c, intake := f.create(t, subject, uuid.New())
	ctx, op := f.op(t, 0)
	c, err := f.service.Revise(ctx, f.actors[0], RevisionRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Content: fixtureContent()})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	other, _ := f.create(t)
	var expiry time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT max(expires_at) FROM legal_cases WHERE id=ANY($1::uuid[])`, []uuid.UUID{c.ID, other.ID}).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return expiry }
	ctx, op = f.op(t, 0)
	if _, err = f.service.Get(ctx, f.actors[0], c.ID); err != nil {
		t.Fatal("historic held read:", err)
	}
	commit(ctx, t, op)
	pool, actions := f.maintenance(t)
	maint, _ := New(f.service.encryptor, Config{Environment: "test"})
	maint.now = f.service.now
	actor := Actor{ID: uuid.New()}
	receiptCount := func() int64 {
		var n int64
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM event_outbox`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := receiptCount()
	dry, err := maint.Cleanup(f.ctx, pool, actions, actor, "spiffe://identity.test/maintenance", 500, true)
	if err != nil || dry.WouldDelete < 1 {
		t.Fatalf("dry=%+v %v", dry, err)
	}
	if receiptCount() != before {
		t.Fatal("dry run committed receipt")
	}
	result, err := maint.Cleanup(f.ctx, pool, actions, actor, "spiffe://identity.test/maintenance", 500, false)
	if err != nil || result.Deleted < 1 {
		t.Fatalf("cleanup=%+v %v", result, err)
	}
	var status string
	if err = f.pool.QueryRow(f.ctx, `SELECT status FROM legal_cases WHERE id=$1`, c.ID).Scan(&status); err != nil || status == "erased" {
		t.Fatal("historic subject hold bypass")
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT status FROM legal_cases WHERE id=$1`, other.ID).Scan(&status); err != nil || status != "erased" {
		t.Fatal("held candidate starved next eligible")
	}
	ctx, op = f.op(t, 0)
	if _, err = holdSvc.Release(ctx, holdID, f.actors[0].ID); err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 0)
	if _, err = f.service.Get(ctx, f.actors[0], c.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("exact expiry=%v", err)
	}
	_ = op.Rollback(ctx)
	if _, err = maint.Cleanup(f.ctx, pool, actions, actor, "spiffe://identity.test/maintenance", 500, false); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 0)
	if _, err = f.service.Create(ctx, f.actors[0], intake); !errors.Is(err, ErrErased) {
		t.Fatalf("erased recreate=%v", err)
	}
	_ = op.Rollback(ctx)
	var histories, subjects, liveReplay int64
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM legal_workflow_events WHERE scope=$1),(SELECT count(*) FROM legal_case_subjects WHERE case_id=$1),(SELECT count(*) FROM legal_workflow_replays WHERE result_id=$1 AND (NOT erased OR event_id IS NOT NULL))`, c.ID).Scan(&histories, &subjects, &liveReplay); err != nil || histories+subjects+liveReplay != 0 {
		t.Fatalf("erasure leaked history=%d subjects=%d replay=%d err=%v", histories, subjects, liveReplay, err)
	}
}

func TestWorkflowStandaloneHoldReviewIntegration(t *testing.T) {
	f := integrationFixture(t)
	subject := uuid.New()
	holdSvc, original, holdID := f.applyHold(t, subject)
	next := time.Now().UTC().Add(-time.Minute)
	r := HoldReviewRequest{Key: uuid.New(), HoldID: holdID, ExpectedVersion: 0, Decision: "continue", Rationale: "fixture advisory only", NextReviewAt: &next}
	ctx, op := f.op(t, 0)
	review, err := f.service.ReviewHold(ctx, f.actors[0], r)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 0)
	again, err := holdSvc.Apply(ctx, original)
	if err != nil || !again.Replayed || !again.Hold.Record.ReviewAt.Time.Equal(original.ReviewAt) {
		t.Fatalf("original hold replay=%+v %v", again, err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 0)
	q, err := f.service.DueReviews(ctx, f.actors[0], ListRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range q.Items {
		if item.ID == holdID && item.Kind == "hold" && item.Version == review.Version {
			found = true
		}
	}
	if !found {
		t.Fatal("standalone review missing")
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 0)
	if _, err = holdSvc.Release(ctx, holdID, f.actors[0].ID); err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	var released time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT released_at FROM legal_holds WHERE id=$1`, holdID).Scan(&released); err != nil {
		t.Fatal(err)
	}
	cutoff := released.Add(f.policy.ReleasedHoldRetention())
	f.service.now = func() time.Time { return cutoff }
	ctx, op = f.op(t, 0)
	if _, err = f.service.ReviewHold(ctx, f.actors[0], r); !errors.Is(err, ErrExpired) {
		t.Fatalf("standalone expiry=%v", err)
	}
	_ = op.Rollback(ctx)
	pool, actions := f.maintenance(t)
	maint, _ := New(f.service.encryptor, Config{Environment: "test"})
	maint.now = f.service.now
	if _, err = maint.Cleanup(f.ctx, pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 500, false); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 0)
	if _, err = f.service.ReviewHold(ctx, f.actors[0], r); !errors.Is(err, ErrErased) {
		t.Fatalf("cleaned standalone replay=%v", err)
	}
	_ = op.Rollback(ctx)
	var preserved bool
	if err = f.pool.QueryRow(f.ctx, `SELECT review_at=$2 AND NOT is_active AND details_encrypted IS NOT NULL FROM legal_holds WHERE id=$1`, holdID, original.ReviewAt).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("original hold mutated %v %v", preserved, err)
	}
}

func TestWorkflowRealLoginPrivilegeBoundariesIntegration(t *testing.T) {
	f := integrationFixture(t)
	pool, actions := f.maintenance(t)
	var role string
	if err := pool.QueryRow(f.ctx, `SELECT current_user`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`UPDATE users SET status='active' WHERE false`,
		`DELETE FROM mvp_audit_logs WHERE false`,
		`DELETE FROM security_event_ledger WHERE false`,
		`TRUNCATE legal_workflow_events`,
		`INSERT INTO legal_cases(id,status,version) VALUES(gen_random_uuid(),'erased',0)`,
		`UPDATE legal_governance_policies SET artifact=artifact WHERE false`,
		`CREATE TABLE public.workflow_forbidden(id integer)`,
		`ALTER TABLE legal_cases DISABLE TRIGGER ALL`,
	} {
		if _, err := pool.Exec(f.ctx, sql); err == nil {
			t.Fatalf("maintenance allowed forbidden operation: %s", sql)
		}
	}
	// An elevated membership must fail even if NOINHERIT masks direct grants.
	var owner string
	if err := f.pool.QueryRow(f.ctx, `SELECT current_user`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `GRANT `+pgx.Identifier{owner}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = ProbeMaintenance(f.ctx, tx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("owner membership escaped probe")
	}
	_ = tx.Rollback(f.ctx)
	if _, err = f.pool.Exec(f.ctx, `REVOKE `+pgx.Identifier{owner}.Sanitize()+` FROM `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// Column-only grants do not appear as table UPDATE privileges.
	if _, err = f.pool.Exec(f.ctx, `GRANT UPDATE(auth_version) ON users TO `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = ProbeMaintenance(f.ctx, tx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("column privilege bypassed maintenance probe")
	}
	_ = tx.Rollback(f.ctx)
	if _, err = f.pool.Exec(f.ctx, `REVOKE UPDATE(auth_version) ON users FROM `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// Owner credentials cannot masquerade as metadata-maintenance credentials.
	if _, err = f.service.Cleanup(f.ctx, f.pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 1, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("owner cleanup probe=%v", err)
	}

	apiRole := "wf_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := uuid.NewString()
	quoted := pgx.Identifier{apiRole}.Sanitize()
	if _, err = f.pool.Exec(f.ctx, `CREATE ROLE `+quoted+` LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + quoted,
		`GRANT SELECT,UPDATE ON users TO ` + quoted,
		`GRANT SELECT ON roles,permissions,user_roles,role_permissions,legal_governance_policies,legal_governance_baseline TO ` + quoted,
		`GRANT SELECT,INSERT,UPDATE ON legal_cases,legal_case_subjects,legal_case_holds,legal_hold_reviews,legal_holds TO ` + quoted,
		`GRANT SELECT,INSERT ON legal_workflow_events,legal_workflow_replays TO ` + quoted,
		`GRANT INSERT ON event_outbox TO ` + quoted,
		`GRANT SELECT,INSERT,UPDATE ON legal_transparency_years,legal_transparency_months TO ` + quoted,
		`GRANT SELECT,INSERT ON legal_transparency_coverage TO ` + quoted,
		`GRANT EXECUTE ON FUNCTION legal_transparency_lock_year(integer),legal_transparency_count(timestamptz,text) TO ` + quoted,
	} {
		if _, err = f.pool.Exec(f.ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = apiRole
	cfg.ConnConfig.Password = password
	apiPool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		apiPool.Close()
		_, _ = f.pool.Exec(context.Background(), `DROP OWNED BY `+quoted)
		_, _ = f.pool.Exec(context.Background(), `DROP ROLE `+quoted)
	})
	apiActions, err := adminaction.New(apiPool, f.service.encryptor, "identity.audit.workflow-api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.actions = apiActions
	c, _ := f.create(t)
	if c.Status != "open" {
		t.Fatal("real API role cannot create")
	}
	for _, sql := range []string{`DELETE FROM legal_workflow_events WHERE false`, `UPDATE legal_workflow_replays SET erased=true WHERE false`, `INSERT INTO legal_governance_baseline(singleton,policy_id) VALUES(true,gen_random_uuid())`, `ALTER TABLE legal_cases DISABLE TRIGGER ALL`} {
		if _, err = apiPool.Exec(f.ctx, sql); err == nil {
			t.Fatalf("API privilege escape: %s", sql)
		}
	}
	if _, err = f.service.Cleanup(f.ctx, apiPool, apiActions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 1, true); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("API used maintenance=%v", err)
	}
}

func TestWorkflowRejectsNonDPOAndPolicyDisabledIntegration(t *testing.T) {
	f := integrationFixture(t)
	c, _ := f.create(t)
	for _, role := range []string{"super_admin", "moderator", "support"} {
		if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1`, f.actors[2].ID); err != nil {
			t.Fatal(err)
		}
		if err := db.New(f.pool).AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: f.actors[2].ID, RoleID: role}); err != nil {
			t.Fatal(err)
		}
		ctx, op := f.op(t, 2)
		if _, err := f.service.Get(ctx, f.actors[2], c.ID); err == nil {
			t.Fatalf("%s read allowed", role)
		}
		_ = op.Rollback(ctx)
	}
	f.service.cfg.Enabled = false
	ctx, op := f.op(t, 0)
	if _, err := f.service.Review(ctx, f.actors[0], ReviewRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, Decision: "accepted", Rationale: "fixture"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("disabled mutation=%v", err)
	}
	_ = op.Rollback(ctx)
	ctx, op = f.op(t, 0)
	if _, err := f.service.Get(ctx, f.actors[0], c.ID); err != nil {
		t.Fatal("disabled intake blocked read:", err)
	}
	commit(ctx, t, op)
}

func TestWorkflowCleanupAndHoldLockOrdersIntegration(t *testing.T) {
	for _, cleanupFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(cleanupFirst), func(t *testing.T) {
			f := integrationFixture(t)
			subject := uuid.New()
			c, _ := f.create(t, subject)
			var cutoff time.Time
			if err := f.pool.QueryRow(f.ctx, `SELECT expires_at FROM legal_cases WHERE id=$1`, c.ID).Scan(&cutoff); err != nil {
				t.Fatal(err)
			}
			_, actions := f.maintenance(t)
			maint, _ := New(f.service.encryptor, Config{Environment: "test"})
			cleanup, err := actions.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cleanup.Rollback(context.Background()) }()
			if err = ProbeMaintenance(f.ctx, cleanup.Tx); err != nil {
				t.Fatal(err)
			}
			holds, err := legalhold.New(db.New(f.pool), f.service.encryptor, legalhold.WithReleasedMetadataRetention(f.policy.ReleasedHoldRetention()))
			if err != nil {
				t.Fatal(err)
			}
			ctx, holdOp := f.op(t, 1)
			req := legalhold.ApplyRequest{AccountRef: subject, AppliedBy: f.actors[1].ID, IdempotencyKey: uuid.New(), Reason: "racing hold", RequestingAuthority: "fixture court", LegalBasis: "fixture law"}
			if cleanupFirst {
				erased, held, err := maint.cleanupRecord(f.ctx, cleanup.Tx, c.ID, "case", cutoff, false)
				if err != nil || !erased || held {
					t.Fatalf("cleanup=%v held=%v err=%v", erased, held, err)
				}
				done := make(chan error, 1)
				go func() { _, err := holds.Apply(ctx, req); done <- err }()
				f.waitBlocked(t, holdOp.Tx.Conn().PgConn().PID())
				cleanup.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/maintenance", EventType: "legal.case.cleaned", ActionStatus: audit.StatusSuccess, Payload: map[string]any{"deleted_count": 1}}
				commit(f.ctx, t, cleanup)
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				commit(ctx, t, holdOp)
				var status string
				if err = f.pool.QueryRow(f.ctx, `SELECT status FROM legal_cases WHERE id=$1`, c.ID).Scan(&status); err != nil || status != "erased" {
					t.Fatal("late hold restored erased data")
				}
			} else {
				if _, err = holds.Apply(ctx, req); err != nil {
					t.Fatal(err)
				}
				type outcome struct {
					erased, held bool
					err          error
				}
				done := make(chan outcome, 1)
				go func() {
					erased, held, err := maint.cleanupRecord(f.ctx, cleanup.Tx, c.ID, "case", cutoff, false)
					done <- outcome{erased, held, err}
				}()
				f.waitBlocked(t, cleanup.Tx.Conn().PgConn().PID())
				commit(ctx, t, holdOp)
				result := <-done
				if result.err != nil || result.erased || !result.held {
					t.Fatalf("hold-first cleanup=%+v", result)
				}
			}
		})
	}
}

func TestWorkflowCleanupRejectsChangedLockSetIntegration(t *testing.T) {
	f := integrationFixture(t)
	subject, nextSubject := uuid.New(), uuid.New()
	c, _ := f.create(t, subject)
	var cutoff time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT expires_at FROM legal_cases WHERE id=$1`, c.ID).Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	_, actions := f.maintenance(t)
	cleanup, err := actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup.Rollback(context.Background()) }()
	change, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = change.Rollback(context.Background()) }()
	if err = pglock.LockAccount(f.ctx, change, subject); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := f.service.cleanupRecord(f.ctx, cleanup.Tx, c.ID, "case", cutoff, false)
		done <- err
	}()
	f.waitBlocked(t, cleanup.Tx.Conn().PgConn().PID())
	if _, err = change.Exec(f.ctx, `INSERT INTO legal_case_subjects(case_id,account_ref,current) VALUES($1,$2,true)`, c.ID, nextSubject); err != nil {
		t.Fatal(err)
	}
	if _, err = change.Exec(f.ctx, `UPDATE legal_cases SET version=version+1 WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if err = change.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrConflict) {
		t.Fatalf("changed discovered set=%v", err)
	}
}

func TestWorkflowConcurrentCreateReplayIntegration(t *testing.T) {
	f := integrationFixture(t)
	r := CreateRequest{Key: uuid.New(), Content: fixtureContent(), ReceivedAt: time.Now().UTC().Add(-time.Minute)}
	ctx1, op1 := f.op(t, 0)
	first, err := f.service.Create(ctx1, f.actors[0], r)
	if err != nil {
		t.Fatal(err)
	}
	ctx2, op2 := f.op(t, 1)
	type outcome struct {
		r   MutationResult
		err error
	}
	done := make(chan outcome, 1)
	go func() { r, err := f.service.Create(ctx2, f.actors[1], r); done <- outcome{r, err} }()
	f.waitBlocked(t, op2.Tx.Conn().PgConn().PID())
	commit(ctx1, t, op1)
	got := <-done
	if got.err != nil || !got.r.Replayed || got.r.ID != first.ID {
		t.Fatalf("concurrent intake=%+v", got)
	}
	commit(ctx2, t, op2)
}

func TestWorkflowDeletedSubjectsHistoricLimitAndAssociationsIntegration(t *testing.T) {
	f := integrationFixture(t)
	u, err := db.New(f.pool).CreateUser(f.ctx, db.CreateUserParams{Email: uuid.NewString() + "@deleted-workflow.test", Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := f.create(t, u.ID)
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM users WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	ctx, op := f.op(t, 0)
	detail, err := f.service.Get(ctx, f.actors[0], c.ID)
	if err != nil || len(detail.SubjectIDs) != 1 || detail.SubjectIDs[0] != u.ID {
		t.Fatalf("deleted subject=%+v %v", detail, err)
	}
	commit(ctx, t, op)
	_, _, holdID := f.applyHold(t, uuid.New())
	ctx, op = f.op(t, 0)
	if _, err = f.service.Revise(ctx, f.actors[0], RevisionRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Content: fixtureContent(), SubjectIDs: []uuid.UUID{u.ID}, HoldIDs: []uuid.UUID{holdID}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("mismatched hold=%v", err)
	}
	_ = op.Rollback(ctx)
	subjects := make([]uuid.UUID, 100)
	for i := range subjects {
		subjects[i] = uuid.New()
	}
	c, _ = f.create(t, subjects...)
	ctx, op = f.op(t, 0)
	if _, err = f.service.Revise(ctx, f.actors[0], RevisionRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Content: fixtureContent(), SubjectIDs: []uuid.UUID{uuid.New()}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("historic union overflow=%v", err)
	}
	_ = op.Rollback(ctx)
}

func TestWorkflowApprovalAndDeliveryAuditRollbackIntegration(t *testing.T) {
	f := integrationFixture(t)
	c, _ := f.prepared(t)
	for _, phase := range []string{"approve", "deliver"} {
		if phase == "deliver" {
			c = f.approve(t, c)
		}
		actor := 1
		if phase == "deliver" {
			actor = 2
		}
		ctx, op := f.op(t, actor)
		if _, err := op.Tx.Exec(ctx, `CREATE FUNCTION pg_temp.workflow_reject_transition() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := op.Tx.Exec(ctx, `CREATE TRIGGER workflow_fixture_transition BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.workflow_reject_transition()`); err != nil {
			t.Fatal(err)
		}
		_, before := f.counters(t)
		var err error
		if phase == "approve" {
			_, err = f.service.ApproveResponse(ctx, f.actors[actor], ApprovalRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1})
		} else {
			_, err = f.service.DeliverResponse(ctx, f.actors[actor], DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: time.Now().UTC(), ReceiptReference: "fixture"})
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = op.Commit(ctx); !errors.Is(err, adminaction.ErrUnavailable) {
			t.Fatalf("%s audit failure=%v", phase, err)
		}
		check, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := load(f.ctx, check, c.ID, false)
		_ = check.Rollback(f.ctx)
		if err != nil || stored.Version != c.Version || stored.Status != "open" {
			t.Fatalf("%s state survived rollback %+v %v", phase, stored, err)
		}
		_, after := f.counters(t)
		if before != after {
			t.Fatal("answer counter survived audit rollback")
		}
	}
}

func TestWorkflowDeliveryChronologyIntegration(t *testing.T) {
	f := integrationFixture(t)
	subject := uuid.New()
	intake := CreateRequest{Key: uuid.New(), ReceivedAt: time.Now().UTC().Add(-24 * time.Hour), Content: fixtureContent(), SubjectIDs: []uuid.UUID{subject}}
	ctx, op := f.op(t, 0)
	c, err := f.service.Create(ctx, f.actors[0], intake)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	c = f.review(t, c, "accepted")
	proposal := fixtureResponse(c.ID, subject)
	proposal.ExpectedVersion = c.Version
	ctx, op = f.op(t, 0)
	c, err = f.service.PrepareResponse(ctx, f.actors[0], proposal)
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	c = f.approve(t, c)
	var approvedAt time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT created_at FROM legal_workflow_events WHERE scope=$1 AND purpose='approve' ORDER BY revision DESC LIMIT 1`, c.ID).Scan(&approvedAt); err != nil {
		t.Fatal(err)
	}
	_, before := f.counters(t)
	for _, when := range []time.Time{intake.ReceivedAt, approvedAt.UTC().Add(-time.Microsecond)} {
		ctx, op = f.op(t, 2)
		_, err = f.service.DeliverResponse(ctx, f.actors[2], DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: when, ReceiptReference: "chronology fixture"})
		if !errors.Is(err, ErrConflict) {
			t.Fatalf("delivery before authority accepted: %v", err)
		}
		_ = op.Rollback(ctx)
	}
	_, after := f.counters(t)
	if before != after {
		t.Fatal("invalid chronology counted an answer")
	}
	ctx, op = f.op(t, 2)
	result, err := f.service.DeliverResponse(ctx, f.actors[2], DeliveryRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, ContentRevision: 1, ProposalRevision: 1, DeliveredAt: time.Now().UTC(), ReceiptReference: "postapproval fixture"})
	if err != nil || result.Status != "closed" {
		t.Fatalf("valid chronology=%+v %v", result, err)
	}
	commit(ctx, t, op)
}
