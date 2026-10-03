//go:build integration

package legalreport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/migrate"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Reports have no restricted narratives. Any attempt to create an encrypted
// admin context is a privacy regression, not something this fixture should hide.
type rejectContextEncryption struct{}

func (rejectContextEncryption) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("reporting must not create restricted action context")
}

type reportFixture struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	actions *adminaction.Service
	service *Service
	actors  [3]Actor
	policy  legalpolicy.Policy
	dsn     string
	year    int
}

func newReportFixture(t *testing.T) *reportFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for legalreport integration, including REQUIRE_LEGAL_WORKFLOW_INTEGRATION=1; use disposable PostgreSQL")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("DATABASE_URL must be a PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "legal_report_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	// Only this randomly created database is migrated or dropped. The database
	// named in DATABASE_URL is only the connection used to create it.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, err := admin.Exec(cleanup, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`)
		admin.Close()
		if err != nil {
			t.Error(err)
		}
	})
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
	cfg.MaxConns = 10
	// Admin operations must override an unsafe connection default, particularly
	// when a fresh statement snapshot is needed after a blocked lock.
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	actions, err := adminaction.New(pool, rejectContextEncryption{}, "identity.audit.report-fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := legalpolicy.Policy{ID: uuid.New(), ApprovalReference: "fixture-report-not-production", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 3600,
		ContextClock: legalpolicy.ClockCreatedAt, ReleasedHoldClock: legalpolicy.ClockReleasedAt,
		HoldTombstoneFields: legalpolicy.HoldTombstoneFields(), HoldTombstoneLifetime: legalpolicy.LifetimeNoExpiry,
		LegacyInventoryReference: "fixture-inventory",
		Workflow: &legalpolicy.WorkflowPolicy{MaxCaseAgeSeconds: 86400, ClosedCaseRetentionSeconds: 3600,
			CaseClock: legalpolicy.ClockCaseExpiry, ReplayFields: legalpolicy.WorkflowReplayFields(), ReplayLifetime: legalpolicy.LifetimeNoExpiry}}
	op, err := actions.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/report-fixture"}
	if err = legalpolicy.Install(ctx, op, p, "test"); err != nil {
		_ = op.Rollback(ctx)
		t.Fatal(err)
	}
	commitReport(ctx, t, op)
	svc, err := New(Config{Enabled: true, PolicyID: p.ID, Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	f := &reportFixture{ctx: ctx, pool: pool, actions: actions, service: svc, policy: p, dsn: dsn, year: time.Now().UTC().Year() - 1}
	for i := range f.actors {
		u, err := db.New(pool).CreateUser(ctx, db.CreateUserParams{Email: uuid.NewString() + "@report.test", Status: "active"})
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

func (f *reportFixture) op(t *testing.T, actor int) (context.Context, *adminaction.Operation) {
	t.Helper()
	op, err := f.actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{ActorID: f.actors[actor].ID, EventType: "legal.transparency.fixture", ActionStatus: audit.StatusSuccess,
		Payload: map[string]any{"operation": "POST /api/v1/admin/legal-transparency/reports"}}
	t.Cleanup(func() { _ = op.Rollback(context.Background()) })
	ctx := session.WithSession(f.ctx, session.Session{UserID: f.actors[actor].ID.String(), Kind: session.KindAuthenticated, AuthVersion: f.actors[actor].AuthVersion, AuthVersionSet: true})
	return adminaction.WithContext(ctx, op), op
}

func commitReport(ctx context.Context, t *testing.T, op *adminaction.Operation) {
	t.Helper()
	if err := op.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f *reportFixture) count(t *testing.T, at time.Time, categories ...string) {
	t.Helper()
	ctx, op := f.op(t, 0)
	for _, category := range categories {
		var err error
		if category == "received" {
			err = CountReceived(ctx, op.Tx, at)
		} else {
			err = CountAnswered(ctx, op.Tx, at, category)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	commitReport(ctx, t, op)
}

func (f *reportFixture) prepare(t *testing.T) (Report, PrepareRequest) {
	t.Helper()
	req := PrepareRequest{Key: uuid.New(), Year: f.year}
	ctx, op := f.op(t, 0)
	report, err := f.service.PrepareReport(ctx, f.actors[0], req)
	if err != nil {
		t.Fatal(err)
	}
	commitReport(ctx, t, op)
	return report, req
}

func approvalFor(r Report) ApproveRequest {
	return ApproveRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version, DataVersion: r.DataVersion, PolicyVersion: r.PolicyVersion, Digest: r.Digest}
}

func (f *reportFixture) approve(t *testing.T, r Report) (Report, ApproveRequest) {
	t.Helper()
	req := approvalFor(r)
	ctx, op := f.op(t, 1)
	r, err := f.service.ApproveReport(ctx, f.actors[1], req)
	if err != nil {
		t.Fatal(err)
	}
	commitReport(ctx, t, op)
	return r, req
}

func (f *reportFixture) scalar(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := f.pool.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func failReportAudit(ctx context.Context, t *testing.T, op *adminaction.Operation) {
	t.Helper()
	if _, err := op.Tx.Exec(ctx, `CREATE FUNCTION pg_temp.report_reject_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := op.Tx.Exec(ctx, `CREATE TRIGGER report_fixture_reject BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION pg_temp.report_reject_outbox()`); err != nil {
		t.Fatal(err)
	}
}

func TestReportingCoverageBeginsWithCommittedCountIntegration(t *testing.T) {
	f := newReportFixture(t)
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_coverage`); n != 0 {
		t.Fatal("migration fabricated reporting coverage")
	}
	ctx, op := f.op(t, 0)
	monthly, err := f.service.Monthly(ctx, f.actors[0], MonthlyRequest{Start: time.Date(f.year, 1, 1, 0, 0, 0, 0, time.UTC), Months: 12})
	if err != nil || !monthly.CoverageStart.IsZero() || !monthly.LateEntriesPossible || len(monthly.Months) != 12 {
		t.Fatalf("empty coverage=%+v %v", monthly, err)
	}
	commitReport(ctx, t, op)
	empty, _ := f.prepare(t)
	if a := assertPrivateArtifact(t, empty.Payload); a.Coverage.Status != "no_coverage" {
		t.Fatalf("empty report claims collection: %+v", a)
	}
	at := time.Date(f.year, 2, 1, 0, 0, 0, 0, time.UTC)
	ctx, op = f.op(t, 0)
	failReportAudit(ctx, t, op)
	if err = CountReceived(ctx, op.Tx, at); err != nil {
		t.Fatal(err)
	}
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_coverage`); n != 0 {
		t.Fatal("uncommitted count exposed coverage")
	}
	if err = op.Commit(ctx); !errors.Is(err, adminaction.ErrUnavailable) {
		t.Fatalf("audit failure=%v", err)
	}
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_coverage`); n != 0 {
		t.Fatal("failed intake persisted coverage")
	}
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_months`); n != 0 {
		t.Fatal("failed intake persisted count")
	}
	var before, started, after time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	f.count(t, at, "received")
	if err = f.pool.QueryRow(f.ctx, `SELECT started_at,clock_timestamp() FROM legal_transparency_coverage`).Scan(&started, &after); err != nil {
		t.Fatal(err)
	}
	if started.Before(before) || started.After(after) || !started.After(at) {
		t.Fatalf("coverage backdated to received time: start=%v bounds=%v..%v", started, before, after)
	}
	f.count(t, at.AddDate(-1, 0, 0), "received")
	var unchanged time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT started_at FROM legal_transparency_coverage`).Scan(&unchanged); err != nil || !unchanged.Equal(started) {
		t.Fatalf("late entry rebound coverage: %v %v", unchanged, err)
	}
}

func TestReportingMonthlyUsesSeparateUTCCohortsIntegration(t *testing.T) {
	f := newReportFixture(t)
	// Local January 1 is still December in UTC.
	receivedAt := time.Date(f.year, 1, 1, 1, 0, 0, 0, time.FixedZone("fixture", 2*60*60))
	f.count(t, receivedAt, "received")
	f.count(t, time.Date(f.year, 1, 2, 0, 0, 0, 0, time.UTC), "full_disclosure", "partial_disclosure", "no_responsive_data", "refusal", "preservation_acknowledgement")
	ctx, op := f.op(t, 0)
	start := time.Date(f.year-1, 12, 1, 0, 0, 0, 0, time.UTC)
	result, err := f.service.Monthly(ctx, f.actors[0], MonthlyRequest{Start: start, Months: 3})
	if err != nil || len(result.Months) != 3 {
		t.Fatalf("monthly=%+v %v", result, err)
	}
	commitReport(ctx, t, op)
	if !result.Months[0].Month.Equal(start) || result.Months[0].Received != 1 || result.Months[0].Answered != 0 {
		t.Fatalf("received cohort=%+v", result.Months[0])
	}
	want := Totals{Answered: 5, FullDisclosure: 1, PartialDisclosure: 1, NoResponsiveData: 1, Refusal: 1, PreservationAcknowledgement: 1}
	if result.Months[1].Totals != want || result.Months[2].Totals != (Totals{}) {
		t.Fatalf("delivery/empty cohorts=%+v", result.Months)
	}
	if n := f.scalar(t, `SELECT data_version FROM legal_transparency_years WHERE year=$1`, f.year); n != 5 {
		t.Fatalf("delivery data version=%d", n)
	}
	for _, req := range []MonthlyRequest{{Start: start, Months: 13}, {Start: start, Months: -1}, {Months: 1}} {
		ctx, op = f.op(t, 0)
		if _, err = f.service.Monthly(ctx, f.actors[0], req); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unbounded/invalid range accepted: %+v %v", req, err)
		}
		_ = op.Rollback(ctx)
	}
}

func TestReportingApprovalBindingAndExactReplayIntegration(t *testing.T) {
	f := newReportFixture(t)
	r, prepare := f.prepare(t)
	if r.Status != "prepared" || r.Version != 1 || r.PreparedBy != f.actors[0].ID || r.PolicyVersion != f.policy.ID || r.ApprovedBy != nil {
		t.Fatalf("prepared=%+v", r)
	}
	digest := sha256.Sum256(r.Payload)
	if r.Digest != hex.EncodeToString(digest[:]) {
		t.Fatal("digest does not bind exact payload bytes")
	}
	assertPrivateArtifact(t, r.Payload)
	ctx, op := f.op(t, 0)
	if _, err := f.service.ApproveReport(ctx, f.actors[0], approvalFor(r)); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("self approval=%v", err)
	}
	_ = op.Rollback(ctx)
	for _, field := range []string{"version", "data", "policy", "digest"} {
		req := approvalFor(r)
		switch field {
		case "version":
			req.ExpectedVersion++
		case "data":
			req.DataVersion++
		case "policy":
			req.PolicyVersion = uuid.New()
		case "digest":
			req.Digest = strings.Repeat("a", 64)
		}
		ctx, op = f.op(t, 1)
		if _, err := f.service.ApproveReport(ctx, f.actors[1], req); err == nil {
			t.Fatalf("approval ignored %s binding", field)
		}
		_ = op.Rollback(ctx)
	}
	ctx, op = f.op(t, 2)
	if _, err := f.service.DownloadReport(ctx, f.actors[2], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version}); err == nil {
		t.Fatal("unapproved artifact downloaded")
	}
	_ = op.Rollback(ctx)
	ctx, op = f.op(t, 0)
	again, err := f.service.PrepareReport(ctx, f.actors[0], prepare)
	if err != nil || !again.Replayed || again.ID != r.ID || !bytes.Equal(again.Payload, r.Payload) {
		t.Fatalf("prepare replay=%+v %v", again, err)
	}
	commitReport(ctx, t, op)
	changedPrepare := prepare
	changedPrepare.ExpectedVersion = 1
	ctx, op = f.op(t, 0)
	if _, err = f.service.PrepareReport(ctx, f.actors[0], changedPrepare); err == nil {
		t.Fatal("changed prepare replay accepted")
	}
	_ = op.Rollback(ctx)
	approved, approval := f.approve(t, r)
	if approved.Version != 2 || approved.Status != "approved" || approved.ApprovedBy == nil || *approved.ApprovedBy != f.actors[1].ID {
		t.Fatalf("approved=%+v", approved)
	}
	ctx, op = f.op(t, 1)
	again, err = f.service.ApproveReport(ctx, f.actors[1], approval)
	if err != nil || !again.Replayed || again.Version != approved.Version || !bytes.Equal(again.Payload, approved.Payload) {
		t.Fatalf("approval replay=%+v %v", again, err)
	}
	commitReport(ctx, t, op)
	changedApproval := approval
	changedApproval.Digest = strings.Repeat("b", 64)
	ctx, op = f.op(t, 1)
	if _, err = f.service.ApproveReport(ctx, f.actors[1], changedApproval); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed approval replay=%v", err)
	}
	_ = op.Rollback(ctx)
	download := DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: approved.Version}
	ctx, op = f.op(t, 2)
	artifact, err := f.service.DownloadReport(ctx, f.actors[2], download)
	if err != nil || artifact.Replayed || !bytes.Equal(artifact.Payload, r.Payload) {
		t.Fatalf("download=%+v %v", artifact, err)
	}
	commitReport(ctx, t, op)
	// Late entries cannot rewrite historical downloaded bytes on an exact retry.
	f.count(t, time.Date(f.year, 3, 1, 0, 0, 0, 0, time.UTC), "received")
	ctx, op = f.op(t, 2)
	replayed, err := f.service.DownloadReport(ctx, f.actors[2], download)
	if err != nil || !replayed.Replayed || !bytes.Equal(replayed.Payload, artifact.Payload) {
		t.Fatalf("historical download replay=%+v %v", replayed, err)
	}
	commitReport(ctx, t, op)
	download.ExpectedVersion++
	ctx, op = f.op(t, 2)
	if _, err = f.service.DownloadReport(ctx, f.actors[2], download); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed download replay=%v", err)
	}
	_ = op.Rollback(ctx)
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_replays`); n != 3 {
		t.Fatalf("replays duplicated transitions: %d", n)
	}
}

func TestReportingChangedYearInvalidatesUnexportedApprovalIntegration(t *testing.T) {
	for _, phase := range []string{"prepared", "approved"} {
		t.Run(phase, func(t *testing.T) {
			f := newReportFixture(t)
			r, _ := f.prepare(t)
			if phase == "approved" {
				r, _ = f.approve(t, r)
			}
			f.count(t, time.Date(f.year, 4, 1, 0, 0, 0, 0, time.UTC), "received")
			ctx, op := f.op(t, 2)
			got, err := f.service.GetReport(ctx, f.actors[2], r.ID)
			if err != nil || !got.Stale || !bytes.Equal(got.Payload, r.Payload) || got.Digest != r.Digest {
				t.Fatalf("stale snapshot inspection=%+v %v", got, err)
			}
			commitReport(ctx, t, op)
			ctx, op = f.op(t, 1)
			if phase == "prepared" {
				_, err = f.service.ApproveReport(ctx, f.actors[1], approvalFor(r))
			} else {
				_, err = f.service.DownloadReport(ctx, f.actors[1], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version})
			}
			if !errors.Is(err, ErrStaleSnapshot) {
				t.Fatalf("stale %s release=%v", phase, err)
			}
			_ = op.Rollback(ctx)
			fresh, _ := f.prepare(t)
			if fresh.ID == r.ID || fresh.DataVersion != r.DataVersion+1 || fresh.Status != "prepared" {
				t.Fatalf("replacement snapshot=%+v", fresh)
			}
		})
	}
}

func TestReportingAuditFailureRollsBackEveryTransitionIntegration(t *testing.T) {
	f := newReportFixture(t)
	for _, phase := range []string{"prepare", "approve", "download"} {
		t.Run(phase, func(t *testing.T) {
			var r Report
			actor := 0
			if phase != "prepare" {
				r, _ = f.prepare(t)
				actor = 1
			}
			if phase == "download" {
				r, _ = f.approve(t, r)
				actor = 2
			}
			beforeReports := f.scalar(t, `SELECT count(*) FROM legal_transparency_reports`)
			beforeReplays := f.scalar(t, `SELECT count(*) FROM legal_transparency_replays`)
			beforeOutbox := f.scalar(t, `SELECT count(*) FROM event_outbox`)
			ctx, op := f.op(t, actor)
			failReportAudit(ctx, t, op)
			var err error
			switch phase {
			case "prepare":
				_, err = f.service.PrepareReport(ctx, f.actors[actor], PrepareRequest{Key: uuid.New(), Year: f.year})
			case "approve":
				_, err = f.service.ApproveReport(ctx, f.actors[actor], approvalFor(r))
			case "download":
				_, err = f.service.DownloadReport(ctx, f.actors[actor], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = op.Commit(ctx); !errors.Is(err, adminaction.ErrUnavailable) {
				t.Fatalf("audit commit=%v", err)
			}
			if f.scalar(t, `SELECT count(*) FROM legal_transparency_reports`) != beforeReports || f.scalar(t, `SELECT count(*) FROM legal_transparency_replays`) != beforeReplays || f.scalar(t, `SELECT count(*) FROM event_outbox`) != beforeOutbox {
				t.Fatal("failed audit persisted report/replay/outbox")
			}
			if phase != "prepare" && f.scalar(t, `SELECT version FROM legal_transparency_reports WHERE id=$1`, r.ID) != r.Version {
				t.Fatal("failed audit persisted state transition")
			}
		})
	}
}

func (f *reportFixture) waitBlocked(t *testing.T, pid uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected PostgreSQL lock wait not observed")
		case <-ticker.C:
		}
	}
}

func TestReportingCounterWriterAndSnapshotLockOrdersIntegration(t *testing.T) {
	for _, writerFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(writerFirst), func(t *testing.T) {
			f := newReportFixture(t)
			ctxWriter, writer := f.op(t, 2)
			ctxSnapshot, snapshot := f.op(t, 0)
			at := time.Date(f.year, 5, 1, 0, 0, 0, 0, time.UTC)
			req := PrepareRequest{Key: uuid.New(), Year: f.year}
			var r Report
			if writerFirst {
				if err := CountReceived(ctxWriter, writer.Tx, at); err != nil {
					t.Fatal(err)
				}
				type outcome struct {
					r   Report
					err error
				}
				done := make(chan outcome, 1)
				go func() {
					r, err := f.service.PrepareReport(ctxSnapshot, f.actors[0], req)
					done <- outcome{r, err}
				}()
				f.waitBlocked(t, snapshot.Tx.Conn().PgConn().PID())
				commitReport(ctxWriter, t, writer)
				got := <-done
				if got.err != nil {
					t.Fatal(got.err)
				}
				r = got.r
				commitReport(ctxSnapshot, t, snapshot)
				if r.DataVersion != 1 || !assertPrivateArtifact(t, r.Payload).Received.Suppressed {
					t.Fatalf("snapshot missed committed writer: %+v", r)
				}
			} else {
				var err error
				r, err = f.service.PrepareReport(ctxSnapshot, f.actors[0], req)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- CountReceived(ctxWriter, writer.Tx, at) }()
				f.waitBlocked(t, writer.Tx.Conn().PgConn().PID())
				commitReport(ctxSnapshot, t, snapshot)
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				commitReport(ctxWriter, t, writer)
				if r.DataVersion != 0 || assertPrivateArtifact(t, r.Payload).Received.Suppressed {
					t.Fatalf("snapshot included uncommitted writer: %+v", r)
				}
			}
			ctx, op := f.op(t, 2)
			stored, err := f.service.GetReport(ctx, f.actors[2], r.ID)
			if err != nil || stored.Stale == writerFirst || !bytes.Equal(stored.Payload, r.Payload) {
				t.Fatalf("snapshot stability=%+v %v", stored, err)
			}
			commitReport(ctx, t, op)
		})
	}
}

func TestReportingApproverRoleRevocationAndDownloadLockOrdersIntegration(t *testing.T) {
	for _, downloadFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(downloadFirst), func(t *testing.T) {
			f := newReportFixture(t)
			f.useAPILogin(t)
			r, _ := f.prepare(t)
			r, _ = f.approve(t, r)
			req := DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version}
			ctx, download := f.op(t, 2)
			revoke, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = revoke.Rollback(context.Background()) }()
			removeRole := func() error {
				if err := pglock.LockAccount(f.ctx, revoke, f.actors[1].ID); err != nil {
					return err
				}
				_, err := revoke.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id='dpo'`, f.actors[1].ID)
				return err
			}
			if downloadFirst {
				if _, err = f.service.DownloadReport(ctx, f.actors[2], req); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- removeRole() }()
				f.waitBlocked(t, revoke.Conn().PgConn().PID())
				commitReport(ctx, t, download)
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				if err = revoke.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				ctx, download = f.op(t, 2)
				if _, err = f.service.DownloadReport(ctx, f.actors[2], req); !errors.Is(err, rbac.ErrForbidden) {
					t.Fatalf("exact retry ignored current approver revocation: %v", err)
				}
				_ = download.Rollback(ctx)
			} else {
				if err = removeRole(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, err := f.service.DownloadReport(ctx, f.actors[2], req); done <- err }()
				f.waitBlocked(t, download.Tx.Conn().PgConn().PID())
				// Waiting for a principal must not already hold report/year row
				// locks, which would invert the shared authorization lock order.
				probe, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = probe.Exec(f.ctx, `SELECT id FROM legal_transparency_reports WHERE id=$1 FOR UPDATE NOWAIT`, r.ID); err != nil {
					_ = probe.Rollback(f.ctx)
					t.Fatalf("report locked before stored principal: %v", err)
				}
				if _, err = probe.Exec(f.ctx, `SELECT year FROM legal_transparency_years WHERE year=$1 FOR UPDATE NOWAIT`, r.Year); err != nil {
					_ = probe.Rollback(f.ctx)
					t.Fatalf("year locked before stored principal: %v", err)
				}
				_ = probe.Rollback(f.ctx)
				if err = revoke.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if err = <-done; !errors.Is(err, rbac.ErrForbidden) {
					t.Fatalf("revoked approver authorized download: %v", err)
				}
				_ = download.Rollback(ctx)
				if f.scalar(t, `SELECT version FROM legal_transparency_reports WHERE id=$1`, r.ID) != r.Version {
					t.Fatal("revocation-first changed report")
				}
			}
		})
	}
}

func TestReportingLiveActorAndStoredPrincipalAuthVersionsIntegration(t *testing.T) {
	f := newReportFixture(t)
	for _, actor := range []int{0, 1, 2} {
		r, _ := f.prepare(t)
		r, _ = f.approve(t, r)
		if _, err := f.pool.Exec(f.ctx, `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, f.actors[actor].ID); err != nil {
			t.Fatal(err)
		}
		ctx, op := f.op(t, 2)
		_, err := f.service.DownloadReport(ctx, f.actors[2], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version})
		if !errors.Is(err, rbac.ErrForbidden) {
			t.Fatalf("stale principal %d auth version accepted: %v", actor, err)
		}
		_ = op.Rollback(ctx)
		// A fresh session can prepare a new report; it cannot revive the old
		// preparation or approval's recorded auth version.
		f.actors[actor].AuthVersion++
		if actor != 2 {
			ctx, op = f.op(t, 2)
			if _, err = f.service.DownloadReport(ctx, f.actors[2], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version}); !errors.Is(err, rbac.ErrForbidden) {
				t.Fatalf("new session revived old principal %d proof: %v", actor, err)
			}
			_ = op.Rollback(ctx)
		}
	}
}

func TestReportingLiveRoleSessionAndPolicyGatesIntegration(t *testing.T) {
	f := newReportFixture(t)
	r, _ := f.prepare(t)
	for _, role := range []string{"super_admin", "moderator", "support"} {
		if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1`, f.actors[2].ID); err != nil {
			t.Fatal(err)
		}
		if err := db.New(f.pool).AssignRoleToUser(f.ctx, db.AssignRoleToUserParams{UserID: f.actors[2].ID, RoleID: role}); err != nil {
			t.Fatal(err)
		}
		ctx, op := f.op(t, 2)
		if _, err := f.service.GetReport(ctx, f.actors[2], r.ID); !errors.Is(err, rbac.ErrForbidden) {
			t.Fatalf("%s read=%v", role, err)
		}
		_ = op.Rollback(ctx)
	}
	for _, kind := range []session.Kind{session.KindRecoveryEnrollment} {
		ctx, op := f.op(t, 0)
		ctx = session.WithSession(ctx, session.Session{UserID: f.actors[0].ID.String(), Kind: kind, AuthVersion: f.actors[0].AuthVersion, AuthVersionSet: true})
		if _, err := f.service.GetReport(ctx, f.actors[0], r.ID); !errors.Is(err, rbac.ErrForbidden) {
			t.Fatalf("recovery session read=%v", err)
		}
		_ = op.Rollback(ctx)
	}
	for _, cfg := range []Config{
		{Environment: "test"},
		{Enabled: true, PolicyID: uuid.New(), Environment: "test"},
		{Enabled: true, PolicyID: f.policy.ID, Environment: "production"},
	} {
		svc, err := New(cfg)
		if err != nil {
			continue
		}
		ctx, op := f.op(t, 0)
		if _, err = svc.PrepareReport(ctx, f.actors[0], PrepareRequest{Key: uuid.New(), Year: f.year}); err == nil {
			t.Fatalf("invalid governance gate accepted: %+v", cfg)
		}
		_ = op.Rollback(ctx)
	}
	ctx, op := f.op(t, 0)
	if _, err := f.service.PrepareReport(ctx, f.actors[0], PrepareRequest{Key: uuid.New(), Year: time.Now().UTC().Year()}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("incomplete calendar year allowed: %v", err)
	}
	_ = op.Rollback(ctx)
}

// Every API exercise uses a real connection with this login. It receives no
// role membership, table ownership, superuser flag, schema CREATE or SET ROLE.
func (f *reportFixture) useAPILogin(t *testing.T) *pgxpool.Pool {
	t.Helper()
	role := "report_api_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{role}.Sanitize()
	password := uuid.NewString()
	if _, err := f.pool.Exec(f.ctx, `CREATE ROLE `+quoted+` LOGIN PASSWORD '`+password+`' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, `DROP OWNED BY `+quoted); err != nil {
			t.Error(err)
		}
		if _, err := f.pool.Exec(ctx, `DROP ROLE `+quoted); err != nil {
			t.Error(err)
		}
	})
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + quoted,
		`GRANT SELECT,UPDATE ON users TO ` + quoted,
		`GRANT SELECT ON user_roles,roles,role_permissions,permissions,legal_governance_policies,legal_governance_baseline TO ` + quoted,
		`GRANT SELECT,INSERT ON legal_transparency_coverage,legal_transparency_replays TO ` + quoted,
		`GRANT SELECT,INSERT,UPDATE ON legal_transparency_years,legal_transparency_months,legal_transparency_reports TO ` + quoted,
		`GRANT EXECUTE ON FUNCTION legal_transparency_lock_year(integer),legal_transparency_count(timestamptz,text) TO ` + quoted,
		`GRANT INSERT ON event_outbox TO ` + quoted,
	} {
		if _, err := f.pool.Exec(f.ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var current, authenticated string
	if err = pool.QueryRow(f.ctx, `SELECT current_user,session_user`).Scan(&current, &authenticated); err != nil || current != role || authenticated != role {
		t.Fatalf("not a real API login: %s/%s %v", current, authenticated, err)
	}
	f.actions, err = adminaction.New(pool, rejectContextEncryption{}, "identity.audit.report-fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestReportingRealLoginGrantsArtifactPrivacyAndNoElevationIntegration(t *testing.T) {
	f := newReportFixture(t)
	api := f.useAPILogin(t)
	if n := f.scalar(t, `SELECT count(*) FROM pg_proc WHERE proname IN ('legal_transparency_count','legal_transparency_lock_year') AND prosecdef`); n != 0 {
		t.Fatal("reporting functions elevate to migration owner")
	}
	if n := f.scalar(t, `SELECT count(*) FROM role_permissions WHERE permission_id IN ('legal.transparency.read','legal.transparency.approve') AND role_id<>'dpo'`); n != 0 {
		t.Fatal("reporting permissions seeded outside DPO")
	}
	f.count(t, time.Date(f.year, 7, 1, 0, 0, 0, 0, time.UTC), "received", "refusal")
	r, _ := f.prepare(t)
	r, _ = f.approve(t, r)
	ctx, op := f.op(t, 2)
	artifact, err := f.service.DownloadReport(ctx, f.actors[2], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version})
	if err != nil {
		t.Fatal(err)
	}
	commitReport(ctx, t, op)
	a := assertPrivateArtifact(t, artifact.Payload)
	if !a.Received.Suppressed || !a.Answered.Suppressed || !a.Outcomes.Suppressed || a.Outcomes.Counts != nil {
		t.Fatalf("small aggregate leaked: %s", artifact.Payload)
	}
	for _, marker := range []string{r.ID.String(), f.policy.ID.String(), r.Digest, f.actors[0].ID.String(), f.actors[1].ID.String(), "report.test", "fixture-inventory", "fixture-report-not-production"} {
		if bytes.Contains(artifact.Payload, []byte(marker)) {
			t.Fatalf("restricted provenance in public artifact: %s", marker)
		}
	}
	var payload string
	if err = f.pool.QueryRow(f.ctx, `SELECT payload::text FROM event_outbox WHERE id=$1`, op.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{r.ID.String(), f.policy.ID.String(), r.Digest, "data_version", "response_digest", "prepared_by", "approved_by", "report.test"} {
		if strings.Contains(payload, marker) {
			t.Fatalf("restricted report data in permanent audit: %s", marker)
		}
	}
	if n := f.scalar(t, `SELECT count(*) FROM admin_action_contexts`); n != 0 {
		t.Fatal("reporting retained restricted action contexts")
	}
	var owner string
	if err = f.pool.QueryRow(f.ctx, `SELECT current_user`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		`SET ROLE ` + pgx.Identifier{owner}.Sanitize(),
		`CREATE TABLE public.report_forbidden(id integer)`,
		`ALTER TABLE legal_transparency_reports DISABLE TRIGGER ALL`,
		`TRUNCATE legal_transparency_reports`,
		`DELETE FROM legal_transparency_reports WHERE false`,
		`UPDATE legal_transparency_replays SET input=input WHERE false`,
		`DELETE FROM legal_transparency_replays WHERE false`,
		`UPDATE legal_transparency_coverage SET started_at=clock_timestamp() WHERE false`,
		`INSERT INTO legal_governance_baseline(singleton,policy_id) VALUES(true,gen_random_uuid())`,
		`UPDATE legal_governance_policies SET artifact=artifact WHERE false`,
		`DELETE FROM legal_workflow_events WHERE false`,
		`DELETE FROM security_event_ledger WHERE false`,
		`UPDATE event_outbox SET payload=payload WHERE false`,
		`UPDATE user_roles SET role_id=role_id WHERE false`,
	} {
		tx, err := api.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.ctx, sql)
		_ = tx.Rollback(f.ctx)
		if err == nil {
			t.Fatalf("ordinary API login escaped grants: %s", sql)
		}
	}
	for _, assignment := range []string{"payload=convert_to('{}','UTF8')", "digest=repeat('a',64)", "data_version=data_version+1", "prepared_by=gen_random_uuid()", "policy_id=gen_random_uuid()"} {
		if _, err = api.Exec(f.ctx, `UPDATE legal_transparency_reports SET `+assignment+` WHERE id=$1`, r.ID); err == nil {
			t.Fatalf("report snapshot rewritten through granted UPDATE: %s", assignment)
		}
	}
	// Functions cannot silently borrow owner privileges if normal table grants
	// are removed, even though their explicit EXECUTE grants remain in place.
	var role string
	if err = api.QueryRow(f.ctx, `SELECT current_user`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `REVOKE INSERT ON legal_transparency_months FROM `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 0)
	if err = CountReceived(ctx, op.Tx, time.Date(f.year, 8, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("counter bypassed revoked ordinary grant: %v", err)
	}
	_ = op.Rollback(ctx)
	if n := f.scalar(t, `SELECT count(*) FROM legal_transparency_months WHERE month=$1`, time.Date(f.year, 8, 1, 0, 0, 0, 0, time.UTC)); n != 0 {
		t.Fatal("denied counter persisted data")
	}
}

func TestReportingRequiresActionTransactionIntegration(t *testing.T) {
	f := newReportFixture(t)
	r, _ := f.prepare(t)
	for _, run := range []func() error{
		func() error {
			_, err := f.service.Monthly(f.ctx, f.actors[0], MonthlyRequest{Start: time.Date(f.year, 1, 1, 0, 0, 0, 0, time.UTC), Months: 1})
			return err
		},
		func() error {
			_, err := f.service.PrepareReport(f.ctx, f.actors[0], PrepareRequest{Key: uuid.New(), Year: f.year})
			return err
		},
		func() error { _, err := f.service.GetReport(f.ctx, f.actors[0], r.ID); return err },
		func() error { _, err := f.service.ApproveReport(f.ctx, f.actors[1], approvalFor(r)); return err },
		func() error {
			_, err := f.service.DownloadReport(f.ctx, f.actors[2], DownloadRequest{Key: uuid.New(), ID: r.ID, ExpectedVersion: r.Version})
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrTransactionRequired) {
			t.Fatalf("missing adminaction transaction=%v", err)
		}
	}
	// Verify the public download object itself carries no internal report fields.
	blob, err := json.Marshal(DownloadResult{Payload: r.Payload})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, raw, "payload", "replayed")
}
