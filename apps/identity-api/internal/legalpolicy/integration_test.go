//go:build integration

package legalpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	embedded "github.com/hatefsystems/identity/apps/identity-api/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

type policyIntegration struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	admin   *pgxpool.Pool
	actions *adminaction.Service
	schema  string
}

type noContextEncryption struct{}

func (noContextEncryption) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("policy installation must not create narrative context")
}

func newPolicyIntegration(t *testing.T) *policyIntegration {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is required for governance integration tests; use a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	schema := "policy_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	cfg.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Use the actual dependency migrations and governance migration in an isolated
	// schema. Task 5.4's migration 11 deliberately targets public; do not replay it
	// against another agent's database while testing this package's singleton.
	files := fstest.MapFS{}
	entries, err := fs.ReadDir(embedded.Migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() > "00012_legal_governance.sql" || strings.HasPrefix(entry.Name(), "00011_") {
			continue
		}
		data, err := fs.ReadFile(embedded.Migrations, "migrations/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = &fstest.MapFile{Data: data}
	}
	sqldb := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = sqldb.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, sqldb, files)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	actions, err := adminaction.New(pool, noContextEncryption{}, "identity.audit.policy-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &policyIntegration{ctx: ctx, pool: pool, admin: admin, actions: actions, schema: schema}
}

func (f *policyIntegration) operation(t *testing.T) *adminaction.Operation {
	t.Helper()
	op, err := f.actions.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/operator/policy"}
	t.Cleanup(func() { _ = op.Rollback(context.Background()) })
	return op
}

func (f *policyIntegration) install(t *testing.T, p Policy) uuid.UUID {
	t.Helper()
	op := f.operation(t)
	if err := Install(f.ctx, op, p, "test"); err != nil {
		t.Fatal(err)
	}
	if err := op.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return op.ID
}

func TestPolicyInstallImmutableAndBoundIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	p := fixturePolicy()
	if _, err := LoadBaseline(f.ctx, f.pool, uuid.Nil, "test"); !errors.Is(err, ErrNotApproved) {
		t.Fatal("unapproved migration enabled baseline")
	}
	actionID := f.install(t, p)
	loaded, err := LoadBaseline(f.ctx, f.pool, p.ID, "test")
	if err != nil || loaded.ID != p.ID {
		t.Fatalf("installed policy unavailable: %v", err)
	}
	if _, err := Load(f.ctx, f.pool, p.ID, "production"); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("stored fixture accepted in production")
	}
	if _, err := LoadBaseline(f.ctx, f.pool, uuid.New(), "test"); !errors.Is(err, ErrMismatch) {
		t.Fatal("configured ID changed immutable baseline")
	}
	if _, err := Load(f.ctx, f.pool, uuid.New(), "test"); !errors.Is(err, ErrNotApproved) {
		t.Fatal("unknown policy loaded")
	}
	if _, err := Load(f.ctx, f.pool, uuid.Nil, "test"); !errors.Is(err, ErrNotApproved) {
		t.Fatal("zero policy loaded")
	}
	var payload string
	if err := f.pool.QueryRow(f.ctx, `SELECT payload FROM event_outbox WHERE id=$1 AND admin_action`, actionID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "legal.policy.installed") || strings.Contains(payload, p.ApprovalReference) || strings.Contains(payload, "hold_tombstone_fields") {
		t.Fatal("installation audit missing or leaked approval artifact")
	}
	var contexts int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM admin_action_contexts`).Scan(&contexts); err != nil || contexts != 0 {
		t.Fatal("policy installer created narrative context")
	}
	slices.Reverse(p.HoldTombstoneFields)
	f.install(t, p) // Set-equivalent inventory is an exact semantic replay.
	for _, query := range []string{
		`UPDATE legal_governance_policies SET artifact=artifact`,
		`DELETE FROM legal_governance_policies`,
		`TRUNCATE legal_governance_policies CASCADE`,
		`UPDATE legal_governance_baseline SET policy_id=policy_id`,
		`DELETE FROM legal_governance_baseline`,
		`TRUNCATE legal_governance_baseline`,
	} {
		if _, err := f.pool.Exec(f.ctx, query); err == nil {
			t.Fatalf("immutable guard accepted %s", query)
		}
	}
	op := f.operation(t)
	p.ApprovalReference = "different-approval"
	if !errors.Is(Install(f.ctx, op, p, "test"), ErrConflict) {
		t.Fatal("same version accepted changed artifact")
	}
	_ = op.Rollback(f.ctx)
	op = f.operation(t)
	p.ID = uuid.New()
	p.ReleasedHoldRetentionSeconds++
	if !errors.Is(Install(f.ctx, op, p, "test"), ErrMismatch) {
		t.Fatal("new policy changed historical retention")
	}
	_ = op.Rollback(f.ctx)
	p.ReleasedHoldRetentionSeconds--
	f.install(t, p)
	bound, err := LoadBaseline(f.ctx, f.pool, uuid.Nil, "test")
	if err != nil || bound.ID != loaded.ID {
		t.Fatal("second policy rebound baseline")
	}
	if _, err := Load(f.ctx, f.pool, p.ID, "test"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyAuditFailureRollsBackBindingIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	p := fixturePolicy()
	op := f.operation(t)
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`ALTER TABLE event_outbox ADD CONSTRAINT reject_policy_test CHECK (id <> '%s'::uuid)`, op.ID)); err != nil {
		t.Fatal(err)
	}
	if err := Install(f.ctx, op, p, "test"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(op.Commit(f.ctx), adminaction.ErrUnavailable) {
		t.Fatal("installation succeeded without durable audit")
	}
	var rows int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM legal_governance_policies`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed audit retained installed policy")
	}
	if _, err := LoadBaseline(f.ctx, f.pool, uuid.Nil, "test"); !errors.Is(err, ErrNotApproved) {
		t.Fatal("failed audit retained baseline binding")
	}
}

func TestPolicyConcurrentFirstBindingIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	first, second := fixturePolicy(), fixturePolicy()
	second.ReleasedHoldRetentionSeconds++
	op1, op2 := f.operation(t), f.operation(t)
	if err := Install(f.ctx, op1, first, "test"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Install(f.ctx, op2, second, "test") }()
	// Observe a real database wait before releasing the first installer. No
	// timing assumption can accidentally make the concurrency assertion pass.
	waitCtx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(waitCtx, `SELECT EXISTS(SELECT 1 FROM pg_locks
			WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, op2.Tx.Conn().PgConn().PID()).Scan(&waiting); err != nil {
			_ = op1.Rollback(f.ctx)
			<-done
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-waitCtx.Done():
			_ = op1.Rollback(f.ctx)
			<-done
			t.Fatal("second installer did not wait for first baseline binding")
		case <-ticker.C:
		}
	}
	if err := op1.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrMismatch) {
		t.Fatalf("concurrent installer ignored newly bound baseline: %v", err)
	}
	_ = op2.Rollback(f.ctx)
	bound, err := LoadBaseline(f.ctx, f.pool, uuid.Nil, "test")
	if err != nil || bound.ID != first.ID {
		t.Fatal("concurrent installer changed baseline")
	}
	if _, err := Load(f.ctx, f.pool, second.ID, "test"); !errors.Is(err, ErrNotApproved) {
		t.Fatal("conflicting concurrent policy was installed")
	}
}

func TestPolicyLegacyInventoryAndMaintenanceIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	p := fixturePolicy()
	p.Workflow = nil
	createdAt := time.Now().UTC().Truncate(time.Microsecond).Add(-24 * time.Hour)
	actionID, holdID := uuid.New(), uuid.New()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO admin_action_contexts(action_id,details_encrypted,created_at,retain_until)
		VALUES($1,'opaque'::bytea,$2,$3)`, actionID, createdAt, createdAt.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO legal_holds(id,account_ref,applied_by,applied_at,is_active,released_at,released_by,details_purged_at)
		VALUES($1,$2,$3,$4,false,$4,$3,$4)`, holdID, uuid.New(), uuid.New(), createdAt); err != nil {
		t.Fatal(err)
	}
	op := f.operation(t)
	if !errors.Is(Install(f.ctx, op, p, "test"), ErrInventoryRequired) {
		t.Fatal("fabricated approval for legacy records without inventory evidence")
	}
	_ = op.Rollback(f.ctx)
	p.LegacyInventoryReference = "fixture-legacy-inventory"
	op = f.operation(t)
	if !errors.Is(Install(f.ctx, op, p, "test"), ErrMismatch) {
		t.Fatal("bound incompatible persisted context clocks")
	}
	_ = op.Rollback(f.ctx)
	p.ContextRetentionSeconds = 7200
	f.install(t, p)
	bound, err := LoadBaseline(f.ctx, f.pool, uuid.Nil, "test")
	if err != nil || ValidateBaseline(bound, 2*time.Hour, 2*time.Hour, "test") != nil {
		t.Fatal("maintenance cannot load stored baseline independently of workflow")
	}
	if !errors.Is(ValidateWorkflow(bound, "test"), ErrNotApproved) {
		t.Fatal("baseline-only policy enabled workflow")
	}
	var applied, released, retainUntil time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT applied_at,released_at FROM legal_holds WHERE id=$1`, holdID).Scan(&applied, &released); err != nil || !applied.Equal(createdAt) || !released.Equal(createdAt) {
		t.Fatal("binding reset hold timestamps")
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT retain_until FROM admin_action_contexts WHERE action_id=$1`, actionID).Scan(&retainUntil); err != nil || !retainUntil.Equal(createdAt.Add(2*time.Hour)) {
		t.Fatal("binding rewrote historical context expiry")
	}
}

func TestPolicyStoredChecksAndAttributionIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	for _, identity := range []string{"", "https://identity.test/operator", "spiffe:///operator", "spiffe://user@identity.test/operator", "spiffe://identity.test/operator?secret=x", "spiffe://identity.test/operator#fragment"} {
		op := f.operation(t)
		op.Event.ActorSPIFFEID = identity
		if !errors.Is(Install(f.ctx, op, fixturePolicy(), "test"), ErrOperatorRequired) {
			t.Fatal("untrusted attribution accepted")
		}
		_ = op.Rollback(f.ctx)
	}
	op := f.operation(t)
	op.Event.ActorID = uuid.Nil
	if !errors.Is(Install(f.ctx, op, fixturePolicy(), "test"), ErrOperatorRequired) {
		t.Fatal("zero operator accepted")
	}
	_ = op.Rollback(f.ctx)
	for _, edit := range []func(*Policy){
		func(p *Policy) { p.ApprovalReference = "" },
		func(p *Policy) { p.ContextRetentionSeconds = 0 },
		func(p *Policy) { p.HoldTombstoneFields = nil },
		func(p *Policy) { p.HoldTombstoneLifetime = "24h" },
		func(p *Policy) { p.Workflow.MaxCaseAgeSeconds = 0 },
		func(p *Policy) { p.Workflow.ReplayFields = []string{"content_digest"} },
		func(p *Policy) { p.Workflow.ReplayLifetime = "24h" },
	} {
		p := fixturePolicy()
		edit(&p)
		artifact, _ := json.Marshal(p)
		if _, err := f.pool.Exec(f.ctx, `INSERT INTO legal_governance_policies
			(id,artifact,installed_by,operator_identity,action_id,installed_environment)
			VALUES($1,$2,$3,'spiffe://identity.test/operator',$4,'test')`, p.ID, artifact, uuid.New(), uuid.New()); err == nil {
			t.Fatal("database accepted invalid approval artifact")
		}
	}
	p := fixturePolicy()
	artifact, _ := json.Marshal(p)
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO legal_governance_policies
		(id,artifact,installed_by,operator_identity,action_id,installed_environment)
		VALUES($1,$2,$3,'spiffe://identity.test/operator',$4,'production')`, p.ID, artifact, uuid.New(), uuid.New()); err == nil {
		t.Fatal("database accepted production fixture approval")
	}
}

func TestPolicyRealLoginRolesIntegration(t *testing.T) {
	f := newPolicyIntegration(t)
	p := fixturePolicy()
	f.install(t, p)
	for _, kind := range []string{"api", "maintenance", "installer"} {
		t.Run(kind, func(t *testing.T) {
			role := "policy_" + kind + "_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			name := pgx.Identifier{role}.Sanitize()
			password := uuid.NewString()
			if _, err := f.admin.Exec(f.ctx, "CREATE ROLE "+name+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = f.admin.Exec(context.Background(), "DROP OWNED BY "+name)
				if _, err := f.admin.Exec(context.Background(), "DROP ROLE "+name); err != nil {
					t.Error(err)
				}
			})
			for _, query := range []string{
				"GRANT USAGE ON SCHEMA " + pgx.Identifier{f.schema}.Sanitize() + " TO " + name,
				"GRANT SELECT ON legal_governance_policies, legal_governance_baseline TO " + name,
			} {
				if _, err := f.pool.Exec(f.ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "installer" {
				if _, err := f.pool.Exec(f.ctx, "GRANT INSERT ON legal_governance_policies,legal_governance_baseline,event_outbox TO "+name); err != nil {
					t.Fatal(err)
				}
			}
			cfg := f.pool.Config().Copy()
			cfg.ConnConfig.User, cfg.ConnConfig.Password = role, password
			login, err := pgxpool.NewWithConfig(f.ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer login.Close()
			var current string
			if err := login.QueryRow(f.ctx, `SELECT current_user`).Scan(&current); err != nil || current != role {
				t.Fatal("test did not authenticate as real restricted login")
			}
			if _, err := Load(f.ctx, login, p.ID, "test"); err != nil {
				t.Fatal(err)
			}
			for _, query := range []string{
				`UPDATE legal_governance_policies SET artifact=artifact`, `DELETE FROM legal_governance_policies`,
				`TRUNCATE legal_governance_policies CASCADE`, `UPDATE legal_governance_baseline SET policy_id=policy_id`,
				`DELETE FROM legal_governance_baseline`, `TRUNCATE legal_governance_baseline`,
				`ALTER TABLE legal_governance_policies DISABLE TRIGGER ALL`, `ALTER TABLE legal_governance_policies OWNER TO ` + name,
				`DROP TABLE legal_governance_baseline`, `CREATE TABLE governance_ddl_bypass(id int)`,
				`SET session_replication_role = replica`, `GRANT ` + pgx.Identifier{f.admin.Config().ConnConfig.User}.Sanitize() + ` TO ` + name,
			} {
				if _, err := login.Exec(f.ctx, query); err == nil {
					t.Fatalf("restricted %s accepted %s", kind, query)
				}
			}
			if kind != "installer" {
				if _, err := login.Exec(f.ctx, `INSERT INTO legal_governance_baseline(singleton,policy_id) VALUES(true,$1)`, p.ID); err == nil {
					t.Fatal("non-installer wrote baseline")
				}
				if _, err := login.Exec(f.ctx, `INSERT INTO legal_governance_policies SELECT * FROM legal_governance_policies LIMIT 0`); err == nil {
					t.Fatal("non-installer obtained policy INSERT")
				}
				return
			}
			actions, err := adminaction.New(login, noContextEncryption{}, "identity.audit.policy-test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			op, err := actions.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = op.Rollback(f.ctx) }()
			op.Event = audit.Event{ActorID: uuid.New(), ActorSPIFFEID: "spiffe://identity.test/operator/policy"}
			next := fixturePolicy()
			if err := Install(f.ctx, op, next, "test"); err != nil {
				t.Fatalf("least-privilege installer failed: %v", err)
			}
			if err := op.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
