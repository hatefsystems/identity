//go:build integration

package retentiondbintegration

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/receiptreconcile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit/signer"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
)

func TestEffectiveSignerPublisherReconciliationPrivileges(t *testing.T) {
	f := newFixture(t)
	mustExec(t, f.ctx, f.admin, "CREATE SEQUENCE public.probe_extra_seq")
	for _, kind := range []string{"signing_probe", "publishing_probe", "reconciliation_probe", "context_probe", "metadata_probe"} {
		t.Run(kind, func(t *testing.T) {
			name := kind + "_" + uuid.New().String()[:8]
			quoted := pgx.Identifier{name}.Sanitize()
			password := uuid.NewString()
			mustExec(t, f.ctx, f.admin, "CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"'")
			f.names[kind] = name
			mustExec(t, f.ctx, f.admin, "GRANT USAGE ON SCHEMA public TO "+quoted)
			var probe func(context.Context) error
			cfg, err := pgx.ParseConfig(f.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			cfg.User, cfg.Password = name, password
			login, err := pgx.ConnectConfig(f.ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = login.Close(context.Background()) })
			var actual, session string
			if err := login.QueryRow(f.ctx, "SELECT current_user,session_user").Scan(&actual, &session); err != nil || actual != name || session != name {
				t.Fatal("fixture is not an actual restricted login")
			}
			switch kind {
			case "signing_probe":
				mustExec(t, f.ctx, f.admin, "GRANT SELECT,INSERT ON public.audit_log_chain,public.security_ledger_chain,public.mvp_audit_logs,public.security_event_ledger TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT SELECT ON public.audit_log_head,public.security_ledger_head,public.security_ledger_erasures,public.users TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT UPDATE(id) ON public.users TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT USAGE ON SEQUENCE public.audit_log_chain_seq,public.security_ledger_chain_seq TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) TO "+quoted)
				probe = func(ctx context.Context) error { return signer.ProbePrivileges(ctx, login) }
			case "publishing_probe":
				mustExec(t, f.ctx, f.admin, "GRANT SELECT,UPDATE(published_at,attempts,next_attempt_at,last_error) ON public.event_outbox TO "+quoted)
				mustExec(t, f.ctx, f.admin, "ALTER TABLE public.event_outbox ENABLE ROW LEVEL SECURITY")
				mustExec(t, f.ctx, f.admin, "CREATE POLICY probe_publisher_read ON public.event_outbox FOR SELECT TO "+quoted+" USING(admin_action AND subject='"+auditSubject+"')")
				mustExec(t, f.ctx, f.admin, "CREATE POLICY probe_publisher_delivery ON public.event_outbox FOR UPDATE TO "+quoted+" USING(admin_action AND subject='"+auditSubject+"') WITH CHECK(admin_action AND subject='"+auditSubject+"')")
				probe = func(ctx context.Context) error { return adminaction.ProbePublisher(ctx, login, auditSubject) }
			case "context_probe":
				mustExec(t, f.ctx, f.admin, "GRANT SELECT,DELETE ON public.admin_action_contexts TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT SELECT ON public.legal_holds,public.legal_governance_policies,public.legal_governance_baseline TO "+quoted)
				probe = func(ctx context.Context) error { return adminaction.ProbeContextMaintenance(ctx, login) }
			case "metadata_probe":
				mustExec(t, f.ctx, f.admin, "GRANT SELECT,UPDATE(details_encrypted,details_purged_at) ON public.legal_holds TO "+quoted)
				mustExec(t, f.ctx, f.admin, "GRANT SELECT ON public.legal_governance_policies,public.legal_governance_baseline TO "+quoted)
				probe = func(ctx context.Context) error { return legalpolicy.ProbeMetadataMaintenance(ctx, login) }
			default:
				mustExec(t, f.ctx, f.admin, "GRANT SELECT ON public.security_ledger_erasures,public.event_outbox,public.mvp_audit_logs,public.audit_log_chain,public.audit_log_head TO "+quoted)
				probe = func(ctx context.Context) error { return receiptreconcile.ProbePrivileges(ctx, login) }
			}
			if err := probe(f.ctx); err != nil {
				t.Fatalf("valid real-login startup: %v", err)
			}
			if _, err := login.Exec(f.ctx, "UPDATE pg_catalog.pg_settings SET setting='replica' WHERE name='session_replication_role'"); err == nil {
				t.Fatal("built-in GUC view bypassed replication parameter privileges")
			}
			changes := []struct{ name, grant, revoke string }{
				{"PUBLIC column update", "GRANT UPDATE(chain_hash) ON public.security_ledger_head TO PUBLIC", "REVOKE UPDATE(chain_hash) ON public.security_ledger_head FROM PUBLIC"},
				{"column insert", "GRANT INSERT(seq) ON public.audit_log_head TO " + quoted, "REVOKE INSERT(seq) ON public.audit_log_head FROM " + quoted},
				{"payload erasure", "GRANT DELETE ON public.mvp_audit_logs TO " + quoted, "REVOKE DELETE ON public.mvp_audit_logs FROM " + quoted},
				{"ledger payload erasure", "GRANT DELETE ON public.security_event_ledger TO " + quoted, "REVOKE DELETE ON public.security_event_ledger FROM " + quoted},
				{"payload update", "GRANT UPDATE(event_type) ON public.security_event_ledger TO " + quoted, "REVOKE UPDATE(event_type) ON public.security_event_ledger FROM " + quoted},
				{"chain update", "GRANT UPDATE(chain_hash) ON public.audit_log_chain TO " + quoted, "REVOKE UPDATE(chain_hash) ON public.audit_log_chain FROM " + quoted},
				{"chain delete", "GRANT DELETE ON public.security_ledger_chain TO " + quoted, "REVOKE DELETE ON public.security_ledger_chain FROM " + quoted},
				{"erasure insert", "GRANT INSERT ON public.security_ledger_erasures TO " + quoted, "REVOKE INSERT ON public.security_ledger_erasures FROM " + quoted},
				{"erasure delete", "GRANT DELETE ON public.security_ledger_erasures TO " + quoted, "REVOKE DELETE ON public.security_ledger_erasures FROM " + quoted},
				{"outbox insert", "GRANT INSERT ON public.event_outbox TO " + quoted, "REVOKE INSERT ON public.event_outbox FROM " + quoted},
				{"head write", "GRANT UPDATE ON public.audit_log_head TO " + quoted, "REVOKE UPDATE ON public.audit_log_head FROM " + quoted},
				{"unrelated read", "GRANT SELECT ON public.role_permissions TO " + quoted, "REVOKE SELECT ON public.role_permissions FROM " + quoted},
				{"unrelated write", "GRANT UPDATE ON public.roles TO " + quoted, "REVOKE UPDATE ON public.roles FROM " + quoted},
				{"references", "GRANT REFERENCES(seq) ON public.security_ledger_chain TO " + quoted, "REVOKE REFERENCES(seq) ON public.security_ledger_chain FROM " + quoted},
				{"trigger", "GRANT TRIGGER ON public.security_ledger_chain TO " + quoted, "REVOKE TRIGGER ON public.security_ledger_chain FROM " + quoted},
				{"truncate", "GRANT TRUNCATE ON public.security_ledger_chain TO " + quoted, "REVOKE TRUNCATE ON public.security_ledger_chain FROM " + quoted},
				{"sequence update", "GRANT UPDATE ON SEQUENCE public.security_ledger_chain_seq TO " + quoted, "REVOKE UPDATE ON SEQUENCE public.security_ledger_chain_seq FROM " + quoted},
				{"sequence SELECT", "GRANT SELECT ON SEQUENCE public.audit_log_chain_seq TO " + quoted, "REVOKE SELECT ON SEQUENCE public.audit_log_chain_seq FROM " + quoted},
				{"PUBLIC sequence", "GRANT USAGE ON SEQUENCE public.probe_extra_seq TO PUBLIC", "REVOKE USAGE ON SEQUENCE public.probe_extra_seq FROM PUBLIC"},
				{"PUBLIC function", "GRANT EXECUTE ON FUNCTION public.chain_table_guard() TO PUBLIC", "REVOKE EXECUTE ON FUNCTION public.chain_table_guard() FROM PUBLIC"},
				{"native file write EXECUTE", "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) TO " + quoted, "REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) FROM " + quoted},
				{"PUBLIC native file write EXECUTE", "GRANT EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) TO PUBLIC", "REVOKE EXECUTE ON FUNCTION pg_catalog.lo_export(oid,text) FROM PUBLIC"},
				{"PUBLIC schema CREATE", "GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
				{"catalog schema CREATE", "GRANT CREATE ON SCHEMA pg_catalog TO " + quoted, "REVOKE CREATE ON SCHEMA pg_catalog FROM " + quoted},
				{"catalog trigger update", "GRANT UPDATE(tgenabled) ON pg_catalog.pg_trigger TO " + quoted, "REVOKE UPDATE(tgenabled) ON pg_catalog.pg_trigger FROM " + quoted},
				{"database CREATE", "GRANT CREATE ON DATABASE " + pgx.Identifier{cfg.Database}.Sanitize() + " TO " + quoted, "REVOKE CREATE ON DATABASE " + pgx.Identifier{cfg.Database}.Sanitize() + " FROM " + quoted},
				{"replication parameter", "GRANT SET ON PARAMETER session_replication_role TO " + quoted, "REVOKE SET ON PARAMETER session_replication_role FROM " + quoted},
				{"replication role", "ALTER ROLE " + quoted + " REPLICATION", "ALTER ROLE " + quoted + " NOREPLICATION"},
				{"inherit role", "ALTER ROLE " + quoted + " INHERIT", "ALTER ROLE " + quoted + " NOINHERIT"},
				{"role administration", "ALTER ROLE " + quoted + " CREATEROLE", "ALTER ROLE " + quoted + " NOCREATEROLE"},
				{"RLS bypass", "ALTER ROLE " + quoted + " BYPASSRLS", "ALTER ROLE " + quoted + " NOBYPASSRLS"},
				{"database administration", "ALTER ROLE " + quoted + " CREATEDB", "ALTER ROLE " + quoted + " NOCREATEDB"},
				{"SET ROLE owner path", "GRANT " + pgx.Identifier{f.admin.Config().User}.Sanitize() + " TO " + quoted, "REVOKE " + pgx.Identifier{f.admin.Config().User}.Sanitize() + " FROM " + quoted},
			}
			if kind == "publishing_probe" {
				changes = append(changes,
					struct{ name, grant, revoke string }{"delivery table UPDATE", "GRANT UPDATE ON public.event_outbox TO " + quoted, "REVOKE UPDATE ON public.event_outbox FROM " + quoted + "; GRANT UPDATE(published_at,attempts,next_attempt_at,last_error) ON public.event_outbox TO " + quoted},
					struct{ name, grant, revoke string }{"outbox payload UPDATE", "GRANT UPDATE(payload) ON public.event_outbox TO " + quoted, "REVOKE UPDATE(payload) ON public.event_outbox FROM " + quoted},
					struct{ name, grant, revoke string }{"RLS disabled", "ALTER TABLE public.event_outbox DISABLE ROW LEVEL SECURITY", "ALTER TABLE public.event_outbox ENABLE ROW LEVEL SECURITY"},
					struct{ name, grant, revoke string }{"PUBLIC unscoped policy", "CREATE POLICY probe_public_read ON public.event_outbox FOR SELECT TO PUBLIC USING(true)", "DROP POLICY probe_public_read ON public.event_outbox"},
					struct{ name, grant, revoke string }{"unscoped read policy", "ALTER POLICY probe_publisher_read ON public.event_outbox USING(true)", "ALTER POLICY probe_publisher_read ON public.event_outbox USING(admin_action AND subject='" + auditSubject + "')"},
					struct{ name, grant, revoke string }{"unscoped delivery check", "ALTER POLICY probe_publisher_delivery ON public.event_outbox WITH CHECK(true)", "ALTER POLICY probe_publisher_delivery ON public.event_outbox WITH CHECK(admin_action AND subject='" + auditSubject + "')"})
				if err := adminaction.ProbePublisher(f.ctx, login, "identity.audit.wrong-subject"); err == nil {
					t.Fatal("publisher accepted a different policy subject")
				}
				mustExec(t, f.ctx, f.admin, `INSERT INTO public.event_outbox(id,subject,payload,admin_action) VALUES
 (gen_random_uuid(),$1,'{}',true),(gen_random_uuid(),$1,'{}',false),(gen_random_uuid(),'identity.audit.other','{}',true)`, auditSubject)
				var visible int
				if err := login.QueryRow(f.ctx, "SELECT count(*) FROM public.event_outbox").Scan(&visible); err != nil || visible != 1 {
					t.Fatal("publisher RLS disclosed unmarked/wrong-subject rows")
				}
				updated, err := login.Exec(f.ctx, "UPDATE public.event_outbox SET last_error='fixture_retry'")
				if err != nil || updated.RowsAffected() != 1 {
					t.Fatal("publisher RLS did not scope delivery writes")
				}
			}
			if kind == "signing_probe" {
				changes = append(changes,
					struct{ name, grant, revoke string }{"grant option", "GRANT SELECT ON public.security_ledger_head TO " + quoted + " WITH GRANT OPTION", "REVOKE GRANT OPTION FOR SELECT ON public.security_ledger_head FROM " + quoted},
					struct{ name, grant, revoke string }{"missing erasure SELECT", "REVOKE SELECT ON public.security_ledger_erasures FROM " + quoted, "GRANT SELECT ON public.security_ledger_erasures TO " + quoted},
					struct{ name, grant, revoke string }{"PUBLIC head EXECUTE", "GRANT EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) TO PUBLIC", "REVOKE EXECUTE ON FUNCTION public.advance_chain_head(text,bigint,bigint,bigint,bigint) FROM PUBLIC"})
			}
			for _, change := range changes {
				t.Run(change.name, func(t *testing.T) {
					mustExec(t, f.ctx, f.admin, change.grant)
					t.Cleanup(func() { mustExec(t, context.Background(), f.admin, change.revoke) })
					if err := probe(f.ctx); err == nil {
						t.Fatal("probe accepted prohibited effective privilege")
					}
				})
				if err := probe(f.ctx); err != nil {
					t.Fatalf("restart after revoking %s: %v", change.name, err)
				}
			}
			for _, guard := range dbprivilege.EvidenceGuards() {
				t.Run(guard.Name, func(t *testing.T) {
					mustExec(t, f.ctx, f.admin, "ALTER TABLE "+guard.Table+" ENABLE REPLICA TRIGGER "+guard.Name)
					t.Cleanup(func() {
						mustExec(t, context.Background(), f.admin, "ALTER TABLE "+guard.Table+" ENABLE TRIGGER "+guard.Name)
					})
					if err := probe(f.ctx); err == nil {
						t.Fatal("probe accepted replica-only guard")
					}
				})
			}
			// Ownership of an otherwise unprivileged object is still a DDL bypass.
			mustExec(t, f.ctx, f.admin, "CREATE TABLE public.probe_owned(id integer)")
			mustExec(t, f.ctx, f.admin, "ALTER TABLE public.probe_owned OWNER TO "+quoted)
			if err := probe(f.ctx); err == nil {
				t.Fatal("probe accepted table ownership")
			}
			mustExec(t, f.ctx, f.admin, "DROP TABLE public.probe_owned")
			mustExec(t, f.ctx, f.admin, "CREATE FUNCTION public.probe_owned() RETURNS integer LANGUAGE sql AS 'SELECT 1'")
			mustExec(t, f.ctx, f.admin, "ALTER FUNCTION public.probe_owned() OWNER TO "+quoted)
			if err := probe(f.ctx); err == nil {
				t.Fatal("probe accepted function ownership")
			}
			mustExec(t, f.ctx, f.admin, "DROP FUNCTION public.probe_owned()")
			mustExec(t, f.ctx, f.admin, "CREATE DOMAIN public.probe_owned AS integer")
			mustExec(t, f.ctx, f.admin, "ALTER DOMAIN public.probe_owned OWNER TO "+quoted)
			if err := probe(f.ctx); err == nil {
				t.Fatal("probe accepted domain ownership")
			}
			mustExec(t, f.ctx, f.admin, "DROP DOMAIN public.probe_owned")
			mustExec(t, f.ctx, f.admin, "CREATE SCHEMA probe_owned AUTHORIZATION "+quoted)
			if err := probe(f.ctx); err == nil {
				t.Fatal("probe accepted schema ownership/CREATE")
			}
			mustExec(t, f.ctx, f.admin, "DROP SCHEMA probe_owned")
			if err := probe(f.ctx); err != nil {
				t.Fatalf("valid real-login restart: %v", err)
			}
		})
	}
}
