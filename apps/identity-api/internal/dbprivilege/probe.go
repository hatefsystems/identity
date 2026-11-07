// Package dbprivilege checks effective maintenance privileges without changing ACLs.
package dbprivilege

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// ErrUnsafe deliberately omits catalog names, identities and database diagnostics.
var ErrUnsafe = errors.New("restricted database privileges required")

// Table describes required table grants and the only permitted column updates.
// A table UPDATE grant is not interchangeable with a narrow column allowance.
type Table struct {
	Name          string
	Select        bool
	Insert        bool
	Update        bool
	Delete        bool
	UpdateColumns []string
}

// Guard binds the trigger name, function and event mask, not just its enabled bit.
type Guard struct {
	Table, Name, Function string
	Type                  int
}

// Contract is an explicit allowlist. All other user-table/sequence privileges are
// refused, including privileges inherited from PUBLIC and column-only grants.
type Contract struct {
	Tables    []Table
	Sequences []string
	Functions []string
	Guards    []Guard
}

// Check requires an actual, non-owner, non-inheriting login with no membership
// (including NOINHERIT SET ROLE paths). It never grants or revokes privileges.
func Check(ctx context.Context, q db.DBTX, contract Contract) error {
	if q == nil {
		return ErrUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if contract.Tables == nil {
		contract.Tables = []Table{}
	}
	if contract.Sequences == nil {
		contract.Sequences = []string{}
	}
	if contract.Functions == nil {
		contract.Functions = []string{}
	}
	if contract.Guards == nil {
		contract.Guards = []Guard{}
	}
	for i := range contract.Tables {
		if contract.Tables[i].UpdateColumns == nil {
			contract.Tables[i].UpdateColumns = []string{}
		}
	}
	encoded, err := json.Marshal(contract)
	if err != nil {
		return ErrUnsafe
	}
	var safe bool
	err = q.QueryRow(ctx, `WITH specification AS (SELECT $1::jsonb AS value),
 allowed AS (SELECT x.*,to_regclass(x."Name") AS oid FROM specification,
   jsonb_to_recordset(value->'Tables') AS x("Name" text,"Select" boolean,"Insert" boolean,
     "Update" boolean,"Delete" boolean,"UpdateColumns" jsonb)),
 relations AS (SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 functions AS (SELECT to_regprocedure(x) AS oid FROM specification,
   jsonb_array_elements_text(coalesce(value->'Functions','[]'::jsonb)) x),
 sequences AS (SELECT to_regclass(x) AS oid FROM specification,
   jsonb_array_elements_text(coalesce(value->'Sequences','[]'::jsonb)) x)
 SELECT current_user=session_user AND r.rolcanlogin AND NOT r.rolinherit
 AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid)
 AND NOT pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_shdepend d
   WHERE d.refclassid='pg_catalog.pg_authid'::regclass AND d.refobjid=r.oid AND d.deptype='o'
   AND (d.dbid=0 OR d.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())))
 AND NOT pg_catalog.has_parameter_privilege(r.oid,'session_replication_role','SET')
 AND current_setting('session_replication_role')='origin'
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace
   WHERE nspowner=r.oid OR pg_catalog.has_schema_privilege(r.oid,oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM relations WHERE relowner=r.oid)
 AND NOT EXISTS(SELECT 1 FROM relations c,
   pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) acl
   WHERE acl.grantee IN (0,r.oid) AND acl.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM relations c JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid,
   pg_catalog.aclexplode(a.attacl) acl WHERE acl.grantee IN (0,r.oid) AND acl.is_grantable)
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND p.proowner=r.oid)
 AND NOT EXISTS(SELECT 1 FROM allowed WHERE oid IS NULL)
 AND NOT EXISTS(SELECT 1 FROM allowed a WHERE
   (a."Select" AND NOT pg_catalog.has_table_privilege(r.oid,a.oid,'SELECT')) OR
   (a."Insert" AND NOT pg_catalog.has_table_privilege(r.oid,a.oid,'INSERT')) OR
   (a."Update" AND NOT pg_catalog.has_table_privilege(r.oid,a.oid,'UPDATE')) OR
   (a."Delete" AND NOT pg_catalog.has_table_privilege(r.oid,a.oid,'DELETE')) OR
   EXISTS(SELECT 1 FROM jsonb_array_elements_text(coalesce(a."UpdateColumns",'[]'::jsonb)) col
     WHERE NOT pg_catalog.has_column_privilege(r.oid,a.oid,col,'UPDATE')))
 AND NOT EXISTS(SELECT 1 FROM relations c LEFT JOIN allowed a ON a.oid=c.oid
   WHERE c.relkind IN ('r','p','v','m','f') AND (
     (NOT coalesce(a."Select",false) AND pg_catalog.has_any_column_privilege(r.oid,c.oid,'SELECT')) OR
     (NOT coalesce(a."Insert",false) AND pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT')) OR
     (NOT coalesce(a."Delete",false) AND pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE')) OR
     pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE,TRIGGER,REFERENCES') OR
     pg_catalog.has_any_column_privilege(r.oid,c.oid,'REFERENCES') OR
     (NOT coalesce(a."Update",false) AND (
       pg_catalog.has_table_privilege(r.oid,c.oid,'UPDATE') OR EXISTS(
         SELECT 1 FROM pg_catalog.pg_attribute col WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped
         AND pg_catalog.has_column_privilege(r.oid,c.oid,col.attnum,'UPDATE')
         AND NOT coalesce(a."UpdateColumns",'[]'::jsonb) ? col.attname)))))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE (n.nspname ~ '^pg_' OR n.nspname='information_schema') AND c.relkind IN ('r','p','v','m','f')
   AND (pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,DELETE,TRUNCATE,TRIGGER,REFERENCES')
     OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT,REFERENCES')
     -- PostgreSQL grants PUBLIC UPDATE on this GUC view; its native update rule
     -- still checks parameter ACLs, including the replication SET denial above.
     OR (c.oid<>'pg_catalog.pg_settings'::regclass AND pg_catalog.has_any_column_privilege(r.oid,c.oid,'UPDATE'))))
 AND NOT EXISTS(SELECT 1 FROM sequences WHERE oid IS NULL OR NOT pg_catalog.has_sequence_privilege(r.oid,oid,'USAGE'))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relkind='S' AND (
   pg_catalog.has_sequence_privilege(r.oid,c.oid,'SELECT,UPDATE') OR
   (pg_catalog.has_sequence_privilege(r.oid,c.oid,'USAGE') AND NOT EXISTS(SELECT 1 FROM sequences WHERE oid=c.oid))))
 AND NOT EXISTS(SELECT 1 FROM functions WHERE oid IS NULL OR NOT pg_catalog.has_function_privilege(r.oid,oid,'EXECUTE'))
 -- Initial catalog/extension ACLs identify privileged native routines even if
 -- deployment accidentally grants them to PUBLIC (for example lo_export).
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   LEFT JOIN pg_catalog.pg_init_privs i ON i.classoid='pg_catalog.pg_proc'::regclass AND i.objoid=p.oid AND i.objsubid=0
   WHERE (n.nspname ~ '^pg_' OR i.objoid IS NOT NULL)
   AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(i.initprivs,pg_catalog.acldefault('f',p.proowner))) acl
     WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')
   AND NOT EXISTS(SELECT 1 FROM functions WHERE oid=p.oid))
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
   AND (p.prosecdef OR p.proname IN ('advance_chain_head','chain_table_guard','security_event_ledger_guard',
     'mvp_audit_logs_guard','legal_governance_immutable','legal_workflow_event_immutable'))
   AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')
   AND NOT EXISTS(SELECT 1 FROM functions WHERE oid=p.oid))
 AND NOT EXISTS(SELECT 1 FROM functions f JOIN pg_catalog.pg_proc p ON p.oid=f.oid
   WHERE NOT p.prosecdef OR NOT coalesce(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, pg_temp']
   OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
     WHERE (acl.grantee=0 AND acl.privilege_type='EXECUTE') OR (acl.grantee=r.oid AND acl.is_grantable)))
 AND NOT EXISTS(SELECT 1 FROM specification,
   jsonb_to_recordset(value->'Guards') AS g("Table" text,"Name" text,"Function" text,"Type" integer)
   WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass(g."Table")
     AND t.tgname=g."Name" AND t.tgfoid=to_regprocedure(g."Function") AND t.tgtype=g."Type"
     AND NOT t.tgisinternal AND t.tgenabled IN ('O','A')))
 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`, encoded).Scan(&safe)
	if err != nil || !safe {
		return ErrUnsafe
	}
	return nil
}

// EvidenceGuards are the v2 append-only and immutable-payload boundaries.
func EvidenceGuards() []Guard {
	return []Guard{
		{"public.audit_log_chain", "trg_audit_log_chain_append_only", "public.chain_table_guard()", 27},
		{"public.audit_log_chain", "trg_audit_log_chain_no_truncate", "public.chain_table_guard()", 34},
		{"public.security_ledger_chain", "trg_security_ledger_chain_append_only", "public.chain_table_guard()", 27},
		{"public.security_ledger_chain", "trg_security_ledger_chain_no_truncate", "public.chain_table_guard()", 34},
		{"public.mvp_audit_logs", "trg_mvp_audit_logs_immutable", "public.mvp_audit_logs_guard()", 19},
		{"public.mvp_audit_logs", "trg_mvp_audit_logs_no_truncate", "public.mvp_audit_logs_guard()", 34},
		{"public.security_event_ledger", "trg_security_event_ledger_immutable", "public.security_event_ledger_guard()", 19},
		{"public.security_event_ledger", "trg_security_event_ledger_no_truncate", "public.security_event_ledger_guard()", 34},
		{"public.security_ledger_erasures", "trg_security_ledger_erasures_append_only", "public.chain_table_guard()", 27},
		{"public.security_ledger_erasures", "trg_security_ledger_erasures_no_truncate", "public.chain_table_guard()", 34},
	}
}
