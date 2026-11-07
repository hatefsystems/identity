package signer

import (
	"context"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// ProbePrivileges checks startup credentials without changing evidence or grants.
// UPDATE(id) on users is the existing row-lock-only allowance required by
// LockAuditSubjects; it does not permit changing account status or narratives.
func ProbePrivileges(ctx context.Context, q db.DBTX) error {
	return dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{
			{Name: "public.audit_log_chain", Select: true, Insert: true},
			{Name: "public.security_ledger_chain", Select: true, Insert: true},
			{Name: "public.mvp_audit_logs", Select: true, Insert: true},
			{Name: "public.security_event_ledger", Select: true, Insert: true},
			{Name: "public.audit_log_head", Select: true},
			{Name: "public.security_ledger_head", Select: true},
			{Name: "public.security_ledger_erasures", Select: true},
			{Name: "public.users", Select: true, UpdateColumns: []string{"id"}},
		},
		Sequences: []string{"public.audit_log_chain_seq", "public.security_ledger_chain_seq"},
		Functions: []string{"public.advance_chain_head(text,bigint,bigint,bigint,bigint)"},
		Guards:    dbprivilege.EvidenceGuards(),
	})
}
