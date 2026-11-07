package receiptreconcile

import (
	"context"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// ProbePrivileges requires a separate read login, never the purge/signer login.
func ProbePrivileges(ctx context.Context, q db.DBTX) error {
	return dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{
			{Name: "public.security_ledger_erasures", Select: true},
			{Name: "public.event_outbox", Select: true},
			{Name: "public.mvp_audit_logs", Select: true},
			{Name: "public.audit_log_chain", Select: true},
			{Name: "public.audit_log_head", Select: true},
		},
		Guards: dbprivilege.EvidenceGuards(),
	})
}
