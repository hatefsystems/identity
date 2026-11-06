package adminaction

import (
	"context"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
)

// ProbePublisher requires delivery-only ACLs and database-enforced subject/marker
// isolation. Accept only the explicit two-policy deployment contract; arbitrary
// logically equivalent policy expressions require separate operator review.
func ProbePublisher(ctx context.Context, q db.DBTX, subject string) error {
	if !validSubject(subject) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{{Name: "public.event_outbox", Select: true,
			UpdateColumns: []string{"published_at", "attempts", "next_attempt_at", "last_error"}}},
		Guards: dbprivilege.EvidenceGuards(),
	}); err != nil {
		return ErrUnavailable
	}
	var scoped bool
	err := q.QueryRow(ctx, `WITH expected AS (
 SELECT format('(admin_action AND ((subject)::text = %L::text))',$1::text) AS predicate),
 applicable AS (SELECT p.* FROM pg_catalog.pg_policy p
 WHERE p.polrelid='public.event_outbox'::regclass AND
 (0=ANY(p.polroles) OR (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)=ANY(p.polroles)))
 SELECT current_setting('row_security')='on'
 AND (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid='public.event_outbox'::regclass)
 AND (SELECT count(*)=2 AND count(*) FILTER(WHERE polcmd='r')=1
   AND count(*) FILTER(WHERE polcmd='w')=1 FROM applicable)
 AND NOT EXISTS(SELECT 1 FROM applicable p,expected e WHERE NOT p.polpermissive
   OR cardinality(p.polroles)<>1 OR 0=ANY(p.polroles)
   OR pg_catalog.pg_get_expr(p.polqual,p.polrelid) IS DISTINCT FROM e.predicate
   OR (p.polcmd='r' AND p.polwithcheck IS NOT NULL)
   OR (p.polcmd='w' AND pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) IS DISTINCT FROM e.predicate))`, subject).Scan(&scoped)
	if err != nil || !scoped {
		return ErrUnavailable
	}
	return nil
}

// ProbeContextMaintenance permits only held-aware context erasure and baseline
// reads. It is distinct from the publisher and requires no narrative key.
func ProbeContextMaintenance(ctx context.Context, q db.DBTX) error {
	if err := dbprivilege.Check(ctx, q, dbprivilege.Contract{
		Tables: []dbprivilege.Table{
			{Name: "public.admin_action_contexts", Select: true, Delete: true},
			{Name: "public.legal_holds", Select: true},
			{Name: "public.legal_governance_policies", Select: true},
			{Name: "public.legal_governance_baseline", Select: true},
		},
		Guards: dbprivilege.EvidenceGuards(),
	}); err != nil {
		return ErrUnavailable
	}
	return nil
}
