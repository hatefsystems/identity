package legalworkflow

import (
	"context"
	"net/url"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/pglock"
)

// ProbeMaintenance refuses owner, role-membership, schema/DDL and evidence-write
// bypasses. Deployment supplies a separate login with precisely these grants.
// It is deliberately not an application DPO authorization check.
func ProbeMaintenance(ctx context.Context, tx pgx.Tx) error {
	var safe bool
	err := tx.QueryRow(ctx, `SELECT current_user=session_user AND
      NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'MEMBER') AND
        (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls))
      AND NOT has_schema_privilege(current_user,current_schema(),'CREATE')
      AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN (current_schema(),'public') AND c.relkind IN ('r','p') AND pg_has_role(current_user,c.relowner,'MEMBER'))
      AND has_table_privilege(current_user,'legal_cases','SELECT')
      AND has_table_privilege(current_user,'legal_cases','UPDATE')
      AND has_table_privilege(current_user,'legal_workflow_replays','SELECT')
      AND has_column_privilege(current_user,'legal_workflow_replays','erased','UPDATE')
      AND has_column_privilege(current_user,'legal_workflow_replays','event_id','UPDATE')
      AND has_table_privilege(current_user,'legal_workflow_events','DELETE')
      AND has_table_privilege(current_user,'legal_case_subjects','SELECT,DELETE')
      AND has_table_privilege(current_user,'legal_case_holds','DELETE')
      AND has_table_privilege(current_user,'legal_hold_reviews','SELECT,DELETE')
      AND has_table_privilege(current_user,'legal_holds','SELECT')
      AND has_table_privilege(current_user,'legal_governance_policies','SELECT')
      AND has_table_privilege(current_user,'legal_governance_baseline','SELECT')
      AND has_table_privilege(current_user,'event_outbox','INSERT')
      AND NOT has_table_privilege(current_user,'legal_cases','INSERT,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_workflow_events','INSERT,UPDATE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_workflow_replays','INSERT,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_case_subjects','INSERT,UPDATE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_case_holds','INSERT,UPDATE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_hold_reviews','INSERT,UPDATE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_governance_policies','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_governance_baseline','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'legal_holds','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'users','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'user_roles','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'role_permissions','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'event_outbox','UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'mvp_audit_logs','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT has_table_privilege(current_user,'security_event_ledger','INSERT,UPDATE,DELETE,TRUNCATE')
      AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[
        'users','roles','permissions','user_roles','role_permissions','legal_holds',
        'legal_governance_policies','legal_governance_baseline','mvp_audit_logs','security_event_ledger',
        'security_ledger_head','security_ledger_checkpoints','security_ledger_retention_settings',
        'legal_transparency_coverage','legal_transparency_years','legal_transparency_months',
        'legal_transparency_reports','legal_transparency_replays']) AS protected(name)
        WHERE has_table_privilege(current_user,name,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
           OR has_any_column_privilege(current_user,name,'INSERT,UPDATE'))
      AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY[
        'legal_workflow_events','legal_case_subjects','legal_case_holds','legal_hold_reviews']) AS restricted(name)
        WHERE has_any_column_privilege(current_user,name,'INSERT,UPDATE') OR has_table_privilege(current_user,name,'TRIGGER'))
      AND NOT has_any_column_privilege(current_user,'legal_cases','INSERT')
      AND NOT has_any_column_privilege(current_user,'legal_workflow_replays','INSERT')
      AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation','scope','idempotency_key','result_id']) AS immutable(name)
        WHERE has_column_privilege(current_user,'legal_workflow_replays',name,'UPDATE'))
      AND NOT has_any_column_privilege(current_user,'event_outbox','UPDATE')
      AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.proname IN ('purge_security_ledger_batch','advance_security_ledger_head') AND has_function_privilege(current_user,p.oid,'EXECUTE'))`).Scan(&safe)
	if err != nil || !safe {
		return ErrUnavailable
	}
	return nil
}

// Cleanup uses a fixed cutoff, skips held records before LIMIT, and commits each
// erasure and sanitized receipt together. A dry run rolls every operation back.
func (s *Service) Cleanup(ctx context.Context, pool *pgxpool.Pool, actions *adminaction.Service, actor Actor, identity string, limit int, dryRun bool) (CleanupResult, error) {
	result := CleanupResult{DryRun: dryRun}
	u, err := url.Parse(identity)
	if pool == nil || actions == nil || actor.ID == uuid.Nil || err != nil || u.Scheme != "spiffe" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(identity) > 255 || limit < 1 || limit > 500 {
		return result, ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cutoff := s.now().UTC().Truncate(time.Microsecond)
	probe, err := pool.Begin(ctx)
	if err != nil {
		return result, ErrUnavailable
	}
	err = ProbeMaintenance(ctx, probe)
	_ = probe.Rollback(context.WithoutCancel(ctx))
	if err != nil {
		return result, err
	}
	rows, err := pool.Query(ctx, `WITH candidates AS (
      SELECT c.id,'case'::text AS kind,c.expires_at AS expiry FROM legal_cases c
      WHERE c.status<>'erased' AND c.expires_at<=$1 AND NOT EXISTS(
        SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref WHERE s.case_id=c.id AND h.is_active)
      UNION ALL
      SELECT r.hold_id,'hold'::text,h.released_at + make_interval(secs => (p.artifact->>'released_hold_retention_seconds')::double precision)
      FROM legal_hold_reviews r JOIN legal_holds h ON h.id=r.hold_id JOIN legal_governance_policies p ON p.id=r.policy_id
      WHERE NOT h.is_active AND h.released_at + make_interval(secs => (p.artifact->>'released_hold_retention_seconds')::double precision)<=$1
        AND NOT EXISTS(SELECT 1 FROM legal_holds other WHERE other.account_ref=r.account_ref AND other.is_active)
    ) SELECT id,kind FROM candidates ORDER BY expiry,kind,id LIMIT $2`, cutoff, limit)
	if err != nil {
		return result, ErrUnavailable
	}
	type candidate struct {
		id   uuid.UUID
		kind string
	}
	var batch []candidate
	for rows.Next() {
		var c candidate
		if rows.Scan(&c.id, &c.kind) != nil {
			rows.Close()
			return result, ErrUnavailable
		}
		batch = append(batch, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, ErrUnavailable
	}
	for _, candidate := range batch {
		result.Considered++
		op, err := actions.Begin(ctx)
		if err != nil {
			return result, err
		}
		erased, held, err := func() (bool, bool, error) {
			defer func() { _ = op.Rollback(context.WithoutCancel(ctx)) }()
			if err := ProbeMaintenance(ctx, op.Tx); err != nil {
				return false, false, err
			}
			if _, err := op.Tx.Exec(ctx, `SET LOCAL lock_timeout='2s'`); err != nil {
				return false, false, ErrUnavailable
			}
			if _, err := op.Tx.Exec(ctx, `SET LOCAL statement_timeout='10s'`); err != nil {
				return false, false, ErrUnavailable
			}
			erased, held, err := s.cleanupRecord(ctx, op.Tx, candidate.id, candidate.kind, cutoff, dryRun)
			if err != nil || !erased || dryRun {
				return erased, held, err
			}
			op.Event = audit.Event{EventType: "legal.case.cleaned", ActorID: actor.ID, ActorSPIFFEID: identity, ActionStatus: audit.StatusSuccess, Payload: map[string]any{"deleted_count": int64(1), "dry_run": false}}
			if err = op.Commit(ctx); err != nil {
				return false, false, err
			}
			return true, false, nil
		}()
		if err != nil {
			return result, err
		}
		if held {
			result.Held++
		}
		if erased {
			if dryRun {
				result.WouldDelete++
			} else {
				result.Deleted++
			}
		}
	}
	return result, nil
}
func (s *Service) cleanupRecord(ctx context.Context, tx pgx.Tx, id uuid.UUID, kind string, cutoff time.Time, dryRun bool) (bool, bool, error) {
	if kind == "case" {
		old, err := load(ctx, tx, id, false)
		if err != nil {
			return false, false, err
		}
		for _, subject := range union(old.targets(nil)) {
			if err = pglock.LockAccount(ctx, tx, subject); err != nil {
				return false, false, ErrUnavailable
			}
		}
		if err = lockScope(ctx, tx, kind, id); err != nil {
			return false, false, err
		}
		c, err := load(ctx, tx, id, true)
		if err != nil {
			return false, false, err
		}
		if !sameDiscovery(old, c) {
			return false, false, ErrConflict
		}
		if c.Status == "erased" || c.ExpiresAt == nil || cutoff.Before(*c.ExpiresAt) {
			return false, false, nil
		}
		if _, err = s.policy(ctx, tx, c.PolicyID.UUID, false); err != nil {
			return false, false, err
		}
		yes, err := held(ctx, tx, c)
		if err != nil {
			return false, false, err
		}
		if yes {
			return false, true, nil
		}
	} else {
		old, err := loadHold(ctx, tx, id, false)
		if err != nil {
			return false, false, err
		}
		if err = pglock.LockAccount(ctx, tx, old.Account); err != nil {
			return false, false, ErrUnavailable
		}
		if err = lockScope(ctx, tx, kind, id); err != nil {
			return false, false, err
		}
		// The original hold belongs to Task 5.3. Its shared account lock is
		// sufficient; maintenance must not need UPDATE privileges on that table.
		h, err := loadHold(ctx, tx, id, false)
		if err != nil {
			return false, false, err
		}
		if !reflect.DeepEqual(old, h) {
			return false, false, ErrConflict
		}
		if !h.PolicyID.Valid {
			return false, false, nil
		}
		accessible, err := s.holdAccessible(ctx, tx, h, cutoff)
		if err != nil {
			return false, false, err
		}
		if accessible {
			return false, true, nil
		}
	}
	if dryRun {
		return true, false, nil
	}
	operationFilter := "operation<>'hold_review'"
	if kind == "hold" {
		operationFilter = "operation='hold_review'"
	}
	if _, err := tx.Exec(ctx, `UPDATE legal_workflow_replays SET erased=true,event_id=NULL WHERE result_id=$1 AND `+operationFilter, id); err != nil {
		return false, false, ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `DELETE FROM legal_workflow_events WHERE scope=$1 AND scope_kind=$2`, id, kind); err != nil {
		return false, false, ErrUnavailable
	}
	if kind == "hold" {
		if _, err := tx.Exec(ctx, `DELETE FROM legal_hold_reviews WHERE hold_id=$1`, id); err != nil {
			return false, false, ErrUnavailable
		}
	} else {
		if _, err := tx.Exec(ctx, `DELETE FROM legal_case_holds WHERE case_id=$1`, id); err != nil {
			return false, false, ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `DELETE FROM legal_case_subjects WHERE case_id=$1`, id); err != nil {
			return false, false, ErrUnavailable
		}
		if _, err := tx.Exec(ctx, `UPDATE legal_cases SET status='erased',version=0,content_revision=0,proposal_revision=0,decision='pending',
            reviewed_revision=0,response_content_revision=0,approved_proposal_revision=0,policy_id=NULL,received_at=NULL,created_at=NULL,
            closed_at=NULL,next_review_at=NULL,expires_at=NULL,content_event=NULL,response_event=NULL,preparer=NULL,preparer_auth_version=NULL,
            approver=NULL,approver_auth_version=NULL WHERE id=$1`, id); err != nil {
			return false, false, ErrUnavailable
		}
	}
	return true, false, nil
}
