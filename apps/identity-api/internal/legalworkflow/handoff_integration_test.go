//go:build integration

package legalworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func TestHoldReviewReadHandoffAndExpiryIntegration(t *testing.T) {
	f := integrationFixture(t)
	holds, original, id := f.applyHold(t, uuid.New())
	// This is a hold-only disclosure, not an implicit case-read grant.
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM role_permissions WHERE role_id='dpo' AND permission_id='legal.cases.read'`); err != nil {
		t.Fatal(err)
	}
	ctx, op := f.op(t, 2)
	never, err := f.service.GetHoldReviews(ctx, f.actors[2], id)
	if err != nil || never.Version != 0 || never.NextReviewAt == nil || !never.NextReviewAt.Equal(original.ReviewAt) || len(never.History) != 0 || never.HistoryTruncated {
		t.Fatalf("unreviewed state=%+v err=%v", never, err)
	}
	commit(ctx, t, op)
	future := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	ctx, op = f.op(t, 0)
	_, err = f.service.ReviewHold(ctx, f.actors[0], HoldReviewRequest{Key: uuid.New(), HoldID: id, Decision: "continue", Rationale: "private handoff narrative", NextReviewAt: &future})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 1)
	first, err := f.service.GetHoldReviews(ctx, f.actors[1], id)
	if err != nil || first.Version != 1 || first.NextReviewAt == nil || !first.NextReviewAt.Equal(future) || len(first.History) != 1 || first.History[0].Actor != f.actors[0].ID {
		t.Fatalf("future handoff=%+v err=%v", first, err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 1)
	_, err = f.service.ReviewHold(ctx, f.actors[1], HoldReviewRequest{Key: uuid.New(), HoldID: id, ExpectedVersion: 1, Decision: "needs_information", Rationale: "different operator", NextReviewAt: nil})
	if err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	ctx, op = f.op(t, 2)
	second, err := f.service.GetHoldReviews(ctx, f.actors[2], id)
	if err != nil || second.Version != 2 || second.NextReviewAt != nil || len(second.History) != 2 || second.History[0].Actor != f.actors[1].ID || second.History[1].Actor != f.actors[0].ID {
		t.Fatalf("null schedule handoff=%+v err=%v", second, err)
	}
	commit(ctx, t, op)
	var leaked bool
	if err = f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM event_outbox WHERE payload::jsonb->>'event_type'='legal.review.hold_read'
        AND (payload LIKE '%private handoff narrative%' OR payload LIKE '%response_digest%' OR payload LIKE $1))`, "%"+id.String()+"%").Scan(&leaked); err != nil || leaked {
		t.Fatalf("handoff leaked general audit material=%v err=%v", leaked, err)
	}
	if _, err = f.pool.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id=$1`, f.actors[2].ID); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 2)
	if _, err = f.service.GetHoldReviews(ctx, f.actors[2], id); !errors.Is(err, rbac.ErrForbidden) {
		t.Fatalf("revoked read=%v", err)
	}
	_ = op.Rollback(ctx)
	ctx, op = f.op(t, 0)
	if _, err = holds.Release(ctx, id, f.actors[0].ID); err != nil {
		t.Fatal(err)
	}
	commit(ctx, t, op)
	var released time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT released_at FROM legal_holds WHERE id=$1`, id).Scan(&released); err != nil {
		t.Fatal(err)
	}
	cutoff := released.Add(f.policy.ReleasedHoldRetention())
	f.service.now = func() time.Time { return cutoff.Add(-time.Microsecond) }
	ctx, op = f.op(t, 0)
	if _, err = f.service.GetHoldReviews(ctx, f.actors[0], id); err != nil {
		t.Fatalf("before expiry=%v", err)
	}
	commit(ctx, t, op)
	f.service.now = func() time.Time { return cutoff }
	ctx, op = f.op(t, 0)
	if _, err = f.service.GetHoldReviews(ctx, f.actors[0], id); !errors.Is(err, ErrExpired) {
		t.Fatalf("equality expiry=%v", err)
	}
	_ = op.Rollback(ctx)
	pool, actions := f.maintenance(t)
	maint, _ := New(f.service.encryptor, Config{Environment: "test"})
	maint.now = f.service.now
	if _, err = maint.Cleanup(f.ctx, pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 500, false); err != nil {
		t.Fatal(err)
	}
	ctx, op = f.op(t, 0)
	if _, err = f.service.GetHoldReviews(ctx, f.actors[0], id); !errors.Is(err, ErrErased) {
		t.Fatalf("erased history impersonated never-created state: %v", err)
	}
	_ = op.Rollback(ctx)
	var preserved bool
	if err = f.pool.QueryRow(f.ctx, `SELECT review_at=$2 AND released_at=$3 FROM legal_holds WHERE id=$1`, id, original.ReviewAt, released).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("original clocks reset=%v err=%v", !preserved, err)
	}
}

func TestHoldReviewHistoryCapsAndUnavailableIntegration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		events   int
		inputLen int
		want     int
	}{
		{"event_cap", 201, 20, 200}, {"byte_cap", 100, 12000, 87},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := integrationFixture(t)
			_, _, id := f.applyHold(t, uuid.New())
			ctx, op := f.op(t, 0)
			// Seed sealed historical envelopes directly so both independent read
			// caps are exercised without 201 unrelated audit transactions.
			input, err := json.Marshal(map[string]any{"rationale": strings.Repeat("x", tc.inputLen)})
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= tc.events; i++ {
				c := state{Summary: Summary{MutationResult: MutationResult{ID: id, Version: int64(i), Status: "reviewed", Decision: "continue"}}}
				if err = f.service.saveEvent(ctx, op, f.actors[0], c, "hold_review", id, uuid.New(), uuid.New(), input); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = op.Tx.Exec(ctx, `INSERT INTO legal_hold_reviews(hold_id,account_ref,policy_id,version) SELECT id,account_ref,$2,$3 FROM legal_holds WHERE id=$1`, id, f.policy.ID, tc.events); err != nil {
				t.Fatal(err)
			}
			commit(ctx, t, op)
			ctx, op = f.op(t, 1)
			result, err := f.service.GetHoldReviews(ctx, f.actors[1], id)
			if err != nil || !result.HistoryTruncated || len(result.History) != tc.want || result.Version != int64(tc.events) {
				t.Fatalf("bounded history len=%d truncated=%v version=%d err=%v", len(result.History), result.HistoryTruncated, result.Version, err)
			}
			commit(ctx, t, op)
			if _, err = f.pool.Exec(f.ctx, `DELETE FROM legal_hold_reviews WHERE hold_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			ctx, op = f.op(t, 1)
			if _, err = f.service.GetHoldReviews(ctx, f.actors[1], id); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("missing aggregate impersonated never-reviewed state=%v", err)
			}
			_ = op.Rollback(ctx)
		})
	}
}

func TestWorkflowStatusEmptyHeldAndLowerBoundsIntegration(t *testing.T) {
	f := integrationFixture(t)
	pool, _ := f.maintenance(t)
	asOf := time.Now().UTC().Truncate(time.Microsecond)
	empty, err := StatusSnapshot(f.ctx, pool, "test", 1000, asOf)
	if err != nil || empty.EligibleExpired.Count != 0 || empty.HeldExpired.Count != 0 || empty.OldestEligibleAgeSeconds != nil || empty.DueReviews.Count != 0 {
		t.Fatalf("empty status=%+v err=%v", empty, err)
	}
	subject := uuid.New()
	_, _, holdID := f.applyHold(t, subject)
	heldCase, _ := f.create(t, subject)
	if _, err = f.pool.Exec(f.ctx, `UPDATE legal_cases SET expires_at=$2,next_review_at=$3 WHERE id=$1`, heldCase.ID, asOf.Add(-time.Hour), asOf); err != nil {
		t.Fatal(err)
	}
	allHeld, err := StatusSnapshot(f.ctx, pool, "test", 1000, asOf)
	if err != nil || allHeld.EligibleExpired.Count != 0 || allHeld.HeldExpired.Count != 1 || allHeld.OldestEligibleAgeSeconds != nil || allHeld.DueReviews.Count != 2 || allHeld.OverdueReviews.Count != 1 {
		t.Fatalf("all-held/equality reviews=%+v err=%v", allHeld, err)
	}
	for i := 0; i < 3; i++ {
		c, _ := f.create(t)
		if _, err = f.pool.Exec(f.ctx, `UPDATE legal_cases SET expires_at=$2 WHERE id=$1`, c.ID, asOf.Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	bounded, err := StatusSnapshot(f.ctx, pool, "test", 1, asOf)
	if err != nil || bounded.EligibleExpired.Count != 1 || !bounded.EligibleExpired.LowerBound || bounded.HeldExpired.Count != 1 || bounded.HeldExpired.LowerBound || !bounded.DueReviews.LowerBound || bounded.OverdueReviews.LowerBound || bounded.OldestEligibleAgeSeconds == nil || *bounded.OldestEligibleAgeSeconds != 7200 {
		t.Fatalf("lower bounds=%+v err=%v", bounded, err)
	}
	encoded, err := json.Marshal(bounded)
	if err != nil || strings.Contains(string(encoded), subject.String()) || strings.Contains(string(encoded), heldCase.ID.String()) || strings.Contains(string(encoded), holdID.String()) {
		t.Fatal("status disclosed restricted identifiers")
	}
	if _, err = StatusSnapshot(f.ctx, pool, "production", 1000, asOf); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fixture policy used in production=%v", err)
	}
}

func TestWorkflowCleanupAuditRollbackIntegration(t *testing.T) {
	f := integrationFixture(t)
	subject := uuid.New()
	c, _ := f.create(t, subject)
	var cutoff time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT expires_at FROM legal_cases WHERE id=$1`, c.ID).Scan(&cutoff); err != nil {
		t.Fatal(err)
	}
	pool, actions := f.maintenance(t)
	maint, _ := New(f.service.encryptor, Config{Environment: "test"})
	maint.now = func() time.Time { return cutoff }
	if _, err := maint.Cleanup(f.ctx, pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 501, false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("workflow limit 501=%v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `CREATE FUNCTION workflow_cleanup_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture outbox failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `CREATE TRIGGER workflow_cleanup_reject BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION workflow_cleanup_reject()`); err != nil {
		t.Fatal(err)
	}
	if _, err := maint.Cleanup(f.ctx, pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 500, false); !errors.Is(err, adminaction.ErrUnavailable) {
		t.Fatalf("cleanup outbox failure=%v", err)
	}
	var intact bool
	if err := f.pool.QueryRow(f.ctx, `SELECT status='open' AND version=$2 AND content_event IS NOT NULL AND policy_id IS NOT NULL AND
        EXISTS(SELECT 1 FROM legal_workflow_events WHERE scope=$1) AND EXISTS(SELECT 1 FROM legal_case_subjects WHERE case_id=$1) AND
        EXISTS(SELECT 1 FROM legal_workflow_replays WHERE result_id=$1 AND NOT erased AND event_id IS NOT NULL) FROM legal_cases WHERE id=$1`, c.ID, c.Version).Scan(&intact); err != nil || !intact {
		t.Fatalf("failed receipt committed erasure/minimization=%v err=%v", !intact, err)
	}
	if _, err := f.pool.Exec(f.ctx, `DROP TRIGGER workflow_cleanup_reject ON event_outbox`); err != nil {
		t.Fatal(err)
	}
	result, err := maint.Cleanup(f.ctx, pool, actions, Actor{ID: uuid.New()}, "spiffe://identity.test/maintenance", 500, false)
	if err != nil || result.Deleted != 1 {
		t.Fatalf("disabled-intake recovery=%+v err=%v", result, err)
	}
}

func TestClosedWorkflowMinimumExpiryAndNoResetIntegration(t *testing.T) {
	for _, lateClose := range []bool{false, true} {
		f := integrationFixture(t)
		created := time.Now().UTC().Truncate(time.Microsecond)
		f.service.now = func() time.Time { return created }
		c, _ := f.create(t)
		originalExpiry := created.Add(f.policy.Workflow.MaxCaseAge())
		closed := created.Add(time.Hour)
		if lateClose {
			closed = originalExpiry.Add(-time.Minute)
		}
		f.service.now = func() time.Time { return closed }
		c = f.review(t, c, "rejected")
		ctx, op := f.op(t, 0)
		r := CloseRequest{Key: uuid.New(), CaseID: c.ID, ExpectedVersion: c.Version, Reason: "no_response_required", Rationale: "fixture closed"}
		_, err := f.service.Close(ctx, f.actors[0], r)
		if err != nil {
			t.Fatal(err)
		}
		commit(ctx, t, op)
		want := closed.Add(f.policy.Workflow.ClosedCaseRetention())
		if originalExpiry.Before(want) {
			want = originalExpiry
		}
		f.service.now = func() time.Time { return closed.Add(time.Second) }
		ctx, op = f.op(t, 1)
		if replay, err := f.service.Close(ctx, f.actors[1], r); err != nil || !replay.Replayed {
			t.Fatalf("closed replay=%+v err=%v", replay, err)
		}
		commit(ctx, t, op)
		var expiry, closedAt time.Time
		if err = f.pool.QueryRow(context.Background(), `SELECT expires_at,closed_at FROM legal_cases WHERE id=$1`, c.ID).Scan(&expiry, &closedAt); err != nil || !expiry.Equal(want) || !closedAt.Equal(closed) {
			t.Fatalf("minimum/reset expiry=%v closure=%v want=%v err=%v", expiry, closedAt, want, err)
		}
	}
}
