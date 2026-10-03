package legalworkflow

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
)

// Create records one incoming request and counts it in its received-time cohort.
func (s *Service) Create(ctx context.Context, a Actor, r CreateRequest) (MutationResult, error) {
	if r.Key == uuid.Nil || r.ExpectedVersion != 0 || !timestamp(r.ReceivedAt) || r.ReceivedAt.After(s.now()) || !optionalTime(r.NextReviewAt) || !content(r.Content) {
		return MutationResult{}, ErrInvalidRequest
	}
	var err error
	r.SubjectIDs, err = ids(r.SubjectIDs)
	if err != nil {
		return MutationResult{}, err
	}
	r.HoldIDs, err = ids(r.HoldIDs)
	if err != nil {
		return MutationResult{}, err
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, err := operation(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	p, err := s.policy(ctx, op.Tx, s.cfg.PolicyID, true)
	if err != nil {
		return MutationResult{}, err
	}
	// The derived ID depends only on the opaque retry token, never content.
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("legalworkflow:create:"+r.Key.String()))
	old, err := load(ctx, op.Tx, id, false)
	absent := errors.Is(err, ErrNotFound)
	if err != nil && !absent {
		return MutationResult{}, err
	}
	if err = authorized(ctx, op, a, old.targets(r.SubjectIDs), "legal.cases.write"); err != nil {
		return MutationResult{}, err
	}
	if err = lockScope(ctx, op.Tx, "case", id); err != nil {
		return MutationResult{}, err
	}
	c, err := load(ctx, op.Tx, id, true)
	if err == nil {
		if !absent && !sameDiscovery(old, c) {
			return MutationResult{}, ErrConflict
		}
		if absent {
			// A simultaneous intake can be replayed only if every newly found
			// target was already locked and no further transition occurred.
			locked := union(append(r.SubjectIDs, a.ID))
			for _, target := range c.targets(nil) {
				if !contains(locked, target) {
					return MutationResult{}, ErrConflict
				}
			}
			if c.Version != 1 {
				return MutationResult{}, ErrConflict
			}
		}
		if err = s.accessible(ctx, op.Tx, c); err != nil {
			return MutationResult{}, err
		}
		if _, err = s.policy(ctx, op.Tx, c.PolicyID.UUID, true); err != nil {
			return MutationResult{}, err
		}
		result, ok, err := s.replay(ctx, op.Tx, "create", uuid.Nil, r.Key, input)
		if err != nil {
			return MutationResult{}, err
		}
		if !ok {
			return MutationResult{}, ErrConflict
		}
		auditResult(ctx, a, "create", true)
		return result, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return MutationResult{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	received := r.ReceivedAt.UTC().Truncate(time.Microsecond)
	expiry := now.Add(p.Workflow.MaxCaseAge())
	c = state{Summary: Summary{MutationResult: MutationResult{ID: id, Version: 1, ContentRevision: 1, Status: "open", Decision: "pending"}, ReceivedAt: &received, CreatedAt: &now, ExpiresAt: &expiry, NextReviewAt: r.NextReviewAt}, PolicyID: nullable(p.ID), Subjects: r.SubjectIDs}
	eventID := uuid.New()
	c.ContentEvent = nullable(eventID)
	_, err = op.Tx.Exec(ctx, `INSERT INTO legal_cases(id,status,version,content_revision,policy_id,received_at,created_at,next_review_at,expires_at,content_event)
        VALUES($1,'open',1,1,$2,$3,$4,$5,$6,$7)`, id, p.ID, received, now, r.NextReviewAt, expiry, eventID)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	if err = associations(ctx, op.Tx, c, r.SubjectIDs, r.HoldIDs); err != nil {
		return MutationResult{}, err
	}
	if err = s.saveEvent(ctx, op, a, c, "create", uuid.Nil, r.Key, eventID, input); err != nil {
		return MutationResult{}, err
	}
	if err = legalreport.CountReceived(ctx, op.Tx, received); err != nil {
		return MutationResult{}, ErrUnavailable
	}
	auditResult(ctx, a, "create", false)
	return c.MutationResult, nil
}
func nullable(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: true} }
func contains(ids []uuid.UUID, id uuid.UUID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func associations(ctx context.Context, tx pgx.Tx, c state, subjects, holds []uuid.UUID) error {
	if len(union(append(append([]uuid.UUID{}, c.Subjects...), subjects...))) > MaxSubjects {
		return ErrInvalidRequest
	}
	// Validate all links before writing. Subject locks serialize hold release,
	// application and hard deletion even when no users row survives.
	accounts := make([]uuid.UUID, len(holds))
	for i, id := range holds {
		err := tx.QueryRow(ctx, `SELECT account_ref FROM legal_holds WHERE id=$1`, id).Scan(&accounts[i])
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidRequest
		}
		if err != nil {
			return ErrUnavailable
		}
		if !contains(subjects, accounts[i]) {
			return ErrInvalidRequest
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE legal_case_subjects SET current=false WHERE case_id=$1`, c.ID); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE legal_case_holds SET current=false WHERE case_id=$1`, c.ID); err != nil {
		return ErrUnavailable
	}
	for _, id := range subjects {
		if _, err := tx.Exec(ctx, `INSERT INTO legal_case_subjects(case_id,account_ref,current) VALUES($1,$2,true)
            ON CONFLICT(case_id,account_ref) DO UPDATE SET current=true`, c.ID, id); err != nil {
			return ErrUnavailable
		}
	}
	for i, id := range holds {
		if _, err := tx.Exec(ctx, `INSERT INTO legal_case_holds(case_id,hold_id,account_ref,current) VALUES($1,$2,$3,true)
            ON CONFLICT(case_id,hold_id) DO UPDATE SET current=true`, c.ID, id, accounts[i]); err != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// Revise increments content revision and invalidates reviewed/approved authority.
func (s *Service) Revise(ctx context.Context, a Actor, r RevisionRequest) (MutationResult, error) {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return MutationResult{}, err
	}
	if !content(r.Content) {
		return MutationResult{}, ErrInvalidRequest
	}
	var err error
	r.SubjectIDs, err = ids(r.SubjectIDs)
	if err != nil {
		return MutationResult{}, err
	}
	r.HoldIDs, err = ids(r.HoldIDs)
	if err != nil {
		return MutationResult{}, err
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, r.SubjectIDs, "legal.cases.write", "revise", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	if err = associations(ctx, op.Tx, c, r.SubjectIDs, r.HoldIDs); err != nil {
		return MutationResult{}, err
	}
	c.ContentRevision++
	c.ReviewedRevision = 0
	c.Decision = "pending"
	c.ApprovedProposalRevision = 0
	c.Approver = uuid.NullUUID{}
	c.ApproverVersion = nil
	id := uuid.New()
	c.ContentEvent = nullable(id)
	return s.finish(ctx, op, a, c, "revise", r.Key, id, input)
}

// Review binds a human decision to content, independently of state bookkeeping.
func (s *Service) Review(ctx context.Context, a Actor, r ReviewRequest) (MutationResult, error) {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return MutationResult{}, err
	}
	if r.ContentRevision < 1 || !decision(r.Decision) || !text(r.Rationale, 4096) || !optionalTime(r.NextReviewAt) {
		return MutationResult{}, ErrInvalidRequest
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, nil, "legal.cases.write", "review", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	if r.ContentRevision != c.ContentRevision {
		return MutationResult{}, ErrConflict
	}
	c.Decision = r.Decision
	c.ReviewedRevision = c.ContentRevision
	c.NextReviewAt = r.NextReviewAt
	c.ApprovedProposalRevision = 0
	c.Approver = uuid.NullUUID{}
	c.ApproverVersion = nil
	return s.finish(ctx, op, a, c, "review", r.Key, uuid.New(), input)
}

// Close terminates without a response and never releases associated holds.
func (s *Service) Close(ctx context.Context, a Actor, r CloseRequest) (MutationResult, error) {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return MutationResult{}, err
	}
	if (r.Reason != "withdrawn" && r.Reason != "no_response_required") || !text(r.Rationale, 4096) {
		return MutationResult{}, ErrInvalidRequest
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, nil, "legal.cases.write", "close", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	if err = s.closeState(ctx, op.Tx, &c); err != nil {
		return MutationResult{}, err
	}
	return s.finish(ctx, op, a, c, "close", r.Key, uuid.New(), input)
}
func (s *Service) closeState(ctx context.Context, tx pgx.Tx, c *state) error {
	p, err := s.policy(ctx, tx, c.PolicyID.UUID, true)
	if err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	expiry := now.Add(p.Workflow.ClosedCaseRetention())
	c.Status = "closed"
	c.ClosedAt = &now
	c.NextReviewAt = nil
	if expiry.Before(*c.ExpiresAt) {
		c.ExpiresAt = &expiry
	}
	return nil
}
