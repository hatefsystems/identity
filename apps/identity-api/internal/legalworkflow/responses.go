package legalworkflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func reviewed(c state, bearing bool) bool {
	return c.ReviewedRevision == c.ContentRevision && c.Decision != "pending" && (!bearing || c.Decision == "accepted")
}

// PrepareResponse freezes exact scope and invalidates any earlier approval.
func (s *Service) PrepareResponse(ctx context.Context, a Actor, r ResponseRequest) (MutationResult, error) {
	if err := r.validate(); err != nil {
		return MutationResult{}, err
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, nil, "legal.cases.write", "prepare", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	if r.ContentRevision != c.ContentRevision || !reviewed(c, dataBearing(r.Outcome)) {
		return MutationResult{}, ErrConflict
	}
	for _, id := range r.Manifest.SubjectIDs {
		var linked bool
		err = op.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_case_subjects WHERE case_id=$1 AND account_ref=$2 AND current)`, c.ID, id).Scan(&linked)
		if err != nil {
			return MutationResult{}, ErrUnavailable
		}
		if !linked {
			return MutationResult{}, ErrInvalidRequest
		}
	}
	id := uuid.New()
	c.ResponseEvent = nullable(id)
	c.ProposalRevision++
	c.ResponseContentRevision = c.ContentRevision
	c.Preparer = nullable(a.ID)
	c.PreparerVersion = &a.AuthVersion
	c.Approver = uuid.NullUUID{}
	c.ApproverVersion = nil
	c.ApprovedProposalRevision = 0
	return s.finish(ctx, op, a, c, "prepare", r.Key, id, input)
}
func (s *Service) proposal(ctx context.Context, op *adminaction.Operation, c state) (ResponseRequest, error) {
	if !c.ResponseEvent.Valid {
		return ResponseRequest{}, ErrConflict
	}
	e, err := s.event(ctx, op.Tx, c.ResponseEvent.UUID, c.ID)
	if err != nil {
		return ResponseRequest{}, err
	}
	var r ResponseRequest
	if e.Purpose != "prepare" || e.Result.ProposalRevision != c.ProposalRevision || json.Unmarshal(e.Input, &r) != nil || r.ContentRevision != c.ResponseContentRevision {
		return ResponseRequest{}, ErrUnavailable
	}
	return r, nil
}

// ApproveResponse requires a currently authorized account distinct from preparer.
func (s *Service) ApproveResponse(ctx context.Context, a Actor, r ApprovalRequest) (MutationResult, error) {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return MutationResult{}, err
	}
	if r.ContentRevision < 1 || r.ProposalRevision < 1 {
		return MutationResult{}, ErrInvalidRequest
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, nil, "legal.responses.approve", "approve", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	p, err := s.proposal(ctx, op, c)
	if err != nil {
		return MutationResult{}, err
	}
	if !dataBearing(p.Outcome) || r.ContentRevision != c.ContentRevision || r.ProposalRevision != c.ProposalRevision || c.ResponseContentRevision != c.ContentRevision || !reviewed(c, true) {
		return MutationResult{}, ErrConflict
	}
	if c.Preparer.UUID == a.ID {
		return MutationResult{}, rbac.ErrForbidden
	}
	if c.PreparerVersion == nil {
		return MutationResult{}, ErrUnavailable
	}
	if err = eligible(ctx, op, c.Preparer.UUID, *c.PreparerVersion, "legal.cases.write"); err != nil {
		return MutationResult{}, err
	}
	c.Approver = nullable(a.ID)
	c.ApproverVersion = &a.AuthVersion
	c.ApprovedProposalRevision = c.ProposalRevision
	return s.finish(ctx, op, a, c, "approve", r.Key, uuid.New(), input)
}

// DeliverResponse rechecks all approval principals, counts one answer and closes.
func (s *Service) DeliverResponse(ctx context.Context, a Actor, r DeliveryRequest) (MutationResult, error) {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return MutationResult{}, err
	}
	if r.ContentRevision < 1 || r.ProposalRevision < 1 || !timestamp(r.DeliveredAt) || r.DeliveredAt.After(s.now()) || !text(r.ReceiptReference, 1024) {
		return MutationResult{}, ErrInvalidRequest
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, c, replay, err := s.mutation(ctx, a, r.CaseID, r.Key, r.ExpectedVersion, nil, "legal.cases.write", "deliver", input)
	if err != nil {
		return MutationResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	p, err := s.proposal(ctx, op, c)
	if err != nil {
		return MutationResult{}, err
	}
	bearing := dataBearing(p.Outcome)
	if r.ContentRevision != c.ContentRevision || r.ProposalRevision != c.ProposalRevision || c.ResponseContentRevision != c.ContentRevision || !reviewed(c, bearing) || c.ReceivedAt == nil || r.DeliveredAt.Before(*c.ReceivedAt) {
		return MutationResult{}, ErrConflict
	}
	if c.PreparerVersion == nil {
		return MutationResult{}, ErrUnavailable
	}
	if err = eligible(ctx, op, c.Preparer.UUID, *c.PreparerVersion, "legal.cases.write"); err != nil {
		return MutationResult{}, err
	}
	if bearing {
		if !c.Approver.Valid || c.Approver.UUID == c.Preparer.UUID || c.ApproverVersion == nil || c.ApprovedProposalRevision != c.ProposalRevision {
			return MutationResult{}, ErrConflict
		}
		if err = eligible(ctx, op, c.Approver.UUID, *c.ApproverVersion, "legal.responses.approve"); err != nil {
			return MutationResult{}, err
		}
	}
	// A manually entered timestamp cannot predate the recorded authority to
	// deliver this exact proposal. This checks chronology, not external transport.
	var preparedAt time.Time
	var approvedAt *time.Time
	err = op.Tx.QueryRow(ctx, `SELECT proposal.created_at,
		(SELECT approval.created_at FROM legal_workflow_events approval WHERE approval.scope=$1
		 AND approval.scope_kind='case' AND approval.purpose='approve' ORDER BY approval.revision DESC LIMIT 1)
		FROM legal_workflow_events proposal WHERE proposal.id=$2 AND proposal.scope=$1
		AND proposal.scope_kind='case' AND proposal.purpose='prepare'`, c.ID, c.ResponseEvent.UUID).Scan(&preparedAt, &approvedAt)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	if r.DeliveredAt.Before(preparedAt) || (bearing && (approvedAt == nil || r.DeliveredAt.Before(*approvedAt))) {
		return MutationResult{}, ErrConflict
	}
	if err = s.closeState(ctx, op.Tx, &c); err != nil {
		return MutationResult{}, err
	}
	if err = legalreport.CountAnswered(ctx, op.Tx, r.DeliveredAt, p.Outcome); err != nil {
		return MutationResult{}, ErrUnavailable
	}
	return s.finish(ctx, op, a, c, "deliver", r.Key, uuid.New(), input)
}
