package legalworkflow

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/google/uuid"
)

// GetHoldReviews needs only live hold-read authority. Account and scope locks
// serialize release, reviews and cleanup before any restricted body is opened.
func (s *Service) GetHoldReviews(ctx context.Context, a Actor, id uuid.UUID) (HoldReviews, error) {
	if id == uuid.Nil {
		return HoldReviews{}, ErrInvalidRequest
	}
	op, err := operation(ctx)
	if err != nil {
		return HoldReviews{}, err
	}
	old, err := loadHold(ctx, op.Tx, id, false)
	if err != nil {
		return HoldReviews{}, err
	}
	if err = authorized(ctx, op, a, []uuid.UUID{old.Account}, "legal.holds.read"); err != nil {
		return HoldReviews{}, err
	}
	if err = lockScope(ctx, op.Tx, "hold", id); err != nil {
		return HoldReviews{}, err
	}
	h, err := loadHold(ctx, op.Tx, id, true)
	if err != nil {
		return HoldReviews{}, err
	}
	if !reflect.DeepEqual(old, h) {
		return HoldReviews{}, ErrConflict
	}
	var erased, created bool
	err = op.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_workflow_replays WHERE operation='hold_review' AND scope=$1 AND erased),
        EXISTS(SELECT 1 FROM legal_workflow_replays WHERE operation='hold_review' AND scope=$1)`, id).Scan(&erased, &created)
	if err != nil {
		return HoldReviews{}, ErrUnavailable
	}
	if erased {
		return HoldReviews{}, ErrErased
	}
	accessible, err := s.holdAccessible(ctx, op.Tx, h, s.now())
	if err != nil {
		return HoldReviews{}, err
	}
	if !accessible {
		return HoldReviews{}, ErrExpired
	}
	if (h.Version == 0) != !created {
		return HoldReviews{}, ErrUnavailable
	}
	result := HoldReviews{Version: h.Version, NextReviewAt: h.NextReviewAt, History: []HistoryEntry{}}
	rows, err := op.Tx.Query(ctx, `SELECT id,revision,purpose,actor,action_id,created_at,body_encrypted FROM legal_workflow_events
        WHERE scope_kind='hold' AND scope=$1 ORDER BY revision DESC LIMIT 201`, id)
	if err != nil {
		return HoldReviews{}, ErrUnavailable
	}
	defer rows.Close()
	historyBytes := 0
	for rows.Next() {
		var entry HistoryEntry
		var blob []byte
		if rows.Scan(&entry.ID, &entry.Revision, &entry.Purpose, &entry.Actor, &entry.ActionID, &entry.CreatedAt, &blob) != nil ||
			entry.Revision != h.Version-int64(len(result.History)) || entry.Purpose != "hold_review" {
			return HoldReviews{}, ErrUnavailable
		}
		if len(result.History) == 200 {
			result.HistoryTruncated = true
			break
		}
		opened, err := s.open(ctx, blob, entry.ID, id, entry.Revision, entry.Purpose)
		if err != nil {
			return HoldReviews{}, err
		}
		historyBytes += len(opened.Input)
		if historyBytes > 1024*1024 {
			result.HistoryTruncated = true
			break
		}
		entry.Input = opened.Input
		result.History = append(result.History, entry)
	}
	if rows.Err() != nil || (!result.HistoryTruncated && int64(len(result.History)) != h.Version) {
		return HoldReviews{}, ErrUnavailable
	}
	auditResult(ctx, a, "hold_read", false)
	return result, nil
}

// Get decrypts one accessible case under the same locks used by cleanup.
func (s *Service) Get(ctx context.Context, a Actor, id uuid.UUID) (Case, error) {
	if id == uuid.Nil {
		return Case{}, ErrInvalidRequest
	}
	op, c, err := s.beginCase(ctx, a, id, nil, "legal.cases.read")
	if err != nil {
		return Case{}, err
	}
	if _, err = s.policy(ctx, op.Tx, c.PolicyID.UUID, false); err != nil {
		return Case{}, err
	}
	e, err := s.event(ctx, op.Tx, c.ContentEvent.UUID, id)
	if err != nil {
		return Case{}, err
	}
	var body RevisionRequest
	if (e.Purpose != "create" && e.Purpose != "revise") || e.Result.ContentRevision != c.ContentRevision || json.Unmarshal(e.Input, &body) != nil {
		return Case{}, ErrUnavailable
	}
	result := Case{Summary: c.Summary, Content: body.Content, SubjectIDs: body.SubjectIDs, HoldIDs: body.HoldIDs, History: []HistoryEntry{}}
	if c.ResponseEvent.Valid {
		p, err := s.proposal(ctx, op, c)
		if err != nil {
			return Case{}, err
		}
		result.Response = &p
	}
	rows, err := op.Tx.Query(ctx, `SELECT id,revision,purpose,actor,action_id,created_at,body_encrypted FROM legal_workflow_events
        WHERE scope_kind='case' AND scope=$1 ORDER BY revision DESC LIMIT 201`, id)
	if err != nil {
		return Case{}, ErrUnavailable
	}
	defer rows.Close()
	historyBytes := 0
	for rows.Next() {
		var h HistoryEntry
		var blob []byte
		if err = rows.Scan(&h.ID, &h.Revision, &h.Purpose, &h.Actor, &h.ActionID, &h.CreatedAt, &blob); err != nil {
			return Case{}, ErrUnavailable
		}
		if len(result.History) == 200 {
			result.HistoryTruncated = true
			break
		}
		opened, err := s.open(ctx, blob, h.ID, id, h.Revision, h.Purpose)
		if err != nil {
			return Case{}, err
		}
		historyBytes += len(opened.Input)
		if historyBytes > 1024*1024 {
			result.HistoryTruncated = true
			break
		}
		h.Input = opened.Input
		result.History = append(result.History, h)
	}
	if rows.Err() != nil {
		return Case{}, ErrUnavailable
	}
	auditResult(ctx, a, "read", false)
	return result, nil
}
func pagination(r *ListRequest) error {
	if r.Limit == 0 {
		r.Limit = 50
	}
	if r.Limit < 1 || r.Limit > 200 || r.Offset < 0 {
		return ErrInvalidRequest
	}
	return nil
}

// List excludes unheld expired material even before cleanup has run.
func (s *Service) List(ctx context.Context, a Actor, r ListRequest) (ListResult, error) {
	if err := pagination(&r); err != nil {
		return ListResult{}, err
	}
	if r.Status == "" {
		r.Status = "all"
	}
	if r.Status != "all" && r.Status != "open" && r.Status != "closed" {
		return ListResult{}, ErrInvalidRequest
	}
	op, err := operation(ctx)
	if err != nil {
		return ListResult{}, err
	}
	if err = authorized(ctx, op, a, nil, "legal.cases.read"); err != nil {
		return ListResult{}, err
	}
	var total int64
	var blob []byte
	// Summaries contain no narrative/subject/authority fields. Expiry and count
	// use one fresh statement snapshot, including independent historical holds.
	err = op.Tx.QueryRow(ctx, `WITH eligible AS (
      SELECT c.id,c.status,c.version,c.content_revision,c.proposal_revision,c.decision,
        c.received_at,c.created_at,c.closed_at,c.next_review_at,c.expires_at
      FROM legal_cases c WHERE status<>'erased' AND ($1='all' OR status=$1)
        AND (expires_at>$2 OR EXISTS(SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref WHERE s.case_id=c.id AND h.is_active))
    ), page AS (SELECT * FROM eligible ORDER BY created_at DESC,id LIMIT $3 OFFSET $4)
    SELECT (SELECT count(*) FROM eligible),COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY created_at DESC,id) FROM page),'[]'::jsonb)`, r.Status, s.now().UTC(), r.Limit, r.Offset).Scan(&total, &blob)
	if err != nil {
		return ListResult{}, ErrUnavailable
	}
	result := ListResult{Total: total, Cases: []Summary{}}
	if json.Unmarshal(blob, &result.Cases) != nil {
		return ListResult{}, ErrUnavailable
	}
	auditResult(ctx, a, "list", false)
	return result, nil
}

// DueReviews requires both live case-read and hold-read permissions.
func (s *Service) DueReviews(ctx context.Context, a Actor, r ListRequest) (QueueResult, error) {
	if err := pagination(&r); err != nil {
		return QueueResult{}, err
	}
	if r.Status != "" && r.Status != "due" {
		return QueueResult{}, ErrInvalidRequest
	}
	op, err := operation(ctx)
	if err != nil {
		return QueueResult{}, err
	}
	if err = authorized(ctx, op, a, nil, "legal.cases.read"); err != nil {
		return QueueResult{}, err
	}
	if err = eligible(ctx, op, a.ID, a.AuthVersion, "legal.holds.read"); err != nil {
		return QueueResult{}, err
	}
	var blob []byte
	var total int64
	err = op.Tx.QueryRow(ctx, `WITH work AS (
      SELECT c.id,'case'::text AS kind,c.version,c.next_review_at FROM legal_cases c
      WHERE c.status='open' AND c.next_review_at<=$1 AND (c.expires_at>$1 OR EXISTS(
        SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref WHERE s.case_id=c.id AND h.is_active))
      UNION ALL
      SELECT h.id,'hold'::text,COALESCE(r.version,0),CASE WHEN r.hold_id IS NULL THEN h.review_at ELSE r.next_review_at END
      FROM legal_holds h LEFT JOIN legal_hold_reviews r ON r.hold_id=h.id
      WHERE h.is_active AND (CASE WHEN r.hold_id IS NULL THEN h.review_at ELSE r.next_review_at END)<=$1
    ), page AS (SELECT * FROM work ORDER BY next_review_at,kind,id LIMIT $2 OFFSET $3)
    SELECT (SELECT count(*) FROM work),COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY next_review_at,kind,id) FROM page),'[]'::jsonb)`, s.now().UTC(), r.Limit, r.Offset).Scan(&total, &blob)
	if err != nil {
		return QueueResult{}, ErrUnavailable
	}
	result := QueueResult{Total: total, Items: []QueueItem{}}
	if json.Unmarshal(blob, &result.Items) != nil {
		return QueueResult{}, ErrUnavailable
	}
	auditResult(ctx, a, "queue", false)
	return result, nil
}
