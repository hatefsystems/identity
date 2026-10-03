package legalworkflow

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type holdState struct {
	ID, Account  uuid.UUID
	Active       bool
	ReleasedAt   *time.Time
	Version      int64
	PolicyID     uuid.NullUUID
	NextReviewAt *time.Time
}

func loadHold(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (holdState, error) {
	sql := `SELECT h.id,h.account_ref,h.is_active,h.released_at,COALESCE(r.version,0),r.policy_id,r.next_review_at
        FROM legal_holds h LEFT JOIN legal_hold_reviews r ON r.hold_id=h.id WHERE h.id=$1`
	if lock {
		sql += " FOR UPDATE OF h"
	}
	var h holdState
	err := tx.QueryRow(ctx, sql, id).Scan(&h.ID, &h.Account, &h.Active, &h.ReleasedAt, &h.Version, &h.PolicyID, &h.NextReviewAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return h, ErrNotFound
	}
	if err != nil {
		return h, ErrUnavailable
	}
	return h, nil
}
func (s *Service) holdAccessible(ctx context.Context, tx pgx.Tx, h holdState, cutoff time.Time) (bool, error) {
	policyID := h.PolicyID.UUID
	if !h.PolicyID.Valid {
		policyID = s.cfg.PolicyID
	}
	p, err := s.policy(ctx, tx, policyID, false)
	if err != nil {
		return false, err
	}
	if h.Active {
		return true, nil
	}
	if h.ReleasedAt == nil {
		return false, ErrUnavailable
	}
	if cutoff.Before(h.ReleasedAt.Add(p.ReleasedHoldRetention())) {
		return true, nil
	}
	var active bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM legal_holds WHERE account_ref=$1 AND is_active)`, h.Account).Scan(&active)
	if err != nil {
		return false, ErrUnavailable
	}
	return active, nil
}

// ReviewHold preserves the original hold input and its idempotency contract.
func (s *Service) ReviewHold(ctx context.Context, a Actor, r HoldReviewRequest) (MutationResult, error) {
	if r.Key == uuid.Nil || r.HoldID == uuid.Nil || r.ExpectedVersion < 0 || r.ExpectedVersion == 1<<63-1 || !text(r.Rationale, 4096) || !optionalTime(r.NextReviewAt) {
		return MutationResult{}, ErrInvalidRequest
	}
	switch r.Decision {
	case "continue", "release_recommended", "needs_information":
	default:
		return MutationResult{}, ErrInvalidRequest
	}
	input, err := canonical(r)
	if err != nil {
		return MutationResult{}, err
	}
	op, err := operation(ctx)
	if err != nil {
		return MutationResult{}, err
	}
	old, err := loadHold(ctx, op.Tx, r.HoldID, false)
	if err != nil {
		return MutationResult{}, err
	}
	if err = authorized(ctx, op, a, []uuid.UUID{old.Account}, "legal.holds.write"); err != nil {
		return MutationResult{}, err
	}
	if err = lockScope(ctx, op.Tx, "hold", r.HoldID); err != nil {
		return MutationResult{}, err
	}
	h, err := loadHold(ctx, op.Tx, r.HoldID, true)
	if err != nil {
		return MutationResult{}, err
	}
	if !reflect.DeepEqual(old, h) {
		return MutationResult{}, ErrConflict
	}
	if !h.PolicyID.Valid {
		h.PolicyID = nullable(s.cfg.PolicyID)
	}
	if _, err = s.policy(ctx, op.Tx, h.PolicyID.UUID, true); err != nil {
		return MutationResult{}, err
	}
	var erased bool
	err = op.Tx.QueryRow(ctx, `SELECT erased FROM legal_workflow_replays WHERE operation='hold_review' AND scope=$1 AND idempotency_key=$2`, r.HoldID, r.Key).Scan(&erased)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return MutationResult{}, ErrUnavailable
	}
	if erased {
		return MutationResult{}, ErrErased
	}
	accessible, err := s.holdAccessible(ctx, op.Tx, h, s.now())
	if err != nil {
		return MutationResult{}, err
	}
	if !accessible {
		return MutationResult{}, ErrExpired
	}
	result, ok, err := s.replay(ctx, op.Tx, "hold_review", r.HoldID, r.Key, input)
	if err != nil {
		return MutationResult{}, err
	}
	if ok {
		auditResult(ctx, a, "hold_review", true)
		return result, nil
	}
	if h.Version != r.ExpectedVersion {
		return MutationResult{}, ErrConflict
	}
	h.Version++
	_, err = op.Tx.Exec(ctx, `INSERT INTO legal_hold_reviews(hold_id,account_ref,policy_id,version,next_review_at) VALUES($1,$2,$3,$4,$5)
        ON CONFLICT(hold_id) DO UPDATE SET version=excluded.version,next_review_at=excluded.next_review_at`, h.ID, h.Account, h.PolicyID.UUID, h.Version, r.NextReviewAt)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	c := state{Summary: Summary{MutationResult: MutationResult{ID: h.ID, Version: h.Version, Status: "reviewed", Decision: r.Decision}}}
	if err = s.saveEvent(ctx, op, a, c, "hold_review", h.ID, r.Key, uuid.New(), input); err != nil {
		return MutationResult{}, err
	}
	auditResult(ctx, a, "hold_review", false)
	return c.MutationResult, nil
}
