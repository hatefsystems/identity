package legalworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Encryptor is the existing envelope implementation, with binding in plaintext.
type Encryptor interface {
	Encrypt(context.Context, []byte) ([]byte, error)
	Decrypt(context.Context, []byte) ([]byte, error)
}

// Service performs transaction-owned legal workflow transitions.
type Service struct {
	encryptor Encryptor
	cfg       Config
	now       func() time.Time
}

// New permits disabled intake for independent stored-policy maintenance.
func New(enc Encryptor, cfg Config) (*Service, error) {
	if enc == nil || (cfg.Enabled && cfg.PolicyID == uuid.Nil) {
		return nil, ErrUnavailable
	}
	return &Service{enc, cfg, time.Now}, nil
}
func operation(ctx context.Context) (*adminaction.Operation, error) {
	op, ok := adminaction.FromContext(ctx)
	if !ok || op.Tx == nil || op.Queries == nil || op.ID == uuid.Nil {
		return nil, ErrTransactionRequired
	}
	return op, nil
}
func (s *Service) policy(ctx context.Context, tx pgx.Tx, id uuid.UUID, mutation bool) (legalpolicy.Policy, error) {
	if mutation && (!s.cfg.Enabled || id != s.cfg.PolicyID) {
		return legalpolicy.Policy{}, ErrUnavailable
	}
	p, err := legalpolicy.Load(ctx, tx, id, s.cfg.Environment)
	if err != nil || legalpolicy.ValidateWorkflow(p, s.cfg.Environment) != nil {
		return legalpolicy.Policy{}, ErrUnavailable
	}
	return p, nil
}
func authorized(ctx context.Context, op *adminaction.Operation, a Actor, targets []uuid.UUID, permission string) error {
	if a.ID == uuid.Nil || a.AuthVersion < 0 {
		return rbac.ErrForbidden
	}
	if sess, ok := session.FromContext(ctx); ok && (sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.UserID != a.ID.String() || sess.AuthVersion != a.AuthVersion) {
		return rbac.ErrForbidden
	}
	if op.Event.ActorID != uuid.Nil && op.Event.ActorID != a.ID {
		return rbac.ErrForbidden
	}
	if err := rbac.LockAuthorized(ctx, op.Tx, a.ID, targets, permission, a.AuthVersion); err != nil {
		if errors.Is(err, rbac.ErrForbidden) {
			return err
		}
		return ErrUnavailable
	}
	return nil
}

// Principals have already been included in the single sorted lock acquisition.
// Never call LockAuthorized again here with an expanded target set.
func eligible(ctx context.Context, op *adminaction.Operation, id uuid.UUID, version int64, permission string) error {
	u, err := op.Queries.GetUserForUpdateIncludingDeleted(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.ErrForbidden
	}
	if err != nil {
		return ErrUnavailable
	}
	if u.Status != "active" || u.DeletedAt.Valid || u.AuthVersion != version {
		return rbac.ErrForbidden
	}
	allowed, err := op.Queries.UserHasPermission(ctx, db.UserHasPermissionParams{UserID: id, PermissionID: permission})
	if err != nil {
		return ErrUnavailable
	}
	if !allowed {
		return rbac.ErrForbidden
	}
	return nil
}

type state struct {
	Summary
	PolicyID                                                            uuid.NullUUID
	ReviewedRevision, ResponseContentRevision, ApprovedProposalRevision int64
	ContentEvent, ResponseEvent, Preparer, Approver                     uuid.NullUUID
	PreparerVersion, ApproverVersion                                    *int64
	Subjects                                                            []uuid.UUID
}

const selectState = `SELECT c.id,c.status,c.version,c.content_revision,c.proposal_revision,c.decision,
 c.received_at,c.created_at,c.closed_at,c.next_review_at,c.expires_at,c.policy_id,c.reviewed_revision,
 c.response_content_revision,c.approved_proposal_revision,c.content_event,c.response_event,
 c.preparer,c.preparer_auth_version,c.approver,c.approver_auth_version,
 ARRAY(SELECT s.account_ref FROM legal_case_subjects s WHERE s.case_id=c.id ORDER BY s.account_ref)
 FROM legal_cases c WHERE c.id=$1`

func load(ctx context.Context, tx pgx.Tx, id uuid.UUID, lock bool) (state, error) {
	sql := selectState
	if lock {
		sql += " FOR UPDATE OF c"
	}
	var c state
	err := tx.QueryRow(ctx, sql, id).Scan(&c.ID, &c.Status, &c.Version, &c.ContentRevision, &c.ProposalRevision, &c.Decision,
		&c.ReceivedAt, &c.CreatedAt, &c.ClosedAt, &c.NextReviewAt, &c.ExpiresAt, &c.PolicyID, &c.ReviewedRevision,
		&c.ResponseContentRevision, &c.ApprovedProposalRevision, &c.ContentEvent, &c.ResponseEvent,
		&c.Preparer, &c.PreparerVersion, &c.Approver, &c.ApproverVersion, &c.Subjects)
	if errors.Is(err, pgx.ErrNoRows) {
		return state{}, ErrNotFound
	}
	if err != nil {
		return state{}, ErrUnavailable
	}
	return c, nil
}
func (c state) targets(extra []uuid.UUID) []uuid.UUID {
	out := append(append([]uuid.UUID{}, c.Subjects...), extra...)
	if c.Preparer.Valid {
		out = append(out, c.Preparer.UUID)
	}
	if c.Approver.Valid {
		out = append(out, c.Approver.UUID)
	}
	return out
}
func sameDiscovery(a, b state) bool {
	return a.Version == b.Version && a.Status == b.Status && a.Preparer == b.Preparer && a.Approver == b.Approver &&
		reflect.DeepEqual(a.Subjects, b.Subjects) && reflect.DeepEqual(a.PreparerVersion, b.PreparerVersion) && reflect.DeepEqual(a.ApproverVersion, b.ApproverVersion)
}
func lockScope(ctx context.Context, tx pgx.Tx, kind string, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "legalworkflow:"+kind+":"+id.String())
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func held(ctx context.Context, tx pgx.Tx, c state) (bool, error) {
	yes, err := db.New(tx).LegalWorkflowCaseHeld(ctx, c.ID)
	if err != nil {
		return false, ErrUnavailable
	}
	return yes, nil
}
func (s *Service) accessible(ctx context.Context, tx pgx.Tx, c state) error {
	if c.Status == "erased" {
		return ErrErased
	}
	if c.ExpiresAt == nil {
		return ErrUnavailable
	}
	if !s.now().Before(*c.ExpiresAt) {
		yes, err := held(ctx, tx, c)
		if err != nil {
			return err
		}
		if !yes {
			return ErrExpired
		}
	}
	return nil
}

type envelope struct {
	ID       uuid.UUID       `json:"id"`
	Scope    uuid.UUID       `json:"scope"`
	Revision int64           `json:"revision"`
	Purpose  string          `json:"purpose"`
	Input    json.RawMessage `json:"input"`
	Result   MutationResult  `json:"result"`
}

func (s *Service) seal(ctx context.Context, e envelope) ([]byte, error) {
	plain, err := json.Marshal(e)
	if err != nil || len(plain) > MaxPlaintext {
		return nil, ErrInvalidRequest
	}
	defer clear(plain)
	blob, err := s.encryptor.Encrypt(ctx, plain)
	if err != nil || len(blob) == 0 {
		return nil, ErrUnavailable
	}
	return blob, nil
}
func (s *Service) open(ctx context.Context, blob []byte, id, scope uuid.UUID, revision int64, purpose string) (envelope, error) {
	plain, err := s.encryptor.Decrypt(ctx, blob)
	if err != nil {
		return envelope{}, ErrUnavailable
	}
	defer clear(plain)
	var e envelope
	if len(plain) > MaxPlaintext || json.Unmarshal(plain, &e) != nil || e.ID != id || e.Scope != scope || e.Revision != revision || e.Purpose != purpose || e.Result.ID != scope || e.Result.Version != revision {
		return envelope{}, ErrUnavailable
	}
	return e, nil
}
func (s *Service) event(ctx context.Context, tx pgx.Tx, id, scope uuid.UUID) (envelope, error) {
	row, err := db.New(tx).GetLegalWorkflowEvent(ctx, id)
	if err != nil || row.Scope != scope {
		return envelope{}, ErrUnavailable
	}
	return s.open(ctx, row.BodyEncrypted, id, scope, row.Revision, row.Purpose)
}
func (s *Service) replay(ctx context.Context, tx pgx.Tx, purpose string, scope, key uuid.UUID, input []byte) (MutationResult, bool, error) {
	row, err := db.New(tx).GetLegalWorkflowReplay(ctx, db.GetLegalWorkflowReplayParams{Operation: purpose, Scope: scope, IdempotencyKey: key})
	if errors.Is(err, pgx.ErrNoRows) {
		return MutationResult{}, false, nil
	}
	if err != nil {
		return MutationResult{}, false, ErrUnavailable
	}
	if row.Erased {
		return MutationResult{}, true, ErrErased
	}
	e, err := s.event(ctx, tx, row.EventID.UUID, row.ResultID)
	if err != nil {
		return MutationResult{}, true, err
	}
	if e.Purpose != purpose || !bytes.Equal(e.Input, input) {
		return MutationResult{}, true, ErrConflict
	}
	e.Result.Replayed = true
	return e.Result, true, nil
}
func (s *Service) saveEvent(ctx context.Context, op *adminaction.Operation, a Actor, c state, purpose string, scope, key, id uuid.UUID, input []byte) error {
	result := c.MutationResult
	blob, err := s.seal(ctx, envelope{ID: id, Scope: c.ID, Revision: c.Version, Purpose: purpose, Input: input, Result: result})
	if err != nil {
		return err
	}
	kind := "case"
	if purpose == "hold_review" {
		kind = "hold"
	}
	_, err = op.Tx.Exec(ctx, `INSERT INTO legal_workflow_events(id,scope,scope_kind,revision,purpose,actor,auth_version,action_id,created_at,body_encrypted)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, c.ID, kind, c.Version, purpose, a.ID, a.AuthVersion, op.ID, s.now().UTC(), blob)
	if err != nil {
		return ErrUnavailable
	}
	_, err = op.Tx.Exec(ctx, `INSERT INTO legal_workflow_replays(operation,scope,idempotency_key,result_id,event_id) VALUES($1,$2,$3,$4,$5)`, purpose, scope, key, c.ID, id)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func auditResult(ctx context.Context, a Actor, purpose string, replayed bool) {
	name := "legal.case." + purpose
	switch purpose {
	case "prepare", "approve", "deliver":
		name = "legal.response." + purpose
	case "review", "hold_review":
		name = "legal.review." + purpose
	}
	adminaction.SetEvent(ctx, audit.Event{EventType: name, ActorID: a.ID, ActionStatus: audit.StatusSuccess, Payload: map[string]any{"replayed": replayed}})
}

// beginCase discovers the complete lock set before touching workflow rows. A
// changed snapshot returns conflict, never an out-of-order additional lock.
func (s *Service) beginCase(ctx context.Context, a Actor, id uuid.UUID, extra []uuid.UUID, permission string) (*adminaction.Operation, state, error) {
	op, err := operation(ctx)
	if err != nil {
		return nil, state{}, err
	}
	old, err := load(ctx, op.Tx, id, false)
	if err != nil {
		return nil, state{}, err
	}
	if len(union(append(append([]uuid.UUID{}, old.Subjects...), extra...))) > MaxSubjects {
		return nil, state{}, ErrInvalidRequest
	}
	if err = authorized(ctx, op, a, old.targets(extra), permission); err != nil {
		return nil, state{}, err
	}
	if err = lockScope(ctx, op.Tx, "case", id); err != nil {
		return nil, state{}, err
	}
	c, err := load(ctx, op.Tx, id, true)
	if err != nil {
		return nil, state{}, err
	}
	if !sameDiscovery(old, c) {
		return nil, state{}, ErrConflict
	}
	if err = s.accessible(ctx, op.Tx, c); err != nil {
		return nil, state{}, err
	}
	return op, c, nil
}
func (s *Service) mutation(ctx context.Context, a Actor, id, key uuid.UUID, version int64, extra []uuid.UUID, permission, purpose string, input []byte) (*adminaction.Operation, state, *MutationResult, error) {
	op, c, err := s.beginCase(ctx, a, id, extra, permission)
	if err != nil {
		return nil, state{}, nil, err
	}
	if _, err = s.policy(ctx, op.Tx, c.PolicyID.UUID, true); err != nil {
		return nil, state{}, nil, err
	}
	r, ok, err := s.replay(ctx, op.Tx, purpose, id, key, input)
	if err != nil {
		return nil, state{}, nil, err
	}
	if ok {
		auditResult(ctx, a, purpose, true)
		return op, c, &r, nil
	}
	if c.Version != version || c.Status != "open" {
		return nil, state{}, nil, ErrConflict
	}
	c.Version++
	return op, c, nil, nil
}
func persist(ctx context.Context, tx pgx.Tx, c state) error {
	_, err := tx.Exec(ctx, `UPDATE legal_cases SET status=$2,version=$3,content_revision=$4,proposal_revision=$5,decision=$6,
        reviewed_revision=$7,response_content_revision=$8,approved_proposal_revision=$9,closed_at=$10,next_review_at=$11,
        expires_at=$12,content_event=$13,response_event=$14,preparer=$15,preparer_auth_version=$16,approver=$17,approver_auth_version=$18 WHERE id=$1`,
		c.ID, c.Status, c.Version, c.ContentRevision, c.ProposalRevision, c.Decision, c.ReviewedRevision, c.ResponseContentRevision, c.ApprovedProposalRevision,
		c.ClosedAt, c.NextReviewAt, c.ExpiresAt, c.ContentEvent, c.ResponseEvent, c.Preparer, c.PreparerVersion, c.Approver, c.ApproverVersion)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) finish(ctx context.Context, op *adminaction.Operation, a Actor, c state, purpose string, key, eventID uuid.UUID, input []byte) (MutationResult, error) {
	if err := s.saveEvent(ctx, op, a, c, purpose, c.ID, key, eventID, input); err != nil {
		return MutationResult{}, err
	}
	if err := persist(ctx, op.Tx, c); err != nil {
		return MutationResult{}, err
	}
	auditResult(ctx, a, purpose, false)
	return c.MutationResult, nil
}
func union(in []uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	unique := out[:0]
	for _, id := range out {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	return unique
}
