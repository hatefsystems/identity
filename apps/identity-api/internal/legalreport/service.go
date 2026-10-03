package legalreport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// Service operates inside the caller's durable administrative transaction.
type Service struct {
	cfg Config
	now func() time.Time
}

// New constructs the optional reporting capability without enabling any policy.
func New(cfg Config) (*Service, error) {
	if cfg.Environment == "" || (cfg.Enabled && cfg.PolicyID == uuid.Nil) {
		return nil, ErrUnavailable
	}
	return &Service{cfg: cfg, now: time.Now}, nil
}

func (s *Service) begin(ctx context.Context, a Actor, permission string, targets []uuid.UUID) (*adminaction.Operation, error) {
	op, ok := adminaction.FromContext(ctx)
	if !ok || op.Tx == nil || op.Queries == nil {
		return nil, ErrTransactionRequired
	}
	if !s.cfg.Enabled || s.cfg.PolicyID == uuid.Nil {
		return nil, ErrUnavailable
	}
	if a.ID == uuid.Nil || a.AuthVersion < 0 || (op.Event.ActorID != uuid.Nil && op.Event.ActorID != a.ID) {
		return nil, rbac.ErrForbidden
	}
	if sess, ok := session.FromContext(ctx); ok && (sess.UserID != a.ID.String() || sess.Kind != session.KindAuthenticated || !sess.AuthVersionSet || sess.AuthVersion != a.AuthVersion) {
		return nil, rbac.ErrForbidden
	}
	if err := rbac.LockAuthorized(ctx, op.Tx, a.ID, targets, permission, a.AuthVersion); err != nil {
		return nil, err
	}
	if err := s.policy(ctx, op, s.cfg.PolicyID); err != nil {
		return nil, err
	}
	return op, nil
}

func (s *Service) policy(ctx context.Context, op *adminaction.Operation, id uuid.UUID) error {
	p, err := legalpolicy.Load(ctx, op.Tx, id, s.cfg.Environment)
	if err != nil {
		return err
	}
	return legalpolicy.ValidateWorkflow(p, s.cfg.Environment)
}

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
	ok, err := op.Queries.UserHasPermission(ctx, db.UserHasPermissionParams{UserID: id, PermissionID: permission})
	if err != nil {
		return ErrUnavailable
	}
	if !ok {
		return rbac.ErrForbidden
	}
	return nil
}

func record(ctx context.Context, a Actor, verb string, count int, replayed bool) {
	adminaction.SetEvent(ctx, audit.Event{EventType: "legal.transparency." + verb, ActorID: a.ID, ActionStatus: audit.StatusSuccess,
		Payload: map[string]any{"result_count": count, "replayed": replayed}})
}

func coverage(ctx context.Context, q *db.Queries) (time.Time, error) {
	value, err := q.GetLegalTransparencyCoverage(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil || !value.Valid {
		return time.Time{}, ErrUnavailable
	}
	return value.Time.UTC(), nil
}

// Monthly returns recorded counts, filling missing months with measured zeros.
func (s *Service) Monthly(ctx context.Context, a Actor, r MonthlyRequest) (MonthlyResult, error) {
	start := r.Start.UTC()
	if r.Start.IsZero() || r.Months < 1 || r.Months > 12 || start.Year() < 1 || start.Year() > 9998 ||
		!r.Start.Equal(time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)) {
		return MonthlyResult{}, ErrInvalidRequest
	}
	op, err := s.begin(ctx, a, PermissionRead, nil)
	if err != nil {
		return MonthlyResult{}, err
	}
	rows, err := op.Queries.ListLegalTransparencyMonths(ctx, db.ListLegalTransparencyMonthsParams{
		StartMonth: pgtype.Date{Time: start, Valid: true}, EndMonth: pgtype.Date{Time: start.AddDate(0, r.Months, 0), Valid: true}})
	if err != nil {
		return MonthlyResult{}, ErrUnavailable
	}
	first, err := coverage(ctx, op.Queries)
	if err != nil {
		return MonthlyResult{}, err
	}
	result := MonthlyResult{CoverageStart: first, LateEntriesPossible: true, Months: make([]Month, r.Months)}
	byMonth := make(map[string]db.LegalTransparencyMonth, len(rows))
	for _, row := range rows {
		byMonth[row.Month.Time.Format("2006-01")] = row
	}
	for i := range result.Months {
		at := start.AddDate(0, i, 0)
		row := byMonth[at.Format("2006-01")]
		result.Months[i] = Month{Month: at, Totals: Totals{row.Received, row.Answered, row.FullDisclosure, row.PartialDisclosure, row.NoResponsiveData, row.Refusal, row.PreservationAcknowledgement}}
	}
	record(ctx, a, "monthly_read", len(result.Months), false)
	return result, nil
}

func requestValid(key, id uuid.UUID, version int64) bool {
	return key != uuid.Nil && id != uuid.Nil && version > 0 && version < math.MaxInt64
}

func inputBytes(input any) ([]byte, error) {
	data, err := json.Marshal(input)
	if err != nil || len(data) > 2048 {
		return nil, ErrInvalidRequest
	}
	return data, nil
}

// Replay locks follow account/report locks and precede year locks everywhere.
func replay(ctx context.Context, op *adminaction.Operation, verb, scope string, key uuid.UUID, input []byte, out any) (bool, error) {
	if _, err := op.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "legalreport:"+verb+":"+scope+":"+key.String()); err != nil {
		return false, ErrUnavailable
	}
	stored, err := op.Queries.GetLegalTransparencyReplay(ctx, db.GetLegalTransparencyReplayParams{Operation: verb, Scope: scope, IdempotencyKey: key})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnavailable
	}
	var left, right any
	if json.Unmarshal(input, &left) != nil || json.Unmarshal(stored.Input, &right) != nil {
		return false, ErrUnavailable
	}
	if !reflect.DeepEqual(left, right) {
		return false, ErrConflict
	}
	if json.Unmarshal(stored.Result, out) != nil {
		return false, ErrUnavailable
	}
	return true, nil
}

func saveReplay(ctx context.Context, op *adminaction.Operation, verb, scope string, key uuid.UUID, input []byte, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return ErrUnavailable
	}
	if err := op.Queries.InsertLegalTransparencyReplay(ctx, db.InsertLegalTransparencyReplayParams{Operation: verb, Scope: scope, IdempotencyKey: key, Input: input, Result: data}); err != nil {
		return ErrUnavailable
	}
	return nil
}

func fromRow(row db.LegalTransparencyReport) (Report, error) {
	digest := sha256.Sum256(row.Payload)
	if row.SchemaVersion != SchemaVersion || !json.Valid(row.Payload) || hex.EncodeToString(digest[:]) != row.Digest {
		return Report{}, ErrUnavailable
	}
	// A matching stored digest is not permission to expose arbitrary JSON.
	var artifact Artifact
	if json.Unmarshal(row.Payload, &artifact) != nil || artifact.Year != int(row.Year) || artifact.SchemaVersion != SchemaVersion ||
		(artifact.Coverage.Status != "partial" && artifact.Coverage.Status != "no_coverage") {
		return Report{}, ErrUnavailable
	}
	canonical, err := json.Marshal(artifact)
	if err != nil || !bytes.Equal(canonical, row.Payload) {
		return Report{}, ErrUnavailable
	}
	r := Report{ID: row.ID, Version: row.Version, Year: int(row.Year), DataVersion: row.DataVersion, PolicyVersion: row.PolicyID,
		Digest: row.Digest, Payload: bytes.Clone(row.Payload), Status: row.Status, PreparedBy: row.PreparedBy, preparedVersion: row.PreparedAuthVersion, approvedVersion: row.ApprovedAuthVersion}
	if row.ApprovedBy.Valid {
		id := row.ApprovedBy.UUID
		r.ApprovedBy = &id
	}
	return r, nil
}

func (s *Service) locked(ctx context.Context, a Actor, id uuid.UUID, permission string) (*adminaction.Operation, Report, error) {
	if id == uuid.Nil {
		return nil, Report{}, ErrInvalidRequest
	}
	op, ok := adminaction.FromContext(ctx)
	if !ok || op.Queries == nil {
		return nil, Report{}, ErrTransactionRequired
	}
	discovered, err := op.Queries.GetLegalTransparencyReport(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, authErr := s.begin(ctx, a, permission, nil); authErr != nil {
			return nil, Report{}, authErr
		}
		return nil, Report{}, ErrNotFound
	}
	if err != nil {
		return nil, Report{}, ErrUnavailable
	}
	targets := []uuid.UUID{discovered.PreparedBy}
	if discovered.ApprovedBy.Valid {
		targets = append(targets, discovered.ApprovedBy.UUID)
	}
	op, err = s.begin(ctx, a, permission, targets)
	if err != nil {
		return nil, Report{}, err
	}
	current, err := op.Queries.GetLegalTransparencyReportForUpdate(ctx, id)
	if err != nil {
		return nil, Report{}, ErrUnavailable
	}
	if current.Version != discovered.Version || current.PreparedBy != discovered.PreparedBy || current.ApprovedBy != discovered.ApprovedBy || current.PreparedAuthVersion != discovered.PreparedAuthVersion || !reflect.DeepEqual(current.ApprovedAuthVersion, discovered.ApprovedAuthVersion) {
		return nil, Report{}, ErrConflict
	}
	if err := s.policy(ctx, op, current.PolicyID); err != nil {
		return nil, Report{}, err
	}
	r, err := fromRow(current)
	return op, r, err
}

func yearVersion(ctx context.Context, op *adminaction.Operation, year int) (int64, error) {
	if year < 1 || year > 9998 {
		return 0, ErrInvalidRequest
	}
	v, err := op.Queries.LockLegalTransparencyYear(ctx, int32(year))
	if err != nil {
		return 0, ErrUnavailable
	}
	return v, nil
}

// PrepareReport freezes a completed-year aggregate without claiming publication.
func (s *Service) PrepareReport(ctx context.Context, a Actor, r PrepareRequest) (Report, error) {
	if r.Key == uuid.Nil || r.ExpectedVersion != 0 || r.Year < 1 || r.Year >= s.now().UTC().Year() || r.Year > 9998 {
		return Report{}, ErrInvalidRequest
	}
	input, err := inputBytes(r)
	if err != nil {
		return Report{}, err
	}
	op, err := s.begin(ctx, a, PermissionRead, nil)
	if err != nil {
		return Report{}, err
	}
	scope := strconv.Itoa(r.Year)
	var result Report
	found, err := replay(ctx, op, "prepare", scope, r.Key, input, &result)
	if err != nil {
		return Report{}, err
	}
	version, err := yearVersion(ctx, op, r.Year)
	if err != nil {
		return Report{}, err
	}
	if found {
		result.Replayed = true
		result.Stale = result.DataVersion != version
		record(ctx, a, "report_prepared", 1, true)
		return result, nil
	}
	start := time.Date(r.Year, 1, 1, 0, 0, 0, 0, time.UTC)
	t, err := op.Queries.GetLegalTransparencyAnnualTotals(ctx, db.GetLegalTransparencyAnnualTotalsParams{StartMonth: pgtype.Date{Time: start, Valid: true}, EndMonth: pgtype.Date{Time: start.AddDate(1, 0, 0), Valid: true}})
	if err != nil {
		return Report{}, ErrUnavailable
	}
	first, err := coverage(ctx, op.Queries)
	if err != nil {
		return Report{}, err
	}
	payload, err := sanitize(r.Year, first, Totals{t.Received, t.Answered, t.FullDisclosure, t.PartialDisclosure, t.NoResponsiveData, t.Refusal, t.PreservationAcknowledgement})
	if err != nil {
		return Report{}, err
	}
	digest := sha256.Sum256(payload)
	result = Report{ID: uuid.New(), Version: 1, Year: r.Year, DataVersion: version, PolicyVersion: s.cfg.PolicyID,
		Digest: hex.EncodeToString(digest[:]), Payload: payload, Status: "prepared", PreparedBy: a.ID, preparedVersion: a.AuthVersion}
	err = op.Queries.InsertLegalTransparencyReport(ctx, db.InsertLegalTransparencyReportParams{ID: result.ID, Year: int32(r.Year), DataVersion: version,
		PolicyID: result.PolicyVersion, Payload: payload, Digest: result.Digest, PreparedBy: a.ID, PreparedAuthVersion: a.AuthVersion})
	if err != nil {
		return Report{}, ErrUnavailable
	}
	if err := saveReplay(ctx, op, "prepare", scope, r.Key, input, result); err != nil {
		return Report{}, err
	}
	record(ctx, a, "report_prepared", 1, false)
	return result, nil
}

// GetReport returns a restricted review representation, not a public artifact.
func (s *Service) GetReport(ctx context.Context, a Actor, id uuid.UUID) (Report, error) {
	op, r, err := s.locked(ctx, a, id, PermissionRead)
	if err != nil {
		return Report{}, err
	}
	v, err := yearVersion(ctx, op, r.Year)
	if err != nil {
		return Report{}, err
	}
	r.Stale = r.DataVersion != v
	record(ctx, a, "report_read", 1, false)
	return r, nil
}

// ApproveReport binds a distinct, live DPO's approval to exact frozen bytes.
func (s *Service) ApproveReport(ctx context.Context, a Actor, r ApproveRequest) (Report, error) {
	if !requestValid(r.Key, r.ID, r.ExpectedVersion) || r.DataVersion < 0 || r.PolicyVersion == uuid.Nil || len(r.Digest) != 64 {
		return Report{}, ErrInvalidRequest
	}
	input, err := inputBytes(r)
	if err != nil {
		return Report{}, err
	}
	op, current, err := s.locked(ctx, a, r.ID, PermissionApprove)
	if err != nil {
		return Report{}, err
	}
	if a.ID == current.PreparedBy {
		return Report{}, rbac.ErrForbidden
	}
	if err := eligible(ctx, op, current.PreparedBy, current.preparedVersion, PermissionRead); err != nil {
		return Report{}, err
	}
	var result Report
	found, err := replay(ctx, op, "approve", r.ID.String(), r.Key, input, &result)
	if err != nil {
		return Report{}, err
	}
	v, err := yearVersion(ctx, op, current.Year)
	if err != nil {
		return Report{}, err
	}
	if found {
		result.Replayed = true
		result.Stale = result.DataVersion != v
		record(ctx, a, "report_approved", 1, true)
		return result, nil
	}
	if current.DataVersion != v {
		return Report{}, ErrStaleSnapshot
	}
	if current.Status != "prepared" || current.Version != r.ExpectedVersion || current.DataVersion != r.DataVersion || current.PolicyVersion != r.PolicyVersion || current.Digest != r.Digest {
		return Report{}, ErrConflict
	}
	if err := op.Queries.ApproveLegalTransparencyReport(ctx, db.ApproveLegalTransparencyReportParams{ID: r.ID, ApprovedBy: uuid.NullUUID{UUID: a.ID, Valid: true}, ApprovedAuthVersion: &a.AuthVersion}); err != nil {
		return Report{}, ErrUnavailable
	}
	current.Version++
	current.Status = "approved"
	current.ApprovedBy = &a.ID
	current.approvedVersion = &a.AuthVersion
	if err := saveReplay(ctx, op, "approve", r.ID.String(), r.Key, input, current); err != nil {
		return Report{}, err
	}
	record(ctx, a, "report_approved", 1, false)
	return current, nil
}

// DownloadReport returns the exact approved bytes only after live authority checks.
// A downloaded artifact is historical; later data never rewrites its contents.
func (s *Service) DownloadReport(ctx context.Context, a Actor, r DownloadRequest) (DownloadResult, error) {
	if !requestValid(r.Key, r.ID, r.ExpectedVersion) {
		return DownloadResult{}, ErrInvalidRequest
	}
	input, err := inputBytes(r)
	if err != nil {
		return DownloadResult{}, err
	}
	op, current, err := s.locked(ctx, a, r.ID, PermissionRead)
	if err != nil {
		return DownloadResult{}, err
	}
	if current.ApprovedBy == nil || current.approvedVersion == nil || *current.ApprovedBy == current.PreparedBy {
		return DownloadResult{}, ErrConflict
	}
	if err := eligible(ctx, op, current.PreparedBy, current.preparedVersion, PermissionRead); err != nil {
		return DownloadResult{}, err
	}
	if err := eligible(ctx, op, *current.ApprovedBy, *current.approvedVersion, PermissionApprove); err != nil {
		return DownloadResult{}, err
	}
	var result DownloadResult
	found, err := replay(ctx, op, "download", r.ID.String(), r.Key, input, &result)
	if err != nil {
		return DownloadResult{}, err
	}
	v, err := yearVersion(ctx, op, current.Year)
	if err != nil {
		return DownloadResult{}, err
	}
	if found {
		if !bytes.Equal(result.Payload, current.Payload) {
			return DownloadResult{}, ErrUnavailable
		}
		result.Replayed = true
		record(ctx, a, "report_downloaded", 1, true)
		return result, nil
	}
	if current.Version != r.ExpectedVersion {
		return DownloadResult{}, ErrConflict
	}
	if current.Status == "approved" {
		if current.DataVersion != v {
			return DownloadResult{}, ErrStaleSnapshot
		}
		if err := op.Queries.DownloadLegalTransparencyReport(ctx, r.ID); err != nil {
			return DownloadResult{}, ErrUnavailable
		}
	} else if current.Status != "downloaded" {
		return DownloadResult{}, ErrConflict
	}
	result = DownloadResult{Payload: current.Payload}
	if err := saveReplay(ctx, op, "download", r.ID.String(), r.Key, input, result); err != nil {
		return DownloadResult{}, err
	}
	record(ctx, a, "report_downloaded", 1, false)
	return result, nil
}
