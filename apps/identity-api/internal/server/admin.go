package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

// Permission ids enforced by the admin routes. They mirror the rows seeded by
// migration 00007; the guard resolves them through UserHasPermission, so these
// constants and that seed must stay in step. An id that exists here but not in
// the table simply denies everyone, which is the safe direction to fail.
const (
	permAdminUsersRead       = "admin.users.read"
	permAdminUsersReadPII    = "admin.users.read.pii"
	permAdminUsersStatusWrit = "admin.users.status.write"
	permAdminRolesAssign     = "admin.roles.assign"
	permAdminAuditLogsRead   = "admin.audit_logs.read"
	permAdminAuditLogsVerify = "admin.audit_logs.verify"
	permLegalHoldsRead       = "legal.holds.read"
	permLegalHoldsWrite      = "legal.holds.write"
	permLegalInquiryLookup   = "legal.inquiry.lookup"
)

// adminAssignableStatuses is the closed set of statuses an administrator may
// set via PATCH /users/{user_id}/status.
//
// pending_deletion and pending_verification are deliberately absent.
// pending_deletion is reachable only through the subject's own "Right to be
// Forgotten" flow: letting an admin set it would be a manual account deletion
// under a different name, which architecture.md ("No Manual Deletion") and
// compliance §14 prohibit. pending_verification is an artifact of registration,
// not a moderation outcome; setting it would strand an account in a state only
// an email link can leave.
var adminAssignableStatuses = map[string]struct{}{
	"active":    {},
	"suspended": {},
	"banned":    {},
}

// AdminStore is the slice of the generated query surface the admin routes need.
// *db.Queries satisfies it; tests supply a fake.
type AdminStore interface {
	ListAuditLogsPage(context.Context, db.ListAuditLogsPageParams) (db.ListAuditLogsPageRow, error)
	ListUsers(ctx context.Context, arg db.ListUsersParams) ([]db.User, error)
	CountUsers(ctx context.Context, status *string) (int64, error)
	GetUserByIDForAdmin(ctx context.Context, id uuid.UUID) (db.User, error)
	GetUserByEmailForAdmin(ctx context.Context, email string) (db.User, error)
	UpdateUserStatus(ctx context.Context, arg db.UpdateUserStatusParams) (int64, error)

	GetRole(ctx context.Context, id string) (db.Role, error)
	AssignRoleToUser(ctx context.Context, arg db.AssignRoleToUserParams) error
	ListUserRoles(ctx context.Context, userID uuid.UUID) ([]db.Role, error)

	ListAuditLogs(ctx context.Context, arg db.ListAuditLogsParams) ([]db.MvpAuditLog, error)
	CountAuditLogs(ctx context.Context, arg db.CountAuditLogsParams) (int64, error)
	ListAuditLogsForChainVerification(ctx context.Context, arg db.ListAuditLogsForChainVerificationParams) ([]db.MvpAuditLog, error)
	GetAuditLogChainHashBySeq(ctx context.Context, seq int64) (string, error)
	GetAuditLogHighWaterSeq(ctx context.Context) (int64, error)
	ListSecurityEventsForChainVerification(ctx context.Context, arg db.ListSecurityEventsForChainVerificationParams) ([]db.SecurityEventLedger, error)
	GetSecurityEventChainHashBySeq(ctx context.Context, seq int64) (string, error)
	GetSecurityEventHighWaterSeq(ctx context.Context) (int64, error)

	HasActiveLegalHold(ctx context.Context, accountRef uuid.UUID) (bool, error)
}

func (s *Server) adminStore(r *http.Request) AdminStore {
	if op, ok := adminaction.FromContext(r.Context()); ok {
		return op.Queries
	}
	return s.deps.AdminStore
}

// adminErrorResponse is the JSON error envelope for every admin route, matching
// privacyErrorResponse.
type adminErrorResponse struct {
	Error string `json:"error"`
}

// adminPage is the envelope for every admin list endpoint.
//
// Items is a slice so it serializes as [] rather than null when empty: a client
// distinguishing "no results" from "field missing" would otherwise have to
// special-case null on every list route.
type adminPage[T any] struct {
	Items  []T   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// adminUserResponse is the hand-built account DTO.
//
// It exists specifically so db.User is never serialized directly. That struct
// carries PasswordHash, PhoneEncrypted, BackupEmailEncrypted,
// MfaTotpSecretEncrypted, PhoneBlindIndex, BackupEmailBlindIndex, and
// WebauthnUserHandle — every one of them with a JSON tag. A single
// writeJSON(w, 200, user) would hand an administrator the password hash, the
// envelope ciphertexts, and the blind indexes that make offline correlation
// possible. Whitelisting fields here is the only structural defence; the
// negative assertions in admin_test.go are the alarm if it is ever bypassed.
//
// Email is a pointer and omitempty so that it is genuinely absent for a caller
// holding only admin.users.read, rather than present-and-empty (which would
// still confirm the field exists and invite a client to depend on it).
type adminUserResponse struct {
	ID           uuid.UUID  `json:"id"`
	Email        *string    `json:"email,omitempty"`
	Status       string     `json:"status"`
	IsMFAEnabled bool       `json:"is_mfa_enabled"`
	CreatedAt    *time.Time `json:"created_at"`
	UpdatedAt    *time.Time `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at"`
}

// newAdminUserResponse projects a db.User onto the safe DTO. includePII gates
// the email address, which is the only Class A field exposed here at all.
func newAdminUserResponse(u db.User, includePII bool) adminUserResponse {
	resp := adminUserResponse{
		ID:           u.ID,
		Status:       u.Status,
		IsMFAEnabled: u.IsMfaEnabled,
		CreatedAt:    timePtr(u.CreatedAt),
		UpdatedAt:    timePtr(u.UpdatedAt),
		DeletedAt:    timePtr(u.DeletedAt),
	}
	if includePII {
		email := u.Email
		resp.Email = &email
	}
	return resp
}

// adminAuditLogResponse is the audit-row DTO.
//
// UserID is a *uuid.UUID rendered as an explicit null rather than omitted. NULL
// in mvp_audit_logs.user_id is not "unknown": it means the subject was purged
// under ON DELETE SET NULL, which is a meaningful, deliberate fact for a DPO
// reading the log. Omitting the key would erase that distinction.
type adminAuditLogResponse struct {
	ID              uuid.UUID  `json:"id"`
	UserID          *uuid.UUID `json:"user_id"`
	ActorID         uuid.UUID  `json:"actor_id"`
	ActorSPIFFEID   string     `json:"actor_spiffe_id"`
	EventType       string     `json:"event_type"`
	ActionStatus    string     `json:"action_status"`
	ClientIP        string     `json:"client_ip"`
	UserAgent       string     `json:"user_agent"`
	Payload         string     `json:"payload"`
	Timestamp       *time.Time `json:"timestamp"`
	SHA256ChainHash string     `json:"sha256_chain_hash"`
	Seq             int64      `json:"seq"`
}

// adminChainVerifyResponse reports one chain-verification pass.
type adminChainVerifyResponse struct {
	FailureReason *string `json:"failure_reason,omitempty"`
	Chain         string  `json:"chain"`
	AfterSeq      int64   `json:"after_seq"`
	ThroughSeq    int64   `json:"through_seq"`
	SeedHash      string  `json:"seed_hash"`
	SeedSource    string  `json:"seed_source"`
	Scope         string  `json:"scope"`
	LastHash      *string `json:"last_hash"`
	Complete      bool    `json:"complete"`
	// Verified is false as soon as any row's recomputed digest differs.
	Verified bool `json:"verified"`
	// Checked counts rows actually recomputed in this call.
	Checked  int    `json:"checked"`
	FirstSeq *int64 `json:"first_seq"`
	LastSeq  *int64 `json:"last_seq"`
	// BrokenAtSeq is the seq of the first mismatching row, or null.
	BrokenAtSeq *int64 `json:"broken_at_seq"`
	// ExpectedHash and StoredHash are populated only on a break, so an operator
	// can see the divergence without re-running anything.
	ExpectedHash *string `json:"expected_hash"`
	StoredHash   *string `json:"stored_hash"`
	// NextAfterSeq is the cursor for the next page, or null when the scan
	// reached the end of the chain. Null is how a caller knows a
	// genesis-to-head verification is actually complete rather than merely
	// clean so far.
	NextAfterSeq *int64 `json:"next_after_seq"`
}

// adminLedgerVerifyResponse distinguishes recomputed content from erased proof.
type adminLedgerVerifyResponse struct {
	adminChainVerifyResponse
	PurgedCount     int64 `json:"purged_count"`
	PurgedSpans     int   `json:"purged_spans"`
	ProofSteps      int   `json:"proof_steps"`
	RestartRequired bool  `json:"restart_required"`
}

// writeAdminError writes the uniform admin error envelope with no-store.
func (s *Server) writeAdminError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, status, adminErrorResponse{Error: code})
}

// writeAdminJSON writes a success body with no-store.
//
// Every admin response is no-store for the same reason recovery.go marks its
// own: these bodies contain moderation state, audit rows, and legal-hold
// records, and a shared cache or browser history entry holding them extends
// their exposure well past the request.
func (s *Server) writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeJSON(w, status, v)
}

// adminActor returns the administrator resolved by the RBAC guard.
//
// A missing actor means the guard did not run, which is a wiring bug rather
// than an authorization outcome — so it is a 500, exactly as the guard treats a
// missing session.
func (s *Server) adminActor(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	actor, ok := rbac.ActorFromContext(r.Context())
	if !ok {
		s.logger.Error("admin: handler reached without an actor in context",
			"method", r.Method)
		s.writeAdminError(w, http.StatusInternalServerError, "server_error")
		return uuid.Nil, false
	}
	return actor, true
}

// parsePagination reads limit/offset, applying the configured default and cap.
//
// An over-large limit is clamped rather than rejected: the caller asked for
// more than is safe to serve in one query, and the useful answer is the largest
// safe page, not an error they have to guess their way out of. A negative or
// non-numeric value is a different case — it is malformed, not merely
// ambitious — so it is rejected.
func (s *Server) parsePagination(r *http.Request) (limit, offset int32, err error) {
	cfg := s.cfg.Admin
	limit = cfg.PageSizeDefault
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 32)
		if parseErr != nil || parsed < 0 {
			return 0, 0, errors.New("invalid limit")
		}
		limit = int32(parsed)
	}
	if limit == 0 {
		limit = cfg.PageSizeDefault
	}
	if limit > cfg.PageSizeMax {
		limit = cfg.PageSizeMax
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, parseErr := strconv.ParseInt(raw, 10, 32)
		if parseErr != nil || parsed < 0 {
			return 0, 0, errors.New("invalid offset")
		}
		offset = int32(parsed)
	}
	return limit, offset, nil
}

// decodeJSONBody decodes a JSON request body, rejecting unknown fields.
//
// DisallowUnknownFields matters more here than on a public route: a typo in
// "reason" on a legal-hold request would otherwise store an empty justification
// for a court order and report success.
func decodeJSONBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("request must contain exactly one JSON object")
	}
	return nil
}

// parseTimeParam accepts RFC 3339 or Unix seconds, matching api-design §1.7.
func parseTimeParam(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("empty time")
	}
	if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// parseInt64Param reads a non-negative integer query parameter.
func parseInt64Param(r *http.Request, name string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed < 0 {
		return 0, errors.New("invalid " + name)
	}
	return parsed, nil
}

// timePtr converts a pgtype timestamp to a *time.Time, mapping SQL NULL to nil.
func timePtr(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time.UTC()
	return &t
}

// nullUUIDPtr converts a uuid.NullUUID to a *uuid.UUID.
func nullUUIDPtr(n uuid.NullUUID) *uuid.UUID {
	if !n.Valid {
		return nil
	}
	id := n.UUID
	return &id
}

// int64Ptr returns a pointer to v.
func int64Ptr(v int64) *int64 { return &v }

// stringPtr returns a pointer to v.
func stringPtr(v string) *string { return &v }

// isNoRows reports whether err is pgx.ErrNoRows.
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
