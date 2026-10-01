package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

func (s *Server) callerHasPII(r *http.Request, actor uuid.UUID) (bool, error) {
	op, ok := adminaction.FromContext(r.Context())
	if !ok {
		return false, errors.New("admin: durable operation required")
	}
	return op.Queries.UserHasPermission(r.Context(), db.UserHasPermissionParams{
		UserID: actor, PermissionID: permAdminUsersReadPII,
	})
}

func (s *Server) handleAdminListUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		if r.URL.Query().Has("email") {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		limit, offset, err := s.parsePagination(r)
		if err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var status *string
		if raw, exists := r.URL.Query()["status"]; exists {
			if len(raw) != 1 || !validAdminUserStatus(raw[0]) {
				s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
				return
			}
			status = &raw[0]
		}
		includePII, err := s.callerHasPII(r, actor)
		if err != nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		op, _ := adminaction.FromContext(r.Context())
		page, err := op.Queries.ListAdminUsersPage(r.Context(), db.ListAdminUsersPageParams{
			Status: status, PageLimit: limit, PageOffset: offset,
		})
		if err != nil {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		items := []adminUserResponse{}
		if err := json.Unmarshal(page.Items, &items); err != nil {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if !includePII {
			for i := range items {
				items[i].Email = nil
			}
		}
		fields := []string{"id", "status", "mfa_enabled", "created_at", "updated_at", "deleted_at"}
		if includePII {
			fields = append(fields, "email")
		}
		metadata := map[string]any{"result_count": len(items), "total": page.Total, "limit": limit, "offset": offset, "selected_fields": fields}
		if status != nil {
			metadata["status_filter"] = *status
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: "admin.users.queried", Payload: metadata})
		s.writeAdminJSON(w, http.StatusOK, adminPage[adminUserResponse]{Items: items, Total: page.Total, Limit: limit, Offset: offset})
	}
}

func validAdminUserStatus(status string) bool {
	switch status {
	case "active", "suspended", "banned", "pending_verification", "pending_deletion":
		return true
	default:
		return false
	}
}

// Exact email lookup is body-only. Never copy its identifier into audit context.
func (s *Server) handleAdminLookupUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		includePII, err := s.callerHasPII(r, actor)
		if err != nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		if !includePII {
			s.writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		var req struct {
			Email string `json:"email"`
		}
		if r.URL.RawQuery != "" {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if err := decodeJSONBody(r, &req); err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		email := strings.ToLower(strings.TrimSpace(req.Email))
		address, err := mail.ParseAddress(email)
		if err != nil || len(email) > 254 || address.Address != email {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		user, err := s.adminStore(r).GetUserByEmailForAdmin(r.Context(), email)
		items := []adminUserResponse{}
		if err != nil && !isNoRows(err) {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if err == nil {
			items = append(items, newAdminUserResponse(user, true))
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: "admin.users.looked_up", Payload: map[string]any{"result_count": len(items), "selected_fields": []string{"id", "status", "email", "mfa_enabled", "created_at", "updated_at", "deleted_at"}}})
		s.writeAdminJSON(w, http.StatusOK, adminPage[adminUserResponse]{Items: items, Total: int64(len(items)), Limit: 1})
	}
}

func (s *Server) handleAdminGetUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		userID, ok := s.adminPathUUID(w, r, "user_id")
		if !ok {
			return
		}
		includePII, err := s.callerHasPII(r, actor)
		if err != nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		user, err := s.adminStore(r).GetUserByIDForAdmin(r.Context(), userID)
		if err != nil {
			if isNoRows(err) {
				s.writeAdminError(w, http.StatusNotFound, "user_not_found")
			} else {
				s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			}
			return
		}
		// Role membership and hold existence are not ordinary account metadata.
		fields := []string{"id", "status", "mfa_enabled", "created_at", "updated_at", "deleted_at"}
		if includePII {
			fields = append(fields, "email")
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: "admin.users.viewed", Payload: map[string]any{"result_count": 1, "selected_fields": fields}})
		s.writeAdminJSON(w, http.StatusOK, newAdminUserResponse(user, includePII))
	}
}

type adminUpdateStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func (s *Server) handleAdminUpdateUserStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		userID, ok := s.adminPathUUID(w, r, "user_id")
		if !ok {
			return
		}
		var req adminUpdateStatusRequest
		if err := decodeJSONBody(r, &req); err != nil {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		reason := strings.TrimSpace(req.Reason)
		if reason == "" || len(reason) > 2000 {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if _, allowed := adminAssignableStatuses[req.Status]; !allowed {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_status")
			return
		}
		if actor == userID {
			s.writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		op, ok := adminaction.FromContext(r.Context())
		if !ok {
			s.writeAdminError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		current, ok := session.FromContext(r.Context())
		if !ok || current.Kind != session.KindAuthenticated {
			s.writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		if err := rbac.LockAuthorized(r.Context(), op.Tx, actor, []uuid.UUID{userID}, permAdminUsersStatusWrit, current.AuthVersion); err != nil {
			if errors.Is(err, rbac.ErrForbidden) {
				s.writeAdminError(w, http.StatusForbidden, "forbidden")
			} else {
				s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
			}
			return
		}
		existing, err := op.Queries.GetUserByIDForAdmin(r.Context(), userID)
		if err != nil {
			if isNoRows(err) {
				s.writeAdminError(w, http.StatusNotFound, "user_not_found")
			} else {
				s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			}
			return
		}
		if _, allowed := adminAssignableStatuses[existing.Status]; !allowed || existing.DeletedAt.Valid {
			s.writeAdminError(w, http.StatusConflict, "account_not_moderatable")
			return
		}
		privileged, err := op.Queries.UserHasPrivilegedRole(r.Context(), userID)
		if err != nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		if privileged {
			s.writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		updated, err := op.Queries.ModerateUserStatus(r.Context(), db.ModerateUserStatusParams{ID: userID, Status: req.Status})
		if err != nil {
			s.writeAdminError(w, http.StatusInternalServerError, "server_error")
			return
		}
		if req.Status != "active" && s.deps.AdminRevoke != nil {
			op.AfterCommit = func() error { return s.deps.AdminRevoke(userID.String()) }
		}
		if err := adminaction.SetDetails(r.Context(), struct {
			Reason string `json:"reason"`
		}{Reason: reason}); err != nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		s.recordAdminEvent(r, audit.Event{
			EventType: audit.EventAdminUserStatusChanged, ActionStatus: audit.StatusSuccess, ActorID: actor, SubjectID: &userID,
			Payload: map[string]any{"old_status": existing.Status, "new_status": updated.Status, "old_auth_version": existing.AuthVersion, "new_auth_version": updated.AuthVersion},
		})
		// Middleware commits this mutation, encrypted reason and audit outbox
		// together before releasing the response. DB versions are the authority;
		// process-local credential cleanup must never be the security boundary.
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) adminPathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, name)))
	if err != nil {
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
		return uuid.Nil, false
	}
	return id, true
}

// Privileged operations never fall back to the best-effort recorder.
func (s *Server) recordAdminEvent(r *http.Request, e audit.Event) {
	e.Security = nil
	e.ActorSPIFFEID = audit.APIActorSPIFFEID
	adminaction.SetEvent(r.Context(), e)
}
