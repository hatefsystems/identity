package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/legalpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalworkflow"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

const (
	permLegalCasesRead        = "legal.cases.read"
	permLegalCasesWrite       = "legal.cases.write"
	permLegalResponsesApprove = "legal.responses.approve"
)

func (s *Server) workflowActor(w http.ResponseWriter, r *http.Request) (legalworkflow.Actor, bool) {
	id, ok := s.adminActor(w, r)
	if !ok {
		return legalworkflow.Actor{}, false
	}
	current, ok := session.FromContext(r.Context())
	if !ok || current.UserID != id.String() {
		s.writeAdminError(w, http.StatusUnauthorized, "unauthorized")
		return legalworkflow.Actor{}, false
	}
	return legalworkflow.Actor{ID: id, AuthVersion: current.AuthVersion}, true
}

// Transport supplies replay keys, path IDs and actors independently of JSON.
func workflowMutation[T any](s *Server, pathParam string, status int,
	run func(context.Context, legalworkflow.Actor, uuid.UUID, uuid.UUID, T) (legalworkflow.MutationResult, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.workflowActor(w, r)
		if !ok {
			return
		}
		var id uuid.UUID
		if pathParam != "" {
			id, ok = s.adminPathUUID(w, r, pathParam)
			if !ok {
				return
			}
		}
		key, err := legalRequestKey(r)
		var request T
		if err != nil || decodeLegalBody(w, r, &request) != nil {
			s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
			return
		}
		result, err := run(r.Context(), actor, id, key, request)
		if err != nil {
			s.writeWorkflowError(w, err)
			return
		}
		code := status
		if result.Replayed {
			code = http.StatusOK
		}
		s.writeAdminJSON(w, code, result)
	}
}

func (s *Server) handleCreateLegalCase() http.HandlerFunc {
	return workflowMutation(s, "", http.StatusCreated, func(ctx context.Context, actor legalworkflow.Actor, _, key uuid.UUID, req legalworkflow.CreateRequest) (legalworkflow.MutationResult, error) {
		req.Key = key
		return s.deps.LegalWorkflow.Create(ctx, actor, req)
	})
}

func (s *Server) handleReviseLegalCase() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.RevisionRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.Revise(ctx, actor, req)
	})
}

func (s *Server) handleReviewLegalCase() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.ReviewRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.Review(ctx, actor, req)
	})
}

func (s *Server) handleCloseLegalCase() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.CloseRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.Close(ctx, actor, req)
	})
}

func (s *Server) handlePrepareLegalResponse() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.ResponseRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.PrepareResponse(ctx, actor, req)
	})
}

func (s *Server) handleApproveLegalResponse() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.ApprovalRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.ApproveResponse(ctx, actor, req)
	})
}

func (s *Server) handleDeliverLegalResponse() http.HandlerFunc {
	return workflowMutation(s, "case_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.DeliveryRequest) (legalworkflow.MutationResult, error) {
		req.CaseID, req.Key = id, key
		return s.deps.LegalWorkflow.DeliverResponse(ctx, actor, req)
	})
}

func (s *Server) handleReviewExistingHold() http.HandlerFunc {
	return workflowMutation(s, "hold_id", http.StatusOK, func(ctx context.Context, actor legalworkflow.Actor, id, key uuid.UUID, req legalworkflow.HoldReviewRequest) (legalworkflow.MutationResult, error) {
		req.HoldID, req.Key = id, key
		return s.deps.LegalWorkflow.ReviewHold(ctx, actor, req)
	})
}

func (s *Server) handleGetLegalCase() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.workflowActor(w, r)
		if !ok {
			return
		}
		id, ok := s.adminPathUUID(w, r, "case_id")
		if !ok {
			return
		}
		if r.URL.RawQuery != "" {
			s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
			return
		}
		result, err := s.deps.LegalWorkflow.Get(r.Context(), actor, id)
		if err != nil {
			s.writeWorkflowError(w, err)
			return
		}
		s.writeAdminJSON(w, http.StatusOK, result)
	}
}

func (s *Server) handleListLegalCases(queue bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.workflowActor(w, r)
		if !ok {
			return
		}
		for key, values := range r.URL.Query() {
			if len(values) != 1 || (key != "status" && key != "limit" && key != "offset") {
				s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
				return
			}
		}
		limit, offset, err := s.parsePagination(r)
		if err != nil {
			s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
			return
		}
		req := legalworkflow.ListRequest{Status: r.URL.Query().Get("status"), Limit: limit, Offset: offset}
		if queue {
			result, err := s.deps.LegalWorkflow.DueReviews(r.Context(), actor, req)
			if err != nil {
				s.writeWorkflowError(w, err)
				return
			}
			s.writeAdminJSON(w, http.StatusOK, adminPage[legalworkflow.QueueItem]{Items: result.Items, Total: result.Total, Limit: limit, Offset: offset})
			return
		}
		result, err := s.deps.LegalWorkflow.List(r.Context(), actor, req)
		if err != nil {
			s.writeWorkflowError(w, err)
			return
		}
		s.writeAdminJSON(w, http.StatusOK, adminPage[legalworkflow.Summary]{Items: result.Cases, Total: result.Total, Limit: limit, Offset: offset})
	}
}

func (s *Server) handleMonthlyLegalTransparency() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.workflowActor(w, r)
		if !ok {
			return
		}
		for key, values := range r.URL.Query() {
			if len(values) != 1 || (key != "start" && key != "months") {
				s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
				return
			}
		}
		start, err := time.Parse("2006-01", r.URL.Query().Get("start"))
		if err != nil {
			s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
			return
		}
		months, err := strconv.Atoi(r.URL.Query().Get("months"))
		if err != nil || months < 1 || months > 12 {
			s.writeWorkflowError(w, legalworkflow.ErrInvalidRequest)
			return
		}
		result, err := s.deps.LegalReports.Monthly(r.Context(), legalreport.Actor{ID: actor.ID, AuthVersion: actor.AuthVersion}, legalreport.MonthlyRequest{Start: start, Months: months})
		if err != nil {
			s.writeWorkflowError(w, err)
			return
		}
		s.writeAdminJSON(w, http.StatusOK, result)
	}
}

func (s *Server) handleLegalReport(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		current, ok := s.workflowActor(w, r)
		if !ok {
			return
		}
		actor := legalreport.Actor{ID: current.ID, AuthVersion: current.AuthVersion}
		var id uuid.UUID
		if action != "prepare" {
			id, ok = s.adminPathUUID(w, r, "report_id")
			if !ok {
				return
			}
		}
		if action == "get" {
			if r.URL.RawQuery != "" {
				s.writeWorkflowError(w, legalreport.ErrInvalidRequest)
				return
			}
			result, err := s.deps.LegalReports.GetReport(r.Context(), actor, id)
			if err != nil {
				s.writeWorkflowError(w, err)
				return
			}
			s.writeAdminJSON(w, http.StatusOK, result)
			return
		}
		key, err := legalRequestKey(r)
		if err != nil {
			s.writeWorkflowError(w, legalreport.ErrInvalidRequest)
			return
		}
		switch action {
		case "prepare":
			var req legalreport.PrepareRequest
			if decodeLegalBody(w, r, &req) != nil {
				s.writeWorkflowError(w, legalreport.ErrInvalidRequest)
				return
			}
			req.Key = key
			result, err := s.deps.LegalReports.PrepareReport(r.Context(), actor, req)
			if err != nil {
				s.writeWorkflowError(w, err)
				return
			}
			status := http.StatusCreated
			if result.Replayed {
				status = http.StatusOK
			}
			s.writeAdminJSON(w, status, result)
		case "approve":
			var req legalreport.ApproveRequest
			if decodeLegalBody(w, r, &req) != nil {
				s.writeWorkflowError(w, legalreport.ErrInvalidRequest)
				return
			}
			req.Key, req.ID = key, id
			result, err := s.deps.LegalReports.ApproveReport(r.Context(), actor, req)
			if err != nil {
				s.writeWorkflowError(w, err)
				return
			}
			s.writeAdminJSON(w, http.StatusOK, result)
		case "download":
			var req legalreport.DownloadRequest
			if decodeLegalBody(w, r, &req) != nil {
				s.writeWorkflowError(w, legalreport.ErrInvalidRequest)
				return
			}
			req.Key, req.ID = key, id
			result, err := s.deps.LegalReports.DownloadReport(r.Context(), actor, req)
			if err != nil {
				s.writeWorkflowError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", `attachment; filename="legal-transparency.json"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(result.Payload)
		}
	}
}

func (s *Server) writeWorkflowError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rbac.ErrForbidden):
		s.writeAdminError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, legalworkflow.ErrInvalidRequest), errors.Is(err, legalreport.ErrInvalidRequest):
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, legalworkflow.ErrNotFound), errors.Is(err, legalreport.ErrNotFound):
		s.writeAdminError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, legalworkflow.ErrErased), errors.Is(err, legalworkflow.ErrExpired):
		s.writeAdminError(w, http.StatusGone, "legal_record_unavailable")
	case errors.Is(err, legalworkflow.ErrConflict), errors.Is(err, legalreport.ErrConflict):
		s.writeAdminError(w, http.StatusConflict, "version_or_replay_conflict")
	case errors.Is(err, legalreport.ErrStaleSnapshot):
		s.writeAdminError(w, http.StatusConflict, "report_snapshot_stale")
	case errors.Is(err, legalpolicy.ErrNotApproved), errors.Is(err, legalpolicy.ErrMismatch), errors.Is(err, legalpolicy.ErrInvalidPolicy):
		s.writeAdminError(w, http.StatusServiceUnavailable, "legal_policy_unavailable")
	default:
		s.writeAdminError(w, http.StatusServiceUnavailable, "legal_workflow_unavailable")
	}
}
