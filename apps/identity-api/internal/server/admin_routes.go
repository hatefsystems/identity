package server

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

// registerAdminRoutes mounts the administrative surface at /api/v1/admin/*
// (docs/api-design.md §1.7).
//
// # Middleware order is fixed and load-bearing
//
// session -> permission -> step-up, always.
//
//   - Session first because both later guards read the caller from the request
//     context; neither establishes identity.
//   - Permission before step-up so an unauthorized caller is never induced to
//     burn a single-use step-up grant on a route it could never reach. Reversed,
//     probing an endpoint you lack permission for would cost you a real grant.
//
// # Fail-closed mounting, with one deliberate deviation
//
// The established doctrine (server.go:293) is all-or-nothing: an absent gate
// means absent routes. That is preserved for the session guard and for each
// permission guard. It is deliberately *not* applied wholesale to step-up.
//
// When no step-up service is configured, only the step-up-gated rows are
// omitted; the read-only rows still mount. Withholding reads would be an
// availability loss with no security gain, because the documentation attaches
// no step-up requirement to them — there is no gate being bypassed. The
// mutating rows keep the strict behaviour: no gate, no route.
//
// A permission guard that fails to construct leaves only its own route
// unmounted and logs at Error, for the same reason: one broken guard should not
// take down the surface, but it must never leave its route ungated.
func (s *Server) registerAdminRoutes() {
	sessGuard, hasSession := s.sessionGuard("admin")
	if !hasSession {
		return
	}
	stepGuard, hasStepUp := s.stepUpGuard("admin")

	// perm builds one permission guard, reporting false when the route must
	// stay unmounted.
	perm := func(permission string) (func(http.Handler) http.Handler, bool) {
		guard, err := rbac.NewRequirePermission(
			s.deps.RBAC,
			permission,
			s.logger,
		)
		if err != nil {
			s.logger.Error("admin: failed to build permission guard; route not mounted",
				slog.String("permission", permission),
				slog.String("error", err.Error()))
			return nil, false
		}
		return guard.Handler, true
	}

	// mount registers one route behind its permission guard, and behind the
	// step-up guard when stepUp is true.
	mount := func(r chi.Router, method, pattern, permission string, stepUp bool, h http.HandlerFunc) {
		permHandler, ok := perm(permission)
		if !ok {
			return
		}
		if stepUp {
			if !hasStepUp {
				s.logger.Warn("admin: step-up unavailable; gated route not mounted",
					slog.String("method", method),
					slog.String("pattern", pattern))
				return
			}
			r.With(permHandler, stepGuard.Handler).Method(method, pattern, h)
			return
		}
		r.With(permHandler).Method(method, pattern, h)
	}

	s.router.Route("/api/v1/admin", func(r chi.Router) {
		r.Use(s.adminTransaction)
		r.Use(sessGuard.Handler)
		r.Use(s.adminActorContext)

		// --- Accounts ---
		mount(r, http.MethodGet, "/users", permAdminUsersRead, false, s.handleAdminListUsers())
		mount(r, http.MethodGet, "/users/{user_id}", permAdminUsersRead, false, s.handleAdminGetUser())
		mount(r, http.MethodPost, "/users/lookup", permAdminUsersRead, false, s.handleAdminLookupUser())
		mount(r, http.MethodPatch, "/users/{user_id}/status", permAdminUsersStatusWrit, true, s.handleAdminUpdateUserStatus())

		// --- Audit ---
		mount(r, http.MethodGet, "/audit-logs", permAdminAuditLogsRead, false, s.handleAdminListAuditLogs())
		mount(r, http.MethodGet, "/audit-logs/verify", permAdminAuditLogsVerify, false, s.handleAdminVerifyAuditChain())
		mount(r, http.MethodGet, "/ledger/verify", permAdminAuditLogsVerify, false, s.handleAdminVerifyLedgerChain())

		// --- Legal (DPO only) ---
		//
		// Mounted only when the legal-hold service exists. Per its constructor
		// contract that additionally means a blind-index pepper was configured:
		// an attribution lookup run with a missing or wrong pepper answers "no
		// records found" to a legal authority, which is indistinguishable from a
		// truthful negative and is the worst outcome this endpoint has. An
		// absent route produces an honest 404 instead.
		if s.deps.LegalHold != nil {
			mount(r, http.MethodPost, "/legal-holds", permLegalHoldsWrite, true, s.handleAdminApplyLegalHold())
			mount(r, http.MethodGet, "/legal-holds", permLegalHoldsRead, false, s.handleAdminListLegalHolds())
			mount(r, http.MethodDelete, "/legal-holds/{hold_id}", permLegalHoldsWrite, true, s.handleAdminReleaseLegalHold())
			mount(r, http.MethodPost, "/preservation-requests", permLegalHoldsWrite, true, s.handleAdminPreservationRequest())
			if s.deps.LegalHold.LookupEnabled() {
				mount(r, http.MethodPost, "/legal-inquiry/lookup", permLegalInquiryLookup, true, s.handleAdminLegalInquiryLookup())
			}
		} else {
			s.logger.Warn("admin: no legal hold service configured; legal routes not mounted")
		}
		if s.cfg.Admin.WorkflowEnabled && s.deps.LegalWorkflow != nil && s.deps.LegalReports != nil {
			mount(r, http.MethodPost, "/legal-cases", permLegalCasesWrite, true, s.handleCreateLegalCase())
			mount(r, http.MethodGet, "/legal-cases", permLegalCasesRead, false, s.handleListLegalCases(false))
			mount(r, http.MethodGet, "/legal-cases/{case_id}", permLegalCasesRead, false, s.handleGetLegalCase())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/revisions", permLegalCasesWrite, true, s.handleReviseLegalCase())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/reviews", permLegalCasesWrite, true, s.handleReviewLegalCase())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/close", permLegalCasesWrite, true, s.handleCloseLegalCase())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/response", permLegalCasesWrite, true, s.handlePrepareLegalResponse())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/response/approve", permLegalResponsesApprove, true, s.handleApproveLegalResponse())
			mount(r, http.MethodPost, "/legal-cases/{case_id}/response/delivery", permLegalCasesWrite, true, s.handleDeliverLegalResponse())
			if holdRead, ok := perm(permLegalHoldsRead); ok {
				mount(r.With(holdRead), http.MethodGet, "/legal-reviews", permLegalCasesRead, false, s.handleListLegalCases(true))
			}
			mount(r, http.MethodPost, "/legal-holds/{hold_id}/reviews", permLegalHoldsWrite, true, s.handleReviewExistingHold())
			mount(r, http.MethodGet, "/legal-transparency/monthly", legalreport.PermissionRead, false, s.handleMonthlyLegalTransparency())
			mount(r, http.MethodPost, "/legal-transparency/reports", legalreport.PermissionRead, true, s.handleLegalReport("prepare"))
			mount(r, http.MethodGet, "/legal-transparency/reports/{report_id}", legalreport.PermissionRead, false, s.handleLegalReport("get"))
			mount(r, http.MethodPost, "/legal-transparency/reports/{report_id}/approve", legalreport.PermissionApprove, true, s.handleLegalReport("approve"))
			mount(r, http.MethodPost, "/legal-transparency/reports/{report_id}/download", legalreport.PermissionRead, true, s.handleLegalReport("download"))
		}
	})
}
