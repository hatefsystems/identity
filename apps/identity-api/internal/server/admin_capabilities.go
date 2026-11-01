package server

import (
	"net/http"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

type adminCapabilities struct {
	UsersRead        bool `json:"users_read"`
	UsersPII         bool `json:"users_pii"`
	UsersLookup      bool `json:"users_lookup"`
	UsersStatusWrite bool `json:"users_status_write"`
	AuditLogsRead    bool `json:"audit_logs_read"`
	AuditChainVerify bool `json:"audit_chain_verify"`
	LedgerVerify     bool `json:"ledger_verify"`
}

type adminCapabilitiesResponse struct {
	Capabilities adminCapabilities `json:"capabilities"`
	Limits       struct {
		PageSizeDefault       int32   `json:"page_size_default"`
		PageSizeMax           int32   `json:"page_size_max"`
		AuditMaxWindowSeconds float64 `json:"audit_max_window_seconds"`
		ChainVerifyMaxLimit   int32   `json:"chain_verify_max_limit"`
	} `json:"limits"`
}

func (s *Server) handleAdminCapabilities(available adminCapabilities) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, actor, ok := profileSession(w, r)
		if !ok {
			return
		}
		if !validAdminQuery(r) {
			s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		op, ok := adminaction.FromContext(r.Context())
		if !ok || op.Queries == nil {
			s.writeAdminError(w, http.StatusServiceUnavailable, "audit_unavailable")
			return
		}
		// Resolve a fixed set on the primary transaction, never a cache or role
		// label. This is presentation metadata, not authority for later requests.
		grants := make(map[string]bool, 5)
		for _, permission := range []string{
			permAdminUsersRead, permAdminUsersReadPII, permAdminUsersStatusWrit,
			permAdminAuditLogsRead, permAdminAuditLogsVerify,
		} {
			allowed, err := op.Queries.UserHasPermission(r.Context(), db.UserHasPermissionParams{
				UserID: actor, PermissionID: permission,
			})
			if err != nil {
				s.writeAdminError(w, http.StatusServiceUnavailable, "service_unavailable")
				return
			}
			grants[permission] = allowed
		}
		caps := adminCapabilities{
			UsersRead:        available.UsersRead && grants[permAdminUsersRead],
			UsersStatusWrite: available.UsersStatusWrite && grants[permAdminUsersStatusWrit],
			AuditLogsRead:    available.AuditLogsRead && grants[permAdminAuditLogsRead],
			AuditChainVerify: available.AuditChainVerify && grants[permAdminAuditLogsVerify],
			LedgerVerify:     available.LedgerVerify && grants[permAdminAuditLogsVerify],
		}
		caps.UsersPII = caps.UsersRead && grants[permAdminUsersReadPII]
		caps.UsersLookup = available.UsersLookup && caps.UsersPII
		if !caps.UsersRead && !caps.UsersStatusWrite && !caps.AuditLogsRead && !caps.AuditChainVerify && !caps.LedgerVerify {
			s.writeAdminError(w, http.StatusForbidden, "forbidden")
			return
		}
		var response adminCapabilitiesResponse
		response.Capabilities = caps
		response.Limits.PageSizeDefault = s.cfg.Admin.PageSizeDefault
		response.Limits.PageSizeMax = s.cfg.Admin.PageSizeMax
		response.Limits.AuditMaxWindowSeconds = s.cfg.Admin.AuditMaxWindow.Seconds()
		response.Limits.ChainVerifyMaxLimit = s.cfg.Admin.ChainVerifyMaxLimit
		adminaction.SetEvent(r.Context(), audit.Event{
			EventType: "admin.capabilities.read", ActorID: actor, ActionStatus: audit.StatusSuccess,
		})
		s.writeAdminJSON(w, http.StatusOK, response)
	}
}
