package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

type adminLegalHoldResponse struct {
	ID                  uuid.UUID  `json:"id"`
	AccountRef          uuid.UUID  `json:"account_ref"`
	RequestKind         string     `json:"request_kind"`
	Reason              string     `json:"reason,omitempty"`
	RequestingAuthority string     `json:"requesting_authority,omitempty"`
	LegalBasis          string     `json:"legal_basis,omitempty"`
	AppliedBy           uuid.UUID  `json:"applied_by"`
	IsActive            bool       `json:"is_active"`
	AppliedAt           *time.Time `json:"applied_at"`
	ReviewAt            *time.Time `json:"review_at"`
	ReleasedAt          *time.Time `json:"released_at"`
	ReleasedBy          *uuid.UUID `json:"released_by"`
	DetailsPurged       bool       `json:"details_purged"`
	Replayed            bool       `json:"replayed"`
}

func newAdminLegalHoldResponse(h legalhold.Hold) adminLegalHoldResponse {
	r := h.Record
	return adminLegalHoldResponse{ID: r.ID, AccountRef: r.AccountRef, RequestKind: r.RequestKind,
		Reason: h.Details.Reason, RequestingAuthority: h.Details.RequestingAuthority, LegalBasis: h.Details.LegalBasis,
		AppliedBy: r.AppliedBy, IsActive: r.IsActive, AppliedAt: timePtr(r.AppliedAt), ReviewAt: timePtr(r.ReviewAt),
		ReleasedAt: timePtr(r.ReleasedAt), ReleasedBy: nullUUIDPtr(r.ReleasedBy), DetailsPurged: h.DetailsPurged}
}

type adminApplyLegalHoldRequest struct {
	AccountRef          string `json:"account_ref"`
	Reason              string `json:"reason"`
	RequestingAuthority string `json:"requesting_authority"`
	LegalBasis          string `json:"legal_basis"`
	ReviewAt            string `json:"review_at"`
}

// Legal endpoints additionally reject all query parameters on body-based paths,
// so a caller cannot accidentally place an identifier or narrative in a URL.
func decodeLegalBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.URL.RawQuery != "" {
		return legalhold.ErrInvalidRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return legalhold.ErrInvalidRequest
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return legalhold.ErrInvalidRequest
	}
	return nil
}

func legalRequestKey(r *http.Request) (uuid.UUID, error) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 {
		return uuid.Nil, legalhold.ErrInvalidRequest
	}
	id, err := uuid.Parse(values[0])
	if err != nil || id == uuid.Nil {
		return uuid.Nil, legalhold.ErrInvalidRequest
	}
	return id, nil
}

func (s *Server) handleAdminApplyLegalHold() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		var req adminApplyLegalHoldRequest
		if decodeLegalBody(w, r, &req) != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		account, err := uuid.Parse(req.AccountRef)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		key, err := legalRequestKey(r)
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		var review time.Time
		if req.ReviewAt != "" {
			review, err = parseTimeParam(req.ReviewAt)
			if err != nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
		}
		result, err := s.deps.LegalHold.Apply(r.Context(), legalhold.ApplyRequest{AccountRef: account,
			Reason: req.Reason, RequestingAuthority: req.RequestingAuthority, LegalBasis: req.LegalBasis,
			AppliedBy: actor, ReviewAt: review, IdempotencyKey: key})
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: audit.EventLegalHoldApplied,
			ActionStatus: audit.StatusSuccess, ActorID: actor, Payload: map[string]any{
				"hold_id": result.Hold.Record.ID.String(), "request_kind": legalhold.KindHold, "replayed": result.Replayed}})
		response := newAdminLegalHoldResponse(result.Hold)
		response.Replayed = result.Replayed
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		s.writeAdminJSON(w, status, response)
	}
}

func (s *Server) handleAdminListLegalHolds() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		for key, values := range r.URL.Query() {
			if (key != "account_ref" && key != "status" && key != "limit" && key != "offset") || len(values) != 1 {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
		}
		limit, offset, err := s.parsePagination(r)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		var account uuid.NullUUID
		if raw := r.URL.Query().Get("account_ref"); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil || id == uuid.Nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
			account = uuid.NullUUID{UUID: id, Valid: true}
		}
		status := r.URL.Query().Get("status")
		if status == "" {
			status = "active"
		}
		result, err := s.deps.LegalHold.List(r.Context(), legalhold.ListRequest{AccountRef: account,
			Status: status, Limit: limit, Offset: offset})
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		items := make([]adminLegalHoldResponse, 0, len(result.Holds))
		for _, hold := range result.Holds {
			items = append(items, newAdminLegalHoldResponse(hold))
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: "legal.holds.list", ActionStatus: audit.StatusSuccess,
			ActorID: actor, Payload: map[string]any{"result_count": len(items), "total": result.Total, "limit": limit,
				"offset": offset, "status_filter": status, "response_digest": legalResponseDigest(items)}})
		s.writeAdminJSON(w, http.StatusOK, adminPage[adminLegalHoldResponse]{Items: items, Total: result.Total, Limit: limit, Offset: offset})
	}
}

func (s *Server) handleAdminReleaseLegalHold() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		id, ok := s.adminPathUUID(w, r, "hold_id")
		if !ok {
			return
		}
		if r.URL.RawQuery != "" {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		result, err := s.deps.LegalHold.Release(r.Context(), id, actor)
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: audit.EventLegalHoldReleased, ActionStatus: audit.StatusSuccess,
			ActorID: actor, Payload: map[string]any{"hold_id": id.String(), "replayed": result.Replayed}})
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusNoContent)
	}
}

type adminPreservationRequest struct {
	AccountRef          string `json:"account_ref"`
	RequestingAuthority string `json:"requesting_authority"`
	Reason              string `json:"reason"`
	ExpiresAt           string `json:"expires_at"`
}

type adminPreservationResponse struct {
	Hold                  adminLegalHoldResponse `json:"hold"`
	Replayed              bool                   `json:"replayed"`
	AccountPresent        bool                   `json:"account_present"`
	LedgerEvidencePresent bool                   `json:"ledger_evidence_present"`
	ObservedAt            time.Time              `json:"observed_at"`
	Note                  string                 `json:"note"`
}

const preservationNote = "preservation does not restore purged data; ingestion may still be pending; account and ledger presence are observations, not completeness guarantees; expires_at is advisory only"

func (s *Server) handleAdminPreservationRequest() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		var req adminPreservationRequest
		if decodeLegalBody(w, r, &req) != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		account, err := uuid.Parse(req.AccountRef)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		key, err := legalRequestKey(r)
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		var expires time.Time
		if req.ExpiresAt != "" {
			expires, err = parseTimeParam(req.ExpiresAt)
			if err != nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
		}
		result, err := s.deps.LegalHold.Preserve(r.Context(), legalhold.PreserveRequest{AccountRef: account,
			RequestingAuthority: req.RequestingAuthority, Reason: req.Reason, AppliedBy: actor,
			ExpiresAt: expires, IdempotencyKey: key})
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		adminaction.SetEvent(r.Context(), audit.Event{EventType: audit.EventLegalPreservationRecorded,
			ActionStatus: audit.StatusSuccess, ActorID: actor, Payload: map[string]any{"hold_id": result.Hold.Record.ID.String(),
				"request_kind": legalhold.KindPreservation, "replayed": result.Replayed, "account_present": result.AccountPresent,
				"ledger_evidence_present": result.LedgerEvidencePresent, "observed_at": result.ObservedAt}})
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		s.writeAdminJSON(w, status, adminPreservationResponse{Hold: newAdminLegalHoldResponse(result.Hold), Replayed: result.Replayed,
			AccountPresent: result.AccountPresent, LedgerEvidencePresent: result.LedgerEvidencePresent,
			ObservedAt: result.ObservedAt, Note: preservationNote})
	}
}

type adminLegalInquiryRequest struct {
	IdentifierType      string   `json:"identifier_type"`
	Identifier          string   `json:"identifier"`
	RequestingAuthority string   `json:"requesting_authority"`
	CaseReference       string   `json:"case_reference"`
	Purpose             string   `json:"purpose"`
	StartTime           string   `json:"start_time"`
	EndTime             string   `json:"end_time"`
	Limit               int32    `json:"limit"`
	Cursor              string   `json:"cursor"`
	Fields              []string `json:"fields"`
}

// These are sensitive pseudonymous records, not anonymous/non-PII data.
type adminLedgerEventResponse struct {
	ID                uuid.UUID  `json:"id"`
	AccountRef        uuid.UUID  `json:"account_ref"`
	EventType         string     `json:"event_type"`
	Timestamp         *time.Time `json:"timestamp"`
	RetainUntil       *time.Time `json:"retain_until"`
	ChainHash         string     `json:"chain_hash"`
	ClientIP          *string    `json:"client_ip,omitempty"`
	IPSubnet          *string    `json:"ip_subnet,omitempty"`
	UserAgent         *string    `json:"user_agent,omitempty"`
	DeviceFingerprint *string    `json:"device_fingerprint,omitempty"`
	ClientID          *string    `json:"client_id,omitempty"`
	Scope             *string    `json:"scope,omitempty"`
}

func newAdminLedgerEvent(e db.SecurityEventLedger, fields []string) adminLedgerEventResponse {
	result := adminLedgerEventResponse{ID: e.ID, AccountRef: e.AccountRef, EventType: e.EventType,
		Timestamp: timePtr(e.Timestamp), RetainUntil: timePtr(e.RetainUntil), ChainHash: e.ChainHash}
	for _, field := range fields {
		switch field {
		case "client_ip":
			result.ClientIP = e.ClientIp
		case "ip_subnet":
			result.IPSubnet = e.IpSubnet
		case "user_agent":
			result.UserAgent = e.UserAgent
		case "device_fingerprint":
			result.DeviceFingerprint = e.DeviceFingerprint
		case "client_id":
			result.ClientID = e.ClientID
		case "scope":
			result.Scope = e.Scope
		}
	}
	return result
}

func legalResponseDigest(v any) string {
	encoded, _ := json.Marshal(v)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (s *Server) handleAdminLegalInquiryLookup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := s.adminActor(w, r)
		if !ok {
			return
		}
		var req adminLegalInquiryRequest
		if decodeLegalBody(w, r, &req) != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		start, err := parseTimeParam(req.StartTime)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		end, err := parseTimeParam(req.EndTime)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		if req.Limit == 0 {
			req.Limit = s.cfg.Admin.PageSizeDefault
		}
		if req.Limit > s.cfg.Admin.PageSizeMax {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		result, err := s.deps.LegalHold.Lookup(r.Context(), legalhold.LookupRequest{IdentifierType: req.IdentifierType,
			Identifier: req.Identifier, RequestingAuthority: req.RequestingAuthority, CaseReference: req.CaseReference,
			Purpose: req.Purpose, ActorID: actor, StartTime: start, EndTime: end, Limit: req.Limit, Cursor: req.Cursor, Fields: req.Fields})
		if err != nil {
			s.writeLegalHoldError(w, err)
			return
		}
		items := make([]adminLedgerEventResponse, 0, len(result.Events))
		for _, event := range result.Events {
			items = append(items, newAdminLedgerEvent(event, result.Fields))
		}
		if err := adminaction.SetDetails(r.Context(), map[string]string{"requesting_authority": strings.TrimSpace(req.RequestingAuthority),
			"case_reference": strings.TrimSpace(req.CaseReference), "purpose": strings.TrimSpace(req.Purpose)}); err != nil {
			s.writeLegalHoldError(w, legalhold.ErrUnavailable)
			return
		}
		fields := append([]string{"id", "account_ref", "event_type", "timestamp", "retain_until", "chain_hash"}, result.Fields...)
		adminaction.SetEvent(r.Context(), audit.Event{EventType: audit.EventLegalInquiryLookup,
			ActionStatus: audit.StatusSuccess, ActorID: actor, Payload: map[string]any{"result_count": len(items),
				"limit": req.Limit, "start_time": start, "end_time": end, "through_seq": result.Coverage.ThroughSeq,
				"selected_fields": fields, "has_more": result.NextCursor != "", "response_digest": legalResponseDigest(items)}})
		s.writeAdminJSON(w, http.StatusOK, struct {
			Items      []adminLedgerEventResponse `json:"items"`
			NextCursor string                     `json:"next_cursor,omitempty"`
			Coverage   legalhold.Coverage         `json:"coverage"`
		}{items, result.NextCursor, result.Coverage})
	}
}

func (s *Server) writeLegalHoldError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rbac.ErrForbidden):
		s.writeAdminError(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, legalhold.ErrInvalidRequest):
		s.writeAdminError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, legalhold.ErrUnsupportedIdentifierType):
		s.writeAdminError(w, http.StatusBadRequest, "unsupported_identifier_type")
	case errors.Is(err, legalhold.ErrHoldNotFound):
		s.writeAdminError(w, http.StatusNotFound, "hold_not_found")
	case errors.Is(err, legalhold.ErrIdempotencyConflict):
		s.writeAdminError(w, http.StatusConflict, "idempotency_conflict")
	default:
		s.writeAdminError(w, http.StatusServiceUnavailable, "legal_unavailable")
	}
}
