package server

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

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

const legalBodyLimit = 32 * 1024

// Preflight runs after live session/permission checks, before one-use step-up.
// Read at most the ceiling plus one byte, including for chunked bodies.
func (s *Server) legalBodyPreflight(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validAdminQuery(r) {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		release := r.Method == http.MethodDelete
		if release && len(r.Header.Values("Idempotency-Key")) != 0 {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		if r.ContentLength > legalBodyLimit {
			s.writeAdminError(w, http.StatusRequestEntityTooLarge, "invalid_request")
			return
		}
		var body []byte
		if r.Body != nil {
			source := r.Body
			defer func() { _ = source.Close() }()
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, legalBodyLimit+1))
			defer clear(body)
			if err != nil || r.Context().Err() != nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
		}
		if len(body) > legalBodyLimit {
			s.writeAdminError(w, http.StatusRequestEntityTooLarge, "invalid_request")
			return
		}
		if release && len(body) != 0 {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if !s.browserRequestAllowed(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// These bodies never accept identifiers or narratives in query parameters.
func decodeLegalBody(w http.ResponseWriter, r *http.Request, dst any) error {
	if !validAdminQuery(r) || r.Body == nil {
		return legalhold.ErrInvalidRequest
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, legalBodyLimit))
	defer clear(raw)
	typeOf := reflect.TypeOf(dst)
	if err != nil || !utf8.Valid(raw) || !json.Valid(raw) || !uniqueJSONFields(raw) || typeOf == nil || typeOf.Kind() != reflect.Pointer {
		return legalhold.ErrInvalidRequest
	}
	if !exactLegalJSON(raw, typeOf.Elem()) || json.Unmarshal(raw, dst) != nil {
		return legalhold.ErrInvalidRequest
	}
	if _, inquiry := dst.(*adminLegalInquiryRequest); inquiry {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if bytes.Equal(bytes.TrimSpace(fields["fields"]), []byte("null")) {
			return legalhold.ErrInvalidRequest
		}
	}
	return nil
}

// encoding/json accepts case aliases and null scalar values. Match declared
// wire names recursively instead; nullable pointers/collections keep their contract.
func exactLegalJSON(raw json.RawMessage, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || exactLegalJSON(raw, typ.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return true
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) {
		return bytes.TrimSpace(raw)[0] == '"'
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || object == nil {
			return false
		}
		fields := make(map[string]reflect.Type)
		for i := range typ.NumField() {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if field.IsExported() && name != "-" {
				if name == "" {
					name = field.Name
				}
				fields[name] = field.Type
			}
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok || !exactLegalJSON(value, field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return false
		}
		for _, value := range values {
			if !exactLegalJSON(value, typ.Elem()) {
				return false
			}
		}
	}
	return true
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
		if !validAdminQuery(r, "account_ref", "status", "limit", "offset") {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		limit, offset, err := s.parsePagination(r)
		if err != nil {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		var account uuid.NullUUID
		query := r.URL.Query()
		if query.Has("account_ref") {
			id, err := uuid.Parse(query.Get("account_ref"))
			if err != nil || id == uuid.Nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
			account = uuid.NullUUID{UUID: id, Valid: true}
		}
		status := query.Get("status")
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
		if !validAdminQuery(r) || len(r.Header.Values("Idempotency-Key")) != 0 {
			s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
			return
		}
		if r.Body != nil {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 || r.Context().Err() != nil {
				s.writeLegalHoldError(w, legalhold.ErrInvalidRequest)
				return
			}
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
	ClientIP          *string    `json:"client_ip,omitempty"`
	IPSubnet          *string    `json:"ip_subnet,omitempty"`
	UserAgent         *string    `json:"user_agent,omitempty"`
	DeviceFingerprint *string    `json:"device_fingerprint,omitempty"`
	ClientID          *string    `json:"client_id,omitempty"`
	Scope             *string    `json:"scope,omitempty"`
	Seq               int64      `json:"seq,string"`
}

// newAdminLedgerEvent projects one disclosure row.
//
// The event UUID comes from the chain node (e.EventID) rather than from the
// payload row, which no longer carries one. Seq is disclosed alongside it because
// it is the chain position an authority needs to request an inclusion proof, and
// it is the cursor the next page is keyed on.
func newAdminLedgerEvent(e db.LookupLegalAttributionRow, fields []string) adminLedgerEventResponse {
	result := adminLedgerEventResponse{ID: e.EventID, AccountRef: e.AccountRef, EventType: e.EventType,
		Timestamp: timePtr(e.Timestamp), RetainUntil: timePtr(e.RetainUntil), Seq: e.Seq}
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
		fields := append([]string{"id", "account_ref", "event_type", "timestamp", "retain_until", "seq"}, result.Fields...)
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
