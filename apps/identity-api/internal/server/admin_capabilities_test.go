package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type adminCapabilitiesDB struct {
	db.DBTX
	actor  uuid.UUID
	grants map[string]bool
	reads  int
	err    error
}

func (d *adminCapabilitiesDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	d.reads++
	if !strings.HasPrefix(query, "-- name: UserHasPermission") || len(args) != 2 || args[0] != d.actor {
		return profileHandlerRow{err: errors.New("unexpected capability permission query")}
	}
	return profileHandlerRow{values: []any{d.grants[args[1].(string)]}, err: d.err}
}

func TestAdminCapabilitiesLegalOnlyAdmissionAndIndependentMounts(t *testing.T) {
	allLegal := adminCapabilities{LegalHoldsRead: true, LegalHoldsApply: true, LegalHoldsRelease: true,
		PreservationRequestsCreate: true, LegalInquiryLookup: true}
	for _, tc := range []struct {
		name        string
		permissions []string
		available   adminCapabilities
		want        adminCapabilities
	}{
		{"legal read only", []string{permLegalHoldsRead}, allLegal, adminCapabilities{LegalHoldsRead: true}},
		{"legal write only", []string{permLegalHoldsWrite}, allLegal, adminCapabilities{LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true}},
		{"inquiry only", []string{permLegalInquiryLookup}, allLegal, adminCapabilities{LegalInquiryLookup: true}},
		{"all legal", []string{permLegalHoldsRead, permLegalHoldsWrite, permLegalInquiryLookup}, allLegal, allLegal},
		{"apply mounted alone", []string{permLegalHoldsWrite}, adminCapabilities{LegalHoldsApply: true}, adminCapabilities{LegalHoldsApply: true}},
		{"release mounted alone", []string{permLegalHoldsWrite}, adminCapabilities{LegalHoldsRelease: true}, adminCapabilities{LegalHoldsRelease: true}},
		{"preservation mounted alone", []string{permLegalHoldsWrite}, adminCapabilities{PreservationRequestsCreate: true}, adminCapabilities{PreservationRequestsCreate: true}},
		{"missing permission", nil, allLegal, adminCapabilities{}},
		{"unmounted legal routes", []string{permLegalHoldsRead, permLegalHoldsWrite, permLegalInquiryLookup}, adminCapabilities{}, adminCapabilities{}},
		{"read is not write", []string{permLegalHoldsRead}, adminCapabilities{LegalHoldsApply: true, LegalHoldsRelease: true, PreservationRequestsCreate: true}, adminCapabilities{}},
		{"write is not inquiry", []string{permLegalHoldsWrite}, adminCapabilities{LegalInquiryLookup: true}, adminCapabilities{}},
		{"PII is not legal", []string{permAdminUsersReadPII}, allLegal, adminCapabilities{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &adminCapabilitiesDB{actor: uuid.New(), grants: make(map[string]bool)}
			for _, permission := range tc.permissions {
				d.grants[permission] = true
			}
			s := &Server{cfg: config.Config{Admin: config.AdminConfig{
				PageSizeDefault: 7, PageSizeMax: 50, AuditMaxWindow: 1500 * time.Millisecond, ChainVerifyMaxLimit: 40,
			}}}
			op := &adminaction.Operation{Queries: db.New(d)}
			current := session.Session{ID: "capability-session", UserID: d.actor.String(), Kind: session.KindAuthenticated,
				AuthVersionSet: true, DPoPJKT: "bound-key", AbsoluteExpiry: time.Now().Add(time.Hour), IdleExpiry: time.Now().Add(time.Hour)}
			request := profileHandlerRequest(current, http.MethodGet, "")
			request = request.WithContext(adminaction.WithContext(request.Context(), op))
			handler := s.handleAdminCapabilities(tc.available)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			if d.reads != 8 {
				t.Fatalf("capabilities did not resolve all current permissions: %d", d.reads)
			}
			if tc.want == (adminCapabilities{}) {
				if w.Code != http.StatusForbidden || w.Body.String() != "{\"error\":\"forbidden\"}\n" {
					t.Fatalf("unavailable capability inferred authority or reason: %d %s", w.Code, w.Body.String())
				}
				return
			}
			var result adminCapabilitiesResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Capabilities != tc.want {
				t.Fatalf("legal permission/mount mismatch: %d %s", w.Code, w.Body.String())
			}
			if result.Limits.PageSizeDefault != 7 || result.Limits.PageSizeMax != 50 || result.Limits.AuditMaxWindowSeconds != 1.5 || result.Limits.ChainVerifyMaxLimit != 40 {
				t.Fatal("capability discovery changed effective numeric limits")
			}
			var raw struct {
				Capabilities map[string]any `json:"capabilities"`
			}
			if json.Unmarshal(w.Body.Bytes(), &raw) != nil || len(raw.Capabilities) != 12 {
				t.Fatal("missing or unexpected capability flags")
			}
			for _, name := range []string{"legal_holds_read", "legal_holds_apply", "legal_holds_release", "preservation_requests_create", "legal_inquiry_lookup"} {
				if _, ok := raw.Capabilities[name].(bool); !ok {
					t.Fatalf("capability %s is not an explicit boolean", name)
				}
			}
			if op.Event.EventType != "admin.capabilities.read" || op.Event.ActorID != d.actor {
				t.Fatal("legal-only discovery omitted its durable audit event")
			}
			clear(d.grants)
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			if w.Code != http.StatusForbidden || d.reads != 16 {
				t.Fatal("capabilities retained revoked authority")
			}
			d.err = errors.New("permission store unavailable")
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "capabilities") {
				t.Fatal("permission outage returned presentation authority")
			}
		})
	}
}
