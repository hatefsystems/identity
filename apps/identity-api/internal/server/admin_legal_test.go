package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

type legalListBoundaryStore struct {
	legalhold.Store
	params db.ListLegalHoldsParams
	calls  int
}

func (s *legalListBoundaryStore) ListLegalHolds(_ context.Context, p db.ListLegalHoldsParams) (db.ListLegalHoldsRow, error) {
	s.params, s.calls = p, s.calls+1
	return db.ListLegalHoldsRow{Items: []byte("[]")}, nil
}

func TestAdminLegalHoldListStrictRawQueryAndPagination(t *testing.T) {
	provider, err := kms.NewMockProvider([]byte(strings.Repeat("x", 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	store := &legalListBoundaryStore{}
	holds, err := legalhold.New(store, enc, legalhold.WithReleasedMetadataRetention(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.Config{Admin: config.AdminConfig{PageSizeDefault: 7, PageSizeMax: 50}}, nil, Deps{LegalHold: holds})
	account := uuid.New()
	for _, query := range []string{
		"account_ref=", "account_ref", "account_ref=%20", "account_ref=not-a-uuid", "account_ref=" + uuid.Nil.String(),
		"account_ref=%zz", "account_ref=%", "account_ref=%20&account_ref=" + account.String(),
		"account_ref=" + account.String() + "&%61ccount_ref=" + account.String(),
		"account_ref=" + account.String() + "&unknown=x", "account_ref=" + account.String() + ";status=all",
		"account_ref=" + account.String() + "&limit=%zz", "user_id=" + account.String(), "%zz=x",
		"limit=1&limit=2", "offset=0&offset=1", "status=active&status=all", "status=unknown", "status=%20",
		"limit=-1", "limit=1.2", "limit=2147483648", "offset=-1", "offset=no", "offset=2147483648",
	} {
		t.Run(query, func(t *testing.T) {
			store.calls = 0
			r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/legal-holds?"+query, nil)
			r = r.WithContext(rbac.WithActor(r.Context(), uuid.New()))
			w := httptest.NewRecorder()
			s.handleAdminListLegalHolds().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || store.calls != 0 || w.Body.String() != "{\"error\":\"invalid_request\"}\n" {
				t.Fatalf("invalid filter widened a legal read: status=%d store calls=%d", w.Code, store.calls)
			}
		})
	}
	for _, tc := range []struct {
		query         string
		account       uuid.NullUUID
		status        string
		limit, offset int32
	}{
		{"", uuid.NullUUID{}, "active", 7, 0},
		{"?", uuid.NullUUID{}, "active", 7, 0},
		{"?account_ref=" + account.String(), uuid.NullUUID{UUID: account, Valid: true}, "active", 7, 0},
		{"?status=all&limit=2147483647&offset=2147483647", uuid.NullUUID{}, "all", 50, 2147483647},
		{"?status=released&limit=1&offset=2", uuid.NullUUID{}, "released", 1, 2},
		{"?status=&limit=&offset=", uuid.NullUUID{}, "active", 7, 0},
		{"?limit=0&offset=0", uuid.NullUUID{}, "active", 7, 0},
	} {
		t.Run("valid"+tc.query, func(t *testing.T) {
			store.calls = 0
			r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/legal-holds"+tc.query, nil)
			r = r.WithContext(rbac.WithActor(r.Context(), uuid.New()))
			w := httptest.NewRecorder()
			s.handleAdminListLegalHolds().ServeHTTP(w, r)
			var page adminPage[adminLegalHoldResponse]
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || store.calls != 1 ||
				store.params.AccountRef != tc.account || store.params.Status != tc.status || store.params.PageLimit != tc.limit || store.params.PageOffset != tc.offset ||
				page.Items == nil || len(page.Items) != 0 || page.Limit != tc.limit || page.Offset != tc.offset {
				t.Fatalf("legal list changed bounded pagination/filter semantics: status=%d params=%+v", w.Code, store.params)
			}
		})
	}
}

func TestAdminLegalBodyBrowserBoundary(t *testing.T) {
	s := &Server{cfg: config.Config{PortalOrigin: testPortalOrigin}}
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid", `{"reason":"reason"}`, true},
		{"unknown", `{"reason":"reason","user_id":"not-an-alias"}`, false},
		{"duplicate", `{"reason":"first","reason":"second"}`, false},
		{"escaped duplicate", `{"reason":"first","\u0072eason":"second"}`, false},
		{"nested duplicate", `{"reason":{"nested":1,"nested":2}}`, false},
		{"trailing object", `{"reason":"reason"} {}`, false},
		{"trailing scalar", `{"reason":"reason"} true`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"UTF8", "{\"reason\":\"\xff\"}", false},
		{"exact body bound", `{"reason":"` + strings.Repeat("x", 32*1024-len(`{"reason":""}`)) + `"}`, true},
		{"over body bound", `{"reason":"` + strings.Repeat("x", 32*1024-len(`{"reason":""}`)+1) + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/legal-holds", strings.NewReader(tc.body))
			r.Header.Set("Origin", testPortalOrigin)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			var body struct {
				Reason string `json:"reason"`
			}
			valid := s.browserRequestAllowed(w, r) && decodeLegalBody(w, r, &body) == nil
			if valid != tc.valid {
				t.Fatalf("legal browser/body boundary accepted=%v want=%v", valid, tc.valid)
			}
		})
	}
}

func TestAdminLegalWriteRoutesRejectEvenBareQuery(t *testing.T) {
	s := &Server{}
	for _, suffix := range []string{"?", "?reason=private", "?account_ref=", "?%zz=x"} {
		for _, path := range []string{"/legal-holds", "/preservation-requests", "/legal-inquiry/lookup"} {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/admin"+path+suffix, strings.NewReader(`{}`))
			var body adminApplyLegalHoldRequest
			if err := decodeLegalBody(httptest.NewRecorder(), r, &body); err == nil {
				t.Fatalf("body route accepted query delimiter: %s", path+suffix)
			}
		}
		r := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/legal-holds/"+uuid.NewString()+suffix, nil)
		route := chi.NewRouteContext()
		route.URLParams.Add("hold_id", uuid.NewString())
		ctx := context.WithValue(rbac.WithActor(r.Context(), uuid.New()), chi.RouteCtxKey, route)
		w := httptest.NewRecorder()
		s.handleAdminReleaseLegalHold().ServeHTTP(w, r.WithContext(ctx))
		if w.Code != http.StatusBadRequest || w.Body.String() != "{\"error\":\"invalid_request\"}\n" {
			t.Fatalf("release accepted a query delimiter: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestAdminLegalRequestKeyIsSingleNonzeroUUID(t *testing.T) {
	key := uuid.New()
	for _, values := range [][]string{nil, {""}, {"not-a-uuid"}, {uuid.Nil.String()}, {key.String(), key.String()}, {key.String() + "," + uuid.NewString()}} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/legal-holds", nil)
		for _, value := range values {
			r.Header.Add("Idempotency-Key", value)
		}
		if _, err := legalRequestKey(r); err == nil {
			t.Fatal("accepted missing, duplicate, malformed, or zero operation key")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/legal-holds", nil)
	r.Header.Set("Idempotency-Key", key.String())
	if actual, err := legalRequestKey(r); err != nil || actual != key {
		t.Fatalf("valid operation UUID changed: %v", err)
	}
}
