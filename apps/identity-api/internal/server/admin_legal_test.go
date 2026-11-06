package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalreport"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalworkflow"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
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

func TestAdminLegalDecoderExactFieldsAndTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		dst  func() any
	}{
		{"hold", `{"account_ref":"account","reason":"reason","requesting_authority":"court","legal_basis":"order","review_at":""}`, func() any { return &adminApplyLegalHoldRequest{} }},
		{"preservation", `{"account_ref":"account","reason":"reason","requesting_authority":"court","expires_at":""}`, func() any { return &adminPreservationRequest{} }},
		{"inquiry", `{"identifier_type":"email","identifier":"private@example.test","requesting_authority":"court","case_reference":"case","purpose":"reason","start_time":"start","end_time":"end","limit":1,"cursor":"","fields":["client_ip"]}`, func() any { return &adminLegalInquiryRequest{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decode := func(body string) error {
				r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
				return decodeLegalBody(httptest.NewRecorder(), r, tc.dst())
			}
			if err := decode(tc.body); err != nil {
				t.Fatal("valid legal wire types rejected")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &fields); err != nil {
				t.Fatal(err)
			}
			for name, value := range fields {
				for _, invalid := range []string{"null", "true", `{}`, `[]`, `1`, `"1"`, `[null]`} {
					if (name == "limit" && invalid == "1") || (value[0] == '"' && invalid == `"1"`) || (name == "fields" && invalid == `[]`) {
						continue
					}
					body := strings.Replace(tc.body, `"`+name+`":`+string(value), `"`+name+`":`+invalid, 1)
					if decode(body) == nil {
						t.Fatalf("accepted invalid type for %s: %s", name, invalid)
					}
				}
				for _, body := range []string{
					strings.Replace(tc.body, `"`+name+`":`, `"`+strings.ToUpper(name)+`":`, 1),
					strings.TrimSuffix(tc.body, "}") + `,"` + name + `":` + string(value) + `}`,
					strings.TrimSuffix(tc.body, "}") + `,"` + strings.ToUpper(name) + `":` + string(value) + `}`,
				} {
					if decode(body) == nil {
						t.Fatalf("accepted alias/duplicate field %s", name)
					}
				}
			}
			for _, body := range []string{`null`, `[]`, `{}`, tc.body + `{}`, strings.TrimSuffix(tc.body, "}") + `,"unknown":"secret"}`} {
				// Required-field semantics remain the service's responsibility.
				if body != `{}` && decode(body) == nil {
					t.Fatal("accepted non-object, trailing, or unknown legal JSON")
				}
			}
		})
	}
	for _, body := range []string{`{"reason":"one","\u0072eason":"two"}`, `{"reason":"one","reason":"one"}`, `{"reason":null}`} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if decodeLegalBody(httptest.NewRecorder(), r, &adminApplyLegalHoldRequest{}) == nil {
			t.Fatal("standalone decoder accepted duplicate or null string")
		}
	}
}

func TestAdminLegalDecoderPreservesWorkflowUUIDTimeAndNullableTypes(t *testing.T) {
	for _, request := range []any{
		&legalworkflow.CreateRequest{ReceivedAt: time.Now().UTC(), SubjectIDs: []uuid.UUID{uuid.New()}, Content: legalworkflow.Content{AuthorityReference: "court"}},
		&legalreport.ApproveRequest{PolicyVersion: uuid.New(), Digest: "digest"},
	} {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(raw)))
		if err := decodeLegalBody(httptest.NewRecorder(), r, request); err != nil {
			t.Fatal("exact decoder rejected existing UUID/time/nullable workflow wire types")
		}
	}
	for _, body := range []string{
		`{"policy_version":null}`, `{"policy_version":[1,2]}`,
		`{"content":{"AuthorityReference":"court"}}`, `{"content":{"authority_reference":null}}`,
	} {
		var dst any = &legalworkflow.CreateRequest{}
		if strings.Contains(body, "policy_version") {
			dst = &legalreport.ApproveRequest{}
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if decodeLegalBody(httptest.NewRecorder(), r, dst) == nil {
			t.Fatal("exact decoder accepted invalid UUID or nested field/type alias")
		}
	}
}

type legalPreflightBody struct {
	reader io.Reader
	read   int
	closed bool
}

func (b *legalPreflightBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *legalPreflightBody) Close() error { b.closed = true; return nil }

type legalInterruptedReader struct{}

func (legalInterruptedReader) Read(p []byte) (int, error) {
	return copy(p, `{"reason":"sensitive-abort`), errors.New("sensitive-abort-error")
}

type legalPreflightPermission struct{ allowed bool }

func (p legalPreflightPermission) UserHasPermission(context.Context, db.UserHasPermissionParams) (bool, error) {
	return p.allowed, nil
}

func TestAdminLegalPreflightBeforeStepUpConsumption(t *testing.T) {
	actor := uuid.New()
	steps := newStepUpServiceForUser(t, actor)
	guard, err := stepup.NewRequireStepUp(steps, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: config.Config{PortalOrigin: testPortalOrigin}}
	exact := `{"reason":"` + strings.Repeat("x", legalBodyLimit-len(`{"reason":""}`)) + `"}`
	for _, tc := range []struct {
		name, method, query, key  string
		body                      io.Reader
		length                    int64
		permission, authenticated bool
		status                    int
	}{
		{"declared oversize", "POST", "", "", strings.NewReader(exact + " "), legalBodyLimit + 1, true, true, 413},
		{"chunked oversize", "POST", "", "", strings.NewReader(exact + strings.Repeat(" ", legalBodyLimit)), -1, true, true, 413},
		{"exact chunked", "POST", "", "", strings.NewReader(exact), -1, true, true, 204},
		{"interrupted", "POST", "", "", legalInterruptedReader{}, -1, true, true, 400},
		{"bare query", "POST", "?", "", strings.NewReader(`{}`), 2, true, true, 400},
		{"private query", "POST", "?reason=sensitive-query", "", strings.NewReader(`{}`), 2, true, true, 400},
		{"release body", "DELETE", "", "", strings.NewReader(`{}`), 2, true, true, 400},
		{"release whitespace", "DELETE", "", "", strings.NewReader(" "), -1, true, true, 400},
		{"release key", "DELETE", "", uuid.NewString(), strings.NewReader(""), -1, true, true, 400},
		{"bodyless keyless release", "DELETE", "", "", strings.NewReader(""), -1, true, true, 204},
		{"permission denial", "POST", "", "", strings.NewReader(exact + " "), -1, false, true, 403},
		{"session denial", "POST", "", "", strings.NewReader(exact + " "), -1, true, false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := session.Session{ID: "legal-preflight", Kind: session.KindAuthenticated, UserID: actor.String()}
			grant, _, err := steps.Mint(stepup.MintParams{UserID: current.UserID, SessionID: current.ID, AMR: []string{"otp"}})
			if err != nil {
				t.Fatal(err)
			}
			permission, err := rbac.NewRequirePermission(legalPreflightPermission{tc.permission}, permLegalHoldsWrite, nil)
			if err != nil {
				t.Fatal(err)
			}
			body := &legalPreflightBody{reader: tc.body}
			r := httptest.NewRequest(tc.method, "/api/v1/admin/legal-holds"+tc.query, nil)
			r.Body, r.ContentLength = body, tc.length
			r.Header.Set("Origin", testPortalOrigin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(stepup.HeaderStepUpAuth, grant)
			if tc.key != "" {
				r.Header.Set("Idempotency-Key", tc.key)
			}
			if tc.authenticated {
				r = r.WithContext(session.WithSession(r.Context(), current))
			}
			calls := 0
			next := permission.Handler(s.legalBodyPreflight(guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				data, err := io.ReadAll(r.Body)
				if err != nil || (tc.method == "POST" && string(data) != exact) {
					t.Fatal("preflight did not preserve the exact bounded body")
				}
				w.WriteHeader(http.StatusNoContent)
			}))))
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, ok := session.FromContext(r.Context()); !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status || body.read > legalBodyLimit+1 || (tc.status != 204 && calls != 0) {
				t.Fatalf("boundary status=%d want=%d read=%d calls=%d", w.Code, tc.status, body.read, calls)
			}
			if (!tc.permission || !tc.authenticated || tc.query != "" || tc.key != "" || tc.length > legalBodyLimit) && body.read != 0 {
				t.Fatal("read body before session/permission/header preflight")
			}
			if body.read > 0 && !body.closed {
				t.Fatal("preflight did not close source body")
			}
			_, err = steps.Validate(context.Background(), grant, current)
			if (tc.status == 204 && !errors.Is(err, stepup.ErrGrantConsumed)) || (tc.status != 204 && err != nil) {
				t.Fatalf("preflight changed one-use authority: %v", err)
			}
		})
	}
}
