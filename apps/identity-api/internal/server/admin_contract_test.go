package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/legalhold"
	"github.com/hatefsystems/identity/apps/identity-api/internal/rbac"
)

func adminStatusBody(t *testing.T, status, reason string, revision int64) string {
	t.Helper()
	body, err := json.Marshal(adminUpdateStatusRequest{Status: status, Reason: reason, ExpectedRevision: strconv.FormatInt(revision, 10)})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAdminStatusBodyRequiresExactRevisionAndReason(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`,
		`{"status":"banned","reason":"valid"}`,
		`{"status":"banned","reason":"valid","expected_revision":null}`,
		`{"status":"banned","reason":"valid","expected_revision":1}`,
		`{"status":"banned","reason":"valid","expected_revision":"01"}`,
		`{"status":"banned","reason":"valid","expected_revision":"+1"}`,
		`{"status":"banned","reason":"valid","expected_revision":"-1"}`,
		`{"status":"banned","reason":"valid","expected_revision":"1.0"}`,
		`{"status":"banned","reason":"valid","expected_revision":"1e1"}`,
		`{"status":"banned","reason":"valid","expected_revision":" 1"}`,
		`{"status":"banned","reason":"valid","expected_revision":"1\n"}`,
		`{"status":"banned","reason":"valid","expected_revision":"9223372036854775808"}`,
		`{"status":"banned","reason":"valid","expected_revision":"0","expected_revision":"1"}`,
		`{"status":"banned","status":"active","reason":"valid","expected_revision":"0"}`,
		`{"status":"banned","reason":"valid","reason":"other","expected_revision":"0"}`,
		`{"status":"banned","reason":"valid","expected_revision":"0","actor":"ignored"}`,
		`{"Status":"banned","reason":"valid","expected_revision":"0"}`,
		`{"status":"banned","reason":"valid","expected_revision":"0"} {}`,
		`{"status":null,"reason":"valid","expected_revision":"0"}`,
		`{"status":"banned","reason":null,"expected_revision":"0"}`,
		`{"status":"banned","expected_revision":"0"}`,
		`{"status":"banned","reason":" \t\n ","expected_revision":"0"}`,
		`{"status":"banned","reason":"\ud800","expected_revision":"0"}`,
		adminStatusBody(t, "banned", strings.Repeat("\u00e9", 1001), 0),
		adminStatusBody(t, "banned", strings.Repeat("a", 64*1024), 0),
		"{\"status\":\"banned\",\"reason\":\"\xff\",\"expected_revision\":\"0\"}",
	} {
		request := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(body))
		if _, _, err := decodeAdminStatusUpdate(request); err == nil {
			t.Fatalf("accepted malformed status body of %d bytes", len(body))
		}
	}
	for _, revision := range []int64{0, 1, 9007199254740993, math.MaxInt64} {
		reason := strings.Repeat("\u00e9", 1000)
		r := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(adminStatusBody(t, "suspended", "  "+reason+"\n", revision)))
		body, actual, err := decodeAdminStatusUpdate(r)
		if err != nil || actual != revision || body.Reason != reason || body.Status != "suspended" {
			t.Fatalf("valid status body rejected or changed at revision %d: %v", revision, err)
		}
	}
}

func TestAdminQueryKeysRejectDuplicatesUnknownsAndMalformedEncoding(t *testing.T) {
	for _, query := range []string{
		"limit=1&limit=2", "limit=1&%6cimit=2", "email=private%40example.test", "offset=0&unknown=x", "limit=%zz", "limit=1;offset=0",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.URL.RawQuery = query
		if validAdminQuery(r, "limit", "offset", "status") {
			t.Fatalf("accepted ambiguous query %q", query)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/?limit=20&offset=0&status=active", nil)
	if !validAdminQuery(r, "limit", "offset", "status") || validAdminQuery(r) {
		t.Fatal("explicit query allowlist not enforced")
	}
}

func TestAdminCoordinatesEncodeOnlyAsExactDecimalStrings(t *testing.T) {
	last := int64(math.MaxInt64)
	for _, value := range []any{
		adminUserResponse{LifecycleRevision: last},
		adminAuditLogResponse{Seq: last},
		adminLedgerEventResponse{Seq: last},
		legalhold.Coverage{ThroughSeq: last},
		adminChainVerifyResponse{AfterSeq: 9007199254740993, ThroughSeq: last, FirstSeq: &last, LastSeq: &last, BrokenAtSeq: &last, NextAfterSeq: &last},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"lifecycle_revision", "seq", "after_seq", "through_seq", "first_seq", "last_seq", "broken_at_seq", "next_after_seq"} {
			if actual, exists := fields[name]; exists && actual != nil {
				text, ok := actual.(string)
				if !ok || (text != "9223372036854775807" && text != "9007199254740993") {
					t.Fatalf("inexact coordinate %s: %v", name, actual)
				}
			}
		}
	}
	var account adminUserResponse
	if json.Unmarshal([]byte(`{"lifecycle_revision":1}`), &account) == nil {
		t.Fatal("numeric account projection fallback accepted")
	}
	var row adminAuditLogResponse
	if json.Unmarshal([]byte(`{"seq":1}`), &row) == nil {
		t.Fatal("numeric audit projection fallback accepted")
	}
	var legalRow adminLedgerEventResponse
	if json.Unmarshal([]byte(`{"seq":1}`), &legalRow) == nil {
		t.Fatal("numeric legal projection fallback accepted")
	}
	var coverage legalhold.Coverage
	if json.Unmarshal([]byte(`{"through_seq":1}`), &coverage) == nil {
		t.Fatal("numeric legal coverage fallback accepted")
	}
	encoded, err := json.Marshal(adminChainVerifyResponse{})
	if err != nil || !strings.Contains(string(encoded), `"after_seq":"0"`) || !strings.Contains(string(encoded), `"first_seq":null`) {
		t.Fatal("zero/null coordinate semantics changed")
	}
}

func TestAdminLegalCoordinatesPreserveSigned64BitPrecision(t *testing.T) {
	for _, seq := range []int64{0, 1, 9007199254740991, 9007199254740992, 9007199254740993, math.MaxInt64 - 1, math.MaxInt64} {
		t.Run(strconv.FormatInt(seq, 10), func(t *testing.T) {
			row := newAdminLedgerEvent(db.LookupLegalAttributionRow{Seq: seq}, nil)
			encoded, err := json.Marshal(struct {
				Item     adminLedgerEventResponse `json:"item"`
				Coverage legalhold.Coverage       `json:"coverage"`
			}{row, legalhold.Coverage{ThroughSeq: seq}})
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Item     map[string]json.RawMessage `json:"item"`
				Coverage map[string]json.RawMessage `json:"coverage"`
			}
			if err := json.Unmarshal(encoded, &result); err != nil {
				t.Fatal(err)
			}
			want := strconv.Quote(strconv.FormatInt(seq, 10))
			if string(result.Item["seq"]) != want || string(result.Coverage["through_seq"]) != want {
				t.Fatalf("legal coordinate lost precision: %s", encoded)
			}
		})
	}
}

type adminAuditPageStore struct {
	AdminStore
	page db.ListAuditLogsPageRow
	err  error
}

func (s adminAuditPageStore) ListAuditLogsPage(context.Context, db.ListAuditLogsPageParams) (db.ListAuditLogsPageRow, error) {
	return s.page, s.err
}

func TestAdminAuditQueryLogSanitizesSensitiveError(t *testing.T) {
	const sentinel = "sensitive-audit-query-account-narrative-sentinel"
	var logs bytes.Buffer
	s := New(config.Config{Admin: config.AdminConfig{PageSizeDefault: 1, PageSizeMax: 200, AuditMaxWindow: 24 * time.Hour}},
		slog.New(slog.NewJSONHandler(&logs, nil)), Deps{AdminStore: adminAuditPageStore{err: errors.New(sentinel)}})
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?start_time=2026-01-01T00:00:00Z&end_time=2026-01-02T00:00:00Z", nil)
	r = r.WithContext(rbac.WithActor(r.Context(), uuid.New()))
	w := httptest.NewRecorder()
	s.handleAdminListAuditLogs().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || strings.Contains(logs.String(), sentinel) || strings.Contains(w.Body.String(), sentinel) || !strings.Contains(logs.String(), `"category":"audit_query_failed"`) {
		t.Fatal("audit query failure did not emit only its fixed sanitized log category")
	}
}

func TestAdminAuditPageEncodesExactNextBeforeSeq(t *testing.T) {
	for _, seq := range []int64{0, 9007199254740993, math.MaxInt64} {
		t.Run(strconv.FormatInt(seq, 10), func(t *testing.T) {
			page := db.ListAuditLogsPageRow{Items: []byte(`[]`), NextBeforeSeq: seq}
			if seq != 0 {
				page.HasMore = true
				page.Items = []byte(`[{"seq":"` + strconv.FormatInt(seq, 10) + `"}]`)
			}
			s := New(config.Config{Admin: config.AdminConfig{
				PageSizeDefault: 1, PageSizeMax: 200, AuditMaxWindow: 24 * time.Hour,
			}}, nil, Deps{AdminStore: adminAuditPageStore{page: page}})
			r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit-logs?start_time=2026-01-01T00:00:00Z&end_time=2026-01-02T00:00:00Z", nil)
			r = r.WithContext(rbac.WithActor(r.Context(), uuid.New()))
			w := httptest.NewRecorder()
			s.handleAdminListAuditLogs().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("audit page status = %d: %s", w.Code, w.Body.String())
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 4 || string(fields["next_before_seq"]) != strconv.Quote(strconv.FormatInt(seq, 10)) || string(fields["limit"]) != "1" || string(fields["has_more"]) != strconv.FormatBool(page.HasMore) {
				t.Fatalf("audit pagination lost its exact string/numeric contract: %s", w.Body.String())
			}
			if seq == 0 && string(fields["items"]) != "[]" {
				t.Fatal("empty audit page changed its zero cursor or empty array sentinel")
			}
		})
	}
}
