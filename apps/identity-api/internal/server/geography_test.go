package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
	"github.com/hatefsystems/identity/apps/identity-api/internal/geography"
)

type geographyFakeReader struct {
	calls        int
	endpoint     string
	input        geography.ListInput
	id, revision string
	deadline     time.Duration
	err          error
	wait         bool
}

func (f *geographyFakeReader) observe(ctx context.Context) error {
	f.calls++
	deadline, ok := ctx.Deadline()
	if ok {
		f.deadline = time.Until(deadline)
	}
	if f.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.err
}

func (f *geographyFakeReader) Provinces(ctx context.Context, input geography.ListInput) (geography.Page, error) {
	f.endpoint, f.input = "provinces", input
	return geography.Page{CatalogRevision: "9223372036854775807", Items: []geography.Place{}, NextCursor: ""}, f.observe(ctx)
}

func (f *geographyFakeReader) Localities(ctx context.Context, input geography.ListInput) (geography.Page, error) {
	f.endpoint, f.input = "localities", input
	return geography.Page{CatalogRevision: "9223372036854775807", Items: []geography.Place{}, NextCursor: ""}, f.observe(ctx)
}

func (f *geographyFakeReader) Lookup(ctx context.Context, id, revision string) (geography.Place, error) {
	f.endpoint, f.id, f.revision = "lookup", id, revision
	return geography.Place{
		ID: id, Label: "Synthetic locality", Type: geography.Type{ID: "7", Label: "Synthetic type"},
		Province:  geography.Summary{ID: "9007199254740993", Label: "Synthetic province", TypeID: "2", TypeLabel: "Synthetic province type"},
		Ancestors: []geography.Summary{}, Retired: true, Selectable: false, CatalogRevision: "9223372036854775807",
	}, f.observe(ctx)
}

type geographyFakeLimiter struct {
	keys     []string
	limits   []int
	contexts []context.Context
	counts   map[string]int
	deadline time.Duration
	err      error
	errCall  int
	denyCall int
	wait     bool
}

func (f *geographyFakeLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	f.keys = append(f.keys, key)
	f.limits = append(f.limits, limit)
	f.contexts = append(f.contexts, ctx)
	if deadline, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(deadline)
	}
	if f.wait {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if f.err != nil {
		return false, f.err
	}
	if f.errCall == len(f.keys) {
		return false, errors.New("limiter unavailable")
	}
	if window != time.Minute {
		return false, errors.New("unexpected window")
	}
	if f.denyCall == len(f.keys) {
		return false, nil
	}
	if f.counts == nil {
		f.counts = make(map[string]int)
	}
	if f.counts[key] >= limit {
		return false, nil
	}
	f.counts[key]++
	return true, nil
}

func newGeographyTestServer() (*Server, *geographyFakeReader, *geographyFakeLimiter) {
	reader, limiter := &geographyFakeReader{}, &geographyFakeLimiter{}
	s := New(config.Config{Environment: "development"}, slog.New(slog.DiscardHandler), Deps{Geography: reader, GeographyLimiter: limiter})
	return s, reader, limiter
}

func geographyRequest(t *testing.T, s *Server, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	if request.RemoteAddr == "" {
		request.RemoteAddr = "203.0.113.1:1234"
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, request)
	for name, want := range map[string]string{
		"Cache-Control": "private, no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff", "Content-Type": "application/json; charset=utf-8",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"Set-Cookie", "DPoP-Nonce", "WWW-Authenticate", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("anonymous read introduced %s", name)
		}
	}
	return rec
}

func TestGeographyAnonymousReadsAndExactWireIDs(t *testing.T) {
	for _, tc := range []struct {
		path, endpoint, query, province, id, revision string
		limit                                         int
	}{
		{path: "/api/v1/geography/provinces?country=IR", endpoint: "provinces", limit: 20},
		{path: "/api/v1/geography/provinces?country=IR&q=%25_%5C&limit=50&cursor=opaque", endpoint: "provinces", query: "%_\\", limit: 50},
		{path: "/api/v1/geography/localities?country=IR&province_id=9223372036854775807&q=" + url.QueryEscape("\u064a\u0643\u00a0\u200c"), endpoint: "localities", province: "9223372036854775807", query: "\u064a\u0643\u00a0\u200c", limit: 20},
		{path: "/api/v1/geography/places/9223372036854775807?country=IR&revision=9007199254740993", endpoint: "lookup", id: "9223372036854775807", revision: "9007199254740993"},
		{path: "/api/v1/geography/places/9007199254740993?country=IR", endpoint: "lookup", id: "9007199254740993"},
	} {
		t.Run(tc.endpoint+tc.path, func(t *testing.T) {
			s, reader, limiter := newGeographyTestServer()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Origin", "https://other.example.test")
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			rec := geographyRequest(t, s, req)
			if rec.Code != http.StatusOK || reader.calls != 1 || reader.endpoint != tc.endpoint || reader.deadline <= 0 || reader.deadline > time.Second {
				t.Fatalf("anonymous bounded read: %d %s, %+v", rec.Code, rec.Body.String(), reader)
			}
			if len(limiter.keys) != 2 || limiter.limits[0] != 120 || limiter.limits[1] != 600 || limiter.deadline <= 0 || limiter.deadline > 250*time.Millisecond {
				t.Fatalf("read bypassed independent bounded budgets: %+v", limiter)
			}
			if limiter.contexts[0] != limiter.contexts[1] || limiter.contexts[0].Err() == nil {
				t.Fatal("limiter dimensions did not share one bounded, canceled admission context")
			}
			if tc.endpoint == "lookup" {
				var place geography.Place
				if err := json.Unmarshal(rec.Body.Bytes(), &place); err != nil {
					t.Fatal(err)
				}
				if reader.id != tc.id || reader.revision != tc.revision || place.ID != tc.id || place.CatalogRevision != "9223372036854775807" || place.Province.ID != "9007199254740993" || !place.Retired || place.Selectable {
					t.Fatalf("lookup altered exact IDs or eligibility: %s", rec.Body.String())
				}
			} else if reader.input.Country != "IR" || reader.input.ProvinceID != tc.province || reader.input.Query != tc.query || reader.input.Limit != tc.limit || !strings.Contains(rec.Body.String(), `"items":[]`) {
				t.Fatalf("list admission altered service authority: %+v %s", reader.input, rec.Body.String())
			}
		})
	}
}

func TestGeographyStrictQueryAndIDAdmission(t *testing.T) {
	paths := []string{
		"/provinces", "/provinces?", "/provinces?country=", "/provinces?country=ir", "/provinces?country=US",
		"/provinces?country=IR&country=IR", "/provinces?country=IR&%63ountry=IR", "/provinces?country=IR&unexpected=x",
		"/provinces?country=IR&province_id=1", "/provinces?country=IR&revision=1", "/provinces?country=IR&q=x&q=y",
		"/provinces?country=IR&q=%zz", "/provinces?country=IR;q=x", "/provinces?country=IR&q=%ff", "/provinces?country=IR&q=%00",
		"/provinces?country=IR&", "/provinces?country=IR&&q=x", "/provinces?country=IR&q", "/provinces?country=IR&=x",
		"/provinces?country=IR&limit=", "/provinces?country=IR&limit=0", "/provinces?country=IR&limit=51", "/provinces?country=IR&limit=01",
		"/provinces?country=IR&limit=%2B1", "/provinces?country=IR&limit=1.0", "/provinces?country=IR&limit=9223372036854775808",
		"/provinces?country=IR&q=" + strings.Repeat("a", 81),
		"/provinces?country=IR&q=" + url.QueryEscape(strings.Repeat("\U0001f600", 65)),
		"/provinces?country=IR&cursor=" + strings.Repeat("x", 2049),
		"/provinces?country=IR&cursor=" + strings.Repeat("%78", 3000),
		"/localities?country=IR", "/localities?country=IR&province_id=", "/localities?country=IR&province_id=0",
		"/localities?country=IR&province_id=01", "/localities?country=IR&province_id=9223372036854775808",
		"/places/1?country=IR&revision=", "/places/1?country=IR&revision=0", "/places/1?country=IR&revision=1&revision=1",
		"/places/1?country=IR&q=x", "/places/1?country=IR&cursor=x", "/places/1?revision=1",
	}
	for _, raw := range []string{"0", "-1", "+1", "01", "1.0", "1e3", "9223372036854775808", "\u06f1", "123456789012345678901"} {
		paths = append(paths, "/places/"+url.PathEscape(raw)+"?country=IR", "/localities?country=IR&province_id="+url.QueryEscape(raw), "/places/1?country=IR&revision="+url.QueryEscape(raw))
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			s, reader, limiter := newGeographyTestServer()
			rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, "/api/v1/geography"+path, nil))
			if rec.Code != http.StatusBadRequest || reader.calls != 0 || len(limiter.keys) != 2 || !strings.Contains(rec.Body.String(), `"error":"invalid_request"`) {
				t.Fatalf("invalid query reached catalog or escaped admission: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.ContentLength = -1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
	} {
		s, reader, _ := newGeographyTestServer()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR", nil)
		mutate(req)
		if rec := geographyRequest(t, s, req); rec.Code != http.StatusBadRequest || reader.calls != 0 {
			t.Fatalf("GET body reached service: %d", rec.Code)
		}
	}
}

func TestGeographyInclusiveInputBoundsAndTighterConfiguration(t *testing.T) {
	s, reader, _ := newGeographyTestServer()
	query := strings.Repeat("\U0001f600", 64)
	path := "/api/v1/geography/provinces?country=IR&q=" + url.QueryEscape(query) + "&cursor=" + strings.Repeat("x", 2048) + "&limit=1"
	if rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, path, nil)); rec.Code != http.StatusOK || reader.input.Query != query || len(reader.input.Cursor) != 2048 || reader.input.Limit != 1 {
		t.Fatalf("inclusive byte bounds rejected: %d", rec.Code)
	}
	path = "/api/v1/geography/provinces?country=IR&q=" + strings.Repeat("a", 80)
	if rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, path, nil)); rec.Code != http.StatusOK {
		t.Fatalf("inclusive rune bound rejected: %d", rec.Code)
	}
	s.cfg.Geography.PageSizeDefault, s.cfg.Geography.PageSizeMax = 10, 25
	if rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR", nil)); rec.Code != http.StatusOK || reader.input.Limit != 10 {
		t.Fatalf("configured default ignored: %d %+v", rec.Code, reader.input)
	}
	before := reader.calls
	if rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR&limit=26", nil)); rec.Code != http.StatusBadRequest || reader.calls != before {
		t.Fatalf("configured maximum ignored: %d", rec.Code)
	}
}

func TestGeographyMapsServiceErrorsWithoutLeakingDetails(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{geography.ErrInvalid, 400, "invalid_request"}, {geography.ErrNotFound, 404, "not_found"},
		{geography.ErrCatalogChanged, 409, "catalog_changed"}, {geography.ErrUnavailable, 503, "temporarily_unavailable"},
		{context.DeadlineExceeded, 503, "temporarily_unavailable"}, {context.Canceled, 503, "temporarily_unavailable"},
		{errors.New("private database diagnostic"), 503, "temporarily_unavailable"},
	} {
		for _, path := range []string{"provinces?country=IR", "localities?country=IR&province_id=1", "places/1?country=IR"} {
			t.Run(tc.code+path, func(t *testing.T) {
				s, reader, _ := newGeographyTestServer()
				reader.err = fmt.Errorf("hidden context: %w", tc.err)
				rec := geographyRequest(t, s, httptest.NewRequest(http.MethodGet, "/api/v1/geography/"+path, nil))
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if rec.Code != tc.status || body["error"] != tc.code || len(body) != 1 {
					t.Fatalf("typed error mapping: %d %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestGeographyDependenciesAndTimeoutsAlwaysFailClosed(t *testing.T) {
	for _, mode := range []string{"development", "test", "production"} {
		for _, failure := range []string{"missing-service", "missing-limiter", "limiter-error", "subnet-error", "ip-quota", "subnet-quota", "limiter-timeout", "database-timeout", "invalid-config", "invalid-peer"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				s, reader, limiter := newGeographyTestServer()
				s.cfg.Environment = mode
				req := httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR", nil)
				switch failure {
				case "missing-service":
					s.deps.Geography = nil
				case "missing-limiter":
					s.deps.GeographyLimiter = nil
				case "limiter-error":
					limiter.err = errors.New("Redis unavailable")
				case "subnet-error":
					limiter.errCall = 2
				case "ip-quota":
					limiter.denyCall = 1
				case "subnet-quota":
					limiter.denyCall = 2
				case "limiter-timeout":
					limiter.wait = true
					s.cfg.Geography.LimiterTimeout = 5 * time.Millisecond
				case "database-timeout":
					reader.wait = true
					s.cfg.Geography.QueryTimeout = 5 * time.Millisecond
				case "invalid-config":
					s.cfg.Geography.PerIPPerMinute = 121
				case "invalid-peer":
					req.RemoteAddr = "not-an-address"
				}
				rec := geographyRequest(t, s, req)
				want := http.StatusServiceUnavailable
				if failure == "ip-quota" || failure == "subnet-quota" {
					want = http.StatusTooManyRequests
				}
				if rec.Code != want || failure != "database-timeout" && reader.calls != 0 {
					t.Fatalf("unavailable authority reached catalog: %d %s, calls=%d", rec.Code, rec.Body.String(), reader.calls)
				}
				if want == http.StatusTooManyRequests && rec.Header().Get("Retry-After") != "60" {
					t.Fatal("quota rejection omitted Retry-After")
				}
			})
		}
	}
}

func TestGeographyRoutesAreGETOnlyWithoutBrowserBoundaryExceptions(t *testing.T) {
	s, reader, limiter := newGeographyTestServer()
	s.cfg.PortalOrigin = "https://identity.example.test"
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/v1/geography/provinces?country=IR", nil)
		req.Header.Set("Origin", s.cfg.PortalOrigin)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Cache-Control") != "private, no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Access-Control-Allow-Origin") != "" || reader.calls != 0 || len(limiter.keys) != 0 {
			t.Fatalf("non-GET geography route exposed: %s %d", method, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geography/provinces?country=IR", nil)
	req.Header.Set("Origin", "https://other.example.test")
	if rec := geographyRequest(t, s, req); rec.Code != http.StatusForbidden || reader.calls != 0 {
		t.Fatalf("geography bypassed existing unsafe-method Origin policy: %d", rec.Code)
	}
}

func TestGeographyRequestCancellationDoesNotReachCatalog(t *testing.T) {
	s, reader, _ := newGeographyTestServer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/geography/provinces?country=IR", nil).WithContext(ctx)
	if rec := geographyRequest(t, s, req); rec.Code != http.StatusServiceUnavailable || reader.calls != 0 {
		t.Fatalf("canceled request reached catalog: %d", rec.Code)
	}
}

func TestGeographyTrustedClientAndSubnetBudgetsAcrossRoutes(t *testing.T) {
	s, reader, limiter := newGeographyTestServer()
	// Rebuild middleware after configuring the immediate proxy trust boundary.
	s = New(config.Config{Environment: "development", TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, slog.New(slog.DiscardHandler), s.deps)
	request := func(path, remote, forwarded string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/geography/"+path, nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("X-Real-IP", "192.0.2.200")
		return geographyRequest(t, s, req)
	}
	key := func(dimension, value string) string {
		digest := sha256.Sum256([]byte(value))
		return "rate:geography:" + dimension + ":v1:" + hex.EncodeToString(digest[:])
	}
	for range 120 {
		if rec := request("provinces?country=IR", "10.0.0.1:1234", "192.0.2.1, 203.0.113.1, 10.0.0.2"); rec.Code != http.StatusOK {
			t.Fatalf("IP budget denied early: %d", rec.Code)
		}
	}
	if limiter.counts[key("ip", "203.0.113.1")] != 120 || limiter.counts[key("subnet", "203.0.113.0/24")] != 120 {
		t.Fatalf("trusted chain did not select closest untrusted hop: %+v", limiter.counts)
	}
	before := reader.calls
	if rec := request("places/1?country=IR", "203.0.113.1:4321", "192.0.2.99"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" || reader.calls != before {
		t.Fatalf("spoofed forwarding reset shared IP budget: %d", rec.Code)
	}
	for ip := 2; ip <= 5; ip++ {
		for range 120 {
			if rec := request("localities?country=IR&province_id=1", fmt.Sprintf("203.0.113.%d:1234", ip), "192.0.2.99"); rec.Code != http.StatusOK {
				t.Fatalf("subnet budget denied early: %d", rec.Code)
			}
		}
	}
	before = reader.calls
	if rec := request("provinces?country=IR", "203.0.113.6:1234", "192.0.2.99"); rec.Code != http.StatusTooManyRequests || reader.calls != before || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("rotating IP escaped shared subnet budget: %d", rec.Code)
	}
	if rec := request("places/1?country=IR", "203.0.114.1:1234", "192.0.2.99"); rec.Code != http.StatusOK {
		t.Fatalf("separate subnet shares wrong budget: %d", rec.Code)
	}
	for _, addr := range []string{"[2001:db8:1::1]:1234", "[2001:db8:1:ffff::2]:4321"} {
		if rec := request("provinces?country=IR", addr, "192.0.2.99"); rec.Code != http.StatusOK {
			t.Fatalf("IPv6 read not admitted: %d", rec.Code)
		}
	}
	if limiter.counts[key("subnet", "2001:db8:1::/48")] != 2 {
		t.Fatal("IPv6 grouping is not /48")
	}
	if rec := request("provinces?country=IR", "10.0.0.1:1234", "malformed, 10.0.0.2"); rec.Code != http.StatusOK || limiter.counts[key("ip", "10.0.0.1")] != 1 {
		t.Fatalf("malformed forwarded chain did not fall back to peer: %d", rec.Code)
	}
}
