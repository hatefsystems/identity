package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hatefsystems/identity/apps/identity-api/internal/config"
)

func TestAdminBodyBoundary(t *testing.T) {
	for _, body := range []string{`{"value":"ok"} {"value":"second"}`, `{"unknown":true}`, `{"value":"` + strings.Repeat("a", 64*1024) + `"}`} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var value struct {
			Value string `json:"value"`
		}
		if err := decodeJSONBody(r, &value); err == nil {
			t.Fatal("accepted invalid body")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"ok"}`))
	var value struct {
		Value string `json:"value"`
	}
	if err := decodeJSONBody(r, &value); err != nil || value.Value != "ok" {
		t.Fatalf("valid body: %v", err)
	}
}

func TestAdminResponseBufferDoesNotStream(t *testing.T) {
	w := &adminResponseBuffer{header: make(http.Header)}
	if _, ok := any(w).(http.Flusher); ok {
		t.Fatal("audit buffer permits streaming")
	}
	if _, err := w.Write(bytes.Repeat([]byte("x"), adminResponseLimit+1)); err == nil || !w.overflow || w.body.Len() != 0 {
		t.Fatal("response cap not enforced")
	}
}

func TestAdminOriginPolicy(t *testing.T) {
	s := &Server{cfg: config.Config{Admin: config.AdminConfig{AllowedOrigins: []string{"https://identity.example"}}}}
	for _, tc := range []struct {
		method, origin, site string
		want                 bool
	}{
		{http.MethodGet, "", "", true}, {http.MethodPost, "", "", false},
		{http.MethodPost, "null", "", false}, {http.MethodPatch, "https://identity.example", "same-origin", true},
		{http.MethodDelete, "https://identity.example", "cross-site", false}, {http.MethodPost, "https://attacker.example", "", false},
	} {
		r := httptest.NewRequest(tc.method, "https://identity.example/api/v1/admin/users", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		if got := s.adminOriginAllowed(r); got != tc.want {
			t.Errorf("%s %s: got %v", tc.method, tc.origin, got)
		}
	}
}

func TestEnabledAdminCannotReportReadyWithoutGates(t *testing.T) {
	s := New(config.Config{Admin: config.AdminConfig{Enabled: true}}, nil, Deps{})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing admin dependencies reported ready: %d", w.Code)
	}
}
