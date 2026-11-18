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

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type privateHTTPFixture struct {
	snapshot      profile.PrivateSnapshot
	err           error
	changed       bool
	reads, writes int
	input         profile.PrivateUpdate
	sess          session.Session
}

func (f *privateHTTPFixture) Get(_ context.Context, sess session.Session) (profile.PrivateSnapshot, error) {
	f.reads++
	f.sess = sess
	return f.snapshot, f.err
}
func (f *privateHTTPFixture) Update(_ context.Context, sess session.Session, in profile.PrivateUpdate) (profile.PrivateUpdateResult, error) {
	f.writes++
	f.input = in
	f.sess = sess
	return profile.PrivateUpdateResult{Snapshot: f.snapshot, Changed: f.changed}, f.err
}

func privateHTTPSetup(t *testing.T) (*Server, *privateHTTPFixture, *profileAuditRecorder, session.Session) {
	t.Helper()
	s, _, recorder, sess := profileHandlerFixture(t)
	f := &privateHTTPFixture{snapshot: profile.PrivateSnapshot{LifecycleRevision: "9007199254740993"}}
	s.deps.PrivateProfile = f
	return s, f, recorder, sess
}

func TestPrivateHTTPExplicitMinimalSnapshotAndCoarseAudit(t *testing.T) {
	s, f, audit, sess := privateHTTPSetup(t)
	for _, initialized := range []bool{false, true} {
		if initialized {
			f.snapshot.PrivateData = &profile.PrivateData{GivenName: "\u0639\u0644\u06cc"}
			f.snapshot.Username = &username.ReadResult{Display: "\u0639\u0644\u06cc"}
		}
		w := httptest.NewRecorder()
		s.handlePrivateProfileGet().ServeHTTP(w, profileHandlerRequest(sess, http.MethodGet, ""))
		var body map[string]json.RawMessage
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 3 || string(body["lifecycle_revision"]) != `"9007199254740993"` || f.sess.ID != sess.ID {
			t.Fatal("private snapshot was expanded, unbound or imprecise")
		}
		if !initialized && (string(body["private_data"]) != "null" || string(body["username"]) != "null") {
			t.Fatal("missing private data/username was fabricated")
		}
		if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Referrer-Policy") != "no-referrer" || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("private response omitted privacy or minted a session")
		}
	}
	f.changed = true
	w := httptest.NewRecorder()
	s.handlePrivateProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, `{"expected_revision":"9007199254740993","gender":"male"}`))
	if w.Code != 200 || f.writes != 1 || len(audit.events) != 1 || f.input.ExpectedRevision != "9007199254740993" {
		t.Fatal("private edit did not preserve exact revision or coarse audit")
	}
	encoded, err := json.Marshal(audit.events[0].Payload)
	if err != nil || strings.Contains(string(encoded), "gender") || !strings.Contains(string(encoded), "private_profile") {
		t.Fatal("private edit audit disclosed individual fields")
	}
	f.changed = false
	w = httptest.NewRecorder()
	s.handlePrivateProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, `{"expected_revision":"9007199254740993","gender":"male"}`))
	if w.Code != 200 || len(audit.events) != 1 {
		t.Fatal("no-op invented private audit")
	}
}

func TestPrivateHTTPRejectsUnrelatedAndMalformedRequests(t *testing.T) {
	for _, body := range []string{
		`{"expected_revision":"0","username":"forged"}`, `{"expected_revision":"0","display_name":"forged"}`, `{"expected_revision":"0","email":"email@invalid"}`, `{"expected_revision":"0","mobile":"1"}`,
		`{"expected_revision":"0","gender":null}`, `{"expected_revision":0,"gender":"male"}`, `{"expected_revision":"0","gender":"male","gender":"female"}`,
		`{"expected_revision":"0","birthday":{"calendar":"gregorian","date":"2000-01-01","date":"2001-01-01"}}`,
		`{"expected_revision":"0","location":{"country":"IR","province_id":"1","locality_id":null}}`, strings.Repeat("x", 8193),
	} {
		s, f, _, sess := privateHTTPSetup(t)
		w := httptest.NewRecorder()
		s.handlePrivateProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, body))
		if w.Code != 400 || f.writes != 0 {
			t.Fatal("invalid private request reached storage")
		}
	}
	for _, mode := range []string{"query", "empty query", "body", "transfer", "media type"} {
		s, f, _, sess := privateHTTPSetup(t)
		r := profileHandlerRequest(sess, http.MethodGet, "")
		switch mode {
		case "query":
			r.URL.RawQuery = "id=" + uuid.NewString()
		case "empty query":
			r.URL.ForceQuery = true
		case "body":
			r = profileHandlerRequest(sess, http.MethodGet, `{}`)
		case "transfer":
			r.TransferEncoding = []string{"chunked"}
		case "media type":
			r = profileHandlerRequest(sess, http.MethodPatch, `{"expected_revision":"0","gender":"male"}`)
			r.Header.Set("Content-Type", "text/plain")
		}
		w := httptest.NewRecorder()
		if mode == "media type" {
			s.handlePrivateProfileUpdate().ServeHTTP(w, r)
		} else {
			s.handlePrivateProfileGet().ServeHTTP(w, r)
		}
		if w.Code != 400 || f.reads+f.writes != 0 {
			t.Fatal("caller query/body/media authority reached private service")
		}
	}
}

func TestPrivateHTTPAuthorityAndSanitizedErrors(t *testing.T) {
	for _, mode := range []string{"missing", "proof", "restricted", "expired", "conflict", "unreadable", "unavailable", "invalid name"} {
		s, f, _, sess := privateHTTPSetup(t)
		want := 401
		switch mode {
		case "restricted":
			sess.Kind = session.KindRecoveryEnrollment
		case "expired":
			sess.AbsoluteExpiry = time.Now().Add(-time.Second)
		case "conflict":
			f.err, want = profile.ErrConflict, 409
		case "unreadable":
			f.err, want = profile.ErrUnreadable, 503
		case "unavailable":
			f.err, want = errors.New("private SQL ciphertext diagnostic"), 503
		case "invalid name":
			f.err, want = profile.ErrInvalidPersonalName, 400
		}
		r := profileHandlerRequest(sess, http.MethodPatch, `{"expected_revision":"0","gender":"male"}`)
		if mode == "missing" {
			r = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/private-data", strings.NewReader(`{}`))
		}
		if mode == "proof" {
			r = r.WithContext(dpop.WithProof(r.Context(), &dpop.Proof{JKT: "foreign"}))
		}
		w := httptest.NewRecorder()
		s.handlePrivateProfileUpdate().ServeHTTP(w, r)
		if w.Code != want || strings.Contains(w.Body.String(), "ciphertext") || strings.Contains(w.Body.String(), "SQL") || strings.Contains(w.Body.String(), "private") {
			t.Fatal("private denial exposed diagnostic or wrong authority status")
		}
	}
}

func TestPrivateRoutesPreserveBrowserBoundary(t *testing.T) {
	for _, mode := range []string{"get", "patch", "no cookie", "no proof", "wrong intent", "wrong origin", "restricted", "delete"} {
		t.Run(mode, func(t *testing.T) {
			_, manager, browser := newSessionTestServer(t)
			cfg := testConfig(t)
			cfg.PortalOrigin = browser.origin
			f := &privateHTTPFixture{snapshot: profile.PrivateSnapshot{LifecycleRevision: "0"}}
			srv := New(cfg, nil, Deps{PrivateProfile: f, SessionManager: manager, DPoPValidator: browser.validator})
			params := session.IssueParams{UserID: uuid.NewString(), AuthVersionSet: true}
			if mode == "restricted" {
				params.Kind = session.KindRecoveryEnrollment
			}
			current, cookies := browser.issueSession(t, manager, params)
			method, body, want := http.MethodPatch, `{"expected_revision":"0","gender":"male"}`, http.StatusOK
			if mode == "get" {
				method, body = http.MethodGet, ""
			}
			if mode == "delete" {
				method, body, want = http.MethodDelete, "", 405
			}
			r := httptest.NewRequest(method, "/api/v1/users/me/private-data", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			browser.authorize(t, r, current, cookies...)
			switch mode {
			case "no cookie":
				r.Header.Del("Cookie")
				want = 401
			case "no proof":
				r.Header.Del(dpop.HeaderProof)
				want = 401
			case "wrong intent":
				r.Header.Set("X-Portal-Session", "foreign")
				want = 409
			case "wrong origin":
				r.Header.Set("Origin", "https://attacker.invalid")
				want = 403
			case "restricted":
				want = 401
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("private browser boundary %s: status %d", mode, w.Code)
			}
			if want != 200 && f.reads+f.writes != 0 {
				t.Fatal("browser denial reached private storage")
			}
		})
	}
}
