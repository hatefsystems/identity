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
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/username"
)

type usernameReadFixture struct {
	id      uuid.UUID
	version int64
	value   *username.ReadResult
	err     error
	calls   int
}

func (f *usernameReadFixture) Get(_ context.Context, id uuid.UUID, version int64) (*username.ReadResult, error) {
	f.calls++
	if id != f.id || version != f.version {
		return nil, username.ErrUnauthorized
	}
	return f.value, f.err
}

func TestUsernameHTTPTruthfulMinimalReadAndPrivacy(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		s, _, _, sess := profileHandlerFixture(t)
		reader := &usernameReadFixture{id: uuid.MustParse(sess.UserID), version: sess.AuthVersion}
		if claimed {
			reader.value = &username.ReadResult{Display: "\u0639\u0644\u06cc.\u0645\u0624\u0645\u0646\u06cc"}
		}
		s.deps.Usernames = reader
		w := httptest.NewRecorder()
		s.handleUsernameGet().ServeHTTP(w, profileHandlerRequest(sess, http.MethodGet, ""))
		var body map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != http.StatusOK || len(body) != 1 || reader.calls != 1 {
			t.Fatal("username read exposed an expanded profile or skipped session-bound read")
		}
		if !claimed {
			if string(body["username"]) != "null" {
				t.Fatal("unclaimed account received a fabricated username")
			}
		} else {
			var name map[string]string
			if json.Unmarshal(body["username"], &name) != nil || len(name) != 1 || name["display"] != reader.value.Display {
				t.Fatal("username read did not preserve exact chosen display")
			}
		}
		if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("username read omitted privacy or minted a session")
		}
	}
}

func TestUsernameHTTPRejectsInvalidSessionAndForeignAuthority(t *testing.T) {
	for _, mode := range []string{"missing", "foreign", "stale", "unbound", "wrong key", "uncaptured", "restricted", "expired", "suspended or deleted", "storage failure", "policy mismatch"} {
		t.Run(mode, func(t *testing.T) {
			s, _, _, sess := profileHandlerFixture(t)
			reader := &usernameReadFixture{id: uuid.MustParse(sess.UserID), version: sess.AuthVersion}
			s.deps.Usernames = reader
			want := http.StatusUnauthorized
			switch mode {
			case "foreign":
				sess.UserID = uuid.NewString()
			case "stale":
				sess.AuthVersion--
			case "unbound":
				sess.DPoPJKT = ""
			case "uncaptured":
				sess.AuthVersionSet = false
			case "restricted":
				sess.Kind = session.KindRecoveryEnrollment
			case "expired":
				sess.AbsoluteExpiry = time.Now().Add(-time.Second)
			case "suspended or deleted":
				reader.err = username.ErrUnauthorized
			case "storage failure":
				reader.err, want = errors.New("private username SQL ciphertext"), http.StatusServiceUnavailable
			case "policy mismatch":
				reader.err, want = username.ErrPolicyMismatch, http.StatusServiceUnavailable
			}
			r := profileHandlerRequest(sess, http.MethodGet, "")
			if mode == "missing" {
				r = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/username", nil)
			}
			if mode == "wrong key" {
				r = r.WithContext(dpop.WithProof(r.Context(), &dpop.Proof{JKT: "foreign"}))
			}
			w := httptest.NewRecorder()
			s.handleUsernameGet().ServeHTTP(w, r)
			if w.Code != want || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "ciphertext") || strings.Contains(w.Body.String(), "policy") {
				t.Fatalf("invalid username read authority/diagnostic: status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestUsernameHTTPRejectsQueryAndBodyWithoutReading(t *testing.T) {
	for _, mode := range []string{"query", "empty query", "body", "transfer"} {
		s, _, _, sess := profileHandlerFixture(t)
		reader := &usernameReadFixture{id: uuid.MustParse(sess.UserID), version: sess.AuthVersion}
		s.deps.Usernames = reader
		r := profileHandlerRequest(sess, http.MethodGet, "")
		switch mode {
		case "query":
			r.URL.RawQuery = "user_id=" + uuid.NewString()
		case "empty query":
			r.URL.ForceQuery = true
		case "body":
			r = profileHandlerRequest(sess, http.MethodGet, `{"username":"forged"}`)
		case "transfer":
			r.TransferEncoding = []string{"chunked"}
		}
		w := httptest.NewRecorder()
		s.handleUsernameGet().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest || reader.calls != 0 {
			t.Fatal("username GET accepted caller data authority")
		}
	}
}

func TestUsernameRoutesRequireBoundSessionAndNeverMountClaim(t *testing.T) {
	for _, mode := range []string{"get", "no cookie", "no proof", "wrong origin", "wrong intent", "restricted", "stale", "claim", "rename", "clear"} {
		t.Run(mode, func(t *testing.T) {
			_, _, _, fixtureSession := profileHandlerFixture(t)
			reader := &usernameReadFixture{id: uuid.MustParse(fixtureSession.UserID), version: fixtureSession.AuthVersion}
			_, manager, browser := newSessionTestServer(t)
			cfg := testConfig(t)
			cfg.PortalOrigin = browser.origin
			srv := New(cfg, nil, Deps{Usernames: reader, SessionManager: manager, DPoPValidator: browser.validator})
			params := session.IssueParams{UserID: reader.id.String(), AuthVersion: reader.version, AuthVersionSet: true}
			if mode == "restricted" {
				params.Kind = session.KindRecoveryEnrollment
			}
			if mode == "stale" {
				params.AuthVersion--
			}
			current, cookies := browser.issueSession(t, manager, params)
			method := http.MethodGet
			switch mode {
			case "claim":
				method = http.MethodPost
			case "rename":
				method = http.MethodPatch
			case "clear":
				method = http.MethodDelete
			}
			r := httptest.NewRequest(method, "/api/v1/users/me/username", nil)
			browser.authorize(t, r, current, cookies...)
			want := http.StatusOK
			switch mode {
			case "no cookie":
				r.Header.Del("Cookie")
				want = http.StatusUnauthorized
			case "no proof":
				r.Header.Del(dpop.HeaderProof)
				want = http.StatusUnauthorized
			case "wrong origin":
				r.Header.Set("Origin", "https://attacker.example")
				// Preserve the existing safe-method session guard: cookie, DPoP,
				// intent and captured auth version still authorize this read.
			case "wrong intent":
				r.Header.Set("X-Portal-Session", "foreign-session")
				want = http.StatusConflict
			case "restricted", "stale":
				want = http.StatusUnauthorized
			case "claim", "rename", "clear":
				want = http.StatusMethodNotAllowed
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("username route boundary %s: status=%d body=%s", mode, w.Code, w.Body.String())
			}
			if mode != "get" && mode != "wrong origin" && mode != "stale" && reader.calls != 0 {
				t.Fatal("unmounted mutation/denial reached username storage")
			}
		})
	}
}
