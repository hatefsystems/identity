package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/profile"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type profileHandlerRow struct {
	values []any
	err    error
}

func (row profileHandlerRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return errors.New("unexpected profile test row")
	}
	for i, value := range row.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(value))
	}
	return nil
}

type profileHandlerDB struct {
	pgx.Tx
	row     db.GetUserProfileRow
	err     error
	queries int
	writes  int
}

func (d *profileHandlerDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return d, d.err
}
func (d *profileHandlerDB) Commit(context.Context) error   { return nil }
func (d *profileHandlerDB) Rollback(context.Context) error { return nil }
func (d *profileHandlerDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	d.queries++
	if d.err != nil {
		return profileHandlerRow{err: d.err}
	}
	if args[0] != d.row.ID {
		return profileHandlerRow{err: pgx.ErrNoRows}
	}
	if strings.Contains(sql, "-- name: AdvanceUserLifecycleRevision") {
		d.row.LifecycleRevision++
		return profileHandlerRow{values: []any{d.row.LifecycleRevision}}
	}
	return profileHandlerRow{values: []any{d.row.ID, d.row.Email, d.row.DisplayName, d.row.Status, d.row.LifecycleRevision, d.row.AuthVersion}}
}
func (d *profileHandlerDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "-- name: UpdateUserDisplayName") {
		d.writes++
		d.row.DisplayName = args[1].(string)
	}
	return pgconn.NewCommandTag("UPDATE 1"), d.err
}

type profileAuditRecorder struct {
	events []audit.Event
	err    error
}

func (r *profileAuditRecorder) Record(_ context.Context, e audit.Event) error {
	r.events = append(r.events, e)
	return r.err
}

func profileHandlerFixture(t *testing.T) (*Server, *profileHandlerDB, *profileAuditRecorder, session.Session) {
	t.Helper()
	d := &profileHandlerDB{row: db.GetUserProfileRow{ID: uuid.New(), Email: "owner@example.invalid", DisplayName: "Old name",
		Status: "active", LifecycleRevision: 1<<53 + 1, AuthVersion: 7}}
	svc, err := profile.New(d)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &profileAuditRecorder{}
	s := &Server{deps: Deps{Profile: svc, AuditRecorder: recorder}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sess := session.Session{ID: "public-session", UserID: d.row.ID.String(), Kind: session.KindAuthenticated,
		AuthVersion: d.row.AuthVersion, AuthVersionSet: true, DPoPJKT: "bound-jkt",
		AbsoluteExpiry: time.Now().Add(time.Hour).UTC(), IdleExpiry: time.Now().Add(time.Minute).UTC()}
	return s, d, recorder, sess
}

func profileHandlerRequest(sess session.Session, method, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/users/me", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r.WithContext(session.WithSession(dpop.WithProof(r.Context(), &dpop.Proof{JKT: sess.DPoPJKT}), sess))
}

func TestProfileHTTPMinimalSnapshotAndRevision(t *testing.T) {
	s, d, _, sess := profileHandlerFixture(t)
	w := httptest.NewRecorder()
	s.handleProfileGet().ServeHTTP(w, profileHandlerRequest(sess, http.MethodGet, ""))
	var result profileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK || result.ID != d.row.ID || result.Email != d.row.Email ||
		result.DisplayName != "Old name" || result.Status != "active" || result.LifecycleRevision != "9007199254740993" || result.Session.ID != sess.ID || !result.Session.ExpiresAt.Equal(sess.AbsoluteExpiry) {
		t.Fatalf("profile snapshot mismatch: status=%d err=%v", w.Code, err)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &raw) != nil || len(raw) != 6 {
		t.Fatal("profile exposed extra fields")
	}
	for _, key := range []string{"id", "email", "display_name", "status", "lifecycle_revision", "session"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing projection field %s", key)
		}
	}
	for _, secret := range []string{"auth_version", "auth_epoch", "DPoP", "bound-jkt", "password", "mfa", "role", "legal"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("profile leaked %s", secret)
		}
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("profile response omitted privacy policy")
	}
}

func TestProfileHTTPUpdateNoopConflictAndAudit(t *testing.T) {
	s, d, recorder, sess := profileHandlerFixture(t)
	for index, tc := range []struct {
		body string
		code int
	}{
		{`{"display_name":" New private name ","expected_revision":"9007199254740993"}`, 200},
		{`{"display_name":"New private name","expected_revision":"9007199254740994"}`, 200},
		{`{"display_name":"New private name","expected_revision":"9007199254740993"}`, 409},
	} {
		w := httptest.NewRecorder()
		s.handleProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, tc.body))
		if w.Code != tc.code || d.writes != 1 || len(recorder.events) != 1 || d.row.AuthVersion != sess.AuthVersion {
			t.Fatalf("update/noop/conflict %d: status=%d writes=%d audits=%d", index, w.Code, d.writes, len(recorder.events))
		}
		if tc.code == 409 && !strings.Contains(w.Body.String(), "profile_conflict") {
			t.Fatal("stale update did not return the agreed conflict code")
		}
	}
	event := recorder.events[0]
	encoded, err := json.Marshal(event)
	if err != nil || event.EventType != profileUpdatedEvent || event.Security != nil || audit.IsLedgerEventType(event.EventType) ||
		event.ActorID != d.row.ID || event.SubjectID == nil || *event.SubjectID != d.row.ID ||
		bytes.Contains(encoded, []byte("New private name")) || bytes.Contains(encoded, []byte("Old name")) || bytes.Contains(encoded, []byte(d.row.Email)) {
		t.Fatal("name change audit disclosed Class A values or invented a ledger category")
	}
	if len(event.Payload) != 2 || event.Payload["lifecycle_revision"] != "9007199254740994" {
		t.Fatal("audit metadata must remain bounded and revision-exact")
	}
	// Recorder delivery is best effort and cannot undo an already committed edit.
	recorder.err = errors.New("recorder unavailable")
	w := httptest.NewRecorder()
	s.handleProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, `{"display_name":"","expected_revision":"9007199254740994"}`))
	if w.Code != 200 || d.row.DisplayName != "" || d.row.LifecycleRevision != 1<<53+3 || len(recorder.events) != 2 {
		t.Fatal("audit failure changed commit semantics")
	}
}

func TestProfileHTTPRejectsInvalidOrForeignAuthority(t *testing.T) {
	for _, mode := range []string{"missing context", "foreign user", "unbound", "wrong key", "missing captured version", "stale version", "restricted", "expired", "suspended", "database error"} {
		t.Run(mode, func(t *testing.T) {
			s, d, _, sess := profileHandlerFixture(t)
			want := http.StatusUnauthorized
			switch mode {
			case "foreign user":
				sess.UserID = uuid.NewString()
			case "unbound":
				sess.DPoPJKT = ""
			case "missing captured version":
				sess.AuthVersionSet = false
			case "stale version":
				sess.AuthVersion--
			case "restricted":
				sess.Kind = session.KindRecoveryEnrollment
			case "expired":
				sess.AbsoluteExpiry = time.Now().Add(-time.Second)
			case "suspended":
				d.row.Status = "suspended"
			case "database error":
				d.err, want = errors.New("private-name owner@example.invalid database failure"), http.StatusServiceUnavailable
			}
			r := profileHandlerRequest(sess, http.MethodGet, "")
			switch mode {
			case "wrong key":
				r = r.WithContext(dpop.WithProof(r.Context(), &dpop.Proof{JKT: "other"}))
			case "missing context":
				r = r.WithContext(context.Background())
			}
			w := httptest.NewRecorder()
			s.handleProfileGet().ServeHTTP(w, r)
			if w.Code != want || strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "owner@") || w.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatalf("unsafe authority result: status=%d", w.Code)
			}
			if want == 401 && (w.Header().Get("WWW-Authenticate") != "Cookie" || !strings.Contains(w.Body.String(), "session_required")) ||
				want == 503 && !strings.Contains(w.Body.String(), "temporarily_unavailable") {
				t.Fatal("dependency failure and session loss were conflated")
			}
		})
	}
}

func TestProfileHTTPStrictBody(t *testing.T) {
	valid := `{"display_name":"Name","expected_revision":"9007199254740993"}`
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"display_name":"name"}`, `{"expected_revision":"0"}`,
		`{"display_name":null,"expected_revision":"0"}`, `{"display_name":5,"expected_revision":"0"}`,
		`{"display_name":"name","expected_revision":0}`, `{"display_name":"name","expected_revision":null}`,
		`{"display_name":"name","expected_revision":"01"}`, `{"display_name":"name","expected_revision":"+0"}`,
		`{"display_name":"name","expected_revision":"9223372036854775808"}`,
		`{"display_name":"name","expected_revision":"0","email":"injected@example.invalid"}`,
		`{"display_name":"name","expected_revision":"0","id":"other"}`,
		`{"display_name":"name","expected_revision":"0","display_name":"last"}`,
		`{"display_name":"name","expected_revision":"0","display_\u006eame":"last"}`,
		`{"display_name":"name","expected_revision":"0","expected_revision":"1"}`,
		valid + `{}`, strings.Replace(valid, `"Name"`, `"bad\n"`, 1),
		strings.Replace(valid, `"Name"`, `"\ud800"`, 1), strings.Replace(valid, `"Name"`, `"\udc00"`, 1),
		strings.Replace(valid, `"Name"`, `"\ud800\u0061"`, 1),
		strings.Replace(valid, "Name", "bad\xff", 1), strings.Replace(valid, "Name", strings.Repeat("x", 81), 1),
		strings.Repeat(" ", 4097) + valid,
	} {
		s, d, _, sess := profileHandlerFixture(t)
		w := httptest.NewRecorder()
		s.handleProfileUpdate().ServeHTTP(w, profileHandlerRequest(sess, http.MethodPatch, body))
		if w.Code != http.StatusBadRequest || d.queries != 0 || d.writes != 0 {
			t.Fatalf("invalid body admitted: status=%d", w.Code)
		}
	}
	for _, name := range []string{`\ud83d\ude00`, `\ufffd`, `a\/b`, `\\ud800`, ""} {
		r := httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", strings.NewReader(strings.Replace(valid, "Name", name, 1)))
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		if _, _, err := decodeProfileUpdate(httptest.NewRecorder(), r); err != nil {
			t.Fatalf("valid Unicode/JSON string rejected: %v", err)
		}
	}
	for _, mediaType := range []string{"", "text/plain", "application/json; charset=iso-8859-1", "application/json; foo=bar", "application/json; charset=utf-8; x=y"} {
		r := httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", strings.NewReader(valid))
		r.Header.Set("Content-Type", mediaType)
		if _, _, err := decodeProfileUpdate(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("invalid media type %q accepted", mediaType)
		}
	}
}

func TestProfileRoutesRequireBoundSessionAndIntent(t *testing.T) {
	for _, mode := range []string{"get", "patch", "no cookie", "no proof", "nonce challenge", "wrong origin", "no intent", "wrong intent", "restricted", "unbound", "stale auth version"} {
		t.Run(mode, func(t *testing.T) {
			handlers, database, recorder, _ := profileHandlerFixture(t)
			_, manager, browser := newSessionTestServer(t)
			cfg := testConfig(t)
			cfg.PortalOrigin = browser.origin
			srv := New(cfg, nil, Deps{Profile: handlers.deps.Profile, SessionManager: manager, DPoPValidator: browser.validator, AuditRecorder: recorder})
			params := session.IssueParams{UserID: database.row.ID.String(), AuthVersion: database.row.AuthVersion, AuthVersionSet: true}
			switch mode {
			case "restricted":
				params.Kind = session.KindRecoveryEnrollment
			case "stale auth version":
				params.AuthVersion--
			}
			var current session.Session
			var cookies []*http.Cookie
			if mode == "unbound" {
				current, cookies = issueSession(t, manager, params)
			} else {
				current, cookies = browser.issueSession(t, manager, params)
			}
			method, body := http.MethodPatch, `{"display_name":"Live profile","expected_revision":"9007199254740993"}`
			if mode == "get" {
				method, body = http.MethodGet, ""
			}
			req := httptest.NewRequest(method, "/api/v1/users/me", strings.NewReader(body))
			browser.authorize(t, req, current, cookies...)
			wantStatus, wantCode := http.StatusOK, ""
			switch mode {
			case "no cookie":
				req.Header.Del("Cookie")
				wantStatus, wantCode = 401, "session_required"
			case "restricted", "unbound", "stale auth version":
				wantStatus, wantCode = 401, "session_required"
			case "no proof":
				req.Header.Del(dpop.HeaderProof)
				wantStatus, wantCode = 401, "invalid_dpop_proof"
			case "nonce challenge":
				req.Header.Set(dpop.HeaderProof, browser.proof(t, req, ""))
				wantStatus, wantCode = 401, "use_dpop_nonce"
			case "wrong origin":
				req.Header.Set("Origin", "https://sibling.example")
				wantStatus, wantCode = 403, "forbidden_origin"
			case "no intent":
				req.Header.Del("X-Portal-Session")
				wantStatus, wantCode = 409, "session_changed"
			case "wrong intent":
				req.Header.Set("X-Portal-Session", "previous-session")
				wantStatus, wantCode = 409, "session_changed"
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			if w.Code != wantStatus || wantCode != "" && !strings.Contains(w.Body.String(), wantCode) {
				t.Fatalf("profile route boundary: status=%d wanted=%d error=%s", w.Code, wantStatus, wantCode)
			}
			if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("profile boundary denial omitted response privacy policy")
			}
			if mode != "patch" && (database.writes != 0 || len(recorder.events) != 0) {
				t.Fatal("denial/read mutated profile or emitted change audit")
			}
			if mode == "patch" && (database.writes != 1 || len(recorder.events) != 1) {
				t.Fatal("authorized route did not perform the profile transaction")
			}
		})
	}
}

func FuzzProfileUpdateBody(f *testing.F) {
	for _, seed := range []string{`{"display_name":"","expected_revision":"0"}`, `{"display_name":"\ud83d\ude00","expected_revision":"0"}`, `{"display_name":"\ud800","expected_revision":"0"}`, "null", "{}"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		_, _, _ = decodeProfileUpdate(httptest.NewRecorder(), r)
	})
}
