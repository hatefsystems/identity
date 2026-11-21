package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type actionProofHTTPMock struct {
	challengeCalls, verifyCalls int
	sess                        session.Session
	first, second, sourceIP     string
	handle                      string
	deadline                    time.Time
	err                         error
}

func (m *actionProofHTTPMock) Challenge(ctx context.Context, sess session.Session, password, channel, sourceIP string) (string, time.Time, error) {
	m.challengeCalls++
	m.sess, m.first, m.second, m.sourceIP = sess, password, channel, sourceIP
	return m.result(ctx, sess)
}

func (m *actionProofHTTPMock) Verify(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	m.verifyCalls++
	m.sess, m.first, m.second = sess, challenge, code
	return m.result(ctx, sess)
}

func (m *actionProofHTTPMock) result(ctx context.Context, sess session.Session) (string, time.Time, error) {
	current, ok := session.FromContext(ctx)
	proof := dpop.ProofFromContext(ctx)
	if !ok || !reflect.DeepEqual(current, sess) || proof == nil || proof.JKT != sess.DPoPJKT {
		return "", time.Time{}, errors.New("missing request-derived browser authority")
	}
	return m.handle, m.deadline, m.err
}

func newActionProofHTTPFixture(t *testing.T) (*boundaryHarness, *actionProofHTTPMock) {
	t.Helper()
	h := newBoundaryHarness(t, nil, nil)
	m := &actionProofHTTPMock{handle: strings.Repeat("a", 43), deadline: time.Now().UTC().Add(2*time.Minute + 123*time.Nanosecond)}
	h.server = New(h.server.cfg, h.server.logger, Deps{SessionManager: h.manager, DPoPValidator: h.client.validator, AccountDeletionProofs: m})
	return h, m
}

func actionProofHTTPRequest(t *testing.T, h *boundaryHarness, operation, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, accountDeletionProofPath+"/"+operation, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.8:4242"
	h.client.authorize(t, r, h.current, h.cookies...)
	return r
}

func actionProofHTTPServe(t *testing.T, s *Server, r *http.Request, status int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != status {
		// Never put request credentials or returned authority in test artifacts.
		t.Fatalf("HTTP status=%d want=%d", w.Code, status)
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Pragma") != "no-cache" ||
		w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("action proof response lost browser security policy")
	}
	if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-Step-Up-Auth") != "" {
		t.Fatal("action proof endpoint issued unrelated authority")
	}
	return w
}

func requireActionProofHTTPError(t *testing.T, w *httptest.ResponseRecorder, key string) {
	t.Helper()
	var body map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 {
		t.Fatal("error response exposed extra fields or was not JSON")
	}
	var actual string
	if json.Unmarshal(body["error"], &actual) != nil || actual != key {
		t.Fatal("unexpected public error category")
	}
}

func TestActionProofHTTPDefaultOffAndMissingSessionManager(t *testing.T) {
	for _, mode := range []string{"default off", "no session manager"} {
		t.Run(mode, func(t *testing.T) {
			h, m := newActionProofHTTPFixture(t)
			if mode == "default off" {
				h.server = New(h.server.cfg, h.server.logger, Deps{SessionManager: h.manager, DPoPValidator: h.client.validator})
			} else {
				h.server = New(h.server.cfg, h.server.logger, Deps{AccountDeletionProofs: m, DPoPValidator: h.client.validator})
			}
			for _, operation := range []string{"challenge", "verify"} {
				actionProofHTTPServe(t, h.server, actionProofHTTPRequest(t, h, operation, `{}`), 404)
			}
			if m.challengeCalls+m.verifyCalls != 0 || h.store.touches.Load() != 0 {
				t.Fatal("absent route reached service or activity")
			}
		})
	}
}

func TestActionProofHTTPExactRequestMatrix(t *testing.T) {
	for _, operation := range []string{"challenge", "verify"} {
		first, second, secondValue := "password", "channel", "email"
		if operation == "verify" {
			first, second, secondValue = "challenge", "code", "123456"
		}
		body := func(a, b string) string { return fmt.Sprintf(`{%q:%s,%q:%s}`, first, a, second, b) }
		valid := body(`"opaque"`, fmt.Sprintf(`%q`, secondValue))
		for _, tc := range []struct {
			name   string
			body   string
			query  string
			mutate func(*http.Request)
			status int
		}{
			{name: "missing all fields", body: `{}`, status: 400},
			{name: "missing first field", body: fmt.Sprintf(`{%q:%q}`, second, secondValue), status: 400},
			{name: "missing second field", body: fmt.Sprintf(`{%q:"opaque"}`, first), status: 400},
			{name: "unknown field", body: strings.TrimSuffix(valid, "}") + `,"extra":"value"}`, status: 400},
			{name: "case alias", body: strings.Replace(valid, first, strings.ToUpper(first), 1), status: 400},
			{name: "duplicate first", body: strings.TrimSuffix(valid, "}") + fmt.Sprintf(`,%q:"other"}`, first), status: 400},
			{name: "duplicate second", body: strings.TrimSuffix(valid, "}") + fmt.Sprintf(`,%q:"other"}`, second), status: 400},
			{name: "escaped duplicate", body: strings.TrimSuffix(valid, "}") + fmt.Sprintf(`,"\u%04x%s":"other"}`, first[0], first[1:]), status: 400},
			{name: "null first", body: body(`null`, fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "null second", body: body(`"opaque"`, `null`), status: 400},
			{name: "number first", body: body(`123`, fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "boolean second", body: body(`"opaque"`, `true`), status: 400},
			{name: "object first", body: body(`{}`, fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "array second", body: body(`"opaque"`, `[]`), status: 400},
			{name: "lone high surrogate", body: body(`"\ud800"`, fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "lone low surrogate", body: body(`"\udfff"`, fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "unpaired second surrogate", body: body(`"opaque"`, `"\ud800x"`), status: 400},
			{name: "invalid UTF8", body: body("\"\xff\"", fmt.Sprintf(`%q`, secondValue)), status: 400},
			{name: "invalid Unicode key", body: strings.TrimSuffix(valid, "}") + `,"\ud800":"other"}`, status: 400},
			{name: "malformed JSON", body: `{`, status: 400},
			{name: "trailing JSON", body: valid + `{}`, status: 400},
			{name: "trailing junk", body: valid + `x`, status: 400},
			{name: "top-level null", body: `null`, status: 400},
			{name: "top-level array", body: `[]`, status: 400},
			{name: "whitespace only", body: " \t\r\n", status: 400},
			{name: "empty body", mutate: func(r *http.Request) { r.Body = http.NoBody }, status: 400},
			{name: "nil body", mutate: func(r *http.Request) { r.Body = nil }, status: 400},
			{name: "body limit", body: valid + strings.Repeat(" ", 8193-len(valid)), status: 400},
			{name: "transport limit", body: valid + strings.Repeat(" ", 65537-len(valid)), status: 413},
			{name: "query credentials", query: "?password=opaque", status: 400},
			{name: "empty query", query: "?", status: 400},
			{name: "malformed query", query: "?%ff=%", status: 400},
			{name: "missing content type", mutate: func(r *http.Request) { r.Header.Del("Content-Type") }, status: 415},
			{name: "duplicate content type", mutate: func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, status: 415},
			{name: "form content type", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, status: 415},
			{name: "wrong charset", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-16") }, status: 415},
			{name: "unknown parameter", mutate: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; profile=custom") }, status: 415},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				if tc.body == "" {
					tc.body = valid
				}
				r := actionProofHTTPRequest(t, h, operation+tc.query, tc.body)
				if tc.mutate != nil {
					tc.mutate(r)
				}
				w := actionProofHTTPServe(t, h.server, r, tc.status)
				key := "invalid_request"
				if tc.status == 415 {
					key = "invalid_content_type"
				}
				requireActionProofHTTPError(t, w, key)
				if m.challengeCalls+m.verifyCalls != 0 || h.store.touches.Load() != 0 {
					t.Fatal("strict request rejection reached service or activity")
				}
			})
		}
		for _, name := range []string{"user_id", "session_id", "jkt", "auth_version", "action", "destination", "source_ip", "action_proof"} {
			t.Run(operation+"/client binding "+name, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				r := actionProofHTTPRequest(t, h, operation, strings.TrimSuffix(valid, "}")+fmt.Sprintf(`,%q:"untrusted"}`, name))
				requireActionProofHTTPError(t, actionProofHTTPServe(t, h.server, r, 400), "invalid_request")
				if m.challengeCalls+m.verifyCalls != 0 {
					t.Fatal("client-supplied binding reached service")
				}
			})
		}
	}
	for _, channel := range []string{"", "EMAIL", "Sms", "phone", " email", "email ", "email,sms"} {
		h, m := newActionProofHTTPFixture(t)
		r := actionProofHTTPRequest(t, h, "challenge", loginHTTPBody(t, map[string]string{"password": "opaque", "channel": channel}))
		requireActionProofHTTPError(t, actionProofHTTPServe(t, h.server, r, 400), "invalid_request")
		if m.challengeCalls != 0 {
			t.Fatal("noncanonical channel reached service")
		}
	}
}

func TestActionProofHTTPBrowserAuthorityMatrix(t *testing.T) {
	for _, operation := range []string{"challenge", "verify"} {
		for _, tc := range []struct {
			name   string
			mutate func(*testing.T, *boundaryHarness, *http.Request)
			status int
			key    string
		}{
			{name: "missing cookie", status: 401, key: "session_required", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del("Cookie") }},
			{name: "missing DPoP", status: 401, key: "invalid_dpop_proof", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del("DPoP") }},
			{name: "duplicate DPoP", status: 401, key: "invalid_dpop_proof", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Add("DPoP", r.Header.Get("DPoP")) }},
			{name: "wrong DPoP key", status: 401, key: "invalid_dpop_proof", mutate: func(t *testing.T, h *boundaryHarness, r *http.Request) {
				other := newPortalTestClient(t, h.client.origin)
				r.Header.Set("DPoP", other.proof(t, r, ""))
			}},
			{name: "wrong DPoP endpoint", status: 401, key: "invalid_dpop_proof", mutate: func(t *testing.T, h *boundaryHarness, r *http.Request) {
				r.Header.Set("DPoP", h.client.proof(t, httptest.NewRequest(http.MethodPost, "/another-endpoint", nil), ""))
			}},
			{name: "missing intent", status: 409, key: "session_changed", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del(portalSessionHeader) }},
			{name: "wrong intent", status: 409, key: "session_changed", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) {
				r.Header.Set(portalSessionHeader, uuid.NewString())
			}},
			{name: "duplicate intent", status: 409, key: "session_changed", mutate: func(_ *testing.T, h *boundaryHarness, r *http.Request) {
				r.Header.Add(portalSessionHeader, h.current.ID)
			}},
			{name: "changed session", status: 409, key: "session_changed", mutate: func(t *testing.T, h *boundaryHarness, r *http.Request) {
				_, cookies := h.client.issueSession(t, h.manager, session.IssueParams{UserID: h.current.UserID, AuthVersion: h.current.AuthVersion, AuthVersionSet: true})
				r.Header.Del("Cookie")
				r.AddCookie(cookies[0])
			}},
			{name: "recovery session", status: 401, key: "session_required", mutate: func(t *testing.T, h *boundaryHarness, r *http.Request) {
				current, cookies := h.client.issueSession(t, h.manager, session.IssueParams{UserID: h.current.UserID, AuthVersion: h.current.AuthVersion, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
				r.Header.Del("Cookie")
				r.AddCookie(cookies[0])
				r.Header.Set(portalSessionHeader, current.ID)
			}},
			{name: "stale account version", status: 401, key: "session_required", mutate: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.accounts.err = session.ErrAccountIneligible }},
			{name: "session outage", status: 503, key: "temporarily_unavailable", mutate: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.store.getErr = session.ErrStoreUnavailable }},
			{name: "missing validator", status: 503, key: "temporarily_unavailable", mutate: func(_ *testing.T, h *boundaryHarness, _ *http.Request) { h.server.deps.DPoPValidator = nil }},
			{name: "missing origin", status: 403, key: "forbidden_origin", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Del("Origin") }},
			{name: "wrong origin", status: 403, key: "forbidden_origin", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) {
				r.Header.Set("Origin", "https://sibling.example")
			}},
			{name: "duplicate origin", status: 403, key: "forbidden_origin", mutate: func(_ *testing.T, h *boundaryHarness, r *http.Request) { r.Header.Add("Origin", h.client.origin) }},
			{name: "cross site", status: 403, key: "forbidden_origin", mutate: func(_ *testing.T, _ *boundaryHarness, r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				body := `{"password":"opaque","channel":"email"}`
				if operation == "verify" {
					body = `{"challenge":"opaque","code":"123456"}`
				}
				r := actionProofHTTPRequest(t, h, operation, body)
				tc.mutate(t, h, r)
				requireActionProofHTTPError(t, actionProofHTTPServe(t, h.server, r, tc.status), tc.key)
				if m.challengeCalls+m.verifyCalls != 0 || h.store.touches.Load() != 0 {
					t.Fatal("browser policy rejection reached proof service or activity")
				}
			})
		}
	}
}

func TestActionProofHTTPBoundSuccessAndOriginalDeadline(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			h, m := newActionProofHTTPFixture(t)
			deadline := m.deadline
			submitted := "  exact \u00e9\x00 bytes  "
			r := actionProofHTTPRequest(t, h, "challenge", loginHTTPBody(t, map[string]string{"password": submitted, "channel": channel}))
			r.Header.Set("X-Forwarded-For", "198.51.100.99")
			// Incoming context cannot override the cookie's server-resolved binding.
			forged := h.current
			forged.ID, forged.UserID, forged.DPoPJKT, forged.AuthVersion = uuid.NewString(), uuid.NewString(), "untrusted", 1
			r = r.WithContext(session.WithSession(dpop.WithProof(r.Context(), &dpop.Proof{JKT: "untrusted"}), forged))
			w := actionProofHTTPServe(t, h.server, r, 202)
			if m.challengeCalls != 1 || m.verifyCalls != 0 || m.first != submitted || m.second != channel || m.sourceIP != "203.0.113.8" ||
				m.sess.ID != h.current.ID || m.sess.UserID != h.current.UserID || m.sess.DPoPJKT != h.current.DPoPJKT || m.sess.AuthVersion != h.current.AuthVersion {
				t.Fatal("challenge did not receive exact values and server-derived binding")
			}
			var challenge map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &challenge) != nil || len(challenge) != 2 || challenge["challenge"] == nil || challenge["expires_at"] == nil {
				t.Fatal("challenge success exposed extra fields")
			}
			var handle string
			var expires time.Time
			if json.Unmarshal(challenge["challenge"], &handle) != nil || handle != m.handle || json.Unmarshal(challenge["expires_at"], &expires) != nil || !expires.Equal(deadline) {
				t.Fatal("challenge success changed handle or original deadline")
			}
			r = actionProofHTTPRequest(t, h, "verify", loginHTTPBody(t, map[string]string{"challenge": handle, "code": "012345"}))
			w = actionProofHTTPServe(t, h.server, r, 200)
			if m.challengeCalls != 1 || m.verifyCalls != 1 || m.first != handle || m.second != "012345" || m.sess.ID != h.current.ID || m.sess.AuthVersion != h.current.AuthVersion {
				t.Fatal("verification changed exact code or browser binding")
			}
			var proof map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &proof) != nil || len(proof) != 2 || proof["action_proof"] == nil || proof["expires_at"] == nil ||
				json.Unmarshal(proof["action_proof"], &handle) != nil || handle != m.handle || json.Unmarshal(proof["expires_at"], &expires) != nil || !expires.Equal(deadline) {
				t.Fatal("verification exposed extra fields or extended original deadline")
			}
			if h.store.touches.Load() != 2 {
				t.Fatal("successful operations did not retain normal activity semantics")
			}
		})
	}
}

func TestActionProofHTTPDecoderPreservesValidUnicodeAndExactByteLimit(t *testing.T) {
	for _, raw := range []string{`"\ud83d\ude00"`, `"\ufffd"`, `"\u00e9"`, `" e\u0301 "`, `"backslash\\ud800"`} {
		h, m := newActionProofHTTPFixture(t)
		body := `{"password":` + raw + `,"channel":"email"}`
		body += strings.Repeat(" ", 8192-len(body))
		r := actionProofHTTPRequest(t, h, "challenge", body)
		r.ContentLength = -1
		r.Header.Set("Content-Type", "application/json; charset=UTF-8")
		actionProofHTTPServe(t, h.server, r, 202)
		var expected string
		if json.Unmarshal([]byte(raw), &expected) != nil || m.first != expected || m.challengeCalls != 1 {
			t.Fatal("valid Unicode was normalized or exact byte limit was rejected")
		}
	}
}

func TestActionProofHTTPServiceErrorsNeverExposeTentativeAuthority(t *testing.T) {
	for _, operation := range []string{"challenge", "verify"} {
		for _, tc := range []struct {
			name   string
			err    error
			status int
			key    string
		}{
			{"invalid", actionproof.ErrInvalid, 400, "invalid_request"},
			{"ineligible or password", actionproof.ErrUnauthorized, 403, "insufficient_user_authentication"},
			{"rate", actionproof.ErrRateLimited, 429, "rate_limited"},
			{"unavailable", actionproof.ErrUnavailable, 503, "temporarily_unavailable"},
			{"issuance uncertain", actionproof.ErrOutcomeUnknown, 503, "outcome_unknown"},
			{"delivery uncertain", contactcode.ErrOutcomeUnknown, 503, "outcome_unknown"},
			{"code invalid", contactcode.ErrInvalidCode, 401, "invalid_code"},
			{"code inactive", contactcode.ErrNoActiveCode, 401, "invalid_code"},
			{"code policy", contactcode.ErrInvalid, 400, "invalid_request"},
			{"code rate", contactcode.ErrRateLimited, 429, "rate_limited"},
			{"code lockout", contactcode.ErrLockedOut, 429, "rate_limited"},
			{"code unavailable", contactcode.ErrUnavailable, 503, "temporarily_unavailable"},
			{"provider disabled", contactcode.ErrDisabled, 503, "temporarily_unavailable"},
			{"delivery rejected", contactcode.ErrSendFailed, 503, "temporarily_unavailable"},
			{"canceled", context.Canceled, 503, "temporarily_unavailable"},
			{"timeout", context.DeadlineExceeded, 503, "temporarily_unavailable"},
			{"unknown", errors.New("private password/code/destination/session/proof details"), 503, "temporarily_unavailable"},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				m.err = fmt.Errorf("private dependency context: %w", tc.err)
				body := `{"password":"opaque","channel":"email"}`
				if operation == "verify" {
					body = `{"challenge":"opaque","code":"123456"}`
				}
				requireActionProofHTTPError(t, actionProofHTTPServe(t, h.server, actionProofHTTPRequest(t, h, operation, body), tc.status), tc.key)
				if m.challengeCalls+m.verifyCalls != 1 || h.store.touches.Load() != 0 {
					t.Fatal("failure retried service or renewed session activity")
				}
			})
		}
	}
}

func TestActionProofHTTPIncompleteSuccessFailsClosed(t *testing.T) {
	for _, operation := range []string{"challenge", "verify"} {
		for _, missing := range []string{"handle", "deadline", "service"} {
			t.Run(operation+"/"+missing, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				switch missing {
				case "handle":
					m.handle = ""
				case "deadline":
					m.deadline = time.Time{}
				case "service":
					h.server.deps.AccountDeletionProofs = nil
				}
				body := `{"password":"opaque","channel":"email"}`
				if operation == "verify" {
					body = `{"challenge":"opaque","code":"123456"}`
				}
				requireActionProofHTTPError(t, actionProofHTTPServe(t, h.server, actionProofHTTPRequest(t, h, operation, body), 503), "temporarily_unavailable")
				if h.store.touches.Load() != 0 {
					t.Fatal("incomplete service success renewed activity")
				}
			})
		}
	}
}

func TestActionProofHTTPDirectHandlerSessionDefense(t *testing.T) {
	for _, operation := range []string{"challenge", "verify"} {
		for _, mode := range []string{"missing", "noncanonical user", "missing ID", "recovery", "uncaptured version", "negative version", "missing JKT", "missing proof", "wrong proof", "expired absolute", "expired idle"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				h, m := newActionProofHTTPFixture(t)
				r := actionProofHTTPRequest(t, h, operation, `{}`)
				current := h.current
				proof := &dpop.Proof{JKT: current.DPoPJKT}
				switch mode {
				case "noncanonical user":
					current.UserID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
				case "missing ID":
					current.ID = ""
				case "recovery":
					current.Kind = session.KindRecoveryEnrollment
				case "uncaptured version":
					current.AuthVersionSet = false
				case "negative version":
					current.AuthVersion = -1
				case "missing JKT":
					current.DPoPJKT = ""
				case "missing proof":
					proof = nil
				case "wrong proof":
					proof.JKT = "untrusted"
				case "expired absolute":
					current.AbsoluteExpiry = time.Now().Add(-time.Second)
				case "expired idle":
					current.IdleExpiry = time.Now().Add(-time.Second)
				}
				if mode != "missing" {
					r = r.WithContext(session.WithSession(dpop.WithProof(r.Context(), proof), current))
				}
				w := httptest.NewRecorder()
				h.server.handleActionProof(operation == "verify").ServeHTTP(w, r)
				if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Cookie" {
					t.Fatal("direct handler skipped profile session defense")
				}
				requireActionProofHTTPError(t, w, "session_required")
				if m.challengeCalls+m.verifyCalls != 0 {
					t.Fatal("invalid direct context reached proof service")
				}
			})
		}
	}
}

func deletionShapedHTTPProof(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal("opaque proof fixture generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func TestActionProofHTTPDeletionProofCannotAuthorizeStepUpOrDeletion(t *testing.T) {
	f := newPrivacyFixture(t, privacyOptions{})
	proof := deletionShapedHTTPProof(t)
	m := &actionProofHTTPMock{handle: proof, deadline: time.Now().UTC().Add(time.Minute)}
	deps := f.server.deps
	deps.AccountDeletionProofs = m
	f.server = New(f.server.cfg, f.server.logger, deps)
	h := &boundaryHarness{server: f.server, client: f.browser, current: f.sess, cookies: []*http.Cookie{f.cookie}}
	issued := actionProofHTTPServe(t, f.server, actionProofHTTPRequest(t, h, "verify", `{"challenge":"opaque","code":"123456"}`), http.StatusOK)
	var result struct {
		Proof string `json:"action_proof"`
	}
	if json.Unmarshal(issued.Body.Bytes(), &result) != nil || result.Proof != proof || m.verifyCalls != 1 {
		t.Fatal("deletion-shaped proof was not returned by its own HTTP boundary")
	}
	before := f.store.users[f.userID]
	lookup := httptest.NewRequest(http.MethodGet, "/", nil)
	lookup.AddCookie(f.cookie)
	beforeSession, err := f.server.deps.SessionManager.Resolve(lookup)
	if err != nil {
		t.Fatal("existing session unavailable after proof issuance")
	}
	for _, tc := range []struct {
		name, method, path, body, key string
		status                        int
	}{
		{"proof as TOTP", http.MethodPost, stepUpVerifyPath, loginHTTPBody(t, map[string]string{"method": "totp", "code": proof}), "invalid_credentials", http.StatusUnauthorized},
		{"proof as unsupported factor", http.MethodPost, stepUpVerifyPath, loginHTTPBody(t, map[string]string{"method": "account_deletion", "action_proof": proof}), "unsupported_method", http.StatusBadRequest},
		{"proof header without factor", http.MethodPost, stepUpVerifyPath, `{}`, "unsupported_method", http.StatusBadRequest},
		{"proof as UV deletion grant", http.MethodDelete, "/api/v1/users/me", "", "insufficient_user_authentication", http.StatusForbidden},
		{"proof as UV deletion grant slash", http.MethodDelete, privacyDeletePath, "", "insufficient_user_authentication", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			f.browser.authorize(t, r, f.sess, f.cookie)
			r.Header.Set(stepup.HeaderStepUpAuth, proof)
			w := actionProofHTTPServe(t, f.server, r, tc.status)
			var body map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &body) != nil {
				t.Fatal("substitution denial was not JSON")
			}
			var key string
			if json.Unmarshal(body["error"], &key) != nil || key != tc.key {
				t.Fatal("substitution denial changed its existing public category")
			}
			wantFields := 1
			if tc.method == http.MethodDelete {
				wantFields = 2
				var acr string
				if json.Unmarshal(body["acr_values"], &acr) != nil || acr != stepup.ACRStepUp {
					t.Fatal("deletion proof bypassed the existing UV step-up challenge")
				}
			}
			if len(body) != wantFields || !reflect.DeepEqual(before, f.store.users[f.userID]) ||
				len(f.store.requests)+len(f.store.intents)+len(f.store.notifications) != 0 {
				t.Fatal("substitution issued authority or applied a deletion mutation")
			}
			current, err := f.server.deps.SessionManager.Resolve(r)
			if err != nil || !reflect.DeepEqual(current, beforeSession) {
				t.Fatal("substitution changed the existing session or authentication evidence")
			}
		})
	}
	if _, err := f.stepUp.Validate(t.Context(), proof, f.sess); !errors.Is(err, stepup.ErrInvalidGrant) || m.verifyCalls != 1 || m.challengeCalls != 0 {
		t.Fatal("deletion proof acquired general step-up authority or restarted its ceremony")
	}
}
