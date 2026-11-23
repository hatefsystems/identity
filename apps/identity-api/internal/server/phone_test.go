package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/accountpolicy"
	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactcode"
	"github.com/hatefsystems/identity/apps/identity-api/internal/contactmanager"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
	"github.com/hatefsystems/identity/apps/identity-api/internal/smsotp"
	"github.com/hatefsystems/identity/apps/identity-api/internal/stepup"
)

type phoneAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *phoneAuditRecorder) Record(_ context.Context, event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}
func (r *phoneAuditRecorder) count(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, event := range r.events {
		if event.EventType == kind {
			n++
		}
	}
	return n
}

type contactHTTPMock struct {
	preflightCalls, startCalls, finishCalls, removeCalls, readCalls int
	sess                                                            session.Session
	target, value, handle, code, source                             string
	auth                                                            contactmanager.Authorization
	result                                                          contactmanager.StartResult
	contacts                                                        contactmanager.Contacts
	changed                                                         bool
	err, preflightErr                                               error
}

func (m *contactHTTPMock) Preflight(target, value, source string) (string, error) {
	m.preflightCalls++
	m.target, m.value, m.source = target, value, source
	if m.preflightErr != nil {
		return "", m.preflightErr
	}
	if target == "phone" {
		canonical, err := smsotp.NormalizePhone(value)
		if err != nil || len(canonical) != 13 || !strings.HasPrefix(canonical, "+989") {
			return "", contactmanager.ErrInvalid
		}
		return canonical, nil
	}
	if !strings.Contains(value, "@") {
		return "", contactmanager.ErrInvalid
	}
	return strings.ToLower(value), nil
}
func (m *contactHTTPMock) check(ctx context.Context, sess session.Session) {
	m.sess = sess
	current, ok := session.FromContext(ctx)
	proof := dpop.ProofFromContext(ctx)
	if !ok || !reflect.DeepEqual(current, sess) || proof == nil || proof.JKT != sess.DPoPJKT {
		panic("missing request-derived authority")
	}
}
func (m *contactHTTPMock) Start(ctx context.Context, sess session.Session, target, value string, auth contactmanager.Authorization, source string) (contactmanager.StartResult, error) {
	m.check(ctx, sess)
	m.startCalls++
	m.target, m.value, m.auth, m.source = target, value, auth, source
	return m.result, m.err
}
func (m *contactHTTPMock) Finish(ctx context.Context, sess session.Session, target, handle, code string) (bool, error) {
	m.check(ctx, sess)
	m.finishCalls++
	m.target, m.handle, m.code = target, handle, code
	return m.changed, m.err
}
func (m *contactHTTPMock) Remove(ctx context.Context, sess session.Session, target string, auth contactmanager.Authorization) (bool, error) {
	m.check(ctx, sess)
	m.removeCalls++
	m.target, m.auth = target, auth
	return m.changed, m.err
}
func (m *contactHTTPMock) Read(ctx context.Context, sess session.Session) (contactmanager.Contacts, error) {
	m.check(ctx, sess)
	m.readCalls++
	return m.contacts, m.err
}

type contactProofHTTPMock struct {
	challengeCalls, verifyCalls                                int
	sess                                                       session.Session
	password, channel, action, target, source, challenge, code string
	handle                                                     string
	deadline                                                   time.Time
	err                                                        error
}

func (m *contactProofHTTPMock) ContactChallenge(ctx context.Context, sess session.Session, password, channel, action, target, source string) (string, time.Time, error) {
	m.challengeCalls++
	m.sess, m.password, m.channel, m.action, m.target, m.source = sess, password, channel, action, target, source
	return m.result(ctx, sess)
}
func (m *contactProofHTTPMock) ContactVerify(ctx context.Context, sess session.Session, challenge, code, action string) (string, time.Time, error) {
	m.verifyCalls++
	m.sess, m.challenge, m.code, m.action = sess, challenge, code, action
	return m.result(ctx, sess)
}
func (m *contactProofHTTPMock) result(ctx context.Context, sess session.Session) (string, time.Time, error) {
	proof := dpop.ProofFromContext(ctx)
	if proof == nil || proof.JKT != sess.DPoPJKT {
		return "", time.Time{}, actionproof.ErrUnauthorized
	}
	return m.handle, m.deadline, m.err
}

type contactHTTPFixture struct {
	*boundaryHarness
	contacts *contactHTTPMock
	proofs   *contactProofHTTPMock
	stepUp   *stepup.Service
	audit    *phoneAuditRecorder
}

func newContactHTTPFixture(t *testing.T) *contactHTTPFixture {
	t.Helper()
	h := newBoundaryHarness(t, nil, nil)
	handle := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	deadline := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)
	m := &contactHTTPMock{result: contactmanager.StartResult{VerificationID: handle, ExpiresAt: deadline}}
	p := &contactProofHTTPMock{handle: handle, deadline: deadline}
	svc, _ := newTestStepUpService(t, newStepUpFakeUserStore(db.User{ID: uuid.MustParse(h.current.UserID), Status: "active", AuthVersion: h.current.AuthVersion, IsMfaEnabled: true}), nil, &stepUpFakeTOTP{valid: "000000"})
	recorder := &phoneAuditRecorder{}
	h.server = New(h.server.cfg, h.server.logger, Deps{SessionManager: h.manager, DPoPValidator: h.client.validator,
		Contacts: m, ContactManagementProofs: p, StepUp: svc, AuditRecorder: recorder})
	return &contactHTTPFixture{h, m, p, svc, recorder}
}

func (f *contactHTTPFixture) request(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "203.0.113.9:5555"
	f.client.authorize(t, r, f.current, f.cookies...)
	return r
}
func (f *contactHTTPFixture) grant(t *testing.T) string { return mintTestGrant(t, f.stepUp, f.current) }
func contactServe(t *testing.T, f *contactHTTPFixture, r *http.Request, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("HTTP status=%d want=%d", w.Code, want)
	}
	if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("contact response lost private browser policy")
	}
	return w
}

func TestPhoneRoutesRequireSessionAndExactBrowserAuthority(t *testing.T) {
	for _, endpoint := range []struct{ method, path, body string }{
		{"GET", "/api/v1/users/me/contacts", ""},
		{"POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`},
		{"POST", "/api/v1/users/me/email/send-code", `{"email":"a@example.invalid"}`},
		{"POST", "/api/v1/users/me/phone/verify", `{"verification_id":"` + strings.Repeat("A", 43) + `","code":"000123"}`},
		{"DELETE", "/api/v1/users/me/email", ""},
		{"POST", contactChangeProofPath + "/challenge", `{"password":"password","channel":"sms","target":"phone"}`},
		{"POST", contactRemovalProofPath + "/verify", `{"challenge":"` + strings.Repeat("A", 43) + `","code":"000123"}`},
	} {
		for _, denial := range []string{"cookie", "restricted", "key", "intent", "origin"} {
			if denial == "origin" && endpoint.method == "GET" {
				continue
			}
			t.Run(endpoint.path+"/"+denial, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				r := f.request(t, endpoint.method, endpoint.path, endpoint.body)
				want := 401
				switch denial {
				case "cookie":
					r.Header.Del("Cookie")
				case "restricted":
					_, cookies := f.client.issueSession(t, f.manager, session.IssueParams{UserID: f.current.UserID, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
					r.Header.Del("Cookie")
					r.AddCookie(cookies[0])
				case "key":
					other := newPortalTestClient(t, f.client.origin)
					r.Header.Set("DPoP", other.proof(t, r, ""))
				case "intent":
					r.Header.Set(portalSessionHeader, "other")
					want = 409
				case "origin":
					r.Header.Set("Origin", f.client.origin+"/")
					want = 403
				}
				contactServe(t, f, r, want)
				if f.contacts.startCalls+f.contacts.finishCalls+f.contacts.removeCalls+f.contacts.readCalls+f.proofs.challengeCalls+f.proofs.verifyCalls != 0 || f.store.touches.Load() != 0 {
					t.Fatal("denial reached service or renewed activity")
				}
			})
		}
	}
}

func TestPhoneSendCodeValidatesBeforeSpendingGrant(t *testing.T) {
	for _, target := range []string{"phone", "email"} {
		for _, malformed := range []string{"missing", "empty", "unknown", "duplicate", "escaped_duplicate", "null", "numeric", "trailing", "utf8", "surrogate", "oversized", "query", "empty_query", "noncanonical_destination", "unsupported_sms"} {
			if malformed == "unsupported_sms" && target == "email" {
				continue
			}
			t.Run(target+"/"+malformed, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				value := "+989123456789"
				if target == "email" {
					value = "a@example.invalid"
				}
				body := fmt.Sprintf(`{%q:%q}`, target, value)
				query := ""
				switch malformed {
				case "missing":
					body = `{}`
				case "empty":
					body = fmt.Sprintf(`{%q:""}`, target)
				case "unknown":
					body = strings.TrimSuffix(body, "}") + `,"extra":"x"}`
				case "duplicate":
					body = strings.TrimSuffix(body, "}") + fmt.Sprintf(`,%q:%q}`, target, value)
				case "escaped_duplicate":
					body = strings.TrimSuffix(body, "}") + fmt.Sprintf(`,"\u%04x%s":%q}`, target[0], target[1:], value)
				case "null":
					body = fmt.Sprintf(`{%q:null}`, target)
				case "numeric":
					body = fmt.Sprintf(`{%q:123}`, target)
				case "trailing":
					body += `{}`
				case "utf8":
					body = fmt.Sprintf(`{%q:"`, target) + "\xff" + `"}`
				case "surrogate":
					body = fmt.Sprintf(`{%q:"\ud800"}`, target)
				case "oversized":
					body += strings.Repeat(" ", 8193-len(body))
				case "query":
					query = "?authority=secret"
				case "empty_query":
					query = "?"
				case "noncanonical_destination":
					body = fmt.Sprintf(`{%q:"invalid"}`, target)
				case "unsupported_sms":
					body = `{"phone":"+15550102020"}`
				}
				grant := f.grant(t)
				r := f.request(t, "POST", "/api/v1/users/me/"+target+"/send-code"+query, body)
				r.Header.Set(stepup.HeaderStepUpAuth, grant)
				contactServe(t, f, r, 400)
				if f.contacts.startCalls != 0 || f.store.touches.Load() != 0 {
					t.Fatal("invalid start reached state or renewal")
				}
				if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
					t.Fatal("input preflight spent strong authority")
				}
			})
		}
	}
}

func TestContactAuthorityHeaderStrictMatrix(t *testing.T) {
	for _, operation := range []string{"start", "remove"} {
		for _, malformed := range []string{"missing", "empty_grant", "empty_proof", "duplicate_grant", "duplicate_proof", "mixed", "comma_grant", "comma_proof", "oversized_grant", "oversized_proof", "padded_proof", "noncanonical_proof", "whitespace_grant", "empty_slice", "mixed_casing"} {
			t.Run(operation+"/"+malformed, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				method, path, body := "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`
				if operation == "remove" {
					method, path, body = "DELETE", "/api/v1/users/me/phone", ""
				}
				r := f.request(t, method, path, body)
				grant := f.grant(t)
				proof := f.proofs.handle
				switch malformed {
				case "empty_grant":
					r.Header.Set(stepup.HeaderStepUpAuth, "")
				case "empty_proof":
					r.Header.Set("X-Action-Proof", "")
				case "duplicate_grant":
					r.Header[stepup.HeaderStepUpAuth] = []string{grant, grant}
				case "duplicate_proof":
					r.Header["X-Action-Proof"] = []string{proof, proof}
				case "mixed":
					r.Header.Set(stepup.HeaderStepUpAuth, grant)
					r.Header.Set("X-Action-Proof", proof)
				case "comma_grant":
					r.Header.Set(stepup.HeaderStepUpAuth, grant+",other")
				case "comma_proof":
					r.Header.Set("X-Action-Proof", proof+",other")
				case "oversized_grant":
					r.Header.Set(stepup.HeaderStepUpAuth, strings.Repeat("A", 16385))
				case "oversized_proof":
					r.Header.Set("X-Action-Proof", strings.Repeat("A", 8193))
				case "padded_proof":
					r.Header.Set("X-Action-Proof", proof+"=")
				case "noncanonical_proof":
					r.Header.Set("X-Action-Proof", strings.Repeat("A", 42)+"B")
				case "whitespace_grant":
					r.Header.Set(stepup.HeaderStepUpAuth, " "+grant)
				case "empty_slice":
					r.Header[stepup.HeaderStepUpAuth] = nil
				case "mixed_casing":
					r.Header.Set(stepup.HeaderStepUpAuth, grant)
					r.Header["x-step-up-auth"] = []string{grant}
				}
				contactServe(t, f, r, 403)
				if f.contacts.startCalls+f.contacts.removeCalls != 0 || f.store.touches.Load() != 0 {
					t.Fatal("ambiguous authority reached service")
				}
				if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
					t.Fatal("malformed headers spent grant")
				}
			})
		}
	}
}

func TestContactFinishAndProofVerifyStrictNonburningRequest(t *testing.T) {
	for _, operation := range []string{"phone", "email", "change_proof", "remove_proof"} {
		for _, malformed := range []string{"empty", "missing", "unknown", "duplicate", "null", "numeric", "short_handle", "padded_handle", "noncanonical_handle", "short_code", "spaces", "unicode_code", "trailing", "oversized", "query", "stepup_header", "proof_header", "empty_header"} {
			t.Run(operation+"/"+malformed, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				path := "/api/v1/users/me/" + operation + "/verify"
				name := "verification_id"
				if operation == "change_proof" {
					path = contactChangeProofPath + "/verify"
					name = "challenge"
				}
				if operation == "remove_proof" {
					path = contactRemovalProofPath + "/verify"
					name = "challenge"
				}
				handle, code := f.proofs.handle, "000123"
				query := ""
				switch malformed {
				case "short_handle":
					handle = "short"
				case "padded_handle":
					handle += "="
				case "noncanonical_handle":
					handle = strings.Repeat("A", 42) + "B"
				case "short_code":
					code = "00123"
				case "spaces":
					code = " 00123"
				case "unicode_code":
					code = "\u06f0\u06f0\u06f0\u06f1\u06f2\u06f3"
				case "query":
					query = "?code=000123"
				}
				body := fmt.Sprintf(`{%q:%q,"code":%q}`, name, handle, code)
				switch malformed {
				case "empty":
					body = ""
				case "missing":
					body = fmt.Sprintf(`{%q:%q}`, name, handle)
				case "unknown":
					body = strings.TrimSuffix(body, "}") + `,"target":"email"}`
				case "duplicate":
					body = strings.TrimSuffix(body, "}") + `,"code":"000123"}`
				case "null":
					body = fmt.Sprintf(`{%q:%q,"code":null}`, name, handle)
				case "numeric":
					body = fmt.Sprintf(`{%q:%q,"code":123}`, name, handle)
				case "trailing":
					body += `{}`
				case "oversized":
					body += strings.Repeat(" ", 8193-len(body))
				}
				r := f.request(t, "POST", path+query, body)
				want := 400
				grant := f.grant(t)
				if malformed == "stepup_header" {
					r.Header.Set(stepup.HeaderStepUpAuth, grant)
					want = 403
				}
				if malformed == "proof_header" {
					r.Header.Set("X-Action-Proof", handle)
					want = 403
				}
				if malformed == "empty_header" {
					r.Header.Set("X-Action-Proof", "")
					want = 403
				}
				contactServe(t, f, r, want)
				if f.contacts.finishCalls+f.proofs.verifyCalls != 0 || f.store.touches.Load() != 0 {
					t.Fatal("invalid finish spent attempts or renewed activity")
				}
				if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
					t.Fatal("finish consumed misplaced authority")
				}
			})
		}
	}
}

func TestContactDeleteRequiresExactlyEmptyBodyAndQuery(t *testing.T) {
	for _, target := range []string{"phone", "email"} {
		for _, input := range []string{"{}", " ", "\n", "?", "?target=phone"} {
			t.Run(target+"/"+input, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				query, body := "", input
				if strings.HasPrefix(input, "?") {
					query, body = input, ""
				}
				r := f.request(t, "DELETE", "/api/v1/users/me/"+target+query, body)
				grant := f.grant(t)
				r.Header.Set(stepup.HeaderStepUpAuth, grant)
				contactServe(t, f, r, 400)
				if f.contacts.removeCalls != 0 {
					t.Fatal("nonempty removal reached writer")
				}
				if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
					t.Fatal("nonempty removal spent grant")
				}
			})
		}
	}
}

func TestContactStrongGrantFrozenDTOAndSingleUse(t *testing.T) {
	for _, amr := range [][]string{{"otp"}, {"hwk", "user"}, {"pwd"}, {"email"}, {"sms"}, {"hwk"}, {"user"}, {"webauthn"}, {"recovery"}, {"otp", "email"}} {
		t.Run(strings.Join(amr, "+"), func(t *testing.T) {
			f := newContactHTTPFixture(t)
			grant := mintMFAGrant(t, f.stepUp, f.current, amr)
			r := f.request(t, "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+98 (912) 345-6789"}`)
			r.Header.Set(stepup.HeaderStepUpAuth, grant)
			strong := reflect.DeepEqual(amr, []string{"otp"}) || reflect.DeepEqual(amr, []string{"hwk", "user"})
			want := 403
			if strong {
				want = 200
			}
			contactServe(t, f, r, want)
			if strong {
				auth := f.contacts.auth.Grant
				method := "totp"
				if len(amr) == 2 {
					method = "webauthn_uv"
				}
				if auth == nil || auth.UserID != f.current.UserID || auth.SessionID != f.current.ID || auth.DPoPJKT != f.current.DPoPJKT || auth.AuthVersion != f.current.AuthVersion || auth.Method != method || auth.ExpiresAt.IsZero() || f.contacts.auth.Proof != "" || f.contacts.value != "+989123456789" {
					t.Fatal("grant lost genuine frozen authority or canonical destination")
				}
			}
			r = f.request(t, "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`)
			r.Header.Set(stepup.HeaderStepUpAuth, grant)
			contactServe(t, f, r, 403)
		})
	}
}

func TestContactProofRoutesFixActionTargetAndExactPassword(t *testing.T) {
	for _, action := range []string{contactChangeAction, contactRemovalAction} {
		for _, target := range []string{"phone", "email"} {
			for _, channel := range []string{"email", "sms"} {
				t.Run(action+"/"+target+"/"+channel, func(t *testing.T) {
					f := newContactHTTPFixture(t)
					path := contactChangeProofPath
					if action == contactRemovalAction {
						path = contactRemovalProofPath
					}
					exactBytes := "  P\u00e4ss\x00word  "
					body, _ := json.Marshal(map[string]string{"password": exactBytes, "channel": channel, "target": target})
					w := contactServe(t, f, f.request(t, "POST", path+"/challenge", string(body)), 202)
					if f.proofs.password != exactBytes || f.proofs.action != action || f.proofs.target != target || f.proofs.channel != channel || f.proofs.source != "203.0.113.9" || !reflect.DeepEqual(f.proofs.sess, f.current) {
						t.Fatal("challenge changed exact password or server bindings")
					}
					var challenge map[string]json.RawMessage
					_ = json.Unmarshal(w.Body.Bytes(), &challenge)
					if len(challenge) != 2 || challenge["challenge"] == nil || challenge["expires_at"] == nil {
						t.Fatal("challenge disclosed extra fields")
					}
					body, _ = json.Marshal(map[string]string{"challenge": f.proofs.handle, "code": "000123"})
					contactServe(t, f, f.request(t, "POST", path+"/verify", string(body)), 200)
					if f.proofs.action != action || f.proofs.code != "000123" || f.proofs.challenge != f.proofs.handle {
						t.Fatal("verify altered action, handle or leading zeros")
					}
					start := f.request(t, "POST", "/api/v1/users/me/"+target+"/send-code", fmt.Sprintf(`{%q:%q}`, target, map[string]string{"phone": "+989123456789", "email": "a@example.invalid"}[target]))
					start.Header.Set("X-Action-Proof", f.proofs.handle)
					contactServe(t, f, start, 200)
					if f.contacts.auth.Grant != nil || f.contacts.auth.Proof != f.proofs.handle || f.contacts.target != target {
						t.Fatal("proof substituted strong authority or target")
					}
				})
			}
		}
	}
}

func TestContactProofChallengeStrictSchemaAndMisplacedAuthority(t *testing.T) {
	for _, path := range []string{contactChangeProofPath, contactRemovalProofPath} {
		for _, malformed := range []string{"empty_password", "missing_target", "unknown", "action", "duplicate_target", "null", "numeric", "unsupported_channel", "unsupported_target", "case_alias", "trailing", "oversized", "query", "stepup_header", "proof_header", "empty_header"} {
			t.Run(path+"/"+malformed, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				body, query := `{"password":"exact password","channel":"email","target":"phone"}`, ""
				switch malformed {
				case "empty_password":
					body = `{"password":"","channel":"email","target":"phone"}`
				case "missing_target":
					body = `{"password":"exact password","channel":"email"}`
				case "unknown":
					body = strings.TrimSuffix(body, "}") + `,"destination":"new@example.invalid"}`
				case "action":
					body = strings.TrimSuffix(body, "}") + `,"action":"contact_remove"}`
				case "duplicate_target":
					body = strings.TrimSuffix(body, "}") + `,"target":"email"}`
				case "null":
					body = `{"password":null,"channel":"email","target":"phone"}`
				case "numeric":
					body = `{"password":123,"channel":"email","target":"phone"}`
				case "unsupported_channel":
					body = `{"password":"exact password","channel":"backup","target":"phone"}`
				case "unsupported_target":
					body = `{"password":"exact password","channel":"email","target":"backup_email"}`
				case "case_alias":
					body = `{"password":"exact password","channel":"email","Target":"phone"}`
				case "trailing":
					body += `{}`
				case "oversized":
					body += strings.Repeat(" ", 8193-len(body))
				case "query":
					query = "?target=phone"
				}
				r := f.request(t, "POST", path+"/challenge"+query, body)
				want := 400
				grant := f.grant(t)
				if malformed == "stepup_header" {
					r.Header.Set(stepup.HeaderStepUpAuth, grant)
					want = 403
				}
				if malformed == "proof_header" {
					r.Header.Set("X-Action-Proof", f.proofs.handle)
					want = 403
				}
				if malformed == "empty_header" {
					r.Header.Set("X-Action-Proof", "")
					want = 403
				}
				contactServe(t, f, r, want)
				if f.proofs.challengeCalls != 0 || f.store.touches.Load() != 0 {
					t.Fatal("invalid challenge reached password/delivery or renewed activity")
				}
				if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
					t.Fatal("challenge spent unrelated strong authority")
				}
			})
		}
	}
}

func TestContactProviderPreflightDoesNotSpendGrant(t *testing.T) {
	f := newContactHTTPFixture(t)
	f.contacts.preflightErr = contactcode.ErrDisabled
	grant := f.grant(t)
	r := f.request(t, "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`)
	r.Header.Set(stepup.HeaderStepUpAuth, grant)
	contactServe(t, f, r, 503)
	if f.contacts.startCalls != 0 {
		t.Fatal("disabled delivery preflight started pending state")
	}
	if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
		t.Fatal("disabled delivery spent strong authority")
	}
}

func TestContactIncompleteServiceOutcomesDoNotReleaseAuthority(t *testing.T) {
	for _, operation := range []string{"start", "challenge", "proof_verify"} {
		for _, missing := range []string{"handle", "deadline", "noncanonical_handle"} {
			t.Run(operation+"/"+missing, func(t *testing.T) {
				f := newContactHTTPFixture(t)
				if missing == "handle" {
					f.contacts.result.VerificationID = ""
					f.proofs.handle = ""
				}
				if missing == "deadline" {
					f.contacts.result.ExpiresAt = time.Time{}
					f.proofs.deadline = time.Time{}
				}
				if missing == "noncanonical_handle" {
					f.contacts.result.VerificationID = strings.Repeat("A", 42) + "B"
					f.proofs.handle = f.contacts.result.VerificationID
				}
				path, body := "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`
				if operation == "challenge" {
					path, body = contactChangeProofPath+"/challenge", `{"password":"secret","channel":"email","target":"phone"}`
				}
				if operation == "proof_verify" {
					path, body = contactChangeProofPath+"/verify", `{"challenge":"`+strings.Repeat("A", 43)+`","code":"000123"}`
				}
				r := f.request(t, "POST", path, body)
				if operation == "start" {
					r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t))
				}
				w := contactServe(t, f, r, 503)
				if errorBody(t, w) != "outcome_unknown" || f.store.touches.Load() != 0 || len(w.Result().Cookies()) != 0 {
					t.Fatal("incomplete outcome released a handle or renewed authority")
				}
			})
		}
	}
}

func TestContactCommittedResponsesSurviveRenewalFailure(t *testing.T) {
	for _, operation := range []string{"start", "challenge", "proof_verify", "absent_remove", "unchanged_finish", "changed_finish", "changed_remove"} {
		t.Run(operation, func(t *testing.T) {
			f := newContactHTTPFixture(t)
			f.store.touchErr = session.ErrStoreUnavailable
			before, err := f.manager.LookupByID(t.Context(), f.current.UserID, f.current.ID)
			if err != nil {
				t.Fatal(err)
			}
			method, path, body, want := "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`, 200
			switch operation {
			case "challenge":
				path, body, want = contactChangeProofPath+"/challenge", `{"password":"secret","channel":"email","target":"phone"}`, 202
			case "proof_verify":
				path, body = contactChangeProofPath+"/verify", `{"challenge":"`+f.proofs.handle+`","code":"000123"}`
			case "absent_remove", "changed_remove":
				method, path, body, want = "DELETE", "/api/v1/users/me/phone", "", 204
			case "unchanged_finish", "changed_finish":
				path, body = "/api/v1/users/me/phone/verify", `{"verification_id":"`+f.proofs.handle+`","code":"000123"}`
			}
			changed := strings.HasPrefix(operation, "changed_")
			f.contacts.changed = changed
			r := f.request(t, method, path, body)
			if operation == "start" || strings.HasSuffix(operation, "remove") {
				r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t))
			}
			w := contactServe(t, f, r, want)
			if changed {
				if w.Header().Get(session.HeaderAuthInvalidated) != "true" || len(w.Result().Cookies()) != 1 || f.store.touches.Load() != 0 {
					t.Fatal("known security change renewed session or lost invalidation")
				}
			} else {
				if w.Header().Get(session.HeaderAuthInvalidated) != "" || len(w.Result().Cookies()) != 0 || f.store.touches.Load() != 1 {
					t.Fatal("renewal failure overwrote success or rotated authority")
				}
				after, err := f.manager.LookupByID(t.Context(), f.current.UserID, f.current.ID)
				if err != nil || !before.AbsoluteExpiry.Equal(after.AbsoluteExpiry) || !before.IdleExpiry.Equal(after.IdleExpiry) {
					t.Fatal("failed renewal extended committed authority")
				}
			}
			count := f.audit.count(audit.EventPhoneVerified) + f.audit.count(audit.EventPhoneRemoved)
			if changed && count != 1 || !changed && count != 0 {
				t.Fatal("success audit does not represent actual phone change")
			}
			for _, event := range f.audit.events {
				if !reflect.DeepEqual(event.Payload, map[string]any{"factor": "sms"}) {
					t.Fatal("phone audit disclosed contact or ceremony")
				}
			}
		})
	}
}

func TestContactUnknownOutcomesHaveNoHandleAuditRenewalOrRetry(t *testing.T) {
	for _, operation := range []string{"start", "finish", "remove", "challenge", "proof_verify"} {
		t.Run(operation, func(t *testing.T) {
			f := newContactHTTPFixture(t)
			f.contacts.err = contactmanager.ErrOutcomeUnknown
			f.contacts.changed = true
			f.proofs.err = actionproof.ErrOutcomeUnknown
			method, path, body := "POST", "/api/v1/users/me/phone/send-code", `{"phone":"+989123456789"}`
			switch operation {
			case "finish":
				path, body = "/api/v1/users/me/phone/verify", `{"verification_id":"`+f.proofs.handle+`","code":"000123"}`
			case "remove":
				method, path, body = "DELETE", "/api/v1/users/me/phone", ""
			case "challenge":
				path, body = contactChangeProofPath+"/challenge", `{"password":"secret","channel":"email","target":"email"}`
			case "proof_verify":
				path, body = contactRemovalProofPath+"/verify", `{"challenge":"`+f.proofs.handle+`","code":"000123"}`
			}
			r := f.request(t, method, path, body)
			if operation == "start" || operation == "remove" {
				r.Header.Set(stepup.HeaderStepUpAuth, f.grant(t))
			}
			w := contactServe(t, f, r, 503)
			if errorBody(t, w) != "outcome_unknown" || strings.Contains(w.Body.String(), f.proofs.handle) || len(w.Result().Cookies()) != 0 || w.Header().Get(session.HeaderAuthInvalidated) != "" || f.store.touches.Load() != 0 || len(f.audit.events) != 0 {
				t.Fatal("unknown outcome disclosed tentative success or changed authority")
			}
			if f.contacts.startCalls+f.contacts.finishCalls+f.contacts.removeCalls+f.proofs.challengeCalls+f.proofs.verifyCalls != 1 {
				t.Fatal("unknown outcome retried service")
			}
		})
	}
}

func TestContactCurrentStateMinimalProjection(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			f := newContactHTTPFixture(t)
			if present {
				at := time.Now().UTC().Truncate(time.Microsecond)
				f.contacts.contacts = contactmanager.Contacts{Email: &contactmanager.Contact{Value: "a@example.invalid", Verified: false}, Phone: &contactmanager.Contact{Value: "+989123456789", Verified: true, VerifiedAt: &at}}
			}
			w := contactServe(t, f, f.request(t, "GET", "/api/v1/users/me/contacts", ""), 200)
			var object map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &object) != nil || len(object) != 2 || object["email"] == nil || object["phone"] == nil {
				t.Fatal("current-state projection is not exact nullable pair")
			}
			if !present {
				if string(object["email"]) != "null" || string(object["phone"]) != "null" {
					t.Fatal("absence fabricated contact evidence")
				}
			} else {
				for _, name := range []string{"email", "phone"} {
					var contact map[string]json.RawMessage
					_ = json.Unmarshal(object[name], &contact)
					if len(contact) != 3 || contact["value"] == nil || contact["verified"] == nil || contact["verified_at"] == nil {
						t.Fatal("contact projection exposed internal state")
					}
				}
			}
		})
	}
}

func TestContactCurrentReadRejectsMisplacedAuthorityBodyAndQuery(t *testing.T) {
	for _, malformed := range []string{"grant", "proof", "empty_header", "query", "empty_query", "body"} {
		t.Run(malformed, func(t *testing.T) {
			f := newContactHTTPFixture(t)
			path, body, want := "/api/v1/users/me/contacts", "", 403
			if malformed == "query" {
				path += "?target=email"
				want = 400
			}
			if malformed == "empty_query" {
				path += "?"
				want = 400
			}
			if malformed == "body" {
				body = "{}"
				want = 400
			}
			r := f.request(t, "GET", path, body)
			grant := f.grant(t)
			if malformed == "grant" {
				r.Header.Set(stepup.HeaderStepUpAuth, grant)
			}
			if malformed == "proof" {
				r.Header.Set("X-Action-Proof", f.proofs.handle)
			}
			if malformed == "empty_header" {
				r.Header.Set("X-Action-Proof", "")
			}
			contactServe(t, f, r, want)
			if f.contacts.readCalls != 0 || f.store.touches.Load() != 0 {
				t.Fatal("invalid current-state request disclosed contacts or renewed session")
			}
			if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err != nil {
				t.Fatal("current-state read spent misplaced grant")
			}
		})
	}
}

func TestContactEmailRemovalGateAndNoop(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(fmt.Sprint(absent), func(t *testing.T) {
			f := newContactHTTPFixture(t)
			if !absent {
				f.contacts.err = contactmanager.ErrEmailRemovalUnavailable
			}
			r := f.request(t, "DELETE", "/api/v1/users/me/email", "")
			grant := f.grant(t)
			r.Header.Set(stepup.HeaderStepUpAuth, grant)
			want := 409
			if absent {
				want = 204
			}
			w := contactServe(t, f, r, want)
			if !absent && errorBody(t, w) != "email_removal_unavailable" || len(f.audit.events) != 0 || w.Header().Get(session.HeaderAuthInvalidated) != "" {
				t.Fatal("email removal gate changed state or fabricated success audit")
			}
			if _, err := f.stepUp.Validate(t.Context(), grant, f.current); err == nil {
				t.Fatal("authorized removal did not spend grant")
			}
		})
	}
}

func TestContactLastVerifiedContactConflictConsumesGrantWithoutSuccess(t *testing.T) {
	f := newContactHTTPFixture(t)
	f.contacts.err = accountpolicy.ErrLastVerifiedContact
	grant := f.grant(t)
	r := f.request(t, "DELETE", "/api/v1/users/me/phone", "")
	r.Header.Set(stepup.HeaderStepUpAuth, grant)
	w := contactServe(t, f, r, 409)
	if errorBody(t, w) != "last_verified_contact" || len(f.audit.events) != 0 || f.store.touches.Load() != 0 {
		t.Fatal("last-contact refusal recorded or renewed success")
	}
	r = f.request(t, "DELETE", "/api/v1/users/me/phone", "")
	r.Header.Set(stepup.HeaderStepUpAuth, grant)
	contactServe(t, f, r, 403)
}

func TestPhoneNoCompetingWriterAndReaderSafeMounting(t *testing.T) {
	f := newContactHTTPFixture(t)
	f.server = New(f.server.cfg, f.server.logger, Deps{SessionManager: f.manager, DPoPValidator: f.client.validator})
	contactServe(t, f, f.request(t, "DELETE", "/api/v1/users/me/phone", ""), 404)
	f.server = New(f.server.cfg, f.server.logger, Deps{SessionManager: f.manager, DPoPValidator: f.client.validator, Contacts: f.contacts})
	contactServe(t, f, f.request(t, "POST", "/api/v1/users/me/phone/verify", `{"verification_id":"`+f.proofs.handle+`","code":"000123"}`), 200)
	contactServe(t, f, f.request(t, "POST", "/api/v1/users/me/email/verify", `{"verification_id":"`+f.proofs.handle+`","code":"000123"}`), 200)
	contactServe(t, f, f.request(t, "DELETE", "/api/v1/users/me/phone", ""), 404)
}

func TestContactErrorsDoNotDiscloseDependencyDetails(t *testing.T) {
	for _, err := range []error{errors.New("private-key destination code provider-body"), contactmanager.ErrOutcomeUnknown, contactcode.ErrUnavailable} {
		w := httptest.NewRecorder()
		writeContactError(w, err)
		if w.Code != 503 || strings.Contains(w.Body.String(), "private-key") || strings.Contains(w.Body.String(), "provider-body") {
			t.Fatal("private dependency error disclosed")
		}
	}
}
