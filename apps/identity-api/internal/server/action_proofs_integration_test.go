//go:build integration

package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

// The proof service owns its DB eligibility/issuance/consumption matrix. This
// test exercises the real browser session policy before that service is called.
func TestActionProofHTTPRealSessionPolicyIntegration(t *testing.T) {
	f := newRealLoginFixture(t, false, false)
	loginServer := f.server
	for _, mode := range []string{"authenticated", "default off", "stale version", "suspended", "revoked", "recovery", "changed session"} {
		t.Run(mode, func(t *testing.T) {
			f.server = loginServer
			a := f.account(t, "password_only", false)
			response := f.request(t, f.browser, "/api/v1/auth/login", map[string]string{"username": a.name, "password": a.secret}, 204)
			current, cookies := f.session(t, response), response.Result().Cookies()
			m := &actionProofHTTPMock{handle: "opaque", deadline: time.Now().UTC().Add(time.Minute)}
			deps := Deps{SessionManager: f.manager, DPoPValidator: f.browser.validator, AccountDeletionProofs: m}
			status, key := 0, ""
			switch mode {
			case "default off":
				deps.AccountDeletionProofs = nil
				status = 404
			case "stale version":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, a.user.ID); err != nil {
					t.Fatal("owned account version mutation failed")
				}
				status, key = 401, "session_required"
			case "suspended":
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET status='suspended',auth_version=auth_version+1 WHERE id=$1`, a.user.ID); err != nil {
					t.Fatal("owned account suspension failed")
				}
				status, key = 401, "session_required"
			case "revoked":
				if err := f.manager.RevokeAllForUser(f.ctx, a.user.ID.String()); err != nil {
					t.Fatal("owned session revocation failed")
				}
				status, key = 401, "session_required"
			case "recovery":
				current, cookies = f.browser.issueSession(t, f.manager, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: current.AuthVersion, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
				status, key = 401, "session_required"
			case "changed session":
				_, cookies = f.browser.issueSession(t, f.manager, session.IssueParams{UserID: a.user.ID.String(), AuthVersion: current.AuthVersion, AuthVersionSet: true})
				status, key = 409, "session_changed"
			}
			f.server = New(loginServer.cfg, loginServer.logger, deps)
			h := &boundaryHarness{server: f.server, client: f.browser, current: current, cookies: cookies}
			for _, operation := range []string{"challenge", "verify"} {
				body := `{"password":"opaque","channel":"email"}`
				want := status
				if want == 0 {
					want = http.StatusAccepted
				}
				if operation == "verify" {
					body = `{"challenge":"opaque","code":"123456"}`
					if status == 0 {
						want = http.StatusOK
					}
				}
				w := actionProofHTTPServe(t, f.server, actionProofHTTPRequest(t, h, operation, body), want)
				if key != "" {
					requireActionProofHTTPError(t, w, key)
				}
			}
			if mode == "authenticated" {
				if m.challengeCalls != 1 || m.verifyCalls != 1 || m.sess.ID != current.ID || m.sess.UserID != a.user.ID.String() ||
					m.sess.AuthVersion != current.AuthVersion || m.sess.DPoPJKT != f.browser.jkt || m.sess.Evidence.PrimaryMethod != session.MethodPassword {
					t.Fatal("real password session was not preserved at proof boundary")
				}
			} else if m.challengeCalls+m.verifyCalls != 0 {
				t.Fatal("real session policy denial reached proof service")
			}
		})
	}
}

func TestActionProofHTTPDeletionProofCannotAuthorizeAdminIntegration(t *testing.T) {
	f := newAdminIntegration(t)
	proof := deletionShapedHTTPProof(t)
	for _, tc := range []struct {
		name, role, method, path, body string
	}{
		{"no administrative capabilities", "ordinary", http.MethodGet, "/capabilities", ""},
		{"no privileged account read", "ordinary", http.MethodGet, "/users", ""},
		{"no moderation permission", "support", http.MethodPatch, "/users/" + f.target.ID.String() + "/status", adminStatusBody(t, "banned", "fixture reason", f.target.LifecycleRevision)},
		{"no general step-up for moderator", "moderator", http.MethodPatch, "/users/" + f.target.ID.String() + "/status", adminStatusBody(t, "banned", "fixture reason", f.target.LifecycleRevision)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.request(t, tc.role, tc.method, tc.path, tc.body, proof)
			if w.Code != http.StatusForbidden || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-Step-Up-Auth") != "" {
				t.Fatal("deletion-shaped proof acquired administrative or step-up authority")
			}
			if tc.role == "moderator" {
				var body stepUpErrorResponse
				if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error != "insufficient_user_authentication" {
					t.Fatal("privileged mutation did not retain its existing step-up gate")
				}
			} else {
				requireActionProofHTTPError(t, w, "forbidden")
			}
			current, err := db.New(f.pool).GetUserByID(t.Context(), f.target.ID)
			if err != nil || !reflect.DeepEqual(current, f.target) || f.sessionStore.touches.Load() != 0 {
				t.Fatal("proof substitution changed target account, deletion state or session activity")
			}
		})
	}
}
