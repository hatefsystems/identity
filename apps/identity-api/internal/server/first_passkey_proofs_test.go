package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hatefsystems/identity/apps/identity-api/internal/actionproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/session"
)

type firstPasskeyHTTPMock struct{ actionProofHTTPMock }

func (m *firstPasskeyHTTPMock) ChallengeFirstPasskey(ctx context.Context, sess session.Session, password, channel, sourceIP string) (string, time.Time, error) {
	return m.Challenge(ctx, sess, password, channel, sourceIP)
}

func (m *firstPasskeyHTTPMock) VerifyFirstPasskey(ctx context.Context, sess session.Session, challenge, code string) (string, time.Time, error) {
	return m.Verify(ctx, sess, challenge, code)
}

func (*firstPasskeyHTTPMock) CheckFirstPasskey(context.Context, session.Session, string) error {
	return actionproof.ErrInvalid
}

func (*firstPasskeyHTTPMock) ConsumeFirstPasskeyStartTx(context.Context, pgx.Tx, session.Session, string) (actionproof.FirstPasskeyAuthorization, error) {
	return actionproof.FirstPasskeyAuthorization{}, actionproof.ErrInvalid
}

func (*firstPasskeyHTTPMock) ValidateFirstPasskeyTx(context.Context, pgx.Tx, session.Session, actionproof.FirstPasskeyAuthorization) error {
	return actionproof.ErrInvalid
}

func TestFirstPasskeyProofHTTPPurposeAndExactRequest(t *testing.T) {
	for _, channel := range []string{"email", "sms"} {
		t.Run(channel, func(t *testing.T) {
			h, generic := newActionProofHTTPFixture(t)
			m := &firstPasskeyHTTPMock{*generic}
			h.server = New(h.server.cfg, h.server.logger, Deps{SessionManager: h.manager, DPoPValidator: h.client.validator, FirstPasskeyProofs: m})
			request := func(operation, body string) *http.Request {
				r := httptest.NewRequest(http.MethodPost, firstPasskeyProofPath+"/"+operation, strings.NewReader(body))
				r.RemoteAddr = "203.0.113.8:4242"
				h.client.authorize(t, r, h.current, h.cookies...)
				return r
			}
			for _, body := range []string{`{}`, `{"password":"opaque","channel":"email","action":"password_change"}`, `{"password":"opaque","channel":"email","channel":"sms"}`} {
				actionProofHTTPServe(t, h.server, request("challenge", body), 400)
			}
			if m.challengeCalls != 0 {
				t.Fatal("invalid first proof request reached service")
			}
			submitted := "  exact\x00 bytes  "
			w := actionProofHTTPServe(t, h.server, request("challenge", loginHTTPBody(t, map[string]string{"password": submitted, "channel": channel})), 202)
			if m.first != submitted || m.second != channel || m.sess != h.current || m.sourceIP != "203.0.113.8" {
				t.Fatal("first proof body/binding/source changed")
			}
			var challenged struct {
				Challenge string    `json:"challenge"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if json.Unmarshal(w.Body.Bytes(), &challenged) != nil || challenged.Challenge != m.handle || !challenged.ExpiresAt.Equal(m.deadline) {
				t.Fatal("first proof challenge lost original deadline")
			}
			w = actionProofHTTPServe(t, h.server, request("verify", loginHTTPBody(t, map[string]string{"challenge": challenged.Challenge, "code": "000042"})), 200)
			var verified struct {
				Proof     string    `json:"action_proof"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if json.Unmarshal(w.Body.Bytes(), &verified) != nil || verified.Proof != m.handle || !verified.ExpiresAt.Equal(challenged.ExpiresAt) || m.verifyCalls != 1 {
				t.Fatal("first proof verify lost purpose/deadline")
			}
			for _, path := range []string{accountDeletionProofPath, passwordChangeProofPath} {
				r := httptest.NewRequest(http.MethodPost, path+"/challenge", strings.NewReader(`{}`))
				h.client.authorize(t, r, h.current, h.cookies...)
				actionProofHTTPServe(t, h.server, r, 404)
			}
		})
	}
}

func TestFirstPasskeyProofHTTPDefaultOffRecoveryAndUncertainty(t *testing.T) {
	for _, mode := range []string{"default-off", "recovery", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			h, generic := newActionProofHTTPFixture(t)
			m := &firstPasskeyHTTPMock{*generic}
			deps := Deps{SessionManager: h.manager, DPoPValidator: h.client.validator}
			status := 404
			if mode != "default-off" {
				deps.FirstPasskeyProofs = m
			}
			h.server = New(h.server.cfg, h.server.logger, deps)
			r := httptest.NewRequest(http.MethodPost, firstPasskeyProofPath+"/challenge", strings.NewReader(`{"password":"opaque","channel":"email"}`))
			h.client.authorize(t, r, h.current, h.cookies...)
			switch mode {
			case "recovery":
				current, cookies := h.client.issueSession(t, h.manager, session.IssueParams{UserID: h.current.UserID, AuthVersion: h.current.AuthVersion, AuthVersionSet: true, Kind: session.KindRecoveryEnrollment})
				r.Header.Del("Cookie")
				r.AddCookie(cookies[0])
				r.Header.Set(portalSessionHeader, current.ID)
				status = 401
			case "unknown":
				m.err, status = actionproof.ErrOutcomeUnknown, 503
			}
			w := actionProofHTTPServe(t, h.server, r, status)
			if mode == "unknown" {
				requireActionProofHTTPError(t, w, "outcome_unknown")
			} else if m.challengeCalls != 0 {
				t.Fatal("absent/recovery proof route reached service")
			}
		})
	}
}
