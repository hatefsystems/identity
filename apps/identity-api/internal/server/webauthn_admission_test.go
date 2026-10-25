package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/dpop"
	"github.com/hatefsystems/identity/apps/identity-api/internal/ratelimit"
)

func TestWebAuthnAdmissionPrecedesNonceAllocationOnBothLoginRoutes(t *testing.T) {
	for _, path := range []string{"/api/v1/auth/webauthn/login/generate-options", "/api/v1/auth/webauthn/login/verify"} {
		t.Run(path, func(t *testing.T) {
			mini := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mini.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
			t.Cleanup(func() { _ = client.Close() })
			limiter, err := ratelimit.NewRedisLimiter(client)
			if err != nil {
				t.Fatal(err)
			}
			nonces, err := dpop.NewRedisNonceStore(client)
			if err != nil {
				t.Fatal(err)
			}
			replay, err := dpop.NewRedisReplayGuard(client)
			if err != nil {
				t.Fatal(err)
			}
			validator, err := dpop.NewValidator(replay, nonces)
			if err != nil {
				t.Fatal(err)
			}
			fx := newWebAuthnTestServer(t)
			fx.srv.deps.WebAuthnLimiter, fx.srv.deps.DPoPValidator = limiter, validator
			proof := fx.browser.proof(t, httptest.NewRequest(http.MethodPost, path, nil), "")
			request := func(remote string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{}`))
				req.RemoteAddr = remote
				req.Header.Set("X-Forwarded-For", "192.0.2.99") // Not a trusted proxy.
				fx.browser.prepare(req)
				req.Header.Set(dpop.HeaderProof, proof)
				rec := httptest.NewRecorder()
				fx.srv.Handler().ServeHTTP(rec, req)
				return rec
			}
			for range webAuthnChallengeSubnetLimit {
				rec := request("203.0.113.1:1234")
				if rec.Code != http.StatusUnauthorized || decodeWebAuthnError(t, rec).Error != "use_dpop_nonce" || rec.Header().Get(dpop.HeaderNonce) == "" {
					t.Fatalf("admitted nonce challenge: %d %s", rec.Code, rec.Body.String())
				}
			}
			before := len(mini.Keys())
			rec := request("203.0.113.250:9999")
			if rec.Code != http.StatusTooManyRequests || decodeWebAuthnError(t, rec).Error != "rate_limited" || rec.Header().Get("Retry-After") != "60" {
				t.Fatalf("same-subnet quota: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get(dpop.HeaderNonce) != "" || len(mini.Keys()) != before {
				t.Fatal("quota rejection allocated a nonce or challenge")
			}
			if rec := request("203.0.114.1:1234"); rec.Code != http.StatusUnauthorized || rec.Header().Get(dpop.HeaderNonce) == "" {
				t.Fatalf("another subnet was not independently admitted: %d", rec.Code)
			}
			mini.SetError("ERR unavailable")
			if rec := request("203.0.114.1:1234"); rec.Code != http.StatusServiceUnavailable || rec.Header().Get(dpop.HeaderNonce) != "" {
				t.Fatalf("limiter outage reached nonce allocation: %d", rec.Code)
			}
		})
	}
}

type webAuthnAdmissionFailure struct{ seenDeadline bool }

func (f *webAuthnAdmissionFailure) Allow(ctx context.Context, _ string, _ int, _ time.Duration) (bool, error) {
	deadline, ok := ctx.Deadline()
	f.seenDeadline = ok && time.Until(deadline) <= 2*time.Second
	return false, errors.New("unavailable")
}

func TestWebAuthnAdmissionFailsClosedOutsideDevelopment(t *testing.T) {
	fx := newWebAuthnTestServer(t)
	fx.srv.cfg.Environment = "production"
	for _, configured := range []bool{false, true} {
		failure := &webAuthnAdmissionFailure{}
		if configured {
			fx.srv.deps.WebAuthnLimiter = failure
		}
		rec := fx.do(http.MethodPost, "/api/v1/auth/webauthn/login/verify", []byte(`{}`), nil)
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(dpop.HeaderNonce) != "" || decodeWebAuthnError(t, rec).Error != "temporarily_unavailable" {
			t.Fatalf("unavailable admission: %d %s", rec.Code, rec.Body.String())
		}
		if configured && !failure.seenDeadline {
			t.Fatal("limiter did not receive a bounded request context")
		}
	}
}
