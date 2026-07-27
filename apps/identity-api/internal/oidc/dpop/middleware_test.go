package dpop

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	mwBaseURL  = "https://identity.hatef.ir"
	mwPath     = "/api/v1/resource"
	mwFullHTU  = mwBaseURL + mwPath
	mwHTMethod = http.MethodGet
)

// newMiddlewareHarness builds a Middleware around a fixed-clock validator and a
// terminal handler that records whether it ran and what proof it saw.
func newMiddlewareHarness(t *testing.T, now time.Time, requireNonce bool) (*Middleware, *bool, **Proof, NonceStore) {
	t.Helper()
	store := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
	v, err := NewValidator(NewMemoryReplayGuard(), store, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	m, err := NewMiddleware(v, mwBaseURL, WithRequireNonce(requireNonce))
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	return m, new(bool), new(*Proof), store
}

// resourceClaims builds a claim set bound to the resource endpoint.
func resourceClaims(now time.Time) proofClaims {
	iat := now.Unix()
	return proofClaims{jti: "jti-" + randToken(), htm: mwHTMethod, htu: mwFullHTU, iat: &iat}
}

func serve(m *Middleware, ran *bool, seen **Proof, req *http.Request) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		*ran = true
		*seen = ProofFromContext(r.Context())
	})
	rec := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rec, req)
	return rec
}

func TestMiddlewareMissingProofUnauthorized(t *testing.T) {
	m, ran, seen, _ := newMiddlewareHarness(t, time.Now(), false)
	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	rec := serve(m, ran, seen, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *ran {
		t.Fatal("next handler must not run without a proof")
	}
	if auth := rec.Header().Get("WWW-Authenticate"); auth == "" {
		t.Error("missing WWW-Authenticate challenge")
	}
}

func TestMiddlewareHappyPath(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, false)
	s := newES256Signer(t)

	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req.Header.Set(HeaderProof, s.sign(t, resourceClaims(now), TypDPoP, s.alg, nil))

	rec := serve(m, ran, seen, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !*ran {
		t.Fatal("next handler must run on a valid proof")
	}
	if *seen == nil {
		t.Fatal("proof must be injected into the request context")
	}
	wantJKT, _ := keysThumbprint(t, s)
	if (*seen).JKT != wantJKT {
		t.Errorf("context proof JKT = %q, want %q", (*seen).JKT, wantJKT)
	}
}

func TestMiddlewareRequireNonceChallenge(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, true)
	s := newES256Signer(t)

	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req.Header.Set(HeaderProof, s.sign(t, resourceClaims(now), TypDPoP, s.alg, nil))

	rec := serve(m, ran, seen, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if *ran {
		t.Fatal("next handler must not run when a nonce is required")
	}
	if nonce := rec.Header().Get(HeaderNonce); nonce == "" {
		t.Fatal("challenge must supply a fresh DPoP-Nonce header")
	}
	if auth := rec.Header().Get("WWW-Authenticate"); auth == "" {
		t.Error("missing WWW-Authenticate challenge")
	}
}

func TestMiddlewareRequireNonceRetrySucceeds(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, true)
	s := newES256Signer(t)

	// First request obtains the nonce from the challenge.
	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req.Header.Set(HeaderProof, s.sign(t, resourceClaims(now), TypDPoP, s.alg, nil))
	rec := serve(m, ran, seen, req)
	nonce := rec.Header().Get(HeaderNonce)
	if nonce == "" {
		t.Fatal("expected a nonce on the challenge")
	}

	// Retry echoing the nonce.
	c := resourceClaims(now)
	c.nonce = nonce
	req2 := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req2.Header.Set(HeaderProof, s.sign(t, c, TypDPoP, s.alg, nil))
	rec2 := serve(m, ran, seen, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", rec2.Code)
	}
	if !*ran {
		t.Fatal("next handler must run on the nonce retry")
	}
}

func TestMiddlewareReplayRejected(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, false)
	s := newES256Signer(t)
	proof := s.sign(t, resourceClaims(now), TypDPoP, s.alg, nil)

	req1 := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req1.Header.Set(HeaderProof, proof)
	if rec := serve(m, ran, seen, req1); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec.Code)
	}

	*ran = false
	req2 := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req2.Header.Set(HeaderProof, proof)
	rec := serve(m, ran, seen, req2)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec.Code)
	}
	if *ran {
		t.Fatal("next handler must not run on a replayed proof")
	}
}

func TestMiddlewareATHBinding(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, false)
	s := newES256Signer(t)
	accessToken := "resource-access-token"

	c := resourceClaims(now)
	c.ath = AccessTokenHash(accessToken)
	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req.Header.Set(HeaderProof, s.sign(t, c, TypDPoP, s.alg, nil))
	req.Header.Set("Authorization", "DPoP "+accessToken)

	rec := serve(m, ran, seen, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (ath bound)", rec.Code)
	}
	if !*ran {
		t.Fatal("next handler must run when ath matches")
	}
}

func TestMiddlewareATHMismatchRejected(t *testing.T) {
	now := time.Now()
	m, ran, seen, _ := newMiddlewareHarness(t, now, false)
	s := newES256Signer(t)

	c := resourceClaims(now)
	c.ath = AccessTokenHash("some-other-token")
	req := httptest.NewRequest(mwHTMethod, mwPath, nil)
	req.Header.Set(HeaderProof, s.sign(t, c, TypDPoP, s.alg, nil))
	req.Header.Set("Authorization", "DPoP the-real-token")

	rec := serve(m, ran, seen, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (ath mismatch)", rec.Code)
	}
	if *ran {
		t.Fatal("next handler must not run on ath mismatch")
	}
}

func TestNewMiddlewareValidation(t *testing.T) {
	if _, err := NewMiddleware(nil, mwBaseURL); err == nil {
		t.Error("expected error for nil validator")
	}
	v, _ := NewValidator(NewMemoryReplayGuard(), nil)
	if _, err := NewMiddleware(v, "   "); err == nil {
		t.Error("expected error for empty base URL")
	}
}

func TestBearerDPoPToken(t *testing.T) {
	if tok, ok := bearerDPoPToken("DPoP abc.def.ghi"); !ok || tok != "abc.def.ghi" {
		t.Errorf("DPoP scheme: got %q,%v", tok, ok)
	}
	if _, ok := bearerDPoPToken("Bearer abc"); ok {
		t.Error("Bearer scheme must not be accepted as DPoP")
	}
	if _, ok := bearerDPoPToken(""); ok {
		t.Error("empty header must not parse")
	}
	if _, ok := bearerDPoPToken("DPoP "); ok {
		t.Error("empty token must not parse")
	}
}

// keysThumbprint returns the RFC 7638 thumbprint of the signer's public JWK.
func keysThumbprint(t *testing.T, s *proofSigner) (string, error) {
	t.Helper()
	proof, err := ParseProof(s.signValid(t, time.Now()))
	if err != nil {
		return "", err
	}
	return proof.JKT, nil
}
