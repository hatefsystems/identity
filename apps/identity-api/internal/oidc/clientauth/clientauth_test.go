package clientauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/clients"
	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

const (
	testClientID = "search-core"
	testAudience = "https://identity.hatef.ir/oauth2/token"
)

// signer bundles a private key with the public key registered for a client so
// tests can mint assertions and the Authenticator can verify them.
type signer struct {
	alg  string
	priv crypto.Signer
	pub  *keys.PublicKey
}

// es256Signer generates a P-256 key pair and derives its registered public
// verification key.
func es256Signer(t *testing.T) *signer {
	t.Helper()
	sk, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	pub, err := keys.ParsePublicJWK(sk.PublicJWK)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	return &signer{alg: keys.AlgES256, priv: sk.Signer, pub: pub}
}

// rs256Signer generates a 2048-bit RSA key pair and derives its registered
// public verification key.
func rs256Signer(t *testing.T) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := keys.JWK{
		Kty: "RSA",
		Alg: keys.AlgRS256,
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	pub, err := keys.ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	return &signer{alg: keys.AlgRS256, priv: priv, pub: pub}
}

// sign produces a compact JWS with the given header and claims, signed with
// s.priv. header["alg"] governs the signature scheme actually used so tests
// can also forge headers that disagree with the key.
func (s *signer) sign(t *testing.T, header map[string]any, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch priv := s.priv.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa sign: %v", err)
		}
	case *ecdsa.PrivateKey:
		r, ss, e := ecdsa.Sign(rand.Reader, priv, digest[:])
		if e != nil {
			t.Fatalf("ecdsa sign: %v", e)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	default:
		t.Fatalf("unsupported signer type %T", s.priv)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// standardClaims returns a valid claim set for testClientID at now.
func standardClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": testClientID,
		"sub": testClientID,
		"aud": testAudience,
		"jti": "jti-" + now.Format("150405.000000000"),
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
}

// harness bundles an Authenticator with a fixed clock and the signer whose key
// is registered for testClientID.
type harness struct {
	auth *Authenticator
	sk   *signer
	now  time.Time
}

func newHarness(t *testing.T, sk *signer) *harness {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	registry, err := clients.NewStaticRegistry([]clients.Client{
		{
			ID:                      testClientID,
			RedirectURIs:            []string{"https://search.hatef.ir/callback"},
			TokenEndpointAuthMethod: clients.AuthMethodPrivateKeyJWT,
			AllowedScopes:           []string{"openid", "search.full"},
			PublicKeys:              map[string]*keys.PublicKey{sk.pub.KID: sk.pub},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticRegistry: %v", err)
	}
	// Pin the replay guard to the same fixed clock as the Authenticator so an
	// assertion minted at the harness's "now" is not treated as already expired
	// (and thus evicted) by the guard's real-time TTL eviction.
	guard := NewMemoryJTIGuard()
	guard.now = func() time.Time { return now }
	auth, err := New(registry, testAudience, guard, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{auth: auth, sk: sk, now: now}
}

// form assembles the token-endpoint form for a client assertion.
func form(assertion string) url.Values {
	return url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {AssertionType},
		"client_assertion":      {assertion},
	}
}

// header returns the standard header for the harness signer.
func (h *harness) header() map[string]any {
	return map[string]any{"alg": h.sk.alg, "typ": "JWT", "kid": h.sk.pub.KID}
}

func TestAuthenticateES256HappyPath(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	assertion := h.sk.sign(t, h.header(), standardClaims(h.now))
	client, err := h.auth.Authenticate(context.Background(), form(assertion))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if client.ID != testClientID {
		t.Errorf("client.ID = %q, want %q", client.ID, testClientID)
	}
}

func TestAuthenticateRS256HappyPath(t *testing.T) {
	h := newHarness(t, rs256Signer(t))
	assertion := h.sk.sign(t, h.header(), standardClaims(h.now))
	client, err := h.auth.Authenticate(context.Background(), form(assertion))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if client.ID != testClientID {
		t.Errorf("client.ID = %q, want %q", client.ID, testClientID)
	}
}

func TestAuthenticateWrongAudience(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["aud"] = "https://evil.example/oauth2/token"
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrBadAudience) {
		t.Fatalf("err = %v, want ErrBadAudience", err)
	}
}

func TestAuthenticateExpired(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["exp"] = h.now.Add(-5 * time.Minute).Unix()
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestAuthenticateExcessiveLifetime(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["exp"] = h.now.Add(30 * time.Minute).Unix()
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrExcessiveLifetime) {
		t.Fatalf("err = %v, want ErrExcessiveLifetime", err)
	}
}

func TestAuthenticateMissingExp(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	delete(claims, "exp")
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrInvalidAssertionClaims) {
		t.Fatalf("err = %v, want ErrInvalidAssertionClaims", err)
	}
}

func TestAuthenticateMissingJTI(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	delete(claims, "jti")
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrMissingJTI) {
		t.Fatalf("err = %v, want ErrMissingJTI", err)
	}
}

func TestAuthenticateReplayedJTI(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["jti"] = "fixed-jti"
	assertion := h.sk.sign(t, h.header(), claims)

	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Same assertion again -> replay.
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

func TestAuthenticateUnknownKid(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	hdr := h.header()
	hdr["kid"] = "not-registered"
	assertion := h.sk.sign(t, hdr, standardClaims(h.now))
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestAuthenticateAlgNoneRejected(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	hdr := h.header()
	hdr["alg"] = "none"
	assertion := h.sk.sign(t, hdr, standardClaims(h.now))
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestAuthenticateAlgHS256Rejected(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	hdr := h.header()
	hdr["alg"] = "HS256"
	assertion := h.sk.sign(t, hdr, standardClaims(h.now))
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestAuthenticateIssSubMismatch(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["sub"] = "someone-else"
	assertion := h.sk.sign(t, h.header(), claims)
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrIssuerSubjectMismatch) {
		t.Fatalf("err = %v, want ErrIssuerSubjectMismatch", err)
	}
}

func TestAuthenticateClientIDMismatch(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	assertion := h.sk.sign(t, h.header(), standardClaims(h.now))
	f := form(assertion)
	f.Set("client_id", "different-client")
	if _, err := h.auth.Authenticate(context.Background(), f); !errors.Is(err, ErrClientIDMismatch) {
		t.Fatalf("err = %v, want ErrClientIDMismatch", err)
	}
}

func TestAuthenticateSignatureMismatch(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	// Sign with a DIFFERENT key but present the registered kid/alg header, so
	// key lookup succeeds but verification fails.
	other := es256Signer(t)
	assertion := other.sign(t, h.header(), standardClaims(h.now))
	if _, err := h.auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestAuthenticateUnknownClient(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	claims := standardClaims(h.now)
	claims["iss"] = "ghost"
	claims["sub"] = "ghost"
	assertion := h.sk.sign(t, h.header(), claims)
	_, err := h.auth.Authenticate(context.Background(), form(assertion))
	if err == nil || !errors.Is(err, clients.ErrUnknownClient) {
		t.Fatalf("err = %v, want ErrUnknownClient", err)
	}
}

func TestAuthenticatePublicClientRejected(t *testing.T) {
	sk := es256Signer(t)
	// Registry where the client is public — but we still try to authenticate
	// it via private_key_jwt. The registry itself forbids public clients from
	// carrying keys, so we construct via a custom registry stub.
	reg := &stubRegistry{client: clients.Client{
		ID:                      testClientID,
		RedirectURIs:            []string{"https://x"},
		TokenEndpointAuthMethod: clients.AuthMethodNone,
	}}
	auth, err := New(reg, testAudience, NewMemoryJTIGuard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	hdr := map[string]any{"alg": sk.alg, "typ": "JWT", "kid": sk.pub.KID}
	assertion := sk.sign(t, hdr, standardClaims(now))
	if _, err := auth.Authenticate(context.Background(), form(assertion)); !errors.Is(err, ErrNotConfidentialClient) {
		t.Fatalf("err = %v, want ErrNotConfidentialClient", err)
	}
}

func TestAuthenticateMissingAssertion(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	f := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {AssertionType}}
	if _, err := h.auth.Authenticate(context.Background(), f); !errors.Is(err, ErrMissingAssertion) {
		t.Fatalf("err = %v, want ErrMissingAssertion", err)
	}
}

func TestAuthenticateWrongAssertionType(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	assertion := h.sk.sign(t, h.header(), standardClaims(h.now))
	f := form(assertion)
	f.Set("client_assertion_type", "urn:something:else")
	if _, err := h.auth.Authenticate(context.Background(), f); !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("err = %v, want ErrUnsupportedType", err)
	}
}

func TestAuthenticateMalformedAssertion(t *testing.T) {
	h := newHarness(t, es256Signer(t))
	if _, err := h.auth.Authenticate(context.Background(), form("not.a.jwt.at.all")); !errors.Is(err, ErrMalformedAssertion) {
		t.Fatalf("err = %v, want ErrMalformedAssertion", err)
	}
	if _, err := h.auth.Authenticate(context.Background(), form("only-one-segment")); !errors.Is(err, ErrMalformedAssertion) {
		t.Fatalf("err = %v, want ErrMalformedAssertion", err)
	}
}

func TestNewValidation(t *testing.T) {
	reg := &stubRegistry{}
	if _, err := New(nil, testAudience, NewMemoryJTIGuard()); err == nil {
		t.Error("nil registry must be rejected")
	}
	if _, err := New(reg, "  ", NewMemoryJTIGuard()); err == nil {
		t.Error("empty audience must be rejected")
	}
	if _, err := New(reg, testAudience, nil); err == nil {
		t.Error("nil guard must be rejected")
	}
}

// stubRegistry returns a fixed client for any id (or ErrUnknownClient when
// none is configured).
type stubRegistry struct {
	client clients.Client
}

func (s *stubRegistry) Lookup(_ string) (clients.Client, error) {

	if s.client.ID == "" {
		return clients.Client{}, clients.ErrUnknownClient
	}
	return s.client, nil
}
