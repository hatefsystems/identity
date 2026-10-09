package dpop

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
	"strings"
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

const (
	testHTM      = "POST"
	testHTU      = "https://identity.hatef.ir/oauth2/token"
	testRealm    = "authorization:https://identity.hatef.ir"
	testStoreJKT = "test-key-thumbprint"
)

// proofSigner carries the key material used to mint test DPoP proofs and the
// public JWK that gets embedded in the proof header.
type proofSigner struct {
	alg    string
	signer crypto.Signer
	jwk    keys.JWK
}

// newES256Signer builds an ES256 proof signer from a fresh P-256 key.
func newES256Signer(t *testing.T) *proofSigner {
	t.Helper()
	sk, err := keys.NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	return &proofSigner{alg: keys.AlgES256, signer: sk.Signer, jwk: sk.PublicJWK}
}

// newRS256Signer builds an RS256 proof signer from a fresh 2048-bit RSA key.
func newRS256Signer(t *testing.T) *proofSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := keys.JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: keys.AlgRS256,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	return &proofSigner{alg: keys.AlgRS256, signer: key, jwk: jwk}
}

// proofClaims is a mutable claim set for building test proofs.
type proofClaims struct {
	jti       string
	htm       string
	htu       string
	iat       *int64
	nonce     string
	ath       string
	overrides map[string]any
}

// defaultClaims returns a well-formed claim set bound to the token endpoint.
func defaultClaims(now time.Time) proofClaims {
	iat := now.Unix()
	return proofClaims{jti: "jti-" + randToken(), htm: testHTM, htu: testHTU, iat: &iat}
}

// sign builds a compact DPoP proof JWS from the given header overrides and
// claims. rawJWK, when non-nil, replaces the embedded JWK entirely (used to
// inject private members or malformed keys).
func (p *proofSigner) sign(t *testing.T, c proofClaims, typ, alg string, rawJWK json.RawMessage) string {
	t.Helper()

	jwkBytes := rawJWK
	if jwkBytes == nil {
		b, err := json.Marshal(p.jwk)
		if err != nil {
			t.Fatalf("marshal jwk: %v", err)
		}
		jwkBytes = b
	}

	header := map[string]any{"typ": typ, "alg": alg, "jwk": json.RawMessage(jwkBytes)}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	claims := map[string]any{}
	if c.jti != "" {
		claims["jti"] = c.jti
	}
	if c.htm != "" {
		claims["htm"] = c.htm
	}
	if c.htu != "" {
		claims["htu"] = c.htu
	}
	if c.iat != nil {
		claims["iat"] = *c.iat
	}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	if c.ath != "" {
		claims["ath"] = c.ath
	}
	for name, value := range c.overrides {
		claims[name] = value
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))

	var sig []byte
	switch s := p.signer.(type) {
	case *ecdsa.PrivateKey:
		r, ss, err := ecdsa.Sign(rand.Reader, s, digest[:])
		if err != nil {
			t.Fatalf("ecdsa sign: %v", err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, s, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa sign: %v", err)
		}
	default:
		t.Fatalf("unsupported signer %T", p.signer)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signValid mints a valid proof for the current time.
func (p *proofSigner) signValid(t *testing.T, now time.Time) string {
	t.Helper()
	return p.sign(t, defaultClaims(now), TypDPoP, p.alg, nil)
}

func (p *proofSigner) thumbprint(t *testing.T) string {
	t.Helper()
	jkt, err := keys.Thumbprint(p.jwk)
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	return jkt
}

// randToken returns a short random base64url token for unique jti values.
func randToken() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// fixedClock returns a clock function pinned to t.
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func TestParseProofValidES256(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	proof, err := ParseProof(s.signValid(t, now))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	wantJKT, _ := keys.Thumbprint(s.jwk)
	if proof.JKT != wantJKT {
		t.Errorf("JKT = %q, want %q", proof.JKT, wantJKT)
	}
	if proof.HTM != testHTM || proof.HTU != testHTU {
		t.Errorf("htm/htu = %q/%q", proof.HTM, proof.HTU)
	}
	if proof.JTI == "" {
		t.Error("empty jti")
	}
}

func TestParseProofValidRS256(t *testing.T) {
	now := time.Now()
	s := newRS256Signer(t)
	proof, err := ParseProof(s.signValid(t, now))
	if err != nil {
		t.Fatalf("ParseProof: %v", err)
	}
	wantJKT, _ := keys.Thumbprint(s.jwk)
	if proof.JKT != wantJKT {
		t.Errorf("JKT = %q, want %q", proof.JKT, wantJKT)
	}
}

func TestParseProofRejectsWrongType(t *testing.T) {
	s := newES256Signer(t)
	compact := s.sign(t, defaultClaims(time.Now()), "jwt", s.alg, nil)
	if _, err := ParseProof(compact); !errors.Is(err, ErrWrongType) {
		t.Fatalf("err = %v, want ErrWrongType", err)
	}
}

func TestParseProofRejectsNoneAlg(t *testing.T) {
	s := newES256Signer(t)
	compact := s.sign(t, defaultClaims(time.Now()), TypDPoP, "none", nil)
	if _, err := ParseProof(compact); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestParseProofRejectsHS256(t *testing.T) {
	s := newES256Signer(t)
	compact := s.sign(t, defaultClaims(time.Now()), TypDPoP, "HS256", nil)
	if _, err := ParseProof(compact); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestParseProofRejectsPrivateJWK(t *testing.T) {
	s := newES256Signer(t)
	// Embed a private "d" member alongside the public EC parameters.
	var obj map[string]any
	b, _ := json.Marshal(s.jwk)
	_ = json.Unmarshal(b, &obj)
	obj["d"] = base64.RawURLEncoding.EncodeToString([]byte("private-scalar"))
	raw, _ := json.Marshal(obj)

	compact := s.sign(t, defaultClaims(time.Now()), TypDPoP, s.alg, raw)
	if _, err := ParseProof(compact); !errors.Is(err, ErrPrivateJWK) {
		t.Fatalf("err = %v, want ErrPrivateJWK", err)
	}
}

func TestParseProofRejectsHeaderKeyMismatch(t *testing.T) {
	s := newES256Signer(t)
	// EC key but header claims RS256.
	compact := s.sign(t, defaultClaims(time.Now()), TypDPoP, keys.AlgRS256, nil)
	if _, err := ParseProof(compact); err == nil {
		t.Fatal("expected error for alg/key mismatch")
	}
}

func TestParseProofRejectsTamperedSignature(t *testing.T) {
	s := newES256Signer(t)
	compact := s.signValid(t, time.Now())

	// Tamper with the decoded signature bytes rather than the last base64
	// character. An ES256 signature is 64 bytes, so its base64url encoding ends
	// on a partial group whose trailing bits are padding: substituting that
	// character can decode to the identical byte string, leaving the proof
	// valid. Flipping a bit in the first byte always changes the signature.
	dot := strings.LastIndex(compact, ".")
	if dot < 0 {
		t.Fatalf("compact proof %q has no signature segment", compact)
	}
	signature, err := base64.RawURLEncoding.DecodeString(compact[dot+1:])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("signature segment is empty")
	}
	signature[0] ^= 0x01
	tampered := compact[:dot+1] + base64.RawURLEncoding.EncodeToString(signature)
	if tampered == compact {
		t.Fatal("tampering did not change the proof")
	}

	if _, err := ParseProof(tampered); !errors.Is(err, ErrSignature) && !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("err = %v, want ErrSignature/ErrMalformedProof", err)
	}
}

func TestParseProofRejectsMalformed(t *testing.T) {
	if _, err := ParseProof("not-a-jwt"); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("err = %v, want ErrMalformedProof", err)
	}
	if _, err := ParseProof(""); !errors.Is(err, ErrMissingProof) {
		t.Fatalf("err = %v, want ErrMissingProof", err)
	}
}

func newTestValidator(t *testing.T, now time.Time, nonces NonceStore) *Validator {
	t.Helper()
	guard := NewMemoryReplayGuard()
	guard.now = fixedClock(now)
	v, err := NewValidator(guard, nonces, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestValidateHappyPath(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)

	proof, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if proof.JTI == "" {
		t.Error("expected jti")
	}
}

func TestValidateMethodMismatch(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: "GET", URL: testHTU,
	})
	if !errors.Is(err, ErrMethodMismatch) {
		t.Fatalf("err = %v, want ErrMethodMismatch", err)
	}
}

func TestValidateURIMismatch(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: "https://identity.hatef.ir/oauth2/other",
	})
	if !errors.Is(err, ErrURIMismatch) {
		t.Fatalf("err = %v, want ErrURIMismatch", err)
	}
}

func TestValidateURICaseAndDefaultPortInsensitive(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	// Scheme/host case and an explicit default port do not change the URI.
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: "https://IDENTITY.hatef.ir:443/oauth2/token",
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateStaleProof(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	// Proof minted 10 minutes ago; validator clock is now.
	old := now.Add(-10 * time.Minute)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, old), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU,
	})
	if !errors.Is(err, ErrStaleProof) {
		t.Fatalf("err = %v, want ErrStaleProof", err)
	}
}

func TestValidateFutureProof(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	future := now.Add(1 * time.Hour)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, future), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU,
	})
	if !errors.Is(err, ErrStaleProof) {
		t.Fatalf("err = %v, want ErrStaleProof", err)
	}
}

func TestValidateMissingIAT(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	c := defaultClaims(now)
	c.iat = nil
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU,
	})
	if !errors.Is(err, ErrMissingIAT) {
		t.Fatalf("err = %v, want ErrMissingIAT", err)
	}
}

func TestValidateMissingJTI(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	c := defaultClaims(now)
	c.jti = ""
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU,
	})
	if !errors.Is(err, ErrMissingJTI) {
		t.Fatalf("err = %v, want ErrMissingJTI", err)
	}
}

func TestValidateReplayRejected(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	compact := s.signValid(t, now)

	if _, err := v.Validate(context.Background(), compact, VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU}); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	_, err := v.Validate(context.Background(), compact, VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU})
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("err = %v, want ErrReplay", err)
	}
}

func TestValidateATHBinding(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	accessToken := "an-access-token"

	c := defaultClaims(now)
	c.ath = AccessTokenHash(accessToken)
	proof := s.sign(t, c, TypDPoP, s.alg, nil)
	if _, err := v.Validate(context.Background(), proof, VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, AccessToken: accessToken,
	}); err != nil {
		t.Fatalf("Validate with ath: %v", err)
	}
}

func TestValidateATHMissing(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, AccessToken: "tok",
	})
	if !errors.Is(err, ErrMissingATH) {
		t.Fatalf("err = %v, want ErrMissingATH", err)
	}
}

func TestValidateATHMismatch(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	c := defaultClaims(now)
	c.ath = AccessTokenHash("some-other-token")
	proof := s.sign(t, c, TypDPoP, s.alg, nil)
	_, err := v.Validate(context.Background(), proof, VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, AccessToken: "the-real-token",
	})
	if !errors.Is(err, ErrATHMismatch) {
		t.Fatalf("err = %v, want ErrATHMismatch", err)
	}
}

func TestValidateNonceRequiredWithoutNonce(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	store := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
	v := newTestValidator(t, now, store)

	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: true,
	})
	if !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("err = %v, want ErrNonceRequired", err)
	}
}

func TestValidateNonceHappyPath(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	store := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
	v := newTestValidator(t, now, store)

	nonce, err := v.IssueNonce(context.Background(), testRealm, s.thumbprint(t))
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	c := defaultClaims(now)
	c.nonce = nonce
	proof := s.sign(t, c, TypDPoP, s.alg, nil)
	if _, err := v.Validate(context.Background(), proof, VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: true,
	}); err != nil {
		t.Fatalf("Validate with nonce: %v", err)
	}
}

func TestValidateNonceRejectsUnknownNonce(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	store := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
	v := newTestValidator(t, now, store)

	c := defaultClaims(now)
	c.nonce = "not-a-real-nonce"
	proof := s.sign(t, c, TypDPoP, s.alg, nil)
	_, err := v.Validate(context.Background(), proof, VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: true,
	})
	if !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("err = %v, want ErrNonceRequired", err)
	}
}

func TestNonceRequiredWithoutStoreErrors(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil) // no nonce store
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: true,
	})
	if err == nil || errors.Is(err, ErrNonceRequired) {
		t.Fatalf("err = %v, want configuration error", err)
	}
}

func TestAccessTokenHashKnownVector(t *testing.T) {
	// ath is base64url(SHA-256(token)).
	sum := sha256.Sum256([]byte("token"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := AccessTokenHash("token"); got != want {
		t.Errorf("AccessTokenHash = %q, want %q", got, want)
	}
}

type replayGuardFunc func(context.Context, string, time.Time) (bool, error)

func (f replayGuardFunc) Remember(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	return f(ctx, key, expiresAt)
}

type nonceStoreFuncs struct {
	issue    func(context.Context, string, string) (string, error)
	validate func(context.Context, string, string, string) (bool, error)
}

func (s nonceStoreFuncs) Issue(ctx context.Context, realm, jkt string) (string, error) {
	return s.issue(ctx, realm, jkt)
}

func (s nonceStoreFuncs) Validate(ctx context.Context, realm, jkt, nonce string) (bool, error) {
	return s.validate(ctx, realm, jkt, nonce)
}

func TestParseProofSizeLimit(t *testing.T) {
	s := newES256Signer(t)
	c := defaultClaims(time.Now())
	base := s.sign(t, c, TypDPoP, s.alg, nil)
	c.jti += strings.Repeat("x", (MaxProofSize-len(base))*3/4)
	compact := s.sign(t, c, TypDPoP, s.alg, nil)
	if len(compact) > MaxProofSize || len(compact) < MaxProofSize-2 {
		t.Fatalf("boundary fixture size = %d", len(compact))
	}
	if _, err := ParseProof(compact); err != nil {
		t.Fatalf("bounded proof: %v", err)
	}
	c.jti += "xxxx"
	oversized := s.sign(t, c, TypDPoP, s.alg, nil)
	if len(oversized) <= MaxProofSize {
		t.Fatal("fixture must exceed the compact proof limit")
	}
	if proof, err := ParseProof(oversized); proof != nil || err != ErrMalformedProof {
		t.Fatalf("oversized proof = %v, %v", proof, err)
	}
	if _, err := ParseProof(strings.Repeat(" ", MaxProofSize+1)); err != ErrMalformedProof {
		t.Fatalf("oversized blank proof: %v", err)
	}
}

func TestParseProofRejectsMalformedClaimTypes(t *testing.T) {
	s := newES256Signer(t)
	for _, tc := range []struct {
		name  string
		claim string
		value any
	}{
		{"numeric jti", "jti", 7},
		{"numeric method", "htm", 7},
		{"array URI", "htu", []string{testHTU}},
		{"string iat", "iat", "123"},
		{"fractional iat", "iat", 123.5},
		{"overflow iat", "iat", json.Number("9223372036854775808")},
		{"numeric nonce", "nonce", 7},
		{"boolean ath", "ath", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultClaims(time.Now())
			c.overrides = map[string]any{tc.claim: tc.value}
			proof, err := ParseProof(s.sign(t, c, TypDPoP, s.alg, nil))
			if proof != nil || err != ErrMalformedProof {
				t.Fatalf("malformed claim = %v, %v", proof, err)
			}
		})
	}
}

func TestValidateClaimNamesAreCaseSensitive(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	for _, tc := range []struct {
		name   string
		change func(*proofClaims)
		want   error
	}{
		{"JTI", func(c *proofClaims) { c.jti = ""; c.overrides = map[string]any{"JTI": "identifier"} }, ErrMissingJTI},
		{"HTM", func(c *proofClaims) { c.htm = ""; c.overrides = map[string]any{"HTM": testHTM} }, ErrMethodMismatch},
		{"HTU", func(c *proofClaims) { c.htu = ""; c.overrides = map[string]any{"HTU": testHTU} }, ErrURIMismatch},
		{"IAT", func(c *proofClaims) { c.iat = nil; c.overrides = map[string]any{"IAT": now.Unix()} }, ErrMissingIAT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := defaultClaims(now)
			tc.change(&c)
			v := newTestValidator(t, now, NewMemoryNonceStore())
			proof, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), VerifyParams{
				Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: true,
			})
			if proof != nil || err != tc.want {
				t.Fatalf("case-sensitive claim = %v, %v; want %v", proof, err, tc.want)
			}
		})
	}
}

func TestValidateInvalidParamsConsumeNothing(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v, err := NewValidator(replayGuardFunc(func(context.Context, string, time.Time) (bool, error) {
		t.Fatal("invalid parameters reached replay state")
		return false, nil
	}), nil, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*VerifyParams)
	}{
		{"missing realm", func(p *VerifyParams) { p.Realm = "" }},
		{"blank realm", func(p *VerifyParams) { p.Realm = " \t" }},
		{"missing method", func(p *VerifyParams) { p.Method = "" }},
		{"missing URL", func(p *VerifyParams) { p.URL = "" }},
		{"relative URL", func(p *VerifyParams) { p.URL = "/oauth2/token" }},
		{"userinfo URL", func(p *VerifyParams) { p.URL = "https://user@identity.hatef.ir/oauth2/token" }},
		{"fragment URL", func(p *VerifyParams) { p.URL += "#fragment" }},
		{"empty fragment URL", func(p *VerifyParams) { p.URL += "#" }},
		{"non HTTP URL", func(p *VerifyParams) { p.URL = "ftp://identity.hatef.ir/oauth2/token" }},
		{"missing nonce store", func(p *VerifyParams) { p.RequireNonce = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU}
			tc.change(&params)
			proof, err := v.Validate(context.Background(), s.signValid(t, now), params)
			if proof != nil || err != ErrInvalidParams {
				t.Fatalf("invalid params = %v, %v", proof, err)
			}
		})
	}
}

func TestValidateStatelessFailuresConsumeNothing(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := newES256Signer(t)
	jkt := s.thumbprint(t)
	for _, tc := range []struct {
		name   string
		change func(*proofClaims, *VerifyParams)
		want   error
	}{
		{"missing jti", func(c *proofClaims, _ *VerifyParams) { c.jti = "" }, ErrMissingJTI},
		{"wrong binding", func(_ *proofClaims, p *VerifyParams) { p.ExpectedJKT = strings.Repeat("x", len(jkt)) }, ErrKeyMismatch},
		{"short binding", func(_ *proofClaims, p *VerifyParams) { p.ExpectedJKT = "x" }, ErrKeyMismatch},
		{"wrong method", func(c *proofClaims, _ *VerifyParams) { c.htm = "GET" }, ErrMethodMismatch},
		{"wrong URI", func(c *proofClaims, _ *VerifyParams) { c.htu += "/other" }, ErrURIMismatch},
		{"userinfo URI", func(c *proofClaims, _ *VerifyParams) { c.htu = "https://user@identity.hatef.ir/oauth2/token" }, ErrURIMismatch},
		{"fragment URI", func(c *proofClaims, _ *VerifyParams) { c.htu += "#fragment" }, ErrURIMismatch},
		{"missing iat", func(c *proofClaims, _ *VerifyParams) { c.iat = nil }, ErrMissingIAT},
		{"stale iat", func(c *proofClaims, _ *VerifyParams) { *c.iat -= 66 }, ErrStaleProof},
		{"future iat", func(c *proofClaims, _ *VerifyParams) { *c.iat += 6 }, ErrStaleProof},
		{"missing ath", func(c *proofClaims, _ *VerifyParams) { c.ath = "" }, ErrMissingATH},
		{"wrong ath", func(c *proofClaims, _ *VerifyParams) { c.ath = AccessTokenHash("other") }, ErrATHMismatch},
		{"malformed nonce", func(c *proofClaims, _ *VerifyParams) { c.overrides = map[string]any{"nonce": 1} }, ErrMalformedProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonces := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
			nonce, err := nonces.Issue(context.Background(), testRealm, jkt)
			if err != nil {
				t.Fatal(err)
			}
			replayCalls, nonceCalls := 0, 0
			v, err := NewValidator(replayGuardFunc(func(context.Context, string, time.Time) (bool, error) {
				replayCalls++
				return true, nil
			}), nonceStoreFuncs{
				issue: nonces.Issue,
				validate: func(ctx context.Context, realm, key, value string) (bool, error) {
					nonceCalls++
					return nonces.Validate(ctx, realm, key, value)
				},
			}, WithClock(fixedClock(now)))
			if err != nil {
				t.Fatal(err)
			}
			c := defaultClaims(now)
			c.nonce, c.ath = nonce, AccessTokenHash("access-token")
			params := VerifyParams{Realm: testRealm, ExpectedJKT: jkt, Method: testHTM, URL: testHTU,
				AccessToken: "access-token", RequireNonce: true}
			tc.change(&c, &params)
			proof, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params)
			if proof != nil || err != tc.want {
				t.Fatalf("stateless failure = %v, %v; want opaque %v", proof, err, tc.want)
			}
			if replayCalls != 0 || nonceCalls != 0 {
				t.Fatalf("state calls: replay=%d, nonce=%d", replayCalls, nonceCalls)
			}
			if ok, err := nonces.Validate(context.Background(), testRealm, jkt, nonce); err != nil || !ok {
				t.Fatalf("valid nonce was consumed: %v, %v", ok, err)
			}
		})
	}
}

func TestValidateNonceChallengeCarriesVerifiedScope(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	for _, supplied := range []string{"", "unknown-nonce"} {
		t.Run("nonce="+supplied, func(t *testing.T) {
			guard := NewMemoryReplayGuard()
			guard.now = fixedClock(now)
			nonces := NewMemoryNonceStore(WithNonceClock(fixedClock(now)))
			v, err := NewValidator(guard, nonces, WithClock(fixedClock(now)))
			if err != nil {
				t.Fatal(err)
			}
			params := VerifyParams{Realm: testRealm, ExpectedJKT: s.thumbprint(t), Method: testHTM, URL: testHTU, RequireNonce: true}
			c := defaultClaims(now)
			c.nonce = supplied
			proof, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params)
			var challenge *NonceChallenge
			if proof != nil || !errors.As(err, &challenge) || !errors.Is(err, ErrNonceRequired) {
				t.Fatalf("nonce challenge = %v, %v", proof, err)
			}
			if challenge.Realm != testRealm || challenge.JKT != params.ExpectedJKT || challenge.Error() != ErrNonceRequired.Error() {
				t.Fatalf("incorrect challenge scope or non-generic error: %#v", challenge)
			}
			if len(guard.seen) != 0 {
				t.Fatal("nonce challenge consumed replay state")
			}
			c.nonce, err = v.IssueNonce(context.Background(), challenge.Realm, challenge.JKT)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), params); err != nil {
				t.Fatalf("retry after challenge: %v", err)
			}
		})
	}
}

func TestValidateReplayScopedToRealmAndVerifiedKey(t *testing.T) {
	now := time.Now()
	s1, s2 := newES256Signer(t), newES256Signer(t)
	guard := NewMemoryReplayGuard()
	guard.now = fixedClock(now)
	v, err := NewValidator(guard, nil, WithClock(fixedClock(now)))
	if err != nil {
		t.Fatal(err)
	}
	c := defaultClaims(now)
	for _, tc := range []struct {
		realm  string
		signer *proofSigner
		want   error
	}{
		{testRealm, s1, nil},
		{testRealm, s1, ErrReplay},
		{"rs:" + testHTU, s1, nil},
		{testRealm, s2, nil},
		{testRealm, s2, ErrReplay},
	} {
		params := VerifyParams{Realm: tc.realm, ExpectedJKT: tc.signer.thumbprint(t), Method: testHTM, URL: testHTU}
		_, err := v.Validate(context.Background(), tc.signer.sign(t, c, TypDPoP, tc.signer.alg, nil), params)
		if err != tc.want {
			t.Fatalf("realm %q: %v, want %v", tc.realm, err, tc.want)
		}
	}
	for key := range guard.seen {
		if len(key) != 43 || strings.Contains(key, c.jti) || strings.Contains(key, testRealm) {
			t.Fatalf("replay key is not opaque: %q", key)
		}
	}
}

func TestValidateTimeWindowBoundaries(t *testing.T) {
	iat := time.Now().Truncate(time.Second)
	s := newES256Signer(t)
	compact := s.signValid(t, iat)
	for _, tc := range []struct {
		name  string
		delta time.Duration
		want  error
	}{
		{"future limit", -clockSkewLeeway, nil},
		{"too far in future", -clockSkewLeeway - time.Nanosecond, ErrStaleProof},
		{"age limit", DefaultProofMaxAge + clockSkewLeeway, nil},
		{"too old", DefaultProofMaxAge + clockSkewLeeway + time.Nanosecond, ErrStaleProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestValidator(t, iat.Add(tc.delta), nil)
			_, err := v.Validate(context.Background(), compact, VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU})
			if err != tc.want {
				t.Fatalf("boundary: %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateMemoryReplayHasNoExpiryGap(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := newES256Signer(t)
	guard := NewMemoryReplayGuard()
	guard.now = func() time.Time { return now }
	v, err := NewValidator(guard, nil, WithClock(guard.now))
	if err != nil {
		t.Fatal(err)
	}
	compact := s.signValid(t, now.Add(clockSkewLeeway))
	params := VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU}
	if _, err := v.Validate(context.Background(), compact, params); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultProofMaxAge + 2*clockSkewLeeway)
	if _, err := v.Validate(context.Background(), compact, params); err != ErrReplay {
		t.Fatalf("replay at inclusive final acceptance instant: %v", err)
	}
	now = now.Add(time.Nanosecond)
	if _, err := v.Validate(context.Background(), compact, params); err != ErrStaleProof {
		t.Fatalf("proof after final acceptance instant: %v", err)
	}
}

func TestValidateExcludesQuery(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	c := defaultClaims(now)
	c.htu += "?proof=query"
	v := newTestValidator(t, now, nil)
	if _, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), VerifyParams{
		Realm: testRealm, Method: testHTM, URL: testHTU + "?request=different",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSameURINormalization(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://EXAMPLE.com:443/resource", "https://example.com/resource", true},
		{"http://example.com:80/resource", "http://example.com/resource", true},
		{"https://example.com", "https://example.com/", true},
		{"https://[0:0:0:0:0:0:0:1]:443/", "https://[::1]/", true},
		{"https://example.com/resource", "https://example.com/resource/", false},
		{"https://example.com/resource", "https://example.com/Resource", false},
		{"https://example.com:8443/resource", "https://example.com/resource", false},
		{"https://example.com/a%2Fb", "https://example.com/a/b", false},
		{"https://user@example.com/resource", "https://example.com/resource", false},
		{"https://example.com:65536/resource", "https://example.com:65536/resource", false},
		{"https://example.com:/resource", "https://example.com/resource", false},
		{"https://[not-an-ip]/resource", "https://[not-an-ip]/resource", false},
		{"not-a-URI", "not-a-URI", false},
	} {
		if got := sameURI(tc.a, tc.b); got != tc.want {
			t.Errorf("sameURI(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestValidatorPreservesStoreErrors(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	for _, failure := range []error{errors.New("backend failure"), context.Canceled, context.DeadlineExceeded} {
		for _, stage := range []string{"replay", "nonce"} {
			t.Run(stage+"/"+failure.Error(), func(t *testing.T) {
				v, err := NewValidator(replayGuardFunc(func(context.Context, string, time.Time) (bool, error) {
					return false, failure
				}), nonceStoreFuncs{
					validate: func(context.Context, string, string, string) (bool, error) { return false, failure },
				}, WithClock(fixedClock(now)))
				if err != nil {
					t.Fatal(err)
				}
				c := defaultClaims(now)
				c.nonce = "nonce"
				proof, err := v.Validate(context.Background(), s.sign(t, c, TypDPoP, s.alg, nil), VerifyParams{
					Realm: testRealm, Method: testHTM, URL: testHTU, RequireNonce: stage == "nonce",
				})
				var challenge *NonceChallenge
				if proof != nil || !errors.Is(err, ErrStoreUnavailable) || !errors.Is(err, failure) || errors.As(err, &challenge) {
					t.Fatalf("store error = %v, %v", proof, err)
				}
			})
		}
	}
}

func TestIssueNonceRejectsEmptyAndFailedIssuance(t *testing.T) {
	for _, failure := range []error{nil, errors.New("nonce backend failure"), context.Canceled, context.DeadlineExceeded} {
		v, err := NewValidator(NewMemoryReplayGuard(), nonceStoreFuncs{
			issue: func(_ context.Context, realm, jkt string) (string, error) {
				if realm != testRealm || jkt != testStoreJKT {
					t.Fatalf("wrong issue scope: %q, %q", realm, jkt)
				}
				return "", failure
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := v.IssueNonce(context.Background(), testRealm, testStoreJKT)
		if nonce != "" || !errors.Is(err, ErrStoreUnavailable) || (failure != nil && !errors.Is(err, failure)) {
			t.Fatalf("failed issuance = %q, %v", nonce, err)
		}
	}
	v := newTestValidator(t, time.Now(), nil)
	if _, err := v.IssueNonce(context.Background(), testRealm, testStoreJKT); err != ErrInvalidParams {
		t.Fatalf("missing store: %v", err)
	}
}

func TestValidatorCanceledContextConsumesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, err := NewValidator(replayGuardFunc(func(context.Context, string, time.Time) (bool, error) {
		t.Fatal("canceled request reached replay state")
		return false, nil
	}), nonceStoreFuncs{
		issue: func(context.Context, string, string) (string, error) {
			t.Fatal("canceled request reached nonce issuance")
			return "", nil
		},
		validate: func(context.Context, string, string, string) (bool, error) {
			t.Fatal("canceled request reached nonce validation")
			return false, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := v.Validate(ctx, "unparsed", VerifyParams{Realm: testRealm, Method: testHTM, URL: testHTU}); proof != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled validation = %v, %v", proof, err)
	}
	if nonce, err := v.IssueNonce(ctx, testRealm, testStoreJKT); nonce != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled issuance = %q, %v", nonce, err)
	}
}
