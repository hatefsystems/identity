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
	"testing"
	"time"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

const (
	testHTM = "POST"
	testHTU = "https://identity.hatef.ir/oauth2/token"
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
	jti   string
	htm   string
	htu   string
	iat   *int64
	nonce string
	ath   string
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
	// Flip the last character of the signature.
	tampered := compact[:len(compact)-1]
	if compact[len(compact)-1] == 'A' {
		tampered += "B"
	} else {
		tampered += "A"
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
	v, err := NewValidator(NewMemoryReplayGuard(), nonces, WithClock(fixedClock(now)))
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
		Method: testHTM, URL: testHTU,
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
		Method: "GET", URL: testHTU,
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
		Method: testHTM, URL: "https://identity.hatef.ir/oauth2/other",
	})
	if !errors.Is(err, ErrURIMismatch) {
		t.Fatalf("err = %v, want ErrURIMismatch", err)
	}
}

func TestValidateURICaseAndTrailingSlashInsensitive(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	// Proof htu matches testHTU; request URL differs only by scheme/host case
	// and a trailing slash — must still validate.
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Method: testHTM, URL: "https://IDENTITY.hatef.ir/oauth2/token/",
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
		Method: testHTM, URL: testHTU,
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
		Method: testHTM, URL: testHTU,
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
		Method: testHTM, URL: testHTU,
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
		Method: testHTM, URL: testHTU,
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

	if _, err := v.Validate(context.Background(), compact, VerifyParams{Method: testHTM, URL: testHTU}); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	_, err := v.Validate(context.Background(), compact, VerifyParams{Method: testHTM, URL: testHTU})
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
		Method: testHTM, URL: testHTU, AccessToken: accessToken,
	}); err != nil {
		t.Fatalf("Validate with ath: %v", err)
	}
}

func TestValidateATHMissing(t *testing.T) {
	now := time.Now()
	s := newES256Signer(t)
	v := newTestValidator(t, now, nil)
	_, err := v.Validate(context.Background(), s.signValid(t, now), VerifyParams{
		Method: testHTM, URL: testHTU, AccessToken: "tok",
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
		Method: testHTM, URL: testHTU, AccessToken: "the-real-token",
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
		Method: testHTM, URL: testHTU, RequireNonce: true,
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

	nonce, err := v.IssueNonce(context.Background())
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	c := defaultClaims(now)
	c.nonce = nonce
	proof := s.sign(t, c, TypDPoP, s.alg, nil)
	if _, err := v.Validate(context.Background(), proof, VerifyParams{
		Method: testHTM, URL: testHTU, RequireNonce: true,
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
		Method: testHTM, URL: testHTU, RequireNonce: true,
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
		Method: testHTM, URL: testHTU, RequireNonce: true,
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
