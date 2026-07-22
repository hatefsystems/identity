package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
)

// es256JWK returns the public JWK for a freshly generated P-256 key alongside
// the private key, for round-trip signature tests.
func es256KeyPair(t *testing.T) (*ecdsa.PrivateKey, JWK) {
	t.Helper()
	sk, err := NewEphemeralES256()
	if err != nil {
		t.Fatalf("NewEphemeralES256: %v", err)
	}
	return sk.Signer.(*ecdsa.PrivateKey), sk.PublicJWK
}

// rsaKeyPair returns a 2048-bit RSA private key and its public JWK.
func rsaKeyPair(t *testing.T) (*rsa.PrivateKey, JWK) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := JWK{
		Kty: "RSA",
		Alg: AlgRS256,
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	return priv, jwk
}

func TestParsePublicJWKES256(t *testing.T) {
	_, jwk := es256KeyPair(t)
	pub, err := ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	if pub.Alg != AlgES256 {
		t.Errorf("Alg = %q, want ES256", pub.Alg)
	}
	if pub.KID == "" {
		t.Error("KID must be derived")
	}
	if _, ok := pub.Key.(*ecdsa.PublicKey); !ok {
		t.Errorf("Key type = %T, want *ecdsa.PublicKey", pub.Key)
	}
}

func TestParsePublicJWKRS256(t *testing.T) {
	_, jwk := rsaKeyPair(t)
	pub, err := ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	if pub.Alg != AlgRS256 {
		t.Errorf("Alg = %q, want RS256", pub.Alg)
	}
	if _, ok := pub.Key.(*rsa.PublicKey); !ok {
		t.Errorf("Key type = %T, want *rsa.PublicKey", pub.Key)
	}
}

func TestParsePublicJWKRejectsWeakRSA(t *testing.T) {
	// Intentionally undersized: this test asserts the parser REJECTS sub-2048
	// bit RSA keys, so a weak key must be generated here on purpose.
	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: deliberately weak to test rejection

	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	jwk := JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
	if _, err := ParsePublicJWK(jwk); !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("err = %v, want ErrInvalidJWK", err)
	}
}

func TestParsePublicJWKRejectsUnknownKty(t *testing.T) {
	if _, err := ParsePublicJWK(JWK{Kty: "oct"}); !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("err = %v, want ErrInvalidJWK", err)
	}
}

func TestParsePublicJWKRejectsWrongCurve(t *testing.T) {
	_, jwk := es256KeyPair(t)
	jwk.Crv = "P-384"
	if _, err := ParsePublicJWK(jwk); !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("err = %v, want ErrInvalidJWK", err)
	}
}

func TestParsePublicJWKRejectsBadPoint(t *testing.T) {
	_, jwk := es256KeyPair(t)
	// Corrupt the X coordinate so the point is no longer on the curve.
	jwk.X = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := ParsePublicJWK(jwk); !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("err = %v, want ErrInvalidJWK", err)
	}
}

func TestVerifyJWSSignatureES256RoundTrip(t *testing.T) {
	priv, jwk := es256KeyPair(t)
	pub, err := ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	input := "header.payload"
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	if err := VerifyJWSSignature(AlgES256, pub.Key, input, sig); err != nil {
		t.Errorf("VerifyJWSSignature: %v", err)
	}
	// Tampered input must fail.
	if err := VerifyJWSSignature(AlgES256, pub.Key, "header.tampered", sig); !errors.Is(err, ErrVerification) {
		t.Errorf("err = %v, want ErrVerification", err)
	}
}

func TestVerifyJWSSignatureRS256RoundTrip(t *testing.T) {
	priv, jwk := rsaKeyPair(t)
	pub, err := ParsePublicJWK(jwk)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	input := "header.payload"
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.Sign: %v", err)
	}

	if err := VerifyJWSSignature(AlgRS256, pub.Key, input, sig); err != nil {
		t.Errorf("VerifyJWSSignature: %v", err)
	}
	if err := VerifyJWSSignature(AlgRS256, pub.Key, "header.tampered", sig); !errors.Is(err, ErrVerification) {
		t.Errorf("err = %v, want ErrVerification", err)
	}
}

func TestVerifyJWSSignatureRejectsUnknownAlg(t *testing.T) {
	_, jwk := es256KeyPair(t)
	pub, _ := ParsePublicJWK(jwk)
	for _, alg := range []string{"none", "HS256", "ES384", ""} {
		if err := VerifyJWSSignature(alg, pub.Key, "a.b", []byte("sig")); !errors.Is(err, ErrAlgMismatch) {
			t.Errorf("alg %q: err = %v, want ErrAlgMismatch", alg, err)
		}
	}
}

func TestVerifyJWSSignatureRejectsKeyTypeMismatch(t *testing.T) {
	_, ecJWK := es256KeyPair(t)
	ecPub, _ := ParsePublicJWK(ecJWK)
	// RS256 against an EC key must be a mismatch.
	if err := VerifyJWSSignature(AlgRS256, ecPub.Key, "a.b", []byte("sig")); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("err = %v, want ErrAlgMismatch", err)
	}

	_, rsaJWK := rsaKeyPair(t)
	rsaPub, _ := ParsePublicJWK(rsaJWK)
	if err := VerifyJWSSignature(AlgES256, rsaPub.Key, "a.b", []byte("sig")); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("err = %v, want ErrAlgMismatch", err)
	}
}
