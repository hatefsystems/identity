package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
)

// pemEncode wraps DER bytes in a PEM block of the given type.
func pemEncode(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func rsaPEM(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pemEncode(t, "PRIVATE KEY", der)
}

func ecPEM(t *testing.T, curve elliptic.Curve) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pemEncode(t, "PRIVATE KEY", der)
}

func TestParsePrivateKeyPEM_RSA2048(t *testing.T) {
	sk, err := ParsePrivateKeyPEM(rsaPEM(t, 2048))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sk.Alg != AlgRS256 {
		t.Errorf("Alg = %q, want RS256", sk.Alg)
	}
	if sk.PublicJWK.Kty != "RSA" || sk.PublicJWK.N == "" || sk.PublicJWK.E == "" {
		t.Errorf("incomplete RSA JWK: %+v", sk.PublicJWK)
	}
	if sk.KID == "" || sk.KID != sk.PublicJWK.Kid {
		t.Errorf("kid mismatch: KID=%q jwk.kid=%q", sk.KID, sk.PublicJWK.Kid)
	}
}

func TestParsePrivateKeyPEM_RejectsWeakRSA(t *testing.T) {
	if _, err := ParsePrivateKeyPEM(rsaPEM(t, 1024)); err == nil {
		t.Fatal("expected error for 1024-bit RSA key, got nil")
	} else if !strings.Contains(err.Error(), "2048") {
		t.Errorf("error should mention the 2048-bit minimum, got: %v", err)
	}
}

func TestParsePrivateKeyPEM_ES256(t *testing.T) {
	sk, err := ParsePrivateKeyPEM(ecPEM(t, elliptic.P256()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sk.Alg != AlgES256 {
		t.Errorf("Alg = %q, want ES256", sk.Alg)
	}
	if sk.PublicJWK.Crv != "P-256" || sk.PublicJWK.X == "" || sk.PublicJWK.Y == "" {
		t.Errorf("incomplete EC JWK: %+v", sk.PublicJWK)
	}
}

func TestParsePrivateKeyPEM_RejectsNonP256Curve(t *testing.T) {
	if _, err := ParsePrivateKeyPEM(ecPEM(t, elliptic.P384())); err == nil {
		t.Fatal("expected error for P-384 key, got nil")
	}
}

func TestParsePrivateKeyPEM_RejectsGarbage(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("not pem at all")); err != ErrNoPEMData {
		t.Fatalf("expected ErrNoPEMData, got %v", err)
	}
}

// TestJWKNeverContainsPrivateMaterial marshals a JWK and asserts none of the
// JOSE private-key member names appear — the struct has no such fields, and
// this test locks that invariant in.
func TestJWKNeverContainsPrivateMaterial(t *testing.T) {
	sk, err := ParsePrivateKeyPEM(ecPEM(t, elliptic.P256()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := json.Marshal(sk.PublicJWK)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal JWK: %v", err)
	}
	for _, forbidden := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := decoded[forbidden]; ok {
			t.Errorf("serialized JWK contains private member %q", forbidden)
		}
	}
}

// TestThumbprintRFC7638Vector checks the RSA thumbprint against the worked
// example in RFC 7638 §3.1.
func TestThumbprintRFC7638Vector(t *testing.T) {
	jwk := JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	kid, err := Thumbprint(jwk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if kid != want {
		t.Errorf("thumbprint = %q, want %q", kid, want)
	}
}

func mustEphemeral(t *testing.T) *SigningKey {
	t.Helper()
	sk, err := NewEphemeralES256()
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	return sk
}

func TestNewManagerRequiresActiveAndNext(t *testing.T) {
	if _, err := NewManager(nil, nil, nil); err != ErrMissingKeys {
		t.Fatalf("expected ErrMissingKeys, got %v", err)
	}
	if _, err := NewManager(mustEphemeral(t), nil, nil); err != ErrMissingKeys {
		t.Fatalf("expected ErrMissingKeys with nil next, got %v", err)
	}
}

func TestManagerJWKSetPublishesAllSlots(t *testing.T) {
	active, next, previous := mustEphemeral(t), mustEphemeral(t), mustEphemeral(t)

	m, err := NewManager(active, next, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if got := len(m.JWKSet().Keys); got != 2 {
		t.Errorf("fresh deployment JWKS should have 2 keys (active+next), got %d", got)
	}

	m, err = NewManager(active, next, previous)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	set := m.JWKSet()
	if got := len(set.Keys); got != 3 {
		t.Fatalf("full cycle JWKS should have 3 keys, got %d", got)
	}
	// Ordering contract: active, next, previous.
	for i, want := range []string{active.KID, next.KID, previous.KID} {
		if set.Keys[i].Kid != want {
			t.Errorf("keys[%d].kid = %q, want %q", i, set.Keys[i].Kid, want)
		}
	}
}

func TestManagerRotateAdvancesCycle(t *testing.T) {
	active, next, previous := mustEphemeral(t), mustEphemeral(t), mustEphemeral(t)
	m, err := NewManager(active, next, previous)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	newNext := mustEphemeral(t)
	if err := m.Rotate(newNext); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if got := m.ActiveSigner().KID; got != next.KID {
		t.Errorf("after rotation active = %q, want old next %q", got, next.KID)
	}
	// Old active must remain resolvable (previous slot) so outstanding
	// unexpired tokens keep verifying — the whole point of the 3-key cycle.
	if m.VerificationKey(active.KID) == nil {
		t.Error("old active key no longer resolvable after rotation")
	}
	// The evicted previous key must be gone.
	if m.VerificationKey(previous.KID) != nil {
		t.Error("evicted previous key still resolvable after rotation")
	}
	if m.VerificationKey(newNext.KID) == nil {
		t.Error("new next key not resolvable after rotation")
	}
	if err := m.Rotate(nil); err != ErrMissingKeys {
		t.Errorf("Rotate(nil) = %v, want ErrMissingKeys", err)
	}
}

// TestManagerConcurrentAccess exercises Rotate and readers together; run with
// -race to catch locking regressions.
func TestManagerConcurrentAccess(t *testing.T) {
	m, err := NewManager(mustEphemeral(t), mustEphemeral(t), nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = m.JWKSet()
				_ = m.ActiveSigner()
				_ = m.VerificationKey("nonexistent")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := m.Rotate(mustEphemeral(t)); err != nil {
					t.Errorf("Rotate: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
