// Package keys implements the OIDC signing keystore for the identity-api:
// private-key parsing with strict algorithm enforcement (RS256 with >=2048-bit
// RSA, or ES256 on NIST P-256 only — symmetric algorithms are prohibited per
// docs/architecture.md "Asymmetric Signing Only"), public JWK (RFC 7517)
// serialization, RFC 7638 thumbprint key IDs, and the graceful
// active/next/previous 3-key rotation cycle backing /oauth2/jwks.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Supported JOSE signing algorithm identifiers.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// minRSABits is the minimum accepted RSA modulus size (docs/architecture.md:
// "RS256 (minimum 2048-bit key size)").
const minRSABits = 2048

// p256CoordinateSize is the fixed byte length of a P-256 coordinate; JWK EC
// coordinates must be zero-padded to the full field size (RFC 7518 §6.2.1.2).
const p256CoordinateSize = 32

// Sentinel errors returned by key parsing.
var (
	// ErrNoPEMData indicates the input contained no decodable PEM block.
	ErrNoPEMData = errors.New("keys: no PEM data found")
	// ErrUnsupportedKey indicates the key type is not RSA or ECDSA.
	ErrUnsupportedKey = errors.New("keys: unsupported key type (only RSA >=2048-bit and ECDSA P-256 are allowed)")
	// ErrWeakRSAKey indicates an RSA key below the 2048-bit minimum.
	ErrWeakRSAKey = errors.New("keys: RSA key below 2048-bit minimum")
	// ErrUnsupportedCurve indicates an ECDSA key on a curve other than P-256.
	ErrUnsupportedCurve = errors.New("keys: unsupported ECDSA curve (only NIST P-256 is allowed)")
)

// JWK is a JSON Web Key (RFC 7517) carrying public parameters only. Private
// fields (d, p, q, ...) are intentionally absent from the struct so that
// private key material can never be serialized to the JWKS endpoint by
// construction.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	// RSA public parameters (RFC 7518 §6.3.1).
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC public parameters (RFC 7518 §6.2.1).
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is the JSON document served by /oauth2/jwks (RFC 7517 §5).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// SigningKey pairs a private signer with its derived public JWK and metadata.
type SigningKey struct {
	// KID is the RFC 7638 SHA-256 thumbprint of the public JWK.
	KID string
	// Alg is the JOSE algorithm this key signs with (RS256 or ES256).
	Alg string
	// Signer is the private key used to sign tokens (Task 3.3 onward).
	Signer crypto.Signer
	// PublicJWK is the public-only JWK representation published via JWKS.
	PublicJWK JWK
}

// ParsePrivateKeyPEM decodes a PEM-encoded private key (PKCS#8 "PRIVATE KEY",
// PKCS#1 "RSA PRIVATE KEY", or SEC1 "EC PRIVATE KEY") and returns a SigningKey
// with its algorithm inferred from the key type. Keys outside the allowed
// RS256/ES256 profile are rejected.
func ParsePrivateKeyPEM(data []byte) (*SigningKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNoPEMData
	}

	var (
		parsed any
		err    error
	)
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("keys: unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key: %w", err)
	}

	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		return newRSASigningKey(key)
	case *ecdsa.PrivateKey:
		return newECDSASigningKey(key)
	default:
		return nil, ErrUnsupportedKey
	}
}

// NewEphemeralES256 generates a throwaway ES256 signing key. It exists solely
// for local development bootstrapping (when no KMS-injected keys are present)
// and for tests; production keys are always injected via configuration.
func NewEphemeralES256() (*SigningKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generate ephemeral ES256 key: %w", err)
	}
	return newECDSASigningKey(key)
}

// newRSASigningKey validates an RSA private key and derives its public JWK
// and RFC 7638 thumbprint kid.
func newRSASigningKey(key *rsa.PrivateKey) (*SigningKey, error) {
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: got %d bits", ErrWeakRSAKey, key.N.BitLen())
	}
	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: AlgRS256,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	kid, err := Thumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk.Kid = kid
	return &SigningKey{KID: kid, Alg: AlgRS256, Signer: key, PublicJWK: jwk}, nil
}

// newECDSASigningKey validates an ECDSA private key (P-256 only) and derives
// its public JWK and RFC 7638 thumbprint kid.
func newECDSASigningKey(key *ecdsa.PrivateKey) (*SigningKey, error) {
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: got %s", ErrUnsupportedCurve, key.Curve.Params().Name)
	}
	// Extract the public point via crypto/ecdh, which returns the SEC 1
	// uncompressed encoding (0x04 || X || Y) with each coordinate already
	// zero-padded to the full field size (RFC 7518 §6.2.1.2/§6.2.1.3). This
	// avoids the deprecated big.Int coordinate accessors on ecdsa.PublicKey.
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		return nil, fmt.Errorf("keys: convert P-256 public key: %w", err)
	}
	point := ecdhPub.Bytes()
	if len(point) != 1+2*p256CoordinateSize {
		return nil, fmt.Errorf("keys: unexpected P-256 point length %d", len(point))
	}
	x := point[1 : 1+p256CoordinateSize]
	y := point[1+p256CoordinateSize:]

	jwk := JWK{
		Kty: "EC",
		Use: "sig",
		Alg: AlgES256,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
	kid, err := Thumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk.Kid = kid
	return &SigningKey{KID: kid, Alg: AlgES256, Signer: key, PublicJWK: jwk}, nil
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint (base64url, no
// padding) over the canonical JSON containing only the required members of
// the key type, in lexicographic order.
func Thumbprint(jwk JWK) (string, error) {
	var canonical string
	switch jwk.Kty {
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk.E, jwk.N)
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk.Crv, jwk.X, jwk.Y)
	default:
		return "", fmt.Errorf("keys: cannot compute thumbprint for kty %q", jwk.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
