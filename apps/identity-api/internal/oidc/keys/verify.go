package keys

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// esSigComponentSize is the byte length of each of the R and S components in a
// JOSE ES256 signature (RFC 7518 §3.4: fixed-size big-endian, zero-padded).
const esSigComponentSize = 32

// Errors returned by public-key parsing and signature verification.
var (
	// ErrInvalidJWK indicates a public JWK is structurally invalid or carries
	// parameters outside the RS256/ES256 profile.
	ErrInvalidJWK = errors.New("keys: invalid public JWK")
	// ErrAlgMismatch indicates the requested algorithm does not match the key
	// type (e.g. RS256 requested against an EC key).
	ErrAlgMismatch = errors.New("keys: algorithm does not match key type")
	// ErrVerification indicates a signature failed cryptographic verification.
	ErrVerification = errors.New("keys: signature verification failed")
)

// PublicKey is a parsed, algorithm-bound public verification key registered for
// a confidential client (RFC 7523 private_key_jwt). It carries only public
// material and the single JOSE algorithm the key may be used to verify.
type PublicKey struct {
	// KID is the key identifier (JWK "kid"); it matches the "kid" header of an
	// incoming client assertion so the right key is selected.
	KID string
	// Alg is the JOSE algorithm this key verifies (RS256 or ES256).
	Alg string
	// Key is the concrete public key (*rsa.PublicKey or *ecdsa.PublicKey).
	Key crypto.PublicKey
}

// ParsePublicJWK validates a public JWK and returns a PublicKey. Only the two
// algorithms permitted by the platform are accepted: RSA (>=2048-bit, RS256)
// and EC on NIST P-256 (ES256). Symmetric keys and any other curve are
// rejected. When the JWK omits "kid", the RFC 7638 thumbprint is used so a key
// is always addressable.
func ParsePublicJWK(jwk JWK) (*PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAPublicJWK(jwk)
	case "EC":
		return parseECPublicJWK(jwk)
	default:
		return nil, fmt.Errorf("%w: unsupported kty %q", ErrInvalidJWK, jwk.Kty)
	}
}

// parseRSAPublicJWK decodes an RSA public JWK, enforcing the 2048-bit minimum.
func parseRSAPublicJWK(jwk JWK) (*PublicKey, error) {
	if jwk.Alg != "" && jwk.Alg != AlgRS256 {
		return nil, fmt.Errorf("%w: RSA key alg must be %s, got %q", ErrInvalidJWK, AlgRS256, jwk.Alg)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil || len(nBytes) == 0 {
		return nil, fmt.Errorf("%w: bad RSA modulus", ErrInvalidJWK)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil || len(eBytes) == 0 {
		return nil, fmt.Errorf("%w: bad RSA exponent", ErrInvalidJWK)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	if pub.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, minimum is %d", ErrInvalidJWK, pub.N.BitLen(), minRSABits)
	}
	if pub.E < 2 {
		return nil, fmt.Errorf("%w: RSA exponent too small", ErrInvalidJWK)
	}
	kid, err := kidFor(jwk)
	if err != nil {
		return nil, err
	}
	return &PublicKey{KID: kid, Alg: AlgRS256, Key: pub}, nil
}

// parseECPublicJWK decodes an EC public JWK, enforcing the P-256 curve and
// verifying the point lies on the curve.
func parseECPublicJWK(jwk JWK) (*PublicKey, error) {
	if jwk.Alg != "" && jwk.Alg != AlgES256 {
		return nil, fmt.Errorf("%w: EC key alg must be %s, got %q", ErrInvalidJWK, AlgES256, jwk.Alg)
	}
	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("%w: unsupported curve %q (only P-256)", ErrInvalidJWK, jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(xBytes) != p256CoordinateSize {
		return nil, fmt.Errorf("%w: bad EC x coordinate", ErrInvalidJWK)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil || len(yBytes) != p256CoordinateSize {
		return nil, fmt.Errorf("%w: bad EC y coordinate", ErrInvalidJWK)
	}
	// Validate the point lies on P-256 via crypto/ecdh, which performs an
	// on-curve check on the uncompressed SEC1 encoding (0x04 || X || Y) and
	// closes off invalid-curve attacks. (elliptic.IsOnCurve is deprecated.)
	uncompressed := make([]byte, 1+2*p256CoordinateSize)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+p256CoordinateSize], xBytes)
	copy(uncompressed[1+p256CoordinateSize:], yBytes)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("%w: EC point is not on P-256", ErrInvalidJWK)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	kid, err := kidFor(jwk)
	if err != nil {
		return nil, err
	}
	return &PublicKey{KID: kid, Alg: AlgES256, Key: pub}, nil
}

// kidFor returns the JWK's declared kid, or the RFC 7638 thumbprint when kid
// is absent, so every registered key is addressable by a stable identifier.
func kidFor(jwk JWK) (string, error) {
	if jwk.Kid != "" {
		return jwk.Kid, nil
	}
	return Thumbprint(jwk)
}

// VerifyJWSSignature verifies a JOSE signature (sig) over the ASCII signing
// input (the "header.payload" portion of a compact JWS) using the given public
// key and algorithm. Only RS256 and ES256 are supported; any other alg — most
// importantly "none" and any HS* MAC — is rejected by ErrAlgMismatch. The
// public key type must agree with alg.
func VerifyJWSSignature(alg string, pub crypto.PublicKey, signingInput string, sig []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	switch alg {
	case AlgRS256:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrAlgMismatch
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
			return ErrVerification
		}
		return nil
	case AlgES256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrAlgMismatch
		}
		if len(sig) != 2*esSigComponentSize {
			return ErrVerification
		}
		r := new(big.Int).SetBytes(sig[:esSigComponentSize])
		s := new(big.Int).SetBytes(sig[esSigComponentSize:])
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return ErrVerification
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrAlgMismatch, alg)
	}
}
