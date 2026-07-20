// Minimal JWS (compact JWT) signing and verification for the token endpoint.
// Only the two algorithms permitted by the platform are implemented — RS256
// (RSASSA-PKCS1-v1_5 with SHA-256) and ES256 (ECDSA P-256 with SHA-256, JOSE
// R||S signature serialization per RFC 7518 §3.4). Symmetric algorithms are
// structurally impossible: signing is driven by the keys.SigningKey type,
// which only ever holds RSA >=2048-bit or P-256 private keys
// (docs/architecture.md "Asymmetric Signing Only").
//
// A deliberate, small hand-rolled implementation is used instead of a JOSE
// dependency, matching the codebase's existing JWK/thumbprint handling in
// internal/oidc/keys and keeping the token-signing surface fully auditable.

// Package token implements the OAuth 2.0 token endpoint: the three supported
// grants, minimal JWS signing/verification, PKCE S256 verification, and the
// authorization-code/refresh-token stores.
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/hatefsystems/identity/apps/identity-api/internal/oidc/keys"
)

// JWT typ header values. Access tokens use the RFC 9068 "at+jwt" profile so
// resource servers can reject a token minted for a different purpose; ID
// tokens use the plain "JWT" type per OIDC Core.
const (
	TypAccessToken = "at+jwt"
	TypJWT         = "JWT"
)

// p256SigComponentSize is the byte length of each of the R and S components in
// a JOSE ES256 signature (RFC 7518 §3.4: fixed-size big-endian, zero-padded).
const p256SigComponentSize = 32

// Sentinel errors returned by signing/verification.
var (
	// ErrMalformedJWT indicates the compact serialization is structurally invalid.
	ErrMalformedJWT = errors.New("token: malformed JWT")
	// ErrSignatureInvalid indicates the signature does not verify with the key.
	ErrSignatureInvalid = errors.New("token: signature verification failed")
	// ErrUnsupportedAlg indicates an algorithm outside the RS256/ES256 profile.
	ErrUnsupportedAlg = errors.New("token: unsupported signing algorithm")
)

// Claims is a JWT claims set. Values must be JSON-serializable.
type Claims map[string]any

// jwsHeader is the protected JOSE header of a signed token.
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Sign produces a compact JWS over claims using the given signing key. The
// typ parameter selects the JOSE typ header (TypAccessToken or TypJWT).
func Sign(key *keys.SigningKey, typ string, claims Claims) (string, error) {
	if key == nil {
		return "", errors.New("token: nil signing key")
	}
	headerJSON, err := json.Marshal(jwsHeader{Alg: key.Alg, Typ: typ, Kid: key.KID})
	if err != nil {
		return "", fmt.Errorf("token: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := signDigest(key, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// signDigest signs a SHA-256 digest with the key's private signer, producing
// the JOSE wire format for the key's algorithm.
func signDigest(key *keys.SigningKey, digest []byte) ([]byte, error) {
	switch signer := key.Signer.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, signer, digest)
		if err != nil {
			return nil, fmt.Errorf("token: ECDSA sign: %w", err)
		}
		// JOSE requires fixed-size big-endian R||S, not ASN.1 DER.
		sig := make([]byte, 2*p256SigComponentSize)
		r.FillBytes(sig[:p256SigComponentSize])
		s.FillBytes(sig[p256SigComponentSize:])
		return sig, nil
	default:
		return nil, ErrUnsupportedAlg
	}
}

// Verify checks the compact JWT's signature against the given key and returns
// its claims. It validates structure, the kid/alg header against the key, and
// the cryptographic signature. Claim-level validation (exp, aud, iss) is the
// caller's responsibility — Verify is a building block, primarily used by
// tests and (later) the internal token-validation RPC.
func Verify(compact string, key *keys.SigningKey) (Claims, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedJWT
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedJWT
	}
	var header jwsHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrMalformedJWT
	}
	if header.Alg != key.Alg {
		return nil, ErrUnsupportedAlg
	}
	if header.Kid != key.KID {
		return nil, fmt.Errorf("%w: kid mismatch", ErrSignatureInvalid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedJWT
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	switch pub := key.Signer.Public().(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return nil, ErrSignatureInvalid
		}
	case *ecdsa.PublicKey:
		if len(sig) != 2*p256SigComponentSize {
			return nil, ErrSignatureInvalid
		}
		r := new(big.Int).SetBytes(sig[:p256SigComponentSize])
		s := new(big.Int).SetBytes(sig[p256SigComponentSize:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return nil, ErrSignatureInvalid
		}
	default:
		return nil, ErrUnsupportedAlg
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedJWT
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrMalformedJWT
	}
	return claims, nil
}
