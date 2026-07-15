# Hatef Identity Platform - Client Integration Guide

This document is an integration handbook for client applications and microservices (e.g., Search Core and Email Service) within the Hatef ecosystem. It details public client integration (using OAuth 2.1 / OIDC and DPoP), confidential client authentication, and internal gRPC communication secured via SPIFFE/SPIRE.

---

## 1. Public Clients Integration (OAuth 2.1 & OIDC)

Public clients (such as the Next.js frontend or mobile applications) run in untrusted environments. They must communicate with the Hatef Identity Platform using OIDC/OAuth 2.1 mechanisms.

### 1.1 Mandatory PKCE (S256)

Every public authorization flow must utilize the Authorization Code flow with Proof Key for Code Exchange (PKCE) according to RFC 7636. Use of the `plain` code challenge method is explicitly blocked.

#### Flow Sequence:
1. Generate a high-entropy random cryptographically secure string (minimum 43 characters) known as the `code_verifier`.
2. Generate the `code_challenge` by hashing the verifier using SHA-256 and base64url-encoding the result:
   $$\text{code\_challenge} = \text{BASE64URL-ENCODE}\big(\text{SHA-256}(\text{code\_verifier})\big)$$
3. Redirect the user to the `/oauth2/auth` endpoint:
   ```http
   GET /oauth2/auth?
       response_type=code
       &client_id=hatef-nextjs-app
       &redirect_uri=https%3A%2F%2Fhatef.ir%2Fcallback
       &scope=openid%20profile%20email
       &code_challenge=E9Melhoa2OwvFrGMTJguCH5KLUAzSAt9GPmy_8_NfXE
       &code_challenge_method=S256
       &state=af0ifjsldkj HTTP/1.1
   Host: identity.hatef.ir
   ```
4. Upon receiving the authorization `code` at the redirect URI, the client exchanges it for tokens at `/oauth2/token` by passing the raw `code_verifier`:
   ```http
   POST /oauth2/token HTTP/1.1
   Host: identity.hatef.ir
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &client_id=hatef-nextjs-app
   &code=SplxlOBeZQQYbYS6WxSbIA
   &redirect_uri=https%3A%2F%2Fhatef.ir%2Fcallback
   &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
   ```

### 1.2 Demonstrating Proof-of-Possession (DPoP - RFC 9449)

To prevent session hijacking via token theft, public clients must bind access and refresh tokens to an ephemeral client-side private key using **DPoP**.

#### 1.2.1 Ephemeral Key Generation (Browser)
Clients must generate an asymmetric ECDSA P-256 keypair via the WebCrypto API with the `extractable: false` attribute. This guarantees that malicious scripts (e.g., in the event of XSS) cannot read the private key.

```javascript
// Generate ECDSA P-256 keypair in IndexedDB
async function generateDPoPKey() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false, // extractable: false prevents private key extraction
    ["sign", "verify"]
  );
  return keyPair;
}
```

#### 1.2.2 Generating the DPoP Proof Assertion
On every token-bound request, the client must generate and sign a JWT assertion included in the `DPoP` request header.

```javascript
async function createDPoPProof(keyPair, httpMethod, requestUrl, nonce) {
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: await window.crypto.subtle.exportKey("jwk", keyPair.publicKey)
  };

  const payload = {
    jti: generateRandomString(16), // Single-use identifier
    htm: httpMethod.toUpperCase(),
    htu: requestUrl,
    iat: Math.floor(Date.now() / 1000),
    ath: await computeAccessTokenHash() // required on token usage endpoints
  };
  
  if (nonce) {
    payload.nonce = nonce; // Bind to server-supplied nonce
  }

  return signJWT(header, payload, keyPair.privateKey);
}
```

#### 1.2.3 Token Endpoint Authentication Configuration
Public clients are incapable of maintaining secrets securely. Therefore:
* Public clients must be registered with their client metadata parameter `token_endpoint_auth_method` set strictly to `"none"`.
* Public clients do **not** use `private_key_jwt` for OIDC authentication. Only confidential back-end services are allowed to use `private_key_jwt`.

---

## 2. Confidential Clients Integration (`private_key_jwt`)

Confidential clients (such as the C++ Search Core backend or Go Email Service) have secure, private infrastructure. They must authenticate to the token endpoint `/oauth2/token` using signed assertions (RFC 7523) instead of static client secrets.

### 2.1 Client Authentication Parameters

* **Authentication Method:** `private_key_jwt`
* **Token Endpoint:** `https://identity.hatef.ir/oauth2/token`
* **Assertion Signing Algorithm:** `RS256` (min 2048-bit RSA) or `ES256` (NIST Curve P-256).

### 2.2 Constructing the Client JWT Assertion

To authenticate, the client generates a JWT signed with its local private key.

#### Header:
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "search-core-key-001"
}
```

#### Payload Claims:
* `iss` (Issuer): The pre-registered `client_id` of the client (e.g., `search-core`).
* `sub` (Subject): The same `client_id` (`search-core`).
* `aud` (Audience): The URL of the IdP token endpoint (`https://identity.hatef.ir/oauth2/token`).
* `jti` (JWT ID): A cryptographically secure random string unique to this request (validated by the server to prevent replay attacks).
* `exp` (Expiration Time): Unix epoch timestamp. Must not be longer than 5 minutes in the future.
* `iat` (Issued At): Unix epoch timestamp of creation.

#### Exchange Request:
```http
POST /oauth2/token HTTP/1.1
Host: identity.hatef.ir
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIs... [signed JWT assertion]
&scope=search.full
```

The Go Identity Server looks up the public key matching `kid` from its database/local keystore and validates the signature.

---

## 3. Internal gRPC Integration (Zero-Trust)

Internal microservices bypass public HTTP routing for token validation, communicating directly with the Identity Platform over **gRPC**.

### 3.1 SPIFFE/SPIRE Bootstrapping

All internal containers run a SPIRE Agent sidecar. The agent exposes the local SPIFFE Workload API (via a Unix Domain Socket at `/run/spire/sockets/agent.sock`).

When a client application starts, it reads its **SVID** (SPIFFE Verifiable Identity Document) from the Workload API:

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"

// Create a connection source to SPIRE Agent
source, err := workloadapi.NewX509Source(ctx, workloadapi.WithAddress("unix:///run/spire/sockets/agent.sock"))
if err != nil {
    log.Fatalf("Unable to connect to SPIRE workload API: %v", err)
}
defer source.Close()
```

### 3.2 Dynamic mTLS gRPC Connections

Using the `X509Source`, the client constructs a secure gRPC connection without hardcoding any TLS certificate files or rotation timers.

```go
import (
    "github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
    "google.golang.org/grpc"
)

// Configure gRPC options using dynamically rotated SPIFFE credentials
creds := grpccredentials.MTLSClientCredentials(source, source, grpccredentials.AuthorizeID(
    spiffeid.RequireFromString("spiffe://hatef.ir/ns/identity/sa/idp-core"),
))

conn, err := grpc.DialContext(ctx, "idp-core.internal:9090", grpc.WithTransportCredentials(creds))
if err != nil {
    log.Fatalf("gRPC connection failure: %v", err)
}
defer conn.Close()
```

### 3.3 Passing Metadata & Token Validation API

Once connected via dynamic mTLS, internal services validate incoming API requests against the IdP.

#### Service Specification (gRPC Interface):
```protobuf
syntax = "proto3";
package hatef.identity.v1;

service TokenValidationService {
    rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
}

message ValidateTokenRequest {
    string access_token = 1;
    string dpop_proof = 2; // Required if the token is DPoP-bound
}

message ValidateTokenResponse {
    bool active = 1;
    string user_id = 2;
    repeated string scopes = 3;
    string client_id = 4;
    int64 expires_at = 5;
}
```

#### Validation Interceptor Behaviors on IdP:
1. **mTLS Handshake:** The IdP verifies the client's X.509 certificate.
2. **SAN Verification:** The IdP Go interceptor inspects the `Subject Alternative Name` (SAN) of the incoming connection to read the client SPIFFE ID.
3. **Application AuthZ:** If `spiffe://hatef.ir/ns/identity/sa/search-core` calls `ValidateToken`, the interceptor permits the invocation. If a service without validation clearance calls it, the interceptor immediately rejects it with `codes.PermissionDenied`.
4. **Token Resolution:** The IdP queries the active token details in Redis/PostgreSQL and returns token metadata.
