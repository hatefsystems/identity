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

Internal microservices must bypass public HTTP routing and authenticate directly to the Identity Platform over **gRPC with mTLS**. Forwarded headers and caller-supplied metadata are not workload credentials.

**Implementation boundary:** Task 6.1 provides `apps/identity-api/internal/grpcauth`, a reusable security layer and self-contained TLS/gRPC tests. The running API is still HTTP-only. Listener activation, Workload API lifecycle, production grants, and the business RPC implementations remain Task 6.2; SPIRE provisioning remains separately approved infrastructure work. The examples below are integration guidance, not a deployed configuration.

### 3.1 SPIFFE/SPIRE Bootstrapping

A future SPIRE deployment must expose an authorized local Workload API to each workload, for example through `unix:///run/spire/sockets/agent.sock`. Agent topology, workload attestation/registration, trust bundles, and socket access controls must be provisioned before enabling the listener. This task neither installs sidecars nor provisions the post-MVP DaemonSet.

When an application starts, a maintained source obtains its **SVID** (SPIFFE Verifiable Identity Document) and trust bundles. With `go-spiffe/v2` v2.8.2:

```go
import "github.com/spiffe/go-spiffe/v2/workloadapi"

source, err := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock")),
)
if err != nil {
    log.Fatalf("Unable to connect to SPIRE workload API: %v", err)
}
defer source.Close()
```

The composition root owns this source. Keep it alive throughout RPC service, and stop RPC activity before closing it or the shared audit recorder. `grpcauth` accepts the source interfaces but does not create a client, acquire credentials, or manage shutdown.

### 3.2 Dynamic mTLS gRPC Connections

Using the `X509Source`, the client constructs a secure gRPC connection without hardcoding any TLS certificate files or rotation timers.

```go
import (
    "crypto/tls"

    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// Example server identity. Production must pin its approved exact identity.
tlsConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(
    spiffeid.RequireFromString("spiffe://hatef.ir/ns/identity/sa/idp-core"),
))
tlsConfig.MinVersion = tls.VersionTLS13

conn, err := grpc.NewClient("dns:///idp-core.internal:9090",
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
)
if err != nil {
    log.Fatalf("gRPC client configuration failure: %v", err)
}
defer conn.Close()
```

The SPIFFE TLS helper verifies the certificate chain and pinned SPIFFE identity instead of a DNS hostname. Do not replace it with a raw `InsecureSkipVerify` configuration. `grpc.NewClient` is lazy: construction is not proof of connectivity or readiness; calls need deadlines and normal error handling.

The server helper requires TLS 1.3 and disables session tickets. New connections perform a fresh handshake, while every new RPC also verifies the peer certificate against the current local trust bundle. Renewing the source does not replace the certificate on an established connection. Define reconnection/connection-age behavior before production so calls do not continue using expired peer credentials.

### 3.3 Method Grants and IdentityService

The canonical contract is [`hatef.identity.v1.IdentityService`](../libs/schemas/proto/hatef/identity/v1/identity_service.proto), not a separate `TokenValidationService`. It defines three unary methods: `ValidateToken`, `CheckPermission`, and `GetInternalUserInfo`. Their business implementations remain Task 6.2. User tokens and DPoP proofs belong to those handlers, not to workload authentication.

The future server composition root can construct the guard as follows, using an existing `audit.Recorder` and maintained source. This example is not a production permission grant:

```go
import "github.com/hatefsystems/identity/apps/identity-api/internal/grpcauth"

guard, err := grpcauth.New(grpcauth.Config{
    TrustDomain: "hatef.ir",
    Grants: map[string][]string{
        "/hatef.identity.v1.IdentityService/ValidateToken": {
            "spiffe://hatef.ir/ns/identity/sa/search-core",
        },
    },
    Bundles: source,
    Recorder: recorder,
    Logger: logger,
})
if err != nil {
    return err
}
options, err := guard.ServerOptions(source)
if err != nil {
    return err
}
server := grpc.NewServer(options...)
// Task 6.2 must register the service, bind a private listener, and own shutdown.
```

Install these options before additional business interceptor chains and never override their transport credentials. The helper registers no services and enables no reflection. Workload policy is immutable and copied on construction: no wildcards, namespace/prefix grants, or defaults. An empty policy denies all methods. The example grants Search Core only `ValidateToken`, not the other two methods. Full method names are limited to 512 characters and SPIFFE IDs to 2048; the configured trust domain must be a bare canonical name.

At each admission the guard requires a completed TLS connection, exactly one URI SAN containing a non-root SPIFFE workload identity in the configured trust domain, a currently valid chain, and valid SVID leaf key usages. Other SAN types do not supply identity. Custom SPIFFE TLS verification can leave `VerifiedChains` empty; the guard verifies the actual peer chain against a snapshot of the current bundle rather than trusting that field or `TLSInfo.SPIFFEID` alone.

| Admission result | gRPC status |
|---|---|
| Missing/invalid TLS, certificate, identity, validity period, or trust | `Unauthenticated` |
| Required trust bundle missing, empty, or unavailable | `Unavailable` |
| Authenticated workload without the exact method grant | `PermissionDenied` |
| Authenticated and explicitly granted | Handler receives the verified ID via `grpcauth.IdentityFromContext`; its result is preserved |

Health and reflection methods have no automatic exemption. Unregistered methods may return gRPC's native `Unimplemented`. TLS-handshake failures occur before interceptor invocation and need not appear as an application authentication status.

Streaming support authorizes **stream creation only**. Expiry and trust changes block new RPC admissions but do not terminate or reauthorize already-open streams. Continuous revocation and forced stream expiry are not provided.

The guard emits `grpc.access.denied` through the existing best-effort recorder for interceptor-stage denials only. Events contain bounded method/status/reason metadata and a verified workload actor when available, never tokens, RPC bodies, raw certificates, or asserted metadata. The existing audit actor column is limited to 255 characters: longer verified IDs are omitted in full and marked with `actor_spiffe_id_omitted: true`, never truncated, hashed, or copied into the payload. These events are audit-only, with no fabricated user or security-ledger attribution. Recorder errors do not alter the rejection. Successful business operations and transport-handshake failures are outside this event's coverage.
