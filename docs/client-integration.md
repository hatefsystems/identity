# Hatef Identity Platform - Client Integration Guide

This guide separates current OAuth/OIDC, first-party browser and private gRPC
contracts from planned integration requirements. OAuth 2.1 remains an active draft,
not a final specification or achieved conformance claim. Target authority is the
[authentication and recovery policy](authentication-and-recovery-policy.md), with
source conflicts in the [assessment](security-architecture-assessment.md) and
release blockers in [security readiness](security-testing-and-readiness.md).

---

## 1. Public Clients Integration (OAuth/OIDC)

The flow below is the intended public-client contract, not a complete working SSO
journey: request validation and PKCE/token mechanisms exist, but interactive
authorization/login/consent and durable grant/session prerequisites remain blocked.
The first-party portal uses the separate Go cookie plus browser-key proof profile
in section 1.3, not OAuth access/refresh tokens for portal state.

### 1.1 Mandatory PKCE (S256)

Every public authorization flow must utilize the Authorization Code flow with Proof Key for Code Exchange (PKCE) according to RFC 7636. Use of the `plain` code challenge method is explicitly blocked.

Configured callbacks require structural HTTPS with valid host/port and no userinfo,
opaque scheme or fragment (including bare `#`); request matching remains exact.
Only explicit development permits canonical localhost/loopback HTTP. Test is not
a development exemption. `OIDC_ISSUER` likewise rejects query/fragment markers,
including bare `?`/`#`, while preserving supported issuer paths. No custom-scheme,
wildcard/prefix or provider-alias exception is added.

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

DPoP constrains stolen access/refresh token use to the bound key; it does not
prevent all session hijacking or same-origin XSS. RFC 9449 resource requests use
`Authorization: DPoP <access_token>` with matching proof and access-token `ath`.
Token-endpoint proofs do not require resource-token `ath`. Canonical `htu` excludes
query/fragment; generate a fresh JTI and handle only explicit nonce challenges.
The cookie plus proof profile in section 1.3 is a Hatef profile, not automatically
RFC 9449 access-token DPoP.

#### 1.2.1 Ephemeral Key Generation (Browser)

Clients generate an asymmetric ECDSA P-256 keypair via WebCrypto with `extractable: false`. This prevents API export of the private key, but same-origin malicious JavaScript may still invoke its signing operations. Non-exportability is not an XSS authorization boundary.

```javascript
// Generate a keypair; persistence requires a reviewed IndexedDB transaction.
async function generateDPoPKey() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // extractable: false prevents private key extraction
    ['sign', 'verify']
  );
  return keyPair;
}
```

#### 1.2.2 Generating the DPoP Proof Assertion

On every token-bound request, the client must generate and sign a JWT assertion included in the `DPoP` request header.

```javascript
async function createDPoPProof(keyPair, httpMethod, requestUrl, nonce, accessToken) {
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: await window.crypto.subtle.exportKey('jwk', keyPair.publicKey),
  };

  const payload = {
    jti: generateRandomString(16), // Single-use identifier
    htm: httpMethod.toUpperCase(),
    htu: canonicalProofUrl(requestUrl), // excludes query/fragment
    iat: Math.floor(Date.now() / 1000),
  };

  if (accessToken) {
    payload.ath = await computeAccessTokenHash(accessToken); // resource requests only
  }

  if (nonce) {
    payload.nonce = nonce; // Bind to server-supplied nonce
  }

  return signJWT(header, payload, keyPair.privateKey);
}
```

This is illustrative pseudocode: reviewed canonical URL, token hashing, random JTI
and JWT helpers are required. Do not use it as a runnable SDK or apply its
access-token hash to HttpOnly cookie requests.

#### 1.2.3 Token Endpoint Authentication Configuration

Public clients are incapable of maintaining secrets securely. Therefore:

- Public clients must be registered with their client metadata parameter `token_endpoint_auth_method` set strictly to `"none"`.
- Public clients do **not** use `private_key_jwt` for OIDC authentication. Only confidential back-end services are allowed to use `private_key_jwt`.

### 1.3 First-Party Portal Sessions (Task 7.3)

Use the application-local adapters in `apps/web/app/_lib/portal` for the portal,
not the OAuth token sample above. The browser sees one canonical HTTPS origin:
pages/static resources route to Next.js and `/api` routes directly to Go.
`PORTAL_ORIGIN` must match the issuer origin and an allowed WebAuthn origin.
There is no cross-origin API mode, BFF or cookie-only fallback.

1. On a deliberate passkey sign-in action, create/open a non-exportable P-256
   private `CryptoKey` and public JWK metadata in IndexedDB. Concurrent tabs select
   the active record transactionally. Persist no other credential/profile material;
   missing or unusable storage requires fresh login, not a weaker authentication mode.
2. Sign `POST /api/v1/auth/webauthn/login/generate-options` and `/login/verify`
   with the same key. The API freezes the verified thumbprint in pending state and
   the issued normal session. Perform real binary WebAuthn option conversion and
   credential serialization; cancellation/expiry is not successful authentication.
3. Bootstrap `GET /api/v1/users/me` using that key and the HttpOnly cookie before
   displaying private data. Keep the returned account/session snapshot transient.
   Its `session.expires_at` is absolute; never invent or extend it client-side.
4. Send `X-Portal-Session: <session.id>` on authenticated mutations and subsequent
   reads. A supplied intent is checked even on GET. `409 session_changed` means
   clear the old snapshot and re-bootstrap, not retry against a different account.
5. Every proof has a fresh JTI, method, canonical origin plus escaped path, current
   time and public JWK. Cookie requests have no access-token `ath`. Keep nonces
   request-local: retry once only for explicit pre-handler `401 use_dpop_nonce`
   plus `DPoP-Nonce`, generating a new proof/JTI. Do not retry uncertain mutations,
   authenticator responses or spent grants after transport failure.
6. Unsafe requests require the exact Origin and valid bounded JSON where a body
   is sent. Fetch uses same-origin cookies, no-store, abort signals and no arbitrary
   redirects. Its `mode: 'cors'` preserves the Origin header under `no-referrer`;
   strict URL validation still forbids cross-origin API calls. Using
   `mode: 'same-origin'` with that referrer policy can send `Origin: null` instead.
   APIs themselves enforce private/no-store/no-referrer on all responses.
7. Pin each sensitive action/target, obtain fresh UV/TOTP step-up when advertised,
   and spend the in-memory grant through `X-Step-Up-Auth`. Registration consumes it
   at options generation and finishes with the same session, without another grant.
   Profile display-name edits need no step-up but require an exact decimal revision.
8. Broadcast invalidation notices only. Clear private views and cancel late work
   on account/session change, sign-out, hide/pagehide or detected loss; resume with
   a new authority check. Do not send credentials/profile data between tabs or poll
   in the background to keep sessions alive.

An ordinary hidden-tab transition may retain a narrow non-secret TOTP action
intent in component/provider memory so switching to an authenticator app is usable.
Restore it only after the same public session ID is freshly verified, with a new
explicit challenge/confirmation. Never retain a factor code, grant, challenge,
proof, recovery batch or an in-flight mutation as resumable authority. Navigation,
pagehide, account change and failed revalidation discard the intent. Notifications
must not echo to their sender and undo a failed sign-out state; failed sign-out
requires explicit reconciliation. Cancelled transmitted mutations are uncertain,
not permission to replay them or restore an older list response.

Distinguish `session_required` from `use_dpop_nonce`, `invalid_dpop_proof` and a
login/step-up `invalid_credentials`. An incorrect TOTP stays in the dialog;
`403 insufficient_user_authentication` requests new step-up, and
`503 temporarily_unavailable` is not a cached authorization or a successful revoke.
The recovery API returns a replacement plaintext batch once. Keep it only in view
memory, support explicit Copy/Download, and clear it by navigation/session loss or
five minutes (whichever bound applies first). A lost generation response may have
invalidated the previous batch; only a new explicit generation can replace it.

For full HTTP shapes and failure handling, see the [browser boundary](api-design.md#first-party-browser-boundary-task-73).

#### First Passkey on a Password Account (T25)

The existing `PortalClient` also exposes a fixed-purpose password/contact path.
It does not infer eligibility from profile email, username or an empty key list.
The server decides whether the account is active, has an existing supported
password, zero current passkeys, no MFA or privileged role and a currently
evidenced selected contact. Recovery sessions cannot use this fallback. Existing
stronger TOTP/UV Step-up remains available under its own server policy.

Call each phase explicitly, using the same live portal client and browser key:

1. `firstPasskeyChallenge(password, channel, signal)` sends exactly
   `{password,channel}` to `POST /api/v1/auth/action-proofs/first-passkey/challenge`.
   `channel` is `email` or `sms`; the server selects the evidenced destination.
   Password bytes are not trimmed, normalized or subjected to new-password
   strength rules. A `202` acknowledges issuance/transport, not inbox receipt.
2. `firstPasskeyVerify(code, signal)` sends the private challenge and exactly six
   ASCII digits to the fixed `/first-passkey/verify` route. It accepts only the
   original `expires_at`, not a refreshed proof lifetime. This client does not
   normalize OTPs or automatically retry verification or delivery.
3. `startFirstPasskey(name, signal)` discards the private proof before validating,
   signing or sending the existing registration-options request. Only this request
   can carry `X-Action-Proof`; it never also carries `X-Step-Up-Auth`. The optional
   cosmetic credential name does not choose the native identity, RP or handle.
   Options must contain authoritative `expires_at`, an origin-compatible server
   RP, a canonical eight-byte handle, bounded server identity and required UV.
   The returned options can only shorten the original authority deadline.
4. `createFirstPasskey(signal)` invokes native creation once. Receiving options
   never opens a native prompt automatically. The credential response stays
   private, and successful native creation never submits a finish automatically.
5. `finishFirstPasskey(signal, onSend?)` discards that response locally before one
   submission to the existing registration-verify route, without a second proof
   or grant. Only a strictly decoded `201` safe credential with
   `user_verified: true` reports `passkeyAdded`. The existing security-outcome
   handling withdraws the old session; normal login follows separately, without
   automatic bootstrap or a replacement session.

The first three methods return only `{purpose: "first_passkey_enrollment",
expires_at}` metadata. It is not a `StepUpGrant`, proof token or resumable receipt.
Challenge, proof, bound options and native response are transient private client
fields. They retain the original account/session/key binding and both wall and
monotonic deadlines, so wall-clock rollback, locale or display-preference changes
cannot extend authority. `clearFirstPasskey()`, cancellation, expiry, disposal,
session/key change or a late response discard the corresponding authority. Never
persist or broadcast passwords, codes, proofs, options or attestations, or include
them in logs, diagnostics or browser artifacts.

`FirstPasskeyError.phase` distinguishes `challenge`, `proof`, `start`, `native`
and `finish`. `uncertain` never grants retry permission.
`credentialMayHaveBeenSaved` is true only for an uncertain finish, not an options
failure. A malformed or non-UV finish success is uncertain and never replayed.
Only the existing strictly identified pre-handler DPoP nonce rejection allows one
fresh-proof/JTI retry of the same logical request; native work is never repeated.
`409 enrollment_in_progress` and `Retry-After` are feedback, not retry scheduling.
The server spends a proof once before publishing options and retains account-wide
exclusion until the original deadline. Cancellation, refusal, response loss or
uncertainty do not refund it or release the slot early. No new portal UI, password/
OTP dialog, provider, preference, dashboard or login journey is implemented here.

### Planned Authentication and Restricted Repair

SEC01 identification uses immutable mandatory username, or explicitly selected
current verified uniquely associated primary email. Mobile is a recovery contact,
not an identifier; discoverable passkey login remains available. Current
contact-code login can issue ordinary authority without a primary and is not
target-compliant. Every target passkey assertion requires server-verified UV;
enabled/required independent MFA remains mandatory even after UV (SEC02-SEC03).

MFA Backup Codes complete only the original eligible-primary-bound MFA challenge;
ARCs plus fresh old-current eligible verified-contact proof authorize one ordinary
factor repair. TOTP repair additionally requires an eligible pre-existing primary.
Never substitute families or turn repair into a normal cookie, OAuth grant, admin,
legal, contact/deletion or general Step-up authority (SEC04-SEC06). `/recover-account`
is exclusively deletion cancellation/reclaim; a loss-factor journey requires a
separately approved route/contract and is not currently implemented.

After repair, the durable SQL barrier prohibits further repair/equivalent factor
mutation until fresh login satisfies the entire authoritative policy. An ordinary
password-only account may clear it with fresh SQL-recorded repaired-password
login; required-MFA accounts remain preauthenticated until actual required TOTP
or an eligible MFA Backup Code completes. Refresh, time, contact OTP, new challenges,
code regeneration and a repaired primary alone under an MFA policy cannot clear
it. Changed contacts have a mandatory 24-hour provenance-based cooldown, with
registration exemption and unknown provenance denied (SEC07-SEC08).

These are target requirements, not new DTOs or current SDK methods. Preserve exact
original deadlines/subject/JKT/purpose/version/contact bindings and explicit
native/send/verify actions; preference changes never replay work. Unknown results
create no authority, refund, automatic retry or cached authentication. SQL-earned
authority and final deciding-transaction checks must precede activation (SEC09-SEC11).

### 1.4 Conditional New-Account Registration

The [canonical registration contract](registration-contract.md) defines the
existing and planned flows for the same `/register` form and signup client.

#### Current Mounted Form

The initial form collects email, Iranian mobile and username, with an explicit
username-check button and a separate Start submission. Start initiates email
link delivery. The email phase offers explicit result checking and resend.
After email proof, the mobile phase offers explicit send/verify. After both
proofs, the passkey phase requests options, opens native resident UV enrollment
and submits the credential through one explicit action. Completion clears
transient signup state and offers `/login`. The uncertain phase offers explicit
outcome checking and ordinary login. The closed phase offers an explicit restart.
The separate verification page uses the same browser key for email-link proof.

Registration and SMS are disabled by default. Enabled signup uses the
[fixed POST routes](api-design.md#15-new-account-registration), exact Origin,
bounded strict JSON and public DPoP nonce/replay, without session cookies as
authority, Authorization, `ath` or `X-Portal-Session`. Start accepts exactly
`{email,phone,username}` and returns `{attempt_id,capability,canonical_email,
username_display,expires_at,email_sent}`. Submission acceptance is not mailbox
ownership. Start sends the initial email in response to the explicit submission.
Verification, resend and SMS sends require explicit actions.

Explicit `/validate` with `{stage:"username",registration:{username}}` returns
`{username_display,available}`; availability does not reserve a name. Use the
server's NFC display, never browser security folding or a Go-regex HTML `pattern`.
Handle `invalid_username`/`username_unavailable` field errors without owner/status
disclosure; `username_policy_changed` requires explicit restart. A locale change
must not validate, send, enroll or extend deadlines. When username support is
enabled, authenticated `GET /users/me/username` returns `{username:{display}|null}`
through the ordinary portal client, not this public signup client; show absence
honestly and expose no claim/rename control.

Keep the original verified non-exportable browser key/JKT and transient attempt
authority. Follow-ups require `{attempt_id,capability}`; email verification alone
requires `{attempt_id,token}` from the original JKT. Scrub
`/register/verify-email#attempt_id=...&token=...` immediately before explicit verify;
a different browser cannot mint a capability/session by opening the link.
Phone send returns `verification_id`; verify adds it plus a six-digit string code
preserving zeros. Passkey options returns `publicKey` for the frozen canonical
email/handle, resident key and UV required. Final adds standard creation JSON.

Pending/email/passkey/receipt validity is 15m/10m/at-most-5m/1h. Final result is
`{state:"completed",next:"login",receipt_expires_at,email_verified:true,
phone_verified:true}`; no user ID, role, password, mailbox or session is returned.
Normal discoverable login follows separately. Start/options/proof failure cannot
create an account or created-event intent. Resend replaces proof and clears phone/
ceremony progress without resetting attempt expiry or abuse counters.

After an ambiguous final response or `503 result_required`, explicitly POST
`/api/v1/auth/register/result` with the same capability/JKT and a new proof/JTI. Pending returns `expires_at`,
failed returns `receipt_expires_at`, completed returns the final shape, all with
proof flags. An observed pending result restores the applicable phase under the
original deadline. The form does not automatically repeat the final body or native
ceremony. An identical authorized completion can return the same receipt, while
changed completion data conflicts. Completed receipts never bootstrap a session. This narrow result/retry contract does not relax ordinary
portal/admin mutation rules, resurrect a consumed OTP or recover capability by
email. Lost memory/key authority requires restart or normal login. No exactly-once
external delivery or inbox/handset receipt is implied by relay/provider ACK.

Use text/email-input-mode controls for supported Unicode, not native ASCII-only
email admission. Server identity is NFC/local lowercase/NFC plus strict IDNA
lowercase ASCII domain; verify/store/deliver/lookup exact canonical bytes.
NFC equivalents converge; Persian/Arabic letters, dot/plus and NFKC-distinct local
parts remain distinct. Generic BlindIndex NFKC stays unchanged; email HMAC input
and captured generation share the explicit canonical profile. No browser hashing,
provider-specific aliases, historical rehash or dual-normalized lookup. SMTPUTF8
must be strictly advertised after verified TLS before EAI AUTH/envelope/DATA;
sender/auth stays ASCII and no mailbox downgrade is permitted.

Moderator `/users/lookup` clients must validate mandatory returned
`canonical_email` against the selected user row before presentation and moderation
pinning. Missing/mismatched binding is invalid output, not an ASCII/raw-input
fallback; the additive field grants no new permission. Enablement, fixed SMS.ir
VERIFY/live-versus-sandbox rules and dedicated cleanup gates are in
[operations](devops-operations.md#registration-enablement-and-cleanup), not asserted
by these integration instructions or historical acceptance.

#### Planned Six-Stage Form and Handoff

The [stage trace](registration-contract.md#planned-stage-to-request-trace)
defines names, personal information, username, contact verification,
authentication method, and location/final review. T34 provides the shared shell,
T35 connects personal/username validators, T36 connects contact and credential
choice, and T37 connects final review and session handoff. The client keeps the
same form, provider, key and absolute deadlines across back navigation and
preference changes. Explicitly validate the complete reviewed candidate and legal
versions before any native prompt. A cancelled passkey step leaves `both`
incomplete.

Only the direct response to the active final action may carry the T33 handoff.
Use the cookie-capable completion transport only at the T33 final boundary. The
response must report a known fresh commit and the exact new subject under the
original browser JKT, with a usable normal cookie. Discard prior authenticated state and
transient signup secrets while retaining the original key for one ordinary
bootstrap. Match the returned profile to that subject before mounting the existing
`/dashboard` portal or showing private data. Missing/unusable cookie, key/subject
mismatch, late response or bootstrap failure goes to ordinary `/login`.

On unknown commit or lost final/session response, offer explicit protected
`/result` checking and ordinary login. A completed receipt clears signup state
and offers ordinary login even if a session was originally issued. It does not
authorize bootstrap or another final submission. Only an authoritative pending
result can return to eligible in-attempt progress within the original deadline.
Failed or still-unknown outcomes never automatically start a new account,
resend or reopen a native prompt. See the
[completion response matrix](registration-contract.md#target-completion-and-reconciliation).

---

## 2. Confidential Clients Integration (`private_key_jwt`)

Confidential clients protect signing keys in approved backend custody; private
infrastructure alone does not establish security. Current `private_key_jwt`
authentication applies to client-credentials exchanges. Its absence from
authorization-code/refresh confidential-client exchanges is a release blocker,
not a supported unauthenticated confidential profile. Planned exchanges must
authenticate the exact client as well as enforcing PKCE/grant/key/session
bindings (SEC16).

### 2.1 Client Authentication Parameters

- **Authentication Method:** `private_key_jwt`
- **Token Endpoint:** `https://identity.hatef.ir/oauth2/token`
- **Assertion Signing Algorithm:** `RS256` (min 2048-bit RSA) or `ES256` (NIST Curve P-256).

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

- `iss` (Issuer): The pre-registered `client_id` of the client (e.g., `search-core`).
- `sub` (Subject): The same `client_id` (`search-core`).
- `aud` (Audience): The URL of the IdP token endpoint (`https://identity.hatef.ir/oauth2/token`).
- `jti` (JWT ID): A cryptographically secure random string unique to this request (validated by the server to prevent replay attacks).
- `exp` (Expiration Time): Unix epoch timestamp. Must not be longer than 5 minutes in the future.
- `iat` (Issued At): Unix epoch timestamp of creation.

Current replay claims are scoped to the canonical client/audience/JTI tuple and atomically
shared in Redis outside explicit development. Retention covers the entire accepted
`exp + 60s` leeway window with rounded absolute expiry. Redis `TIME`, not each
replica's wall clock, governs admission and the atomic claim's deadline check.
A recognized replay, corrupt/no-TTL state, clock failure or storage outage fails
authentication, never memory fallback. Different
replicas must share the same replay authority. This is a runtime contract, not
evidence of deployed Redis/fleet acceptance. SEC09/SEC16 require durable SQL-owned
admission before Redis becomes non-authoritative; do not flush/restore current
replay markers as disposable cache state.

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

**Implementation boundary:** Task 6.1 provides `internal/grpcauth`; Task 6.2 implements the three business RPCs and an opt-in private listener in the API process. HTTP-only operation remains the default. SPIRE provisioning, workload registrations, production grants and private networking remain operator-approved infrastructure work. The examples below are guidance, not deployed permissions.

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
    grpc.WithDisableRetry(),
)
if err != nil {
    log.Fatalf("gRPC client configuration failure: %v", err)
}
defer conn.Close()
```

The SPIFFE TLS helper verifies the certificate chain and pinned SPIFFE identity instead of a DNS hostname. Do not replace it with a raw `InsecureSkipVerify` configuration. `grpc.NewClient` is lazy: construction is not proof of connectivity or readiness; calls need deadlines and normal error handling.

The server requires TLS 1.3 and disables session tickets. New connections perform a fresh handshake, while every new RPC verifies the peer certificate against the current local trust bundle. Source renewal does not replace certificates on established connections. The runtime therefore uses a five-minute maximum connection age with 30-second grace; clients must maintain their source and reconnect with renewed credentials. Do not add automatic application retries to a proof-consuming RPC: after an ambiguous failure, the external client must generate a new proof rather than replay the old one.

### 3.3 Method Grants and IdentityService

The canonical contract is [`hatef.identity.v1.IdentityService`](../libs/schemas/proto/hatef/identity/v1/identity_service.proto), not a separate `TokenValidationService`. It implements three unary methods: `ValidateToken`, `CheckPermission`, and `GetInternalUserInfo`. User tokens and DPoP proofs belong to those handlers, not to workload authentication.

The server composition root uses the following guard pattern, with an existing `audit.Recorder` and maintained source. This example is not a production permission grant:

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
// cmd/server additionally registers IdentityService, applies limits/deadlines,
// binds the private listener, and owns bounded shutdown and source cleanup.
```

Install these options before additional business interceptor chains and never override their transport credentials. The helper registers no services and enables no reflection. Workload policy is immutable and copied on construction: no wildcards, namespace/prefix grants, or defaults. An empty policy denies all methods. The example grants Search Core only `ValidateToken`, not the other two methods. Full method names are limited to 512 characters and SPIFFE IDs to 2048; the configured trust domain must be a bare canonical name.

At each admission the guard requires a completed TLS connection, exactly one URI SAN containing a non-root SPIFFE workload identity in the configured trust domain, a currently valid chain, and valid SVID leaf key usages. Other SAN types do not supply identity. Custom SPIFFE TLS verification can leave `VerifiedChains` empty; the guard verifies the actual peer chain against a snapshot of the current bundle rather than trusting that field or `TLSInfo.SPIFFEID` alone.

| Admission result                                                      | gRPC status                                                                                  |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Missing/invalid TLS, certificate, identity, validity period, or trust | `Unauthenticated`                                                                            |
| Required trust bundle missing, empty, or unavailable                  | `Unavailable`                                                                                |
| Authenticated workload without the exact method grant                 | `PermissionDenied`                                                                           |
| Authenticated and explicitly granted                                  | Handler receives the verified ID via `grpcauth.IdentityFromContext`; its result is preserved |

Health and reflection methods have no automatic exemption. Unregistered methods may return gRPC's native `Unimplemented`. TLS-handshake failures occur before interceptor invocation and need not appear as an application authentication status.

Streaming support authorizes **stream creation only**. Expiry and trust changes block new RPC admissions but do not terminate or reauthorize already-open streams. Continuous revocation and forced stream expiry are not provided.

The guard emits `grpc.access.denied` through the existing best-effort recorder for interceptor-stage denials only. Events contain bounded method/status/reason metadata and a verified workload actor when available, never tokens, RPC bodies, raw certificates, or asserted metadata. The existing audit actor column is limited to 255 characters: longer verified IDs are omitted in full and marked with `actor_spiffe_id_omitted: true`, never truncated, hashed, or copied into the payload. These events are audit-only, with no fabricated user or security-ledger attribution. Recorder errors do not alter the rejection. Successful business operations and transport-handshake failures are outside this event's coverage.

### 3.4 Runtime Configuration and Rollout

Use shared PostgreSQL/Redis and an authorized local Workload API. This example uses reserved domains and grants only the named methods:

```dotenv
APP_ENV=production
GRPC_ENABLED=true
GRPC_ADDR=127.0.0.1:9090
GRPC_TRUST_DOMAIN=example.test
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock
GRPC_REQUEST_TIMEOUT=2s
GRPC_METHOD_GRANTS_JSON={"/hatef.identity.v1.IdentityService/ValidateToken":["spiffe://example.test/search"],"/hatef.identity.v1.IdentityService/GetInternalUserInfo":["spiffe://example.test/email"]}
GRPC_VALIDATION_POLICIES_JSON={"spiffe://example.test/search":{"audiences":["https://identity.example.test"],"origins":["https://search.example.test"]}}
```

`OIDC_ISSUER` must match the explicitly allowed audience; current tokens use `aud == issuer`, not independently selected resource audiences. Origins are canonical scheme/host/port values, without paths or wildcard suffixes. HTTPS is required except explicitly configured loopback HTTP in development. Every ValidateToken grant needs a validation policy; missing/invalid configuration fails startup. Explicit empty maps deny all. Neither an origin policy nor an administrator role implicitly grants an RPC.

The runtime bounds initial dependency/SVID acquisition to ten seconds, handshakes to five seconds, messages to 64 KiB, compact tokens/proofs to 16 KiB each, and audience/URI fields to 2 KiB. The default RPC deadline is two seconds, configurable to a positive value at most 30 seconds; shorter caller deadlines are preserved. Each HTTP/2 connection admits at most 100 concurrent streams. HTTP `/readyz` additionally checks enabled gRPC readiness, live usable SVID/trust, Redis and PostgreSQL. `/healthz` remains dependency-independent. No gRPC health or reflection bypass is registered.

Deploy issuers and shared stores together, drain old process-local sessions and require reauthentication before enabling consumers. Legacy access JWTs without the new grant/session/version claims are inactive through this RPC. Generated clients must supply the new request context. A lost/reset Redis namespace invalidates credentials; do not reconstruct authority from JWTs or restore stale credential/replay snapshots. Disable/drain the private listener for rollback rather than silently falling back to local-only JWT validation. SPIRE, federation, public ingress, resource-audience issuance and independent offline grants are not deployed by this change.

The [canonical packaged migration inventory](devops-operations.md#canonical-packaged-migration-inventory) install uses
`public.identity_schema_version`, refusing all retired `public.goose_db_version`,
untracked nonempty application schemas and contradictory histories without
upgrade/adoption. Stop all old writers before switching to explicitly scoped fresh
PostgreSQL and matching fresh/isolated Redis/NATS state; do not reuse old sessions,
events or consumer checkpoints. Reconcile each consumer baseline before activation.
Wire formats, cryptographic contracts and production/manual gates are unchanged.
The username migration preserves existing NULL usernames and seeds no active policy;
its [installation gates](devops-operations.md#username-policy-and-preflight-gates)
are separate from schema setup.
Baseline Down/reset refuse; any existing-environment reset needs separately explicit
scoped authorization. See [active setup](admin-operations.md#migration-and-contraction).

### 3.5 Validation and Error Forwarding

Send the exact raw access token, observed authorization scheme and expected audience. For DPoP, forward the proof plus original HTTP method and absolute URI observed at the resource's trusted HTTP edge. Do not extract method/URI from the proof or trust end-user forwarding headers. The service excludes query data during RFC 9449 URI comparison and never fetches the supplied URI. A bound token cannot be sent as Bearer or rebound to another key during refresh.

| Result                                   | Consumer behavior                                                                                                                                                            |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `active=true`                            | Use `principal_type` and `subject`; only USER has `user_id`. Enforce the resource's scopes/permissions and bind the action to this subject. Do not cache until `expires_at`. |
| `active=false`, unspecified DPoP outcome | Reject the access token without claims; typically HTTP 401 `invalid_token`.                                                                                                  |
| `DPOP_OUTCOME_INVALID_PROOF`             | Reject with HTTP 401 and the appropriate DPoP `WWW-Authenticate` error. No identity claims are returned.                                                                     |
| `DPOP_OUTCOME_USE_NONCE`                 | Return HTTP 401, `DPoP-Nonce: <dpop_nonce>` and `WWW-Authenticate: DPoP error="use_dpop_nonce"`. The external client creates a new proof/JTI containing that nonce.          |
| `Unavailable`                            | Treat as a dependency outage, not user inactivity. Fail closed; never authorize from an old success or switch to an offline verifier.                                        |
| `InvalidArgument` / `PermissionDenied`   | Correct the request or operator policy; neither is resolved by repeatedly submitting a user proof.                                                                           |
| `Canceled` / `DeadlineExceeded`          | Preserve cancellation semantics. An ambiguous proof-consuming attempt must not be automatically replayed.                                                                    |

Browser logout, individual session revocation, idle expiry and absolute expiry end all linked user access/refresh authority. Validation and refresh do not count as browser activity. The existing `offline_access` scope name remains accepted, but does not extend that browser lifetime. Client-credentials tokens have no browser or user identity. Read-only permission/profile RPCs are independently workload-authorized queries: a returned profile is not an authorization decision. Profiles disclose email and display name only for active/pending-verification accounts, omit both for suspended/banned accounts, and return NotFound for deleting/deleted accounts. Name and lifecycle revision come from the same snapshot.

Email is an existing optional protobuf field: preserve presence/absence, do not
remove it, fabricate a mailbox or substitute an empty string/hash. Subject identity
is the validated `(iss, sub)` pair plus explicit `USER` versus `CLIENT` principal
type. A UUID-shaped client ID never creates a human account or consumer recovery
eligibility. Bind subject, permissions and exact same-snapshot revisions; profile
data, method inventory and a role label are not earned MFA/hardware evidence.
SEC04/SEC16 privileged consumers need policy-admitted evidence and live
authorization at the action boundary; existing `active=true` is not proof that
that stronger consumer fence is delivered. Do not claim offline JWTs instantly
observe revocation or retroactively cancel already admitted work.

Current WebAuthn challenges, browser nonce/replay, bound sessions and scoped
client-assertion claims use shared Redis outside development. Missing/corrupt state
fails closed under current checks, but forged earned claims or lost replay markers
are not made trustworthy by SQL version checks. SEC09 requires primary SQL-earned
authority, and SEC16 requires durable tokens/consumer/restore gates before launch.
See [API design](api-design.md#22-identityservice) and
[security-state architecture](data-architecture.md).

## 4. User Lifecycle Consumption

The [lifecycle contract](api-design.md#3-asynchronous-events-nats-jetstream) is metadata-only. Each service needs its own durable pull consumer on `IDENTITY_USERS`, subscribing to all four subjects with explicit acknowledgements. Do not share a durable between different microservices: that distributes work instead of synchronizing both services. Subscribers need explicitly granted broker credentials and independent gRPC grants to fetch allowed profile data.

1. Validate subject, schema, UUIDs, revision and bounded fields. V1 supports `status`/`email`; v2 adds `display_name` and the coarse `private_profile` marker (updated active account, that marker alone). Current real email changes emit v1, display-name/private-profile writes emit v2; creation/status/deletion and supported revision-less tombstone adaptation remain v1. No private value or exact private-field list enters the event. ProtoJSON uint64 revisions are decimal strings; never round through JavaScript `number`. Unknown versions/fields or malformed events require quarantine/alerting, not silent acknowledgement.
2. Commit projection changes, idempotency information and the processing checkpoint together before acknowledging. A crashed consumer may receive the same event again, and publisher duplicates can outlive JetStream's two-minute deduplication window. Reject already-applied/older revisions even if the transport sequence is new.
3. Treat a validated deletion as terminal for that UUID, including a supported revision-less legacy deletion. Scrub local Class A profile data without erasing independently protected legal/security evidence. Older created/updated messages must never resurrect it. Keep tombstone/revision protection while older replay/redelivery remains possible; policy-driven expiry requires a reconciled baseline.
4. For other events, use the exact status to invalidate or disable the projection. Pending deletion is reversible, not permanent erasure. Fetch current allowed data through `GetInternalUserInfo` when needed; its `lifecycle_revision` must be at least the event revision. Apply the returned snapshot only if it has not been superseded locally. This RPC is not an authorization decision.
5. `NotFound` can mean pending deletion as well as absence. Apply only a temporary invalidation, guarded against the triggering event being superseded during the RPC; commit/ack it so later events can advance. Never infer irreversible deletion from NotFound. Dependency failures remain retryable, and authorization must fail closed rather than use stale cached authority.
6. Persist the stream creation identity and contiguous processing checkpoint. Missing/recreated streams or consumers, expired history, and sequence gaps require reconciliation before treating the projection as authoritative. Starting at latest or acknowledging a truncated stream is not reconciliation. Handle out-of-order worker completion without advancing past an uncommitted gap.

Limits retention is a finite replay buffer: acknowledgements do not delete history, and an indefinitely offline consumer has no delivery guarantee. Bootstrap for existing users and full reconciliation after a gap are deployment prerequisites; this task provides neither an enumeration/snapshot RPC nor production consumers. New consumers must establish an authoritative baseline and matching stream checkpoint before activation. The integration suite contains executable contract fixtures, not a downstream implementation.

Deploy and validate dual-version readers/publishers and actual downstream consumers
before enabling display-name/private-profile writers. A `display_name` event contains
no name value; fetch the allowed current snapshot only under independent grants
and apply exact revision protection. A `private_profile` marker grants no private
attribute disclosure; use only separately authorized snapshot/grant contracts.
Preserve mixed v1/v2 replay and terminal legacy tombstones. During
rollback, keep v2-capable publishing/consumption while v2 outbox or retained broker
history exists; never run an old strict-v1 worker over those rows. Consumer code and
deployment outside this repository remain explicit operator release gates.

Planned T40/T41 security events stay metadata-only and preserve exact revision,
optional email and existing audit/envelope formats/readers (SEC14). Never insert
private attributes, code values, recipient/token payloads or new audit bytes into
these lifecycle events to make recovery observable. Reader compatibility and
notification foundation precede writers; schema documentation is not downstream
consumer deployment or baseline reconciliation. During failover/restore quarantine,
consumers reject stale authority and reconcile checkpoints without resurrecting
erased accounts, revoked credentials or spent codes (SEC16).

## 5. Geography Selector (T08/T09)

`apps/web/app/_components/location-selector.tsx` exports controlled
`LocationSelector` with `value: LocationInput | null`, `onChange`, and optional
`disabled`. `apps/web/app/_lib/geography-client.ts` owns the bounded anonymous
same-origin transport; `libs/ui` supplies a locale-agnostic searchable-list
primitive. Mount inside the stable display provider. English and Persian messages
belong to the application, not transport/domain/UI-library code.

Province is required; city, urban area or village is optional. Locality remains
disabled until an explicit province selection. Typed search is draft text, never a
committed ID. The current selector displays original name, source type and
ancestor path. T09 acceptance must also distinguish records with the same name,
type and ancestry while preserving their distinct source IDs. Exercise that case
with a synthetic fixture. Explicit clear/skip actions do not auto-select a result. Changing/clearing
province clears incompatible locality and announces it. Retained pages are bounded
and loaded explicitly; requests debounce 250 ms and use cancellation plus generation
guards against late responses. Loading, empty, unavailable, rate-limit and catalog
change states remain distinct. Mobile uses the existing native dialog; desktop
uses combobox/listbox keyboard interaction. Names/paths use automatic direction,
technical IDs use LTR isolation, and preference changes do not replay API work.

Future T34/T37 can insert this component into the existing registration component's
location stage when that stage is separately implemented. Do not insert it into
the current email/phone/passkey flow or alter current request/completion behavior.
Client selection is only an advisory draft; future T10 must revalidate and encrypt
the server-owned snapshot revision with the IDs. A lookup of retired/historical
data is display-only, not eligibility for a new selection.

`web:test-geography-browser` builds an API-connected fixture only inside a
run-owned disposable test application. No production route or production build
flag exposes that fixture. Use synthetic fixtures in public CI and browser
artifacts. Operators obtain real data through the
[T07 release and custody process](devops-operations.md#t07-dataset-release).
