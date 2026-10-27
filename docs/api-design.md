# Hatef Identity Platform - API Design

This document outlines the API contracts for the Hatef Identity Platform. As per the architecture, all contracts are defined via **Protocol Buffers (.proto)**. This document serves as a high-level representation of the generated gRPC and REST/OIDC endpoints.

## 1. External APIs (REST & OIDC)
These endpoints are exposed through the Traefik API Gateway and are consumed by the Next.js frontend, mobile applications, and third-party OAuth clients.

### 1.1 Standard OIDC/OAuth2 Endpoints
Implemented strictly according to OpenID Connect Core 1.0 and OAuth 2.1 specifications.
- `GET /.well-known/openid-configuration`: Discovery endpoint. Indicates mandatory PKCE support (`code_challenge_methods_supported: ["S256"]`), DPoP support, and supported client authentication methods (`token_endpoint_auth_methods_supported: ["private_key_jwt", "none"]`).
- `GET /oauth2/jwks`: Returns the JSON Web Key Set containing only asymmetric public keys (**RS256** and **ES256**) mapped across a graceful 3-key rotation cycle: `active` (currently signing new tokens), `next` (pre-generated and published key), and `previous` (recently expired key, kept to verify outstanding unexpired tokens).
- `GET /oauth2/auth`: Authorization endpoint (redirects to login/consent UI). Requires `code_challenge` (S256) and `code_challenge_method=S256` for public clients.
- `POST /oauth2/token`: Token exchange endpoint (Auth Code, Refresh Token, Client Credentials).
  - **PKCE Verification:** Rejects exchange requests using the `plain` method; strictly validates `code_verifier` with SHA-256 (`S256`).
  - **Refresh Token Rotation (RTR):** Invalidates the old refresh token and issues a new one. If a previously exchanged/used refresh token is presented, immediate breach detection triggers and revokes all active session tokens for that user.
  - **DPoP Binding (RFC 9449):** Expects a `DPoP` header containing a valid signed proof JWT. Validates the server-issued `DPoP-Nonce` and verifies that the `jti` of the proof has not been replayed. Returns sender-constrained access and refresh tokens bound to the thumbprint of the client's public key, and issues a `DPoP-Nonce` response header if a nonce refresh is required.
  - **Client Authentication (`private_key_jwt`):** Confidential clients must authenticate by sending a signed client assertion (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) signed with their pre-registered asymmetric private key. The assertion must contain a unique `jti` and an expiration time `exp` no greater than 5 minutes from generation.

### 1.2 Authentication Flow (Frontend API)
Used exclusively by the Hatef web platform to authenticate users. Task 7.3 enables discoverable-passkey sign-in for existing accounts, not signup or password login.
- `POST /api/v1/auth/register`: Planned account registration; not connected by the portal.
- `POST /api/v1/auth/verify-email/request`: Planned primary-email verification request.
- `POST /api/v1/auth/verify-email/confirm`: Planned primary-email verification confirmation.
- `POST /api/v1/auth/login`: Planned username/password login; its public form remains disabled.
- `POST /api/v1/auth/logout`: Revokes the current live bound session and clears its cookie. Requires browser proof and matching session intent while a live session exists. Missing/expired-cookie logout remains an idempotent `204`, with exact Origin still required. Dependency failure is not successful revocation.

#### First-Party Browser Boundary (Task 7.3)

Pages/assets go to Next.js and `/api` goes directly to Go through one HTTPS origin. There is no BFF, CORS workaround, bearer token in browser storage, or cookie-only fallback. `PORTAL_ORIGIN` is a canonical origin, matching the `OIDC_ISSUER` origin and one `WEBAUTHN_RP_ORIGINS` entry. HTTP is permitted only for explicit loopback development. Proof target URIs use this trusted origin plus the escaped request path, never caller-controlled Host or forwarding headers.

- Normal authenticated routes require a live `__Host-` Secure/HttpOnly/SameSite=Strict cookie, an active account and a DPoP proof using the session's originally bound key. Restricted recovery-enrollment and old unbound cookies cannot bootstrap the portal. A missing browser key requires fresh passkey authentication, not attaching a replacement key to an old cookie.
- Every unsafe first-party request, including login/logout, requires one exact `Origin`. Missing, `null`, multiple, sibling and noncanonical origins are rejected. JSON bodies are bounded UTF-8 objects with valid media types; duplicate fields/trailing documents are rejected, and endpoint-specific schemas reject unknown fields where specified. OAuth token and private gRPC protocols retain their separate admission rules; admin RBAC/Origin requirements are not replaced.
- Browser DPoP uses its own realm and shared Redis nonce/replay authority. The proof has a fresh JTI, `htm`, canonical `htu`, `iat`, public JWK and server nonce, but no fabricated access-token `ath`. Wrong session kind/key/intent must fail before consuming nonce or replay state. Only fully authorized successful requests renew browser activity.
- A pre-handler `401 {"error":"use_dpop_nonce"}` includes `DPoP-Nonce` and `WWW-Authenticate: DPoP error="use_dpop_nonce"`. Retry at most once with a fresh proof/JTI and that nonce. No handler, grant or ceremony has been consumed by this challenge. Do not retry uncertain mutations, authenticator responses or used grants after transport failures.
- Bootstrap supplies `session.id`; send it as `X-Portal-Session` on authenticated mutations. The portal also sends it on post-bootstrap reads. A supplied mismatched/empty/duplicate intent returns `409 session_changed`, including on reads; discard old account state and re-bootstrap. This public ID is an intent marker, not an authentication credential.
- All first-party API responses, including errors and empty responses, are `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`. They do not inherit Next.js document middleware. Never log bodies, proofs, cookies, grants, recovery codes, names or identity-bearing URLs; use route-template diagnostics.

| Response | Client handling |
|---|---|
| `401 session_required` with Cookie challenge | Normal browser authority is missing, expired, revoked, restricted, unbound or inactive. Clear private state and require authentication. |
| `401 invalid_dpop_proof` | Proof/key/method/URI/replay validation failed; never downgrade to cookie-only access. |
| `401 invalid_credentials` during login/step-up | Credential verification failed, not proof that an existing session was lost. An incorrect TOTP stays in the dialog. |
| `403 insufficient_user_authentication` | Obtain a new, single-use step-up grant. |
| `409 profile_conflict` | Refresh the saved profile/revision without discarding the unsaved draft. |
| `409 session_changed` | Clear the stale session snapshot before any further account operation. |
| `429 rate_limited` | Surface throttling; do not loop challenges or mutations. |
| `503 temporarily_unavailable` | Dependency failure; do not authorize from cached state or report a successful mutation. |

### 1.3 Advanced Security, WebAuthn & Step-up Auth
Endpoints for phishing-resistant logins, Multi-Factor Authentication, and short-lived Step-up verification.

#### WebAuthn Device Management
- `GET /api/v1/auth/webauthn/keys`: Array of owned credentials, including `id`, `name`, enrollment/last-use metadata and existing authenticator flags. Never includes COSE keys. A user-chosen label is not a verified device model.
- `PATCH /api/v1/auth/webauthn/keys/{id}`: Strict required `{"name":"..."}` plus fresh `X-Step-Up-Auth`; returns the updated credential projection. Foreign/missing IDs share `404 credential_not_found`. Names use the same optional, single-line, 80-code-point normalization as display names below; an empty string clears the label.
- `DELETE /api/v1/auth/webauthn/keys/{id}`: Remove a specific WebAuthn device (Requires Step-up authentication in `X-Step-Up-Auth`). `{id}` is the unpadded base64url credential ID as returned by `GET /keys`. Scoped to the caller's account: a credential belonging to another account is reported as `404 credential_not_found`, identical to one that does not exist, so credential IDs cannot be probed. Refuses with `409 {"error":"last_credential"}` when it is the account's final passkey. WebAuthn is currently the only surface that issues a normal browser session, so TOTP/password fields do not make deleting the final passkey safe; enrol another passkey first.

#### WebAuthn Registration & Login Flows
- `POST /api/v1/auth/webauthn/register/generate-options`: Optional `{"name":"..."}` for a new credential on an already authenticated account. The normalized name is frozen in pending state. Requires Step-up authentication in `X-Step-Up-Auth`; the single-use grant is consumed when the ceremony starts. Enforces RP ID as a clean domain name and validates the exact clientDataJSON origin. The returned `user.id` is a CSPRNG-generated random 64-bit handle, not the account UUID.
- `POST /api/v1/auth/webauthn/register/verify`: Existing serialized credential-response body; it cannot supply a replacement name. Requires the same bound session, not a second grant, and returns `201` with the created named credential. A foreign-session attempt neither completes nor consumes the pending ceremony.
- `POST /api/v1/auth/webauthn/login/generate-options`: Get challenge for WebAuthn login. Supports discoverable credentials (usernameless login with an empty `allowCredentials` list) to completely neutralize account harvesting. For legacy user-named flows, if the input identity is unregistered, the endpoint returns a mock challenge with identical structure and delay, although discoverable credentials remain the recommended path due to browser-level key-lookup speed variances on local devices.
- `POST /api/v1/auth/webauthn/login/verify`: Verify the assertion using the same verified DPoP key that started options generation, issue a bound session cookie and return `204`. The client must then bootstrap `/users/me` before rendering private content.

Every pending WebAuthn challenge is tagged with its ceremony flow and applicable account/session/key bindings. Shared Redis atomically checks bindings before single-use consumption, allowing start on one API replica and completion on another. Wrong bindings do not burn legitimate state; concurrent valid finishes have one winner. The versioned store has native TTLs (configured default five minutes, maximum fifteen), bounded 64-KiB serialized state and two-second operation deadlines. Redis faults fail closed without process-local fallback. Anonymous login options/verification and reclaim-options admission share a 30-request/IP-subnet/minute budget before allocating challenge/nonce state; the explicit nonce retry also counts. Memory storage is for isolated tests/development only.

#### Multi-Factor Authentication (TOTP) & SMS OTP
- `POST /api/v1/auth/mfa/generate`: Generate a pending TOTP secret and QR code. Requires Step-up authentication in `X-Step-Up-Auth` because adding an authenticator changes who can satisfy future Step-up checks. The response contains `enrollment_id`, `secret`, `otpauth_url`, `issuer`, and `account_name`; keep the secret client-side only until confirmation.
- `POST /api/v1/auth/mfa/verify`: Verify `{"enrollment_id":"...","code":"123456"}` and enable TOTP. The pending enrollment is bound to the authenticated user, exact session that called `/generate`, and the `maintenance` purpose; by default it expires after 10 minutes and permits at most five failed attempts. A foreign enrollment/session is reported as `mfa_not_setup` without burning the legitimate attempt. The Step-up grant was consumed at `/generate`, so verification needs the same live session but no second grant. Success returns `{"status":"enabled"}`.
- `DELETE /api/v1/auth/mfa`: Disable TOTP MFA (Requires Step-up authentication in `X-Step-Up-Auth`). Returns `409 {"error":"last_factor"}` unless at least one passkey remains.
- There is deliberately no general-purpose `/api/v1/auth/mfa/verify-code` endpoint. Enabled TOTP secrets can only be checked inside a purpose-specific login/Step-up flow, preventing an authenticated-session code-validity oracle. Step-up uses `POST /api/v1/auth/stepup/verify` and collapses wrong, replayed, and stale codes into `401 invalid_credentials`.
- `POST /api/v1/auth/recovery-codes/generate`: Generates a new batch of one-time backup codes (stored securely in PostgreSQL hashed via **SHA-256** to prevent CPU Denial of Service during validation). Requires Step-up authentication in `X-Step-Up-Auth`: a fresh batch is a set of long-lived bypasses for every other factor, so minting one must cost a re-asserted strong factor. This is not circular, because a recovery code cannot itself satisfy Step-up.
- `GET /api/v1/auth/recovery-codes/status`: Returns only `{"remaining":10,"low":false}`. Generation returns `{"codes":["..."],"count":10}` once and atomically invalidates every previous code. There is no GET endpoint for previous plaintext batches. A lost generation response may mean replacement committed; require explicit new generation and fresh step-up rather than replaying/caching the old response.

#### Restricted Recovery Flow
- `POST /api/v1/auth/recovery/start`: Anonymous start endpoint. Accepts `{"email":"user@example.com"}` and always returns the same no-store `202` shape for active, inactive, deleted, and unknown accounts: `transaction_id` (256-bit opaque base64url value), `expires_at`, and `expires_in` (600 seconds). The transaction is stored by SHA-256 hash, expires after 10 minutes, and is atomically single-use. A lookup timing floor and deterministic decoy subject prevent account enumeration.
- `POST /api/v1/auth/mfa/verify-recovery-code`: Accepts `{"transaction_id":"...","code":"..."}`. The transaction is consumed before the code check, so a failed guess cannot be retried under it. A valid high-entropy code is located and physically deleted in the same ACID transaction, then the server issues a 10-minute `recovery_enrollment` session and returns `{"next":"enroll_factor","expires_in":600}`. Invalid, spent, foreign, and decoy transactions collapse into `401 {"error":"invalid_credentials"}`; a saturated recovery limit returns `429 {"error":"rate_limited"}`.
- `POST /api/v1/auth/enrollment/webauthn/register/generate-options`: The only ceremony a `recovery_enrollment` session may start. It requires WebAuthn user verification (`UV`), is bound to the restricted session, and cannot be called by a normal session.
- `POST /api/v1/auth/enrollment/webauthn/register/verify`: Completes that UV-required ceremony. The restricted session may claim at most one replacement passkey and is revoked after success; the response is `{"next":"login"}`. A duplicate or already-claimed use returns `409 {"error":"enrollment_already_used"}`. It never becomes a normal authenticated session and cannot access profile, Step-up, recovery-code generation, or other account-management routes.

If issuing the restricted session fails after a recovery code was consumed, the server fails closed and does not resurrect the code. The user must start again with another unused code.

#### Short-Lived Step-up Authentication
- `POST /api/v1/auth/stepup/challenge`: Generates a challenge for the Step-up auth flow, supporting `userVerification: "required"` (biometrics/PIN via WebAuthn) or TOTP verification. Requires a normal live session and binds the pending WebAuthn assertion to its exact session ID. Returns `methods` (the factors this account can present, WebAuthn first) plus the WebAuthn assertion options when a passkey is enrolled. Unlike the login options endpoint there is no mock/decoy branch — the caller is already authenticated as this account, so there is nothing to enumerate. `409 no_stepup_factor` means the account has neither a passkey nor TOTP and cannot perform Step-up until one is enrolled.
- `POST /api/v1/auth/stepup/verify`: Verifies the WebAuthn UV assertion or active TOTP token. On success, returns a short-lived (3-5 minutes) Step-up token carrying the ACR claim `https://ref.hatef.ir/acr/stepup`. This token must be passed in the `X-Step-Up-Auth` header for sensitive endpoints.
  - **Grant format:** a compact JWS (`typ: stepup+jwt`) signed by the same rotating keystore as access and ID tokens, carrying `iss`, `sub`, `aud`, `acr`, `amr` (RFC 8176: `["hwk","user"]` for a UV assertion, `["otp"]` for TOTP), `auth_time`, `sid`, `jti`, `iat`, `exp`, and `cnf.jkt` when the earning session is DPoP-bound. The distinct `typ` is load-bearing: access tokens are signed by the same keys and already use `aud == iss`, so without it an access token would satisfy every other check.
  - **Single use:** the `jti` is consumed on first successful validation, so one grant authorises one operation. Outside explicit development, every replica atomically claims the HMAC-derived replay identity in shared Redis for the remaining grant lifetime; Redis errors fail closed. This is what makes Step-up a per-operation check rather than a 5-minute window of elevated privilege.
  - **Session bound:** the `sid` claim pins the grant to the session that earned it. A grant cannot be paired with a different session's cookie, even for the same user.
  - **Factors:** Generic step-up accepts WebAuthn with `userVerification: "required"` (verified server-side) or an active TOTP passcode. Deletion is stricter: it requires the verified grant's `hwk` and `user` AMR and never accepts TOTP. A TOTP passcode is single-use across its acceptance window. Recovery codes are not step-up factors.
  - **Rate limited** per subnet and per account (per-minute and per-hour), with the subnet window evaluated first so a saturated shared proxy cannot burn a targeted account's budget.
  - `403 user_verification_required` distinguishes "your authenticator only proved presence" from a generic failure, because it is the one outcome the user can act on. Every other credential failure collapses into an opaque `401 invalid_credentials`.

**Challenge response on gated endpoints.** A request to any Step-up gated endpoint without a valid grant is answered `403` with `{"error": "insufficient_user_authentication", "acr_values": "https://ref.hatef.ir/acr/stepup"}`. The error code follows RFC 9470 (OAuth 2.0 Step Up Authentication Challenge Protocol); the status is `403` rather than RFC 9470's `401` because these are cookie-session endpoints where `401` already means "session gone, re-authenticate" — reusing it would send the user through a full login instead of the inline overlay in `frontend-pages.md` §5.3. Missing, malformed, expired, already-spent, and foreign-session grants all render identically so the response cannot be probed.

**Fail-closed mounting.** When the Step-up service cannot be constructed (for example, its required database is absent in development), gated endpoints are **not mounted at all** rather than served without their gate. Outside development, missing Redis or replay-key configuration prevents startup. A user with no enrolled Step-up factor receives `409 no_stepup_factor`; no condition turns a gated route into an ungated one.

### 1.4 User Profile & Privacy (GDPR)
- `GET /api/v1/users/me`: Bootstrap projection: `id`, `email`, `display_name`, `status`, decimal-string `lifecycle_revision`, `deletion_enabled`, and `session: {id, expires_at}`. `deletion_enabled` is a server-controlled capability, not a legal-hold disclosure; clients default a missing field to false during rollout. `expires_at` is the session's real absolute RFC 3339 deadline. No roles, backup contacts, factor secrets, ciphertext or legal data.
- `PATCH /api/v1/users/me`: Strict required string fields `{"display_name":"Example","expected_revision":"42"}`; returns the same projection. No step-up is required for this cosmetic field. Revision strings are canonical nonnegative decimals, at most `9223372036854775807`; JSON numbers, signs, leading zeros, nulls, unknown/duplicate fields and trailing bodies are rejected.
- `GET /api/v1/users/me/sessions`: Array of live owned browser authority with public `id`, `current`, creation/activity times and bounded IP/user-agent metadata. A session is not a physical-device identity or standalone OAuth grant.
- `DELETE /api/v1/users/me/sessions/{session_id}`: Owner-scoped individual revocation (`204`/`404`); deleting the current session also clears its cookie. Linked access/refresh authority fails subsequent live validation immediately. Already admitted requests may finish; remote DOM clears on detection, not instantaneously. No bulk-revocation portal action.
- `PUT /api/v1/users/me/password` and `POST /api/v1/users/me/export-data`: Planned interfaces, outside this portal implementation.

Display and credential names reject invalid UTF-8, Unicode control characters and line/paragraph separators, then trim outer Unicode whitespace and limit the result to 80 code points. Empty clears the optional name; names are not unique. The profile service locks the account and rechecks active status/captured auth-version before comparing the expected lifecycle revision. A stale revision returns `409 profile_conflict`. A no-op at the current revision changes no timestamps/revision and emits no event. A real display-name edit commits the name, one lifecycle revision increment and metadata-only v2 outbox intent in one transaction; enqueue failure rolls it all back. It does not change auth-version or revoke sessions. Name values are excluded from audit/event payloads; ordinary sanitized audit recording remains best-effort, not a durable commit guarantee.

Task 7.4 adds `/dashboard/privacy` and an independent `/recover-account` page.

- `DELETE /api/v1/users/me` and its trailing-slash alias require normal cookie/DPoP/Origin/session-intent admission and a fresh `X-Step-Up-Auth` grant with verified WebAuthn UV. A valid TOTP-only grant is consumed and rejected with the existing `403 insufficient_user_authentication` challenge, without logging the session out.
- **Transactional acceptance:** under the account lock, active status and captured `auth_version` are rechecked. Soft deletion, version advancement, reversible lifecycle event, hashed single-use reclaim request, and encrypted per-recipient notification intents commit together. Encryption/enqueue failure rolls back; concurrent suspension/ban must not be overwritten.
- **Response and revocation:** confirmed acceptance returns empty `204` and clears the current cookie. Live authorization rejects old sessions/grants; revocation cleanup is bounded after commit. No receipt, token, exact deadline or inbox-delivery result is returned. A lost response or post-commit activity failure is an uncertain outcome, not proof of rollback. Never automatically replay DELETE or infer success from a later `401`.
- **Coalescing, not authenticated resend:** concurrent requests admitted under the original authority share its request, token, deadline and notice set. After deactivation, authenticated admission rejects the account. Automatic SMTP retries operate independently, never mint a token or extend the deadline. The old resend-cooldown setting and public resend promise no longer apply.
- **Delivery:** `deletion-notifier` sends separate messages to the server-selected primary and configured backup. Identical mailboxes are deduplicated, preserving local-part case. Stable message IDs aid retries, but SMTP is at least once; ambiguous acknowledgements can duplicate mail. Relay acceptance does not prove inbox delivery.
- **Enablement:** `GDPR_DELETION_ENABLED` defaults to false. PostgreSQL transactions, envelope encryption, shared Redis, sessions/token revocation, and WebAuthn/step-up must be configured. Recovery and accepted notice draining remain independent of the switch and SMTP availability. First verify a working supervised SMTP worker and an independently accessible recovery mailbox.
- **Limits and authority:** the account/day limit defaults to 3 and returns `429 rate_limited` on saturation. Production recovery/purge policy is exactly `720h`. Live account/version validation prevents recovery from reviving old authority; offline JWT-only consumers retain residual authority until expiry, at most ten minutes. Already admitted requests may finish.

#### Account Reclamation (cancel a pending deletion)
A `pending_deletion` account cannot log in at all, so reclamation is a separate anonymous ceremony rather than an ordinary login: the emailed single-use token plus one verified strong factor. Both endpoints are token-bearing and mounted outside the session group — they deliberately do not live under `/users/me`, because that prefix implies a session and there is none.

- `POST /api/v1/auth/deletion/reclaim/options`: Accepts `{"token":"..."}` and returns the single factor to present: `{"factor":"webauthn","webauthn":{...}}` (a `userVerification: "required"` assertion challenge bound to this deletion request) or `{"factor":"totp"}`. It does **not** consume the token, so a user who abandons the ceremony halfway can restart it. Exactly one factor is named; the response never enumerates the account's factors.
- `POST /api/v1/auth/deletion/reclaim/`: Accepts `{"token":"...","factor":"webauthn","assertion":{...}}` or `{"token":"...","factor":"totp","code":"123456"}`. Success restores `active`, invalidates outstanding reclaim tokens, and returns `204` without a session; normal login follows separately. The deciding transaction rechecks the exact request/token, original expiry, attempt cap and current pending account after factor verification. Expiry or retirement during verification cannot be bypassed.
  - **Both factors are accepted deliberately.** A passkey-only account has no TOTP secret, and forcing TOTP here would make such accounts unrecoverable. The WebAuthn ceremony is tagged distinctly from login and Step-up, so a reclaim challenge can never be redeemed to mint a session and a login challenge can never satisfy a reclaim. A TOTP passcode is single-use across its whole ±1-step acceptance window.
  - **Bounded failed factors:** a wrong factor alone does not consume the token, but `GDPR_RECLAIM_MAX_ATTEMPTS` (default 5) failures retire it. Increment and retirement are atomic under concurrency; infrastructure failures are not bad-factor attempts.
  - **Opaque failures.** Unknown, expired, consumed, and foreign tokens, a wrong factor, a missing account, a wrong account status, and an account with no verifiable factor at all render identically as `401 {"error":"invalid_token"}`. A saturated limit returns `429 {"error":"rate_limited"}`. Only a genuine infrastructure fault returns `500`, and it does not depend on the token's validity. Rate limited per subnet then per account (`GDPR_RECLAIM_PER_SUBNET_PER_HOUR`, `GDPR_RECLAIM_PER_ACCOUNT_PER_HOUR`).
  - **Identifier reservation.** The account's email, phone, and backup-email uniqueness indexes cover `pending_deletion` rows for the whole window, so a third party cannot claim the identifier while a deletion is pending and cause the reclaim to fail. A registration attempt on a reserved identifier must be reported as `409`.

Reclaim is anonymous, not unprotected: exact Origin, bounded JSON, shared admission/rate limits and token-plus-factor verification apply. No cookie or existing IndexedDB/DPoP key is needed. Mail links use a fixed HTTPS origin and `/recover-account#token=<opaque token>`; the browser immediately scrubs the fragment and retains bounded memory only. Opening/scanning a link performs no redemption. There is no query/path token, email-only fallback or public resend endpoint. Legal holds delay erasure, never token expiry.

### 1.5 Account Verification & Anti-Spam
To prevent fake account creation (e.g., for the Email Service), the platform uses standard Server-to-Client SMS or Backup Email verification. All phone numbers and backup emails are stored using AES-GCM-256 application-layer Envelope Encryption.
- `POST /api/v1/users/me/phone/send-code`: Sends a 6-digit verification code via SMS to the provided phone number. Requires Step-up authentication in `X-Step-Up-Auth`, because adding a password-reset/recovery channel changes account authority. Returns `{"status":"sent","verification_id":"..."}`; `verification_id` is a 256-bit opaque base64url handle, not the phone number or an authorization credential.
- `POST /api/v1/users/me/phone/verify`: Verifies `{"verification_id":"...","code":"123456"}` and marks the server-side pending phone as verified, returning `{"status":"verified"}`. The pending record is bound to the account, exact initiating session, normalized phone, and code hash. The client cannot replace the phone during verification; a foreign account/session sees `no_active_code` and does not consume the challenge or an attempt. The Step-up grant was consumed at `/send-code`, so this endpoint needs the same live session but no second grant.
- `DELETE /api/v1/users/me/phone`: Removes the verified phone number from the account (Requires Step-up authentication in `X-Step-Up-Auth`). The encrypted payload and its blind index are cleared together so they cannot drift apart. Returns `204` and is idempotent with respect to the phone: removing an absent phone succeeds.
- `POST /api/v1/users/me/backup-email/send-code`: Sends a verification link/code to an alternative backup email address.
- `POST /api/v1/users/me/backup-email/verify`: Verifies and links the backup email to the account.
- `DELETE /api/v1/users/me/backup-email`: Removes the backup email from the account (Requires Step-up authentication in `X-Step-Up-Auth`).

### 1.6 Password Reset & Account Recovery
- `POST /api/v1/auth/password-reset/request`: Initiates password reset flow. Can be routed to the Primary Email, Backup Email, or Verified Phone (via SMS).
- `POST /api/v1/auth/password-reset/verify-otp`: Validates the OTP received via SMS or Backup Email to authorize a password change.
- `POST /api/v1/auth/password-reset/confirm`: Confirms the new password securely.

### 1.7 Admin & Moderation API

Admin routes require an active, non-deleted account, a normal DPoP-bound browser session under the first-party boundary above, and live database permissions. Recovery-enrollment sessions cannot access them. The existing admin Origin allow-list and audit/permission checks remain additional requirements. Mutations and legal attribution consume a single-use, session-bound step-up grant **after** permission checks. All responses use `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`. Session activity renews only when the final authorized response is released after the durable admin transaction commits, not when a handler writes a tentative buffered response.

| Route under `/api/v1/admin` | Seeded role | Contract |
|---|---|---|
| `GET /users`, `GET /users/{user_id}` | Support, Moderator | Safe account summary; only Moderator receives email. No roles, legal-hold state, encrypted material or authentication secrets. |
| `POST /users/lookup` | Moderator | Exact normalized email in JSON `{email}`. Legacy `GET /users?email=...` is rejected. |
| `PATCH /users/{user_id}/status` | Moderator + step-up | Required `{status, reason}`; active/suspended/banned only, no self or privileged-account moderation. Pending verification/deletion and deleted accounts are refused. |
| `GET /audit-logs` | DPO | Required `start_time`, `end_time` (RFC3339 or Unix seconds), at most 31 days; optional bounded `event_type`. Returns stored row hashes. |
| `GET /audit-logs/verify`, `GET /ledger/verify` | DPO, Super Admin | Content-free verification; no actors, network data, payloads or account data. |
| `POST /legal-holds` | DPO + step-up | Required `account_ref`, `reason`, `requesting_authority`, `legal_basis`; optional advisory `review_at`; UUID `Idempotency-Key` header. |
| `GET /legal-holds` | DPO | Optional `account_ref`; `status=active|released|all`; true snapshot total. |
| `DELETE /legal-holds/{hold_id}` | DPO + step-up | Releases only that request; 204 for release or already released, 404 for unknown ID. |
| `POST /preservation-requests` | DPO + step-up | Required `account_ref`, `reason`, `requesting_authority`; optional advisory `expires_at`; UUID `Idempotency-Key`. Atomically records a hold and observed evidence presence even without a live account. |
| `POST /legal-inquiry/lookup` | DPO + step-up | JSON identifier/type (`email` only), authority/case context, time bounds, optional fields and cursor. Requires a verified signer fixture before mounting. No GET alias. |

Offset lists use `{items,total,limit,offset}` with default 50 and maximum 200. Lists and counts share a statement snapshot; empty items are `[]`. Attribution uses `{items,next_cursor,coverage}`, a fixed high-water bound, and a fresh retention/hold check on every page. Empty results mean no matching **indexed, eligible records in that scope**, not proof of no activity. Default fields are record/account references, event type, timestamps and hash; network/client/device fields require explicit selection and case purpose. Phone attribution returns `400 unsupported_identifier_type`.

Independent requests may protect the same account. New requests return 201; matching retries return 200 with `replayed=true` and current state. Reusing a key with different inputs returns 409. Replaying a released request cannot reactivate it. Advisory dates never release a hold. Release resumes original retention clocks; preservation neither restores purged data nor creates an immutable snapshot.

Every successful read commits sanitized disclosure intent before any response bytes. Mutations, encrypted restricted context and audit intent commit together. Audit storage failure returns `503 audit_unavailable`; an unavailable store cannot guarantee durable recording of that rejected attempt. An acknowledged outbox worker delivers Class C intent to the signer. Ordinary security-event recording retains its existing best-effort transport.

Verification defaults to a 1,000-step page (maximum 5,000), captures `through_seq`, and resumes with `after_seq`, that fixed bound, and optional `predecessor_hash`. It reports the seed, checked range, completion, next cursor and first mismatch. Valid sequence allocation gaps are allowed. Class C `/audit-logs/verify` behavior is unchanged. Hashes in a filtered audit list do not form a contiguous-chain proof.

`/ledger/verify` reads the durable head, surviving rows and compact erased-span
checkpoints in one bounded read-only REPEATABLE READ snapshot per request. That
snapshot is separate from the administrative audit transaction; the response is
still withheld until durable disclosure intent commits. Authorization and the
content-free response boundary are unchanged. No route grants retention DELETE
or exposes erased metadata.

| Ledger response field | Meaning |
|---|---|
| `checked` | Retained records whose canonical bodies were recomputed, not erased rows. |
| `purged_count`, `purged_spans` | Authorized erased rows and checkpoint spans traversed on this page. |
| `proof_steps` | Bounded live-record plus checkpoint work; the page limit applies to both kinds. |
| `seed_source` | May be `checkpoint_boundary` when the exact historical boundary digest remains available. |
| `restart_required` | The requested exact historical boundary was erased inside a compacted span and is unavailable. |
| `scope` | Declares database-relative retained-segment verification; erased bodies are not recomputed and ingestion completeness/independent authenticity are not proved. |

A legitimate prefix/interior/tail purge is traversed through authorized
checkpoint transitions rather than treated as missing evidence corruption. If
no retained bodies are checked, including a fully purged ledger, the result is
`verified=false`, `failure_reason=no_retained_records`; proof traversal may still
be complete or return a next cursor. It is neither successful content verification
nor a tampering alarm, and is audited as a non-tamper outcome.

Continuation never silently moves `through_seq` or approximates an interior
digest. Exact retained/checkpoint boundaries remain usable. If compaction makes
a requested boundary unavailable, the content-free result has
`failure_reason=retention_boundary_unavailable`, `restart_required=true`,
`verified=false`, `complete=false` and no next cursor. Restart a fresh verification
from genesis without the stale boundary/high-water parameters. Unknown supplied
sequence boundaries that are not explained by retention remain invalid requests.

`missing_head`, `head_mismatch`, `invalid_checkpoint`, `checkpoint_overlap`,
`checkpoint_link_mismatch` and `missing_proof` indicate invalid proof state;
`hash_mismatch` and supplied `predecessor_mismatch` remain failures. None yields
`verified=true`. The durable head detects inconsistent tail/sequence state, but
checkpoints and Class C receipts do not independently defeat a privileged coherent
database rewrite or backup rollback. External anchoring is explicitly deferred.

HTTP role assignment and trigger-reset are unmounted. Use the controlled [admin operations procedure](admin-operations.md) for provisioning. Ban/suspension invalidate credentials across instances. `ValidateToken` applies the live account/version gate; offline JWT consumers still retain at most the configured ten-minute token lifetime. Reactivation does not revive old credentials or prevent re-registration.

### 1.8 Operational Legal Workflow

These routes are under `/api/v1/admin` and require the additional opt-in workflow
and approved immutable policy. Only explicit DPO permissions are seeded; Super
Admin has no bypass. All writes and annual artifact downloads require a fresh
step-up grant, exact Origin and a UUID `Idempotency-Key`. JSON actor/ID/key
overrides, unknown fields, trailing bodies and query strings on body-based routes
are rejected. Read responses and mutations are withheld until durable audit
intent commits. New workflow responses do not create permanent response-body
fingerprints in audit.

| Method and suffix | Contract |
|---|---|
| `POST /legal-cases` | `expected_version=0`, UTC `received_at`, optional advisory `next_review_at`, encrypted `content`, `subject_ids`, `hold_ids`. One request, zero-to-many subjects. |
| `GET /legal-cases`, `GET /legal-cases/{case_id}` | Bounded `{items,total,limit,offset}` summary list (`status=all|open|closed`) or restricted detail/history; expired unheld/erased detail is unavailable. |
| `POST /legal-cases/{case_id}/revisions` | Expected state version, replacement content and current subject/hold selection; historical subject protection is retained. |
| `POST /legal-cases/{case_id}/reviews` | Expected state version, `content_revision`, decision, rationale and optional next review. |
| `POST /legal-cases/{case_id}/close` | Explicit closure without a response; never releases a hold. |
| `GET /legal-reviews` | Due review queue requiring both case-read and hold-read permissions. |
| `POST /legal-holds/{hold_id}/reviews` | Advisory review/history, starting at `expected_version=0`; original hold replay fields are unchanged. |
| `POST /legal-cases/{case_id}/response` | Exact content revision, outcome, rationale and encrypted manifest (recipient/evidence/legal basis and exact subject/time/field/artifact selection). |
| `POST /legal-cases/{case_id}/response/approve` | Exact expected state, content and proposal revisions; different DPO for data-bearing outcomes. |
| `POST /legal-cases/{case_id}/response/delivery` | Same approved revisions, UTC `delivered_at`, external `receipt_reference`; attests one final delivery and closes the case. |
| `GET /legal-transparency/monthly?start=YYYY-MM&months=N` | Exact audited aggregates for 1-12 months, explicit coverage and late-entry limitations. |
| `POST /legal-transparency/reports` | Prepare a completed UTC `year`, `expected_version=0`; immutable snapshot. |
| `GET /legal-transparency/reports/{report_id}` | Internal approval representation including digest, source/policy version and staleness. |
| `POST /legal-transparency/reports/{report_id}/approve` | Different DPO approves exact `expected_version`, `data_version`, `policy_version`, `digest`. |
| `POST /legal-transparency/reports/{report_id}/download` | Expected version; returns only the approved aggregate JSON bytes, not the internal report representation. |

Cases distinguish optimistic state version from immutable content revision, so
review bookkeeping does not invalidate itself. Pending/needs-information/rejected
reviews cannot authorize data disclosure. Scope edits require a fresh accepted
review and approval. Delivery timestamps cannot precede preparation or required
approval. `content.request_type` is `disclosure|preservation|other`;
`notification_disposition` is `pending|notify|restricted|not_applicable`, with
restriction text required for `restricted`. Hold review decisions are
`continue|release_recommended|needs_information`; closure reasons are
`withdrawn|no_response_required`. At most 100 distinct historical subjects are
allowed, not 100 new subjects per amendment. Detail history exposes truncation
explicitly. Replay does not consume a second request/answer counter;
changed input or stale versions produce 409. Retention-erased cases return 410,
policy/storage failures 503, and authorization failures 403. Operator delivery
attestation is not evidence that the API transferred data. Supplements, reopening,
external messaging, uploads, public publishing and the UI are not implemented by
this contract. See [operator procedures](admin-operations.md#legal-review-and-transparency-task-55).

## 2. Internal APIs (gRPC)
These services are strictly internal, protected by mTLS, and never exposed to the public internet. They allow other microservices in the Hatef ecosystem (e.g., Email Service, Search Core) to interact with the IdP securely and efficiently.

Task 6.1 supplies `internal/grpcauth`; Task 6.2 composes it with `IdentityService` and an opt-in private listener in the existing API process. `GRPC_ENABLED=false` retains HTTP-only operation. Enabling requires PostgreSQL, Redis, a local Workload API socket, an explicit trust domain, exact method grants, and caller validation policies. No SPIRE deployment, production grants, or public gRPC routing is implied.

### 2.1 Identity SAN Validation (gRPC RBAC)
`grpcauth` verifies the client's X.509-SVID at each unary call or stream creation, using exactly one URI **Subject Alternative Name (SAN)** containing a valid workload **SPIFFE ID**, for example `spiffe://hatef.ir/ns/identity/sa/email-service`. The identity must belong to the explicitly configured trust domain and its certificate chain must verify against the current injected bundle. CN, DNS SANs, metadata, forwarding headers, OAuth clients, and administrator roles are not workload authentication.

Service RBAC is an immutable exact-full-method-to-SPIFFE-ID allowlist supplied by the composition root. There are no default, wildcard, or prefix grants. Unknown grants are never inferred from service names, and health/reflection methods have no exemption. Authorization denies the RPC, not other independently permitted calls on the same authenticated connection. The helper installs TLS 1.3 mTLS credentials and both guards without opening a listener or owning credential-source lifetime.

RPC-stage authentication failures return `Unauthenticated`, unavailable trust material returns `Unavailable`, and authenticated callers without a matching grant receive `PermissionDenied`. Allowed handlers can read the verified service identity through `grpcauth.IdentityFromContext`. Streaming authorization is admission-only; already-open streams are not revoked automatically. Interceptor denials produce sanitized, best-effort `grpc.access.denied` audit events, without user/security-ledger attribution or request contents. Handshake failures and unregistered-method dispatch can occur before an interceptor. See [client integration](client-integration.md#3-internal-grpc-integration-zero-trust) for wiring, certificate renewal, error, and audit limits.

### 2.2 `IdentityService`
Implemented by `internal/identitygrpc` using the [canonical protobuf contract](../libs/schemas/proto/hatef/identity/v1/identity_service.proto). Workload admission does not replace token, account, scope, or permission checks.

| RPC | Contract |
|---|---|
| `ValidateToken` | Required raw `access_token`, explicit `expected_audience`, and observed `authorization_scheme` (`Bearer` or `DPoP`). DPoP also requires `dpop_proof`, original `http_method`, and independently observed absolute `http_uri`. Any supplied HTTP context is validated against the caller's exact permitted origins. |
| `CheckPermission` | Nonzero `user_id` UUID and exact `permission` identifier, at most 100 characters. Uses the existing primary-DB predicate for active, nondeleted accounts. Role names, OAuth scopes, wildcard expansion, and administrator bypasses are not supported. Unknown users/permissions return `allowed=false`. |
| `GetInternalUserInfo` | Nonzero `user_id` UUID. Active/pending-verification users return ID, primary email, display name, status and `lifecycle_revision`; suspended/banned users omit both email and display name. Missing, deleted and pending-deletion users return `NotFound`. Name and revision come from the same snapshot. The revision orders shared-profile changes, not credentials or authorization. No encrypted contacts, factors, hashes or legal metadata are returned. |

`ValidateToken` verifies the local rotating key, `typ=at+jwt`, algorithm, issuer, audience, expiry and required claims. User tokens require the matching live normal browser session, OAuth grant, and captured primary-DB `auth_version`; client-credentials tokens use an explicit `CLIENT` principal and never acquire a user identity, even when the client ID is UUID-shaped. Recovery-enrollment sessions, ID tokens, step-up grants, assertions and legacy unlinked access JWTs are rejected.

Active responses contain `principal_type`, `subject`, `client_id`, scopes and JWT `expires_at`; `user_id` is populated only for `USER`. Invalid, expired or revoked authority returns `active=false` without claims. Invalid required proofs additionally return `DPOP_OUTCOME_INVALID_PROOF`. A nonce challenge returns only `DPOP_OUTCOME_USE_NONCE` and `dpop_nonce`, not claims or a revocation assertion. Malformed RPC envelopes return `InvalidArgument`, caller policy violations `PermissionDenied`, dependency/corrupt-state failures `Unavailable`, and cancellation/deadlines preserve their gRPC codes.

Signatures use local keys; shared Redis serves session/grant and DPoP state. Successful user validation still performs an indexed primary-DB account check. Neither validation results nor positive permissions are cached, and `expires_at` is not a safe cache lifetime. Validation and refresh never touch browser activity. Logout, device revocation, two-hour default idle expiry, or 24-hour default absolute expiry end linked access/refresh authority, even if a refresh token's own lifetime is longer. The retained `offline_access` scope name does not grant independent offline lifetime.

Refresh rotation is atomic across instances, cannot change its original DPoP key, and retains consumed-secret evidence. Recognized reuse preserves the account-wide breach policy: advance primary account authority, revoke browser sessions, and invalidate all user grants. A Redis cleanup failure cannot revive old account versions. Missing Redis authority is inactive; backend failures never become successful validation or an in-memory fallback.

`CheckPermission` and profile lookup authorize the calling workload to query a supplied user ID; they do not prove that an end user delegated that operation. Consuming services must bind their action to the validated subject and enforce relevant scopes. Profile disclosures emit sanitized, best-effort audit events, without security-ledger attribution or sensitive response contents. See the client integration guide for error forwarding and rollout requirements.

---

## 3. Asynchronous Events (NATS JetStream)

Task 6.3 uses the canonical [`UserLifecycleEvent`](../libs/schemas/proto/hatef/identity/v1/user_lifecycle_event.proto) contract and a separate `IDENTITY_USERS` stream. The Go worker publishes committed outbox intent with JetStream acknowledgements. The audit stream, signer and legal evidence retention are independent.

| Subject | Trigger |
|---|---|
| `identity.user.created` | Transactional `lifecycle.CreateUser` for a new active/pending-verification account. No new registration HTTP endpoint is provided; passkey enrollment and the synthetic lookup probe are not account creation. |
| `identity.user.updated` | Actual ban/reactivation, pending-deletion or reclamation transition (v1), or a real display-name update (v2). `changed_fields` names the changed shared fields, never their values. Primary-email changes remain reserved; that mutation endpoint is separate work. |
| `identity.user.suspended` | Actual transition into the literal `suspended` status, including from banned. Repeating the same status does not emit an event even when credentials are invalidated. |
| `identity.user.deleted` | Exactly one hold-checked physical user DELETE and its terminal intent commit atomically. Soft deletion, dry runs, held subjects, no-row deletes and rolled-back transactions never emit a tombstone. |

Both supported versions use ProtoJSON with snake_case keys: `schema_version`, UUID `event_id`, exact `event_type`, UUID `user_id`, UTC `occurred_at`, positive `revision` as a decimal JSON string, optional named-enum `status`, and `changed_fields`. Version 1 validation remains unchanged (`status`/`email` only). Version 2 explicitly adds `display_name` to the bounded changed-field set. Only display-name updates emit v2 in this task; existing creation/status/deletion producers and legacy deletion adaptation stay v1. Unknown versions/fields remain errors, and persisted v1 payloads are never rewritten. Deletion omits status/changed fields. Payloads are limited to 16 KiB and exclude name/email/contact values, credentials, ciphertexts, IPs and moderation narratives. Identifiers/timestamps remain linkable metadata, not anonymous data.

`users.lifecycle_revision` is independent of `auth_version` and `auth_epoch`. Existing accounts begin at 0 without synthetic history; transaction-aware creation starts at 1. Each real captured change increments once, and deletion uses the locked account's last revision plus one. Outbox IDs/times/revisions stay stable across retries. Phone, MFA, password, passkey, recovery-code, role and session mutations do not belong to this shared-profile stream. Direct SQL and fixtures are outside the explicit Go capture boundary.

The worker accepts existing exact `{"user_id":"<uuid>"}` deletion payloads, validates them, and creates a versioned terminal envelope from their persisted row ID/time without inventing a revision. This is the only supported revision-less event. Persisted legacy payloads are not rewritten.

Delivery is **at least once**. A PubAck followed by an uncertain database commit can replay the same ID, including outside the broker's finite deduplication window. Limits retention enables independent consumers; it is not the audit stream's work queue. A delayed or poisoned per-account head blocks its later revisions while other accounts can progress. Consumers must implement [idempotency, reconciliation and terminal tombstones](client-integration.md#4-user-lifecycle-consumption). Events synchronize projections, not instantaneous access revocation; continue using live authorization checks.

Deploy dual-version publishing/readers and downstream consumers before enabling display-name writers. Downstream deployment is an explicit release prerequisite, not evidence supplied by repository tests. Rollback must retain v2-capable publishing/consumption while any v2 intent or replay remains; see [portal cutover](devops-operations.md#user-portal-cutover-task-73).
