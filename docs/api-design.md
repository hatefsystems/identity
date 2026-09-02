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
Used exclusively by the Hatef web platform to authenticate users.
- `POST /api/v1/auth/register`: Register a new user account. Passwords hashed using standard Argon2id before database insertion.
- `POST /api/v1/auth/verify-email/request`: Request/resend primary email verification link.
- `POST /api/v1/auth/verify-email/confirm`: Validate the token and mark the primary email as verified.
- `POST /api/v1/auth/login`: Standard username/password login. Returns a session cookie (`__Host-` prefixed) or initial DPoP-bound token.
- `POST /api/v1/auth/logout`: Invalidates the current session.

### 1.3 Advanced Security, WebAuthn & Step-up Auth
Endpoints for phishing-resistant logins, Multi-Factor Authentication, and short-lived Step-up verification.

#### WebAuthn Device Management
- `GET /api/v1/auth/webauthn/keys`: List all registered WebAuthn devices.
- `DELETE /api/v1/auth/webauthn/keys/{id}`: Remove a specific WebAuthn device (Requires Step-up authentication in `X-Step-Up-Auth`). `{id}` is the unpadded base64url credential ID as returned by `GET /keys`. Scoped to the caller's account: a credential belonging to another account is reported as `404 credential_not_found`, identical to one that does not exist, so credential IDs cannot be probed. Refuses with `409 {"error":"last_credential"}` when it is the account's final passkey. WebAuthn is currently the only surface that issues a normal browser session, so TOTP/password fields do not make deleting the final passkey safe; enrol another passkey first.

#### WebAuthn Registration & Login Flows
- `POST /api/v1/auth/webauthn/register/generate-options`: Get a challenge for registering a hardware key/biometric on an already authenticated account. Requires Step-up authentication in `X-Step-Up-Auth`; the single-use grant is consumed when the ceremony starts. Enforces RP ID strictly as a clean domain name (e.g., `identity.hatef.ir` without protocol, port, or path) according to W3C specs, while validating origin details (protocol, domain, port) against clientDataJSON. The returned `user.id` field contains a CSPRNG-generated random 64-bit value to prevent user identity correlation.
- `POST /api/v1/auth/webauthn/register/verify`: Verify the WebAuthn registration, validating the signature counter and requiring the exact authenticated session that generated the challenge. It does not require a second Step-up grant: the pending ceremony carries the initiating session ID and a foreign-session attempt neither completes nor consumes it.
- `POST /api/v1/auth/webauthn/login/generate-options`: Get challenge for WebAuthn login. Supports discoverable credentials (usernameless login with an empty `allowCredentials` list) to completely neutralize account harvesting. For legacy user-named flows, if the input identity is unregistered, the endpoint returns a mock challenge with identical structure and delay, although discoverable credentials remain the recommended path due to browser-level key-lookup speed variances on local devices.
- `POST /api/v1/auth/webauthn/login/verify`: Verify WebAuthn login assertion.

Every pending WebAuthn challenge is tagged with its ceremony flow, and every authenticated ceremony is bound to the initiating session. A registration, login, Step-up, or recovery-registration challenge cannot be redeemed by another verifier. Binding mismatches do not burn the legitimate caller's challenge.

#### Multi-Factor Authentication (TOTP) & SMS OTP
- `POST /api/v1/auth/mfa/generate`: Generate a pending TOTP secret and QR code. Requires Step-up authentication in `X-Step-Up-Auth` because adding an authenticator changes who can satisfy future Step-up checks. The response contains `enrollment_id`, `secret`, `otpauth_url`, `issuer`, and `account_name`; keep the secret client-side only until confirmation.
- `POST /api/v1/auth/mfa/verify`: Verify `{"enrollment_id":"...","code":"123456"}` and enable TOTP. The pending enrollment is bound to the authenticated user, exact session that called `/generate`, and the `maintenance` purpose; by default it expires after 10 minutes and permits at most five failed attempts. A foreign enrollment/session is reported as `mfa_not_setup` without burning the legitimate attempt. The Step-up grant was consumed at `/generate`, so verification needs the same live session but no second grant. Success returns `{"status":"enabled"}`.
- `DELETE /api/v1/auth/mfa`: Disable TOTP MFA (Requires Step-up authentication in `X-Step-Up-Auth`). Returns `409 {"error":"last_factor"}` unless at least one passkey remains.
- There is deliberately no general-purpose `/api/v1/auth/mfa/verify-code` endpoint. Enabled TOTP secrets can only be checked inside a purpose-specific login/Step-up flow, preventing an authenticated-session code-validity oracle. Step-up uses `POST /api/v1/auth/stepup/verify` and collapses wrong, replayed, and stale codes into `401 invalid_credentials`.
- `POST /api/v1/auth/recovery-codes/generate`: Generates a new batch of one-time backup codes (stored securely in PostgreSQL hashed via **SHA-256** to prevent CPU Denial of Service during validation). Requires Step-up authentication in `X-Step-Up-Auth`: a fresh batch is a set of long-lived bypasses for every other factor, so minting one must cost a re-asserted strong factor. This is not circular, because a recovery code cannot itself satisfy Step-up.
- `GET /api/v1/auth/recovery-codes/status`: Check how many valid recovery codes are remaining.

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
  - **Factors:** WebAuthn with `userVerification: "required"` (the flag is verified, not merely requested) or an active TOTP passcode. A passcode is single-use across its whole ±1-step acceptance window. **Recovery codes are explicitly not accepted** — they are a login bypass, so honouring one would let a stolen code authorise account deletion or regenerate the code batch.
  - **Rate limited** per subnet and per account (per-minute and per-hour), with the subnet window evaluated first so a saturated shared proxy cannot burn a targeted account's budget.
  - `403 user_verification_required` distinguishes "your authenticator only proved presence" from a generic failure, because it is the one outcome the user can act on. Every other credential failure collapses into an opaque `401 invalid_credentials`.

**Challenge response on gated endpoints.** A request to any Step-up gated endpoint without a valid grant is answered `403` with `{"error": "insufficient_user_authentication", "acr_values": "https://ref.hatef.ir/acr/stepup"}`. The error code follows RFC 9470 (OAuth 2.0 Step Up Authentication Challenge Protocol); the status is `403` rather than RFC 9470's `401` because these are cookie-session endpoints where `401` already means "session gone, re-authenticate" — reusing it would send the user through a full login instead of the inline overlay in `frontend-pages.md` §5.3. Missing, malformed, expired, already-spent, and foreign-session grants all render identically so the response cannot be probed.

**Fail-closed mounting.** When the Step-up service cannot be constructed (for example, its required database is absent in development), gated endpoints are **not mounted at all** rather than served without their gate. Outside development, missing Redis or replay-key configuration prevents startup. A user with no enrolled Step-up factor receives `409 no_stepup_factor`; no condition turns a gated route into an ungated one.

### 1.4 User Profile & Privacy (GDPR)
- `GET /api/v1/users/me`: Get current user profile.
- `PATCH /api/v1/users/me`: Update profile details.
- `PUT /api/v1/users/me/password`: Change password for the authenticated user. Requires current password (bypassed if existing `password_hash` is NULL for WebAuthn-only accounts) and the Step-up ACR token in the `X-Step-Up-Auth` header.
- `GET /api/v1/users/me/sessions`: List all active sessions for the user.
- `DELETE /api/v1/users/me/sessions/{session_id}`: Revoke a specific session remotely.
- `POST /api/v1/users/me/export-data`: Request a downloadable archive of user data.
- `DELETE /api/v1/users/me`: "Right to be Forgotten" - Initiates soft delete of the account. Strictly requires the valid Step-up ACR token passed in the `X-Step-Up-Auth` header. Returns `204`. In one transaction the account becomes `pending_deletion` with `deleted_at` stamped, every outstanding reclaim token is invalidated, and a fresh single-use reclaim token is minted; after the commit all stateful sessions and refresh-token families are revoked and the token is emailed to the primary and (when set) backup address.
  - **Idempotent.** A repeat call on an account already in `pending_deletion` also returns `204` and does not deactivate twice, so a client retrying after a dropped response cannot use the endpoint to probe prior account state.
  - **Resend cooldown.** Whether a repeat call also mints and re-sends a fresh token is governed by `GDPR_DELETE_RESEND_COOLDOWN` (default 1h), measured from the last *delivered* notice. Inside the cooldown the call succeeds and does nothing; outside it, a user who lost the first mail gets a replacement. Without this the idempotent endpoint would be an email bomb. A notice that failed to send never arms the cooldown, so the next call retries delivery.
  - **Residual access-token authority.** Sessions and refresh tokens are revoked synchronously, but an access token already issued to a downstream client remains valid until it expires — at most the 10-minute access-token TTL. There is no revocation epoch and no per-request account-status re-read, so cutoff across the ecosystem is bounded by that TTL rather than instantaneous. Clients must not assume otherwise.
  - **Fail-closed mounting.** The route is not mounted when the Step-up service is unavailable (see §1.3), nor when no notifier capable of delivering the reclaim token is configured: a deletion whose reclaim token cannot be delivered has no recovery window at all, which is strictly worse than refusing the request.
  - Rate limited per account per day (`GDPR_DELETE_PER_ACCOUNT_PER_DAY`, default 3); a saturated limit returns `429 {"error":"rate_limited"}`.

#### Account Reclamation (cancel a pending deletion)
A `pending_deletion` account cannot log in at all, so reclamation is a separate anonymous ceremony rather than an ordinary login: the emailed single-use token plus one verified strong factor. Both endpoints are token-bearing and mounted outside the session group — they deliberately do not live under `/users/me`, because that prefix implies a session and there is none.

- `POST /api/v1/auth/deletion/reclaim/options`: Accepts `{"token":"..."}` and returns the single factor to present: `{"factor":"webauthn","webauthn":{...}}` (a `userVerification: "required"` assertion challenge bound to this deletion request) or `{"factor":"totp"}`. It does **not** consume the token, so a user who abandons the ceremony halfway can restart it. Exactly one factor is named; the response never enumerates the account's factors.
- `POST /api/v1/auth/deletion/reclaim`: Accepts `{"token":"...","factor":"webauthn","assertion":{...}}` or `{"token":"...","factor":"totp","code":"123456"}`. On success the account returns to `active`, every outstanding reclaim token for it is invalidated, and the response is `204` with **no session** — the user must now log in normally.
  - **Both factors are accepted deliberately.** A passkey-only account has no TOTP secret, and forcing TOTP here would make such accounts unrecoverable. The WebAuthn ceremony is tagged distinctly from login and Step-up, so a reclaim challenge can never be redeemed to mint a session and a login challenge can never satisfy a reclaim. A TOTP passcode is single-use across its whole ±1-step acceptance window.
  - **A wrong factor does not consume the token.** Consuming it would permanently destroy the account's only recovery path — the opposite trade-off from the single-use recovery-code transaction in §1.3, and intentional. `GDPR_RECLAIM_MAX_ATTEMPTS` (default 5) failed checks retire the request instead, and each failure is audit-logged.
  - **Opaque failures.** Unknown, expired, consumed, and foreign tokens, a wrong factor, a missing account, a wrong account status, and an account with no verifiable factor at all render identically as `401 {"error":"invalid_token"}`. A saturated limit returns `429 {"error":"rate_limited"}`. Only a genuine infrastructure fault returns `500`, and it does not depend on the token's validity. Rate limited per subnet then per account (`GDPR_RECLAIM_PER_SUBNET_PER_HOUR`, `GDPR_RECLAIM_PER_ACCOUNT_PER_HOUR`).
  - **Identifier reservation.** The account's email, phone, and backup-email uniqueness indexes cover `pending_deletion` rows for the whole window, so a third party cannot claim the identifier while a deletion is pending and cause the reclaim to fail. A registration attempt on a reserved identifier must be reported as `409`.

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
Protected by strict RBAC. Accessed only by authorized Admin/Moderator roles.
- `GET /api/v1/admin/users`: List users (with pagination and filtering).
- `GET /api/v1/admin/users/{user_id}`: View detailed account status.
- `POST /api/v1/admin/users/{user_id}/trigger-reset`: Send a password reset email to the user (Helpdesk/Support capability).
- `PATCH /api/v1/admin/users/{user_id}/status`: Change account status (Active, Suspended, Banned). *Note: Hard delete is not available.*
- `POST /api/v1/admin/roles/assign`: Assign a role (e.g., Moderator, DPO) to a user (Super Admin only).
- `GET /api/v1/admin/audit-logs`: Query system audit logs. **(MVP Fallback: During the MVP phase, queries are executed against the `mvp_audit_logs` table in PostgreSQL. Post-MVP, this is migrated to ClickHouse without API changes).** Requires mandatory query parameters `start_time` and `end_time` (Unix timestamp or RFC 3339) to restrict query limits and prevent Denial of Service (DoS) overhead. Returns a JSON list of immutable audit events, including the cryptographic chaining hash (`sha256_chain_hash`) of each row to allow client-side validation of the integrity and ordering of the logs.

#### Legal Hold & Preservation (DPO / Legal role only)
Endpoints supporting lawful-request handling. A Legal Hold is a **precedence lock** over all retention timers (holds > retention): while active, it prevents both the 30-day hard-delete Cron and the `security_event_ledger` purge from removing the subject's data. See `compliance-and-data-governance.md` and the `legal_holds` / `security_event_ledger` schemas in `data-architecture.md`.
- `POST /api/v1/admin/legal-holds`: Apply a Legal Hold on a subject (`account_ref`). Body requires `reason`, `requesting_authority` (court/agency/case reference), and `legal_basis`. Every application is audit-logged. A hold has no time cap and stays until explicitly released.
- `GET /api/v1/admin/legal-holds`: List active/historical holds (with pagination and filtering by `account_ref` or status).
- `DELETE /api/v1/admin/legal-holds/{hold_id}`: Release a Legal Hold. Sets `is_active = false` and records `released_by`/`released_at`. Released data returns to normal retention timers and is purged on the next cycle if already past its window.
- `POST /api/v1/admin/preservation-requests`: Record a preservation ("freeze-before-order") request and immediately apply a Legal Hold on the target `account_ref`, freezing the subject's data before a full order arrives. Body requires `requesting_authority`, `reason`, and optional `expires_at` (advisory review date). *Note: preservation cannot resurrect data already hard-deleted; it only prevents future purge of data still present.*
- `GET /api/v1/admin/legal-inquiry/lookup`: Attribution lookup. Given an identity value provided by an authority, the server computes the blind index and returns matching `security_event_ledger` rows (non-PII metadata) within the retention window. Read-only; the lookup itself is audit-logged.

---

## 2. Internal APIs (gRPC)
These services are strictly internal, protected by mTLS, and never exposed to the public internet. They allow other microservices in the Hatef ecosystem (e.g., Email Service, Search Core) to interact with the IdP securely and efficiently.

### 2.1 Identity SAN Validation (gRPC RBAC)
Every internal RPC method call is intercepted by a security middleware that extracts the client's X.509 certificate metadata and verifies the **SPIFFE ID** contained within the **Subject Alternative Name (SAN)** field (e.g., `spiffe://hatef.ir/ns/identity/sa/email-service`). Method-level RBAC is strictly applied, rejecting connection requests if the SPIFFE identity is not pre-authorized for the targeted RPC call.

### 2.2 `IdentityService`
Used by microservices to validate user identity and permissions.
- `rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse)`: Parses a JWT, checks if it's revoked in Redis, and returns user claims. Extremely fast, heavily cached.
- `rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse)`: Evaluates if a specific User ID has a specific role or permission (RBAC evaluation).
- `rpc GetInternalUserInfo(GetUserInfoRequest) returns (GetUserInfoResponse)`: Fetches basic user info (e.g., email, display name) needed by other services (e.g., Email service needing to address the user).

---

## 3. Asynchronous Events (NATS JetStream)
The IdP broadcasts events to the NATS broker so other services can react asynchronously.
- **Subject:** `identity.user.created` (Payload: User ID, Email) - Triggered on registration.
- **Subject:** `identity.user.updated` (Payload: User ID, changed fields)
- **Subject:** `identity.user.suspended` (Payload: User ID, Reason) - Search core or other services can instantly cut off access.
- **Subject:** `identity.user.deleted` (Payload: User ID) - Signals other services to scrub this user's PII from their localized databases (GDPR propagation). Published through a **transactional outbox** (`event_outbox`), not directly from the purge worker: the outbox insert and the physical `DELETE` share one transaction, so there is no event without a commit and no commit without an event. A `DELETE` affecting anything other than exactly one row rolls both back, which is what stops an `identity.user.deleted` from ever naming a subject that still exists. Draining the outbox into JetStream is a separate task; until it lands, rows accumulate and an unpublished-row-count alert is required.
