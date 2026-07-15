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
- `DELETE /api/v1/auth/webauthn/keys/{id}`: Remove a specific WebAuthn device (Requires Step-up authentication).

#### WebAuthn Registration & Login Flows
- `POST /api/v1/auth/webauthn/register/generate-options`: Get challenge for registering a hardware key/biometric. Enforces RP ID strictly as a clean domain name (e.g., `identity.hatef.ir` without protocol, port, or path) according to W3C specs, while validating origin details (protocol, domain, port) against clientDataJSON. The returned `user.id` field contains a CSPRNG-generated random 64-bit value to prevent user identity correlation.
- `POST /api/v1/auth/webauthn/register/verify`: Verify the WebAuthn registration, validating signature counter to prevent cloned authenticators.
- `POST /api/v1/auth/webauthn/login/generate-options`: Get challenge for WebAuthn login. Supports discoverable credentials (usernameless login with an empty `allowCredentials` list) to completely neutralize account harvesting. For legacy user-named flows, if the input identity is unregistered, the endpoint returns a mock challenge with identical structure and delay, although discoverable credentials remain the recommended path due to browser-level key-lookup speed variances on local devices.
- `POST /api/v1/auth/webauthn/login/verify`: Verify WebAuthn login assertion.

#### Multi-Factor Authentication (TOTP) & SMS OTP
- `POST /api/v1/auth/mfa/generate`: Generate TOTP secret and QR code.
- `POST /api/v1/auth/mfa/verify`: Verify TOTP code and enable MFA.
- `DELETE /api/v1/auth/mfa`: Disable TOTP MFA (Requires Step-up authentication).
- `POST /api/v1/auth/recovery-codes/generate`: Generates a new batch of one-time backup codes (stored securely in PostgreSQL hashed via **SHA-256** to prevent CPU Denial of Service during validation). Requires Step-up authentication.
- `GET /api/v1/auth/recovery-codes/status`: Check how many valid recovery codes are remaining.
- `POST /api/v1/auth/mfa/verify-recovery-code`: Endpoint used during login to bypass standard MFA/WebAuthn. If valid, the backup code is deleted in the same atomic database transaction.

#### Short-Lived Step-up Authentication
- `POST /api/v1/auth/stepup/challenge`: Generates a challenge for the Step-up auth flow, supporting `userVerification: "required"` (biometrics/PIN via WebAuthn) or TOTP verification.
- `POST /api/v1/auth/stepup/verify`: Verifies the WebAuthn UV assertion or active TOTP token. On success, returns a short-lived (3-5 minutes) Step-up token carrying the ACR claim `https://ref.hatef.ir/acr/stepup`. This token must be passed in the `X-Step-Up-Auth` header for sensitive endpoints.

### 1.4 User Profile & Privacy (GDPR)
- `GET /api/v1/users/me`: Get current user profile.
- `PATCH /api/v1/users/me`: Update profile details.
- `PUT /api/v1/users/me/password`: Change password for the authenticated user. Requires current password (bypassed if existing `password_hash` is NULL for WebAuthn-only accounts) and the Step-up ACR token in the `X-Step-Up-Auth` header.
- `GET /api/v1/users/me/sessions`: List all active sessions for the user.
- `DELETE /api/v1/users/me/sessions/{session_id}`: Revoke a specific session remotely.
- `POST /api/v1/users/me/export-data`: Request a downloadable archive of user data.
- `DELETE /api/v1/users/me`: "Right to be Forgotten" - Initiates soft delete of the account. Strictly requires the valid Step-up ACR token passed in the `X-Step-Up-Auth` header.

### 1.5 Account Verification & Anti-Spam
To prevent fake account creation (e.g., for the Email Service), the platform uses standard Server-to-Client SMS or Backup Email verification. All phone numbers and backup emails are stored using AES-GCM-256 application-layer Envelope Encryption.
- `POST /api/v1/users/me/phone/send-code`: Sends a 6-digit verification code via SMS to the provided phone number.
- `POST /api/v1/users/me/phone/verify`: Verifies the submitted SMS code and marks the phone as verified.
- `DELETE /api/v1/users/me/phone`: Removes the verified phone number from the account (Requires Step-up authentication in `X-Step-Up-Auth`).
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
- **Subject:** `identity.user.deleted` (Payload: User ID) - Signals other services to scrub this user's PII from their localized databases (GDPR propagation).
