# Hatef Identity Platform - Architecture Documentation

## 1. System Architecture
### High-Level Design
The Hatef Identity Platform is designed as a centralized, privacy-first Identity Provider (IdP) and unified access portal. It is built to serve as the Single Sign-On (SSO) gateway for the entire Hatef ecosystem (e.g., Search Engine, Email Service, and future applications), ensuring strict separation of concerns and maximum scalability.

- **Frontend Layer:** Built with Next.js, managed via Nx. This layer handles user interactions, login flows, the admin dashboard, and user profile management.
- **Identity & API Layer (Go):** The core Identity Provider (IdP) built in Go (Golang). It manages OIDC/OAuth2 flows, Role-Based Access Control (RBAC), token issuance, and acts as the central authority for authentication across all Hatef microservices.
  - **Web Framework & Routing:** The platform utilizes **`go-chi/chi`** combined with the standard library `net/http` to handle all REST and OIDC routing. Heavy frameworks (like Fiber, Gin, or Echo) are strictly avoided. `go-chi/chi` is chosen because it remains 100% standard-library compatible, allowing native integration with `grpc-gateway`, seamless propagation of `context.Context` (critical for OpenTelemetry tracing and SPIFFE mTLS context), and provides a clean middleware pattern for injecting Strict-Nonce CSP headers and Redis rate limiting without memory bloat.
- **Databases:** 
  - **PostgreSQL:** The primary relational database for the IdP. Used strictly for user identities, roles, and transactional data, ensuring ACID compliance. *(Data Access in Go is strictly handled via **`sqlc`** for type-safe code generation from raw SQL, combined with the **`pgx`** driver. Heavy ORMs like GORM are explicitly avoided to guarantee raw performance, query predictability, and to prevent accidental data leaks in this privacy-first system).*
  - **Redis:** An in-memory data store for caching user sessions, OAuth tokens, and enforcing strict Rate Limiting to prevent scraping and abuse.

### Inter-Service Communication (gRPC) & Zero-Trust Service Identity
While external clients interact with the IdP via standard HTTP/REST or OIDC endpoints, internal microservices within the Hatef ecosystem (regardless of their underlying language, such as Go or C++) interact with the IdP for token validation or authorization checks.
- **High-Performance Transport:** Internal communication is strictly conducted over **gRPC** for low latency and high throughput.
- **Dynamic mTLS with SPIFFE/SPIRE:** Mutual TLS is enforced for all inter-service communication. To eliminate static, long-lived credentials and certificate files, service identities are dynamically bootstrapped and rotated using **SPIFFE/SPIRE**. This automates short-lived cryptographic X.509 SVID issuance and rotation.
- **Method-Level gRPC RBAC (SAN Verification):** To prevent lateral movement if an internal node or microservice (such as the Search Core) is compromised, the Go gRPC interceptors inspect the client's **SPIFFE ID** inside the certificate's **Subject Alternative Name (SAN)** (e.g., `spiffe://hatef.ir/ns/identity/sa/email-service`). It then strictly enforces method-level Role-Based Access Control (RBAC), ensuring that only authorized services can invoke specific RPC APIs (such as token validation or direct identity resolution).

### Network Flow & API Gateway (Ingress)
To ensure optimal performance and security, an API Gateway / Ingress Controller (**Traefik**) is designed for the network edge. Traefik is chosen for its native Go synergy, lightweight memory footprint, and automated SSL provisioning.

*(Note: In the current **MVP Phase**, Traefik is not deployed. Instead, an existing **host-level Nginx** on the Ubuntu host performs the Reverse Proxying, TLS Termination, and path-based routing directly to the Docker containers to minimize memory and system overhead. Traefik will be adopted post-MVP).*

- **Path-Based Routing:** 
  - Requests for UI, static assets, and Server-Side Rendered (SSR) pages (e.g., `/login`, `/dashboard`, `/_next/*`) are routed directly to the **Next.js** containers.
  - Requests for authentication, API endpoints, and identity management (e.g., `/api/v1/*`, `/.well-known/*`, `/oauth2/*`) are routed directly to the **Go IdP** containers.
- **Why this approach?** This prevents Next.js from acting as an unnecessary proxy, reduces latency, and allows external applications (e.g., mobile apps, third-party services) to interact directly with the Go APIs for authentication using standard OIDC protocols.

### Asynchronous Operations & Task Queues
- **Message Broker (NATS JetStream):** Chosen for its extremely low memory footprint, high throughput, and native Go ecosystem synergy. It is used for asynchronous communication, event broadcasting, and reliable message queuing (with persistence via JetStream) between the Go APIs and other microservices. This ensures that background tasks or cross-service events are processed reliably without tight coupling or heavy resource overhead.

### Monorepo Benefits for Web/Identity Layer
- **Shared Tooling & CI/CD:** Unified testing, linting, and deployment pipelines using Nx.
- **Code Reusability:** Shared types and utility functions between the Next.js frontend and Go backend (via code generation/shared schemas).
- **Atomic Commits:** Changes requiring frontend and API updates can be committed together, ensuring version consistency.

## 2. Identity & Security (Privacy-First)
### IdP Architecture & Standard Compliance
The Identity Provider (IdP) is custom-built in Go, designed with a Zero-Trust, privacy-first architecture aligned with NIST SP 800-63B and OWASP ASVS Level 4.
- **OIDC / OAuth 2.1 Compliance:** Fully implements the OpenID Connect Core 1.0 and OAuth 2.1 specifications.
  - **Asymmetric Signing Only:** Use of symmetric token signing algorithms (e.g., `HS256`) is strictly prohibited. Tokens must be signed using asymmetric cryptography: **RS256** (minimum 2048-bit key size) or **ES256** (ECDSA over NIST Curve P-256).
  - **Graceful JWKS Rotation:** JWKS endpoints (`/oauth2/jwks`) maintain a graceful 3-key rotation cycle: `active` (currently signing new tokens), `next` (pre-generated and published key), and `previous` (recently expired key, kept to verify outstanding unexpired tokens). This completely prevents session disruption during key rotation.
  - **Mandatory PKCE (RFC 7636):** For all public clients (including the Next.js frontend), PKCE with the `S256` hashing method is strictly enforced. The insecure `plain` method is rejected at the protocol layer.
  - **Refresh Token Rotation (RTR):** Single-use refresh tokens are enforced. If a previously-used refresh token is presented, the system triggers breach detection: it immediately revokes all active sessions and refresh tokens for that user (mitigating token-theft replay attacks).
  - **DPoP (RFC 9449):** Implements Demonstrating Proof-of-Possession to sender-constrain access and refresh tokens, binding token usage to a client-generated asymmetric key to protect against token theft via XSS.
- **Secure Client Authentication (`private_key_jwt`):** Registration of internal clients (e.g., Search Engine, Email Service) is managed via static configuration (Infrastructure as Code) or a Super Admin internal API, avoiding a public developer portal to strictly control the ecosystem's security perimeter.
  - **Forbid Secret-in-Body/URL:** Insecure authentication methods like `client_secret_post` or raw secrets in URL query parameters are entirely forbidden.
  - **RFC 7523 Private Key JWTs:** Confidential clients must authenticate at the token endpoint using client assertions signed with their own private keys (`private_key_jwt`). The server verifies assertions against pre-registered public keys and strictly validates required `jti` and `exp` claims to prevent assertion replay.

### Advanced Cryptographic Controls & Data Protection
To guarantee extreme safety and satisfy rigorous privacy requirements:
- **NIST-Compliant Password Hashing:** User passwords are hashed using **Argon2id** with secure parameters: $m=64\text{MB}$ (memory cost), $t=3\text{ iterations}$ (time cost), and $p=4\text{ parallelism}$, generating a cryptographically secure salt per user.
- **Application-Layer Envelope Encryption:** Sensitive Personal Identifiable Information (PII) such as phone numbers, backup emails, and MFA secrets is never stored in plain text in PostgreSQL. It is encrypted in-transit in the application layer using **AES-GCM-256** for Data Encryption Keys (DEKs). The DEKs are encrypted (wrapped) by a master Key Encryption Key (KEK) managed in our central KMS (Infisical).
- **Timing Attack Resistance:** All cryptographic matching (including OTP verification, token comparison, and credentials validation) is executed via constant-time comparison algorithms (`crypto/subtle.ConstantTimeCompare`) to eliminate timing side-channels.

### Account Security & Advanced Authentication
To protect user identities against modern threats (e.g., phishing, credential stuffing), the IdP implements enterprise-grade security features:
- **Phishing-Resistant WebAuthn / FIDO2:** Full support for passwordless and highly secure logins using external hardware security keys (e.g., YubiKey) and platform authenticators (e.g., Touch ID, FaceID, Windows Hello).
  - **Origin & RP ID Binding:** Strict enforcement of origin verification (matching protocol, domain, port) against Relying Party ID in registration/login verification to block phishing.
  - **Signature Counter Auditing:** Verifies that the incoming `SignCount` from the authenticator is strictly greater than the stored value to detect and block cloned authenticators.
  - **Anonymized `user.id` Mapping:** In WebAuthn challenge generation, the `user.id` field is populated with a cryptographically secure, random 64-bit identifier generated via Go's `crypto/rand` CSPRNG, which is mapped internally to the real user UUID. This completely prevents correlation of account identities or biometrics by third-party network sniffers.
  - **User Harvesting & Timing Attack Defenses (Discoverable Credentials):** While user-named login flows return a mock challenge of identical payload size for non-existent users, client-side execution times can vary due to browser-level `allowCredentials` handling. Therefore, the platform enforces **discoverable credentials (usernameless login)** as the primary secure path to completely neutralize user harvesting. The user is prompted directly for biometrics, and the authenticator returns the selected identity inside the signed assertion, eliminating any username-probing vector.
  - **User Presence (UP) vs. User Verification (UV):** Normal login requires UP (button tap). High-risk operations (disabling MFA, unlinking emails/phones, deleting account) strictly require UV (`userVerification: "required"`), returning a WebAuthn assertion with `uv: true` verified by the backend.
- **Multi-Factor Authentication (MFA) & Redis-Based OTP Hardening:** Support for Time-based One-Time Passwords (TOTP) via authenticator apps and standard SMS OTP.
  - **Independent Dimension Rate Limiting:** SMS OTP triggers are rate-limited in Redis independently per phone number (e.g., maximum 1 request/minute and 5 requests/hour globally) and per IP subnet range (e.g., maximum 10 requests/hour globally). This completely prevents composite key bypasses (such as SMS bombing via proxy rotation or distributed toll fraud).
  - **Automatic Lockout and Purification:** OTP verification allows a maximum of 3 failed attempts. On the third failure, the key is instantly deleted from Redis and the user's phone is locked out for 15 minutes to thwart Brute-Force/guessing attacks.
- **SHA-256 Recovery Codes (Backup Codes):** To prevent permanent account lockouts, the system generates high-entropy (minimum 128-bit) one-time-use cryptographic recovery codes during MFA/WebAuthn enrollment.
  - **SHA-256 Hashing:** Because recovery codes are generated with high entropy, they are already cryptographically immune to offline dictionary attacks. They are stored hashed using **SHA-256** (or SHA-512) in PostgreSQL. This allows direct indexed $O(1)$ database query verification, completely neutralizing the CPU-exhaustion Denial of Service (DoS) vulnerability inherent to sequential memory-hard hashing checks (like Argon2id).
  - **Atomic Transactional Destruction:** Upon verification of a backup code, the check and permanent physical deletion of the code from PostgreSQL are performed within the same atomic database transaction (ACID transaction) to neutralize race-condition replay attacks.
- **Session Management & Transport Hardening:**
  - **Cookie Security:** Next.js and Go session cookies enforce the **`__Host-`** secure prefix. Flags: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, blocking cross-site tracking, cookie hijacking, and CSRF.
  - **Next.js & Go Strict-Nonce CSP:** Frontend and backend web templates enforce a Strict-Nonce Content Security Policy (CSP) header. This completely mitigates XSS-based injection and prevents extraction of the non-extractable DPoP private keys from IndexedDB.
  - **DPoP Replay Mitigation:** To prevent replay of intercepted DPoP-bound tokens, the Go backend caches the unique DPoP proof identifier (`jti` claim) in Redis for the duration of the signature's short-lived validity (60 seconds) and strictly validates the server-issued `DPoP-Nonce` header on each request.
  - **Step-up Auth Context (ACR):** Successful WebAuthn UV or MFA validation returns a short-lived (3-5 minutes) token containing the ACR claim `https://ref.hatef.ir/acr/stepup`. High-security endpoints (such as password change, email/phone removal, and account deletion) strictly require this token in the header.
- **Risk-Based Authentication:** The system monitors for anomalies (e.g., logins from unknown IPs, new devices, or impossible travel times). Suspicious activities trigger automatic account lockouts or require step-up authentication (MFA/WebAuthn), preventing brute-force and fraud attempts.

### Role-Based Access Control (RBAC) & Admin Capabilities
The IdP uses a strict Role-Based Access Control (RBAC) model adhering to the Principle of Least Privilege. Admin capabilities are decoupled from user data modification where possible.

#### Admin Roles & Scopes
1. **System Administrator (Super Admin):**
   - **Scope:** Infrastructure and Role Management.
   - **Capabilities:** Can assign/revoke roles to other admins, modify system-wide configurations (e.g., rate limits).
   - **Restrictions:** Does NOT have access to read individual user raw data or private telemetry.

2. **Trust & Safety / Content Moderator:**
   - **Scope:** Account Abuse Prevention.
   - **Capabilities:** Can **Suspend** or **Ban** abusive user accounts across the ecosystem to prevent platform-wide spam.
   - **Restrictions:** Cannot Hard Delete users, and has no capabilities regarding client-specific data moderation (which are delegated to downstream clients like the Search Engine or Email Service). Banning a user deactivates the account and retains a hashed fingerprint to prevent re-registration, but does not wipe the soft-deleted data manually.

3. **Data Protection Officer (DPO):**
   - **Scope:** Compliance and Audit.
    - **Capabilities:** Read-only access to system Audit Logs (stored in PostgreSQL during the MVP phase, and ClickHouse post-MVP). Can monitor automated deletion pipelines and oversee user Data Export requests.

4. **Support / Helpdesk:**
   - **Scope:** Basic User Assistance.
   - **Capabilities:** Can view high-level account status (active/suspended) and trigger password reset flows.
   - **Restrictions:** No access to personal data, IPs, or behavioral history.

#### The "Zero Trust" Admin Philosophy
- **No Manual Deletion:** Admins cannot manually perform a "Hard Delete" on a user account. Hard Deletes are exclusively triggered by the user via the "Right to be Forgotten" self-service flow, which initiates a scheduled Cron Job.
- **Immutable Audit Logging:** Every state change initiated by an admin (e.g., banning a user, changing a role, triggering password resets) is immutably logged in the database ledger. To minimize resource utilization during the MVP phase, these logs are stored in a dedicated PostgreSQL table; they are migrated to the analytical database (ClickHouse) post-MVP.
  - **Cryptographic Log Chaining:** To prevent any out-of-band manipulation of logs on the physical disk, each audit log row's cryptographic hash is chained to the hash of the preceding row (forming a secure cryptographic ledger). Any unauthorized deletion or modification instantly breaks the chain, raising high-severity system alerts.

### Privacy & GDPR Compliance
- **PII Masking:** Personally Identifiable Information is masked at the application layer before logging or analytics processing.
- **Grace Period & Soft Deletes (Right to be Forgotten):** User data deletion requests do not trigger immediate physical deletion. Instead, they initiate a **30-day Grace Period (Deactivation window)**, which aligns with industry best practices and global compliance standards (GDPR Article 17, CCPA/CPRA).
  - **The 30-Day Recovery Window:** Upon initiating deletion, the user's account status is set to `pending_deletion`, and all active sessions/refresh tokens are instantly revoked across the ecosystem. The account is suspended from all user-facing services.
  - **Account Reclamation (Cancellation of Deletion):** If the deletion was accidental, impulsive, or triggered during an Account Takeover (ATO) by an attacker, the legitimate user has 30 days to reclaim their account. To cancel deletion, the user must perform a secure login (including WebAuthn/MFA) and explicit step-up authentication. An automated alert is also sent to their primary and backup emails at the start of the deletion queue.
  - **Data Minimization:** Only essential data required for service operation is collected.
- **Hard Delete Cron Jobs:** Once the 30-day legal retention and grace window expires, a Go worker (Cron Job) is scheduled to permanently purge soft-deleted records (`pending_deletion` users where `deleted_at < NOW() - INTERVAL '30 days'`) from PostgreSQL. This completely and physically wipes the user's records across all tables (ACID transactions), fully satisfying GDPR "Right to be Forgotten" mandates.
- **Append-Only Log Management (ClickHouse / PostgreSQL MVP Fallback):** System logs and audit trails are designed to be stored in a high-performance, append-only column-oriented database (**ClickHouse**), rather than the transactional database, preventing database write bottlenecks. However, **during the MVP phase, ClickHouse is completely bypassed to reduce server memory overhead by ~1.2 GB**. Instead, logs are written to PostgreSQL using a dedicated `mvp_audit_logs` table, while strictly maintaining the same cryptographic chaining and append-only access controls (administrative database roles do not possess `UPDATE` or `DELETE` permissions on the audit logs table, guaranteeing that audit trails are permanent and tamper-proof).

## 3. Observability & Secret Management
### Observability (Monitoring & Tracing)
A comprehensive observability stack is critical for a distributed, privacy-first system.
- **Metrics:** **Prometheus** scrapes metrics from both Go services and Next.js applications, visualized via **Grafana**.
- **Tracing:** **OpenTelemetry** is used to trace requests as they flow from the Ingress Gateway, through the Go APIs, and down to other dependent microservices. This allows developers to pinpoint latency bottlenecks without logging user PII.

### Secret Management
- **Centralized Vault:** Secrets (e.g., mTLS certificates, OIDC signing keys, PostgreSQL credentials) are never stored in the source code or environment variables directly. They are managed via a secure KMS (Key Management Service) such as **Infisical** or **Kubernetes Sealed Secrets / SOPS** for a lightweight, self-hosted, and cloud-agnostic approach. Kubernetes injects these secrets into containers at runtime.

## 4. Monorepo Strategy
### Development Workflow
- **Nx:** Orchestrates builds, caching, and task execution across the monorepo, providing seamless integration for both TypeScript (Next.js) and Go projects.
- **Project Structure:** The Nx workspace is structured logically:
  - `apps/web`: The Next.js frontend application.
  - `apps/identity-api`: The Go Identity Provider service.
  - `libs/`: Shared TypeScript components (UI), Go utility packages, and generated protobuf schemas.
- **Shared Packages:** Common configurations (ESLint, Prettier, Tailwind) and UI components (using **shadcn/ui**) are extracted into shared packages.

### Type Safety (Next.js & Go)
- To maintain strict type safety across the stack, API contracts are defined exclusively using **Protocol Buffers (protobuf)** as the single source of truth.
- TypeScript types, Go structs, and OpenAPI (Swagger) documentation are auto-generated from these `.proto` schemas using tools like `buf` or `grpc-gateway`. This ensures the frontend, backend, internal gRPC services, and external HTTP REST documentation are always perfectly in sync.

## 5. API Design & Integration
### Internal vs. External APIs
- **Internal APIs (gRPC):** Used for fast, low-latency communication between the IdP and other Hatef microservices (e.g., token validation).
- **External APIs (REST/OIDC):** The Go backend exposes well-documented REST endpoints and standard OIDC discovery endpoints for the Next.js frontend, mobile applications, and third-party integrations. GraphQL is deliberately avoided in the authentication layer to reduce complexity and attack vectors.

## 6. Infrastructure & Deployment
### Separation of Concerns
The Identity Platform is isolated in its own repository (`hatefsystems/identity`). It is completely agnostic of the applications consuming it, allowing independent scaling based on authentication traffic alone.

### Deployment Strategy
- **Containerization:** All services (Next.js, Go) are containerized using Docker.
- **Orchestration:** Kubernetes (K8s) is used to manage deployments, scaling, and networking (handling the mTLS mesh).
- **CI/CD:** Automated pipelines handle testing, building, and deploying containers to staging and production environments.

## 7. Contribution Guidelines
### Prerequisites
- Docker & Docker Compose
- Go (latest stable)
- Node.js (LTS) & npm/yarn/pnpm
- Nx CLI

### Local Setup
1. Clone the repository: `git clone https://github.com/hatefsystems/identity.git`
2. Install dependencies: `npm install`
3. Start the development environment: `nx run-many --target=serve --all`

### Coding Standards
- **Go:** Follow standard Go formatting (`gofmt`) and linting (`golangci-lint`). Use `sqlc` to generate type-safe database queries instead of ORMs.
- **Next.js/TypeScript:** Adhere to the ESLint and Prettier configurations provided in the monorepo.
- **Commit Messages:** Follow Conventional Commits format for automated changelog generation.

### Security First
- **Never commit secrets:** Use environment variables and secret management tools.
- **Review for Privacy:** Always consider the privacy implications of new features. Ensure data minimization and proper masking of PII in logs.
