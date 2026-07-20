# Hatef Identity Platform (LDP) - Implementation Roadmap

This document outlines the complete step-by-step roadmap for implementing the Hatef Identity Platform. The tasks are structured from the bottom up, starting from workspace setup and infrastructure to database design, security engines, and finally the frontend application.

---

## Definition of Done (DoD)
A task is considered complete only when it meets the following criteria:
1. **Unit Test Coverage:** All business logic methods, utility functions, and architectural layers must have comprehensive unit tests covering both happy paths and edge cases.
2. **Integration Tests:** API endpoints and gRPC services must be verified using real integration tests with proper mocking of databases and external backing services.
3. **No Hardcoded Secrets:** No sensitive credentials or secrets are permitted in the source code; everything must utilize the centralized Key Management Service (KMS/Secrets) and environment variables.
4. **Validation and Linting:** All automated tests, type-checks, and code-quality linters (such as `golangci-lint` or ESLint/Prettier) must run and pass without any warnings or errors.

---

## Phase 1: Workspace Setup & Infrastructure Configuration
- [x] **Task 1.1:** Initialize the Nx monorepo workspace structure with empty configurations.
- [x] **Task 1.2:** Scaffold the Go backend application in `apps/identity-api` with base directory structure, dependencies (`go.mod`), and a basic health check server.
- [x] **Task 1.3:** Scaffold the Next.js frontend application in `apps/web` integrated with the Nx workspace, Tailwind CSS, and a shared UI library in `libs/ui` (shadcn/ui setup).
- [x] **Task 1.4:** Create the local backing services configuration (`docker-compose.dev.yml`) containing PostgreSQL, Redis, and NATS JetStream.
- [x] **Task 1.5:** Configure Protocol Buffers building (`buf`) in `libs/schemas` and compile-time database access code generation (`sqlc`) in `apps/identity-api`.

## Phase 2: Database Schemas & Cryptography Engine
- [x] **Task 2.1:** Implement initial database migrations in `apps/identity-api/db/migrations` covering tables: `users`, `roles`, `permissions`, `role_permissions`, `user_roles`, `webauthn_credentials`, `recovery_codes`, and `mvp_audit_logs`.
- [x] **Task 2.1b:** Add migration `00002_legal_hold_and_security_ledger.sql` for the persistent, account-decoupled `security_event_ledger` (Class B minimal metadata that survives hard-delete, with `account_ref` + `identity_blind_index` + `retain_until`, append-only trigger) and the `legal_holds` precedence-lock table (compliance-and-data-governance.md §6-7, data-architecture.md §1.1 tables 5-6).
- [x] **Task 2.2:** Define `sqlc` queries in `apps/identity-api/db/queries` for transactional entities and generate Go models/repository code.
- [x] **Task 2.3:** Implement the AES-GCM-256 Application-Layer Envelope Encryption module with secure serialization (Version, Nonces, Tag, DEK, Ciphertext) and a mock/stub driver for Infisical Key Management Service (KMS), along with SHA-256 Cryptographic Blind Indexing for search lookups.

- [x] **Task 2.4:** Implement the Argon2id password hashing library with strict parameters ($m=64\text{MB}, t=3, p=4$) and constant-time comparison helpers (`crypto/subtle`).


## Phase 3: OIDC & OAuth 2.1 Protocol Engine (Go Backend)
- [x] **Task 3.1:** Implement the OIDC Discovery endpoint (`/.well-known/openid-configuration`) and JSON Web Key Set (JWKS) endpoint (`/oauth2/jwks`) featuring a graceful 3-key active/next/previous rotation cycle (RS256/ES256).
- [ ] **Task 3.2:** Implement the OIDC Authorization endpoint (`/oauth2/auth`) with strict Proof Key for Code Exchange (PKCE S256) validation.
- [ ] **Task 3.3:** Implement the Token endpoint (`/oauth2/token`) with PKCE exchange, client credentials grant, and Refresh Token Rotation (RTR) coupled with session breach detection (instant revocation of all active keys upon duplicate reuse).
- [ ] **Task 3.4:** Implement RFC 7523 Private Key JWT Client Authentication (`private_key_jwt`) for confidential internal clients (Search Engine, Email Service).
- [ ] **Task 3.5:** Implement the Sender-Constraining DPoP (RFC 9449) validation middleware, checking short-lived proof JWTs, tracking `jti` in Redis to prevent replay attacks, and enforcing the `DPoP-Nonce` header lifecycle.

## Phase 4: User Authentication & Device Hardening
- [ ] **Task 4.1:** Implement stateful session management utilizing secure cookies with the strict `__Host-` prefix and `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/` attributes.
- [ ] **Task 4.2:** Implement WebAuthn/FIDO2 passwordless registration and verification flows (origin checks, RP ID binding, signature counter validation, random 64-bit user ID challenge mapping).
- [ ] **Task 4.3:** Implement WebAuthn discoverable credentials (usernameless login) as the primary secure path, plus mock challenge fallback for legacy user-named flows to mitigate account harvesting.
- [ ] **Task 4.4:** Implement Multi-Factor Authentication (MFA) via TOTP, including secret generation, QR code mapping, and verification.
- [ ] **Task 4.5:** Implement SMS OTP workflows with independent Redis-based rate limiting via sorted sets (ZSET) Lua scripts (rate-limiting per phone number and per IP `/24` or `/48` subnet window), plus failed-attempt brute-force lockout.
- [ ] **Task 4.6:** Implement high-entropy (minimum 128-bit) recovery backup codes stored hashed with SHA-256, performing verification and physical deletion in an atomic ACID database transaction.
- [ ] **Task 4.7:** Implement the Step-up Authentication framework, issuing short-lived ACR tokens (`https://ref.hatef.ir/acr/stepup`) upon successful MFA/WebAuthn UV challenge, required for high-risk endpoints.

## Phase 5: Privacy (GDPR), Admin Mod, & Cryptographic Logging
- [ ] **Task 5.1:** Implement user-initiated "Right to be Forgotten" soft deactivation, instantly revoking all tokens, setting account status to `pending_deletion`, and starting a 30-day grace/recovery period. Create a Go cron worker to physically hard-delete records older than 30 days. **The worker MUST call `HasActiveLegalHold(account_ref)` before purging any subject and skip the purge entirely when an active hold exists (holds > retention, compliance-and-data-governance.md §6); each skip is audit-logged. The 30-day window is strictly a user-recovery mechanism and is independent of Legal Hold and security-ledger retention. Hard-delete removes only Class A PII and MUST NOT touch `security_event_ledger`.**
- [ ] **Task 5.2:** Build an asynchronous event-driven audit logging pipeline using a NATS JetStream queue (`identity.audit.logs`) and a single-threaded signing worker that sequentially computes the cryptographic log chain:
  $$\text{chain\_hash}(N) = \text{SHA-256}\Big(\text{chain\_hash}(N-1) \ \big|\big|\ \text{serialize}\big(\text{audit\_log\_record}(N)\big)\Big)$$
  and writes records in batches to the `mvp_audit_logs` table in PostgreSQL. **In the same pipeline, write minimal, non-PII Class B rows to `security_event_ledger` for security-relevant actions (register, login success/fail, token/authorization issuance, RTR breach, MFA/WebAuthn changes), storing a stable `account_ref` and `identity_blind_index` (never raw PII) with an independent `retain_until` (e.g., 6-18 months). The ledger uses the same chaining formula.**
- [ ] **Task 5.3:** Implement Admin REST endpoints (`/api/v1/admin/*`) under strict RBAC, including paginated user lookup, account suspension/banning, and ledger verification query. **Add DPO/Legal-only endpoints (api-design.md §1.7): `POST/GET/DELETE /api/v1/admin/legal-holds` (apply/list/release a hold), `POST /api/v1/admin/preservation-requests` (freeze-before-order: record + apply hold), and `GET /api/v1/admin/legal-inquiry/lookup` (attribution lookup via blind index against `security_event_ledger`). Every action here is itself audit-logged.**

- [ ] **Task 5.4:** Implement the independent Security Event Ledger retention purge worker. It removes rows past `retain_until` (`PurgeExpiredSecurityEvents`) ONLY when no active Legal Hold covers the `account_ref`, running under a dedicated maintenance role per the documented append-only exemption procedure. Retention is a single configured value, not "keep indefinitely" (compliance-and-data-governance.md §3, §7).
- [ ] **Task 5.5:** Implement the Legal Hold & Preservation service layer backing Task 5.3's endpoints: apply/release holds (`legal_holds`), record preservation requests (freeze-before-order via immediate hold), and blind-index attribution lookups against `security_event_ledger`. Enforce that a hold is a no-time-cap precedence lock and that preservation cannot resurrect data already hard-deleted (threat-modeling.md R2).

## Phase 6: gRPC Microservices & Inter-Service Security
- [ ] **Task 6.1:** Build gRPC interceptors to perform method-level service-to-service RBAC by verifying SPIFFE IDs (e.g., `spiffe://hatef.ir/ns/identity/sa/email-service`) in the SAN field of mTLS X.509 certificates.
- [ ] **Task 6.2:** Implement the gRPC `IdentityService` providing high-performance methods: `ValidateToken` (integrated with Redis-based session caching), `CheckPermission`, and `GetInternalUserInfo`.
- [ ] **Task 6.3:** Configure Go publishers to broadcast asynchronous lifecycle events (`identity.user.created`, `identity.user.updated`, `identity.user.suspended`, `identity.user.deleted`) to NATS JetStream so that other microservices can maintain data sync.

## Phase 7: Next.js Client Portal & Identity Management
- [ ] **Task 7.1:** Implement Next.js security middleware injecting a strict-nonce Content Security Policy (CSP) header into SSR and static pages.
- [ ] **Task 7.2:** Design responsive, clean, and accessible UI forms (Login, Registration, WebAuthn Login, TOTP Verify, Password Reset) using shadcn/ui.
- [ ] **Task 7.3:** Implement the User Portal containing user profile settings, WebAuthn keys management, session revocation, and recovery backup codes viewer.
- [ ] **Task 7.4:** Implement the "Right to be Forgotten" self-service portal requiring Step-up Auth (WebAuthn UV) and triggering the 30-day deletion queue with automatic email notification.
- [ ] **Task 7.5:** Design the Admin Control Panel for moderators to suspend/ban abusive accounts and for auditors (DPO) to query system audit logs and verify cryptographic chain integrity.
- [ ] **Task 7.6:** Design the DPO/Legal compliance panel: apply/release Legal Holds, record preservation ("freeze-before-order") requests, and run attribution lookups (identity input -> blind-index match against `security_event_ledger`), presenting only non-PII ledger metadata. Reflects the endpoints in api-design.md §1.7.
