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
- [x] **Task 3.2:** Implement the OIDC Authorization endpoint (`/oauth2/auth`) with strict Proof Key for Code Exchange (PKCE S256) validation.

- [x] **Task 3.3:** Implement the Token endpoint (`/oauth2/token`) with PKCE exchange, client credentials grant, and Refresh Token Rotation (RTR) coupled with session breach detection (instant revocation of all active keys upon duplicate reuse).
- [x] **Task 3.4:** Implement RFC 7523 Private Key JWT Client Authentication (`private_key_jwt`) for confidential internal clients (Search Engine, Email Service).

- [x] **Task 3.5:** Implement the Sender-Constraining DPoP (RFC 9449) validation middleware, checking short-lived proof JWTs, tracking `jti` in Redis to prevent replay attacks, and enforcing the `DPoP-Nonce` header lifecycle.

## Phase 4: User Authentication & Device Hardening
- [x] **Task 4.1:** Implement stateful session management utilizing secure cookies with the strict `__Host-` prefix and `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/` attributes.
- [x] **Task 4.2:** Implement WebAuthn/FIDO2 passwordless registration and verification flows (origin checks, RP ID binding, signature counter validation, random 64-bit user ID challenge mapping).
- [x] **Task 4.3:** Implement WebAuthn discoverable credentials (usernameless login) as the primary secure path, plus mock challenge fallback for legacy user-named flows to mitigate account harvesting.
- [x] **Task 4.4:** Implement Multi-Factor Authentication (MFA) via TOTP, including secret generation, QR code mapping, and verification.
- [x] **Task 4.5:** Implement SMS OTP workflows with independent Redis-based rate limiting via sorted sets (ZSET) Lua scripts (rate-limiting per phone number and per IP `/24` or `/48` subnet window), plus failed-attempt brute-force lockout.

- [x] **Task 4.6:** Implement high-entropy (minimum 128-bit) recovery backup codes stored hashed with SHA-256, performing verification and physical deletion in an atomic ACID database transaction.
- [x] **Task 4.7:** Implement the Step-up Authentication framework, issuing short-lived ACR tokens (`https://ref.hatef.ir/acr/stepup`) upon successful MFA/WebAuthn UV challenge, required for high-risk endpoints.

## Phase 5: Privacy (GDPR), Admin Mod, & Cryptographic Logging
- [x] **Task 5.1:** Implement user-initiated "Right to be Forgotten" soft deactivation, instantly revoking all tokens, setting account status to `pending_deletion`, and starting a 30-day grace/recovery period. Create a Go cron worker to physically hard-delete records older than 30 days. **The worker MUST call `HasActiveLegalHold(account_ref)` before purging any subject and skip the purge entirely when an active hold exists (holds > retention, compliance-and-data-governance.md §6); each skip is audit-logged. The 30-day window is strictly a user-recovery mechanism and is independent of Legal Hold and security-ledger retention. Hard-delete removes only Class A PII and MUST NOT touch `security_event_ledger`.**
  - **Decisions Tasks 5.2-5.5 inherit:**
    - **`account_ref` is `users.id`, always.** The purge worker passes `users.id` to `HasActiveLegalHold`, and `security_event_ledger.account_ref` carries the same value. Any other derivation silently decouples holds from ledger rows and defeats threat-modeling.md R2.
    - **Auditing goes through `internal/audit`'s `Recorder` interface.** Task 5.1 ships `LogRecorder` (slog); 5.2 swaps in the NATS publisher behind the same interface with no call-site changes. **No `Recorder` may compute or persist a `chain_hash`** — recorders run concurrently in the API and in the worker, so only 5.2's single-threaded signing consumer can assign chain positions.
    - **Task 5.2's canonical `serialize(record)` MUST exclude `user_id`.** Task 5.1's hard delete nulls `mvp_audit_logs.user_id` via `ON DELETE SET NULL`, so including it in the hashed serialization would make the stored chain hash unverifiable for every purged subject — turning a correct GDPR erasure into a permanent integrity alarm and making `ListAuditLogsForChainVerification` useless. Attribution after deletion is `security_event_ledger`'s job.
    - **`identity.user.deleted` is published via a transactional outbox** (`event_outbox`), written in the same commit as the `DELETE`. Draining it into JetStream belongs to 5.2/6.x, which must also add an unpublished-row-count alert.
    - **Residual access-token authority is bounded at the access-token TTL** (10 minutes). Soft-delete revokes only stateful sessions and refresh-token families; there is no revocation epoch and no per-request status re-read. Closing that window is a separate task.
- [x] **Task 5.2:** Build an asynchronous event-driven audit logging pipeline using a NATS JetStream queue (`identity.audit.logs`) and a single-threaded signing worker that sequentially computes the cryptographic log chain:
  $$\text{chain\_hash}(N) = \text{SHA-256}\Big(\text{chain\_hash}(N-1) \ \big|\big|\ \text{serialize}\big(\text{audit\_log\_record}(N)\big)\Big)$$
  and writes records in batches to the `mvp_audit_logs` table in PostgreSQL. **In the same pipeline, write minimal, non-PII Class B rows to `security_event_ledger` for security-relevant actions (register, login success/fail, token/authorization issuance, RTR breach, MFA/WebAuthn changes), storing a stable `account_ref` and `identity_blind_index` (never raw PII) with an independent `retain_until` (e.g., 6-18 months). The ledger uses the same chaining formula.**
- [ ] **Task 5.3:** Admin REST/RBAC/legal preservation is implemented; deployment closure remains pending. Runtime wiring, durable disclosure auditing, operator role provisioning, encrypted metadata maintenance, shared account restrictions and a signer lookup probe are implemented. On 2026-10-01, unit tests, Linux race detection, SQL/static checks, API/worker builds, PostgreSQL/Redis/JetStream integration suites, and repeated database-query tests passed. Coverage includes independent hold/purge races, post-deletion attribution, audit rollback, and cross-instance credential invalidation. See [admin operations](docs/admin-operations.md) for the remaining approved-retention, backfill, production grant, proxy-redaction, and deployed lookup-probe gates. Keep unchecked until those deployment controls and the full acceptance matrix are verified.

- [ ] **Task 5.4:** Independent Security Event Ledger retention purge, durable signer head, compact erased-span checkpoints and retained-segment verification. The separately credentialed worker deletes only `retain_until < cutoff` rows without any active hold on the original `account_ref`, including deleted accounts, through a narrowly scoped SECURITY DEFINER routine, never direct runtime DELETE or trigger bypass. Policy remains `SECURITY_LEDGER_RETENTION=8760h` (365 days from occurrence); Class A/Class C are unchanged. Packaging, mandatory real-role integration coverage and the [operator runbook](docs/admin-operations.md#security-ledger-retention-task-54) are part of acceptance. Keep unchecked until implementation verification and explicit history/bootstrap, grant-denial, compatible deployment, image/dry-run/audit-delivery and restore gates pass. External anchoring is explicitly deferred: database-relative checkpoints/receipts do not defeat a privileged coherent rewrite. No Task 5.3 production sign-off or Task 5.5 narrative-retention approval is implied.
- [ ] **Task 5.5:** Backend implementation and local verification completed on 2026-10-03: operational legal case/review and two-person response approvals, internal monthly statistics, reviewed suppressed annual exports, governance gating and hold-aware metadata cleanup. Unit/race tests, integration-tag lint/vet, SQL checks, mandatory legal-workflow integration, API/operator builds and runtime packaging checks passed. Production enablement remains separate in [admin operations](docs/admin-operations.md#legal-review-and-transparency-task-55). Governance must approve numeric restricted-narrative retention and the actual linkable hold/minimized workflow replay inventories and lifetimes before intake is enabled; no production approval is implied. Keep unchecked until production gates are closed. Hold/preservation remains Task 5.3. Identifier/pepper lifecycle, finite replay expiry, supplemental responses/reopening, external transfers, public publishing and UI remain separately scoped.

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
