# Hatef Identity Platform - Architecture Documentation

## 1. System Architecture
### High-Level Design
The Hatef Identity Platform is designed as a centralized, privacy-first Identity Provider (IdP) and unified access portal. It is built to serve as the Single Sign-On (SSO) gateway for the entire Hatef ecosystem (e.g., Search Engine, Email Service, and future applications), ensuring strict separation of concerns and maximum scalability.

- **Frontend Layer:** Built with Next.js, managed via Nx. This layer handles user interactions, login flows, the admin dashboard, and user profile management.
- **Identity & API Layer (Go):** The core Identity Provider (IdP) built in Go (Golang). It manages OIDC/OAuth2 flows, Role-Based Access Control (RBAC), token issuance, and acts as the central authority for authentication across all Hatef microservices.
- **Databases:** 
  - **PostgreSQL:** The primary relational database for the IdP. Used strictly for user identities, roles, and transactional data, ensuring ACID compliance.
  - **Redis:** An in-memory data store for caching user sessions, OAuth tokens, and enforcing strict Rate Limiting to prevent scraping and abuse.

### Inter-Service Communication (gRPC)
While external clients interact with the IdP via standard HTTP/REST or OIDC endpoints, internal microservices within the Hatef ecosystem (regardless of their underlying language, such as Go or C++) interact with the IdP for token validation or authorization checks.
- Internal communication is strictly conducted over **gRPC** for low latency and high throughput.
- **mTLS (Mutual TLS)** is enforced for all inter-service communication to guarantee data integrity and prevent unauthorized access within the internal network.

### Asynchronous Operations & Task Queues
- **Message Broker (NATS JetStream):** Chosen for its extremely low memory footprint, high throughput, and native Go ecosystem synergy. It is used for asynchronous communication, event broadcasting, and reliable message queuing (with persistence via JetStream) between the Go APIs and other microservices. This ensures that background tasks or cross-service events are processed reliably without tight coupling or heavy resource overhead.

### Monorepo Benefits for Web/Identity Layer
- **Shared Tooling & CI/CD:** Unified testing, linting, and deployment pipelines using Nx.
- **Code Reusability:** Shared types and utility functions between the Next.js frontend and Go backend (via code generation/shared schemas).
- **Atomic Commits:** Changes requiring frontend and API updates can be committed together, ensuring version consistency.

## 2. Identity & Security (Privacy-First)
### IdP Architecture
The Identity Provider (IdP) is custom-built in Go, focusing entirely on a privacy-first approach.
- **OIDC/OAuth2 Flow:** Implements standard OpenID Connect for secure authentication and authorization.

### Account Security & Advanced Authentication
To protect user identities against modern threats (e.g., phishing, credential stuffing), the IdP implements enterprise-grade security features:
- **WebAuthn / FIDO2 (Hardware & Platform Keys):** Full support for passwordless and highly secure logins using external hardware security keys (e.g., USB YubiKey) and platform authenticators (e.g., laptop built-in biometrics like Windows Hello, TPM, or Touch ID). This provides the highest level of phishing resistance.
- **Multi-Factor Authentication (MFA):** Support for Time-based One-Time Passwords (TOTP) via authenticator apps as a secondary or fallback authentication method.
- **Session Management:** Users have full visibility into their active sessions across all devices and can remotely revoke access to any unrecognized session.
- **Risk-Based Authentication:** The system monitors for anomalies (e.g., logins from unknown IPs, new devices, or impossible travel times). Suspicious activities trigger automatic account lockouts or require step-up authentication (MFA/WebAuthn), preventing brute-force and fraud attempts.

### Role-Based Access Control (RBAC) & Admin Capabilities
The IdP uses a strict Role-Based Access Control (RBAC) model adhering to the Principle of Least Privilege. Admin capabilities are decoupled from user data modification where possible.

#### Admin Roles & Scopes
1. **System Administrator (Super Admin):**
   - **Scope:** Infrastructure and Role Management.
   - **Capabilities:** Can assign/revoke roles to other admins, modify system-wide configurations (e.g., rate limits).
   - **Restrictions:** Does NOT have access to read individual user search history or private telemetry.

2. **Trust & Safety / Content Moderator:**
   - **Scope:** Search Results and Abuse Prevention.
   - **Capabilities:** Can manage global platform abuse prevention lists. Can **Suspend** or **Ban** abusive user accounts across the ecosystem.
   - **Restrictions:** Cannot Hard Delete users. Banning a user deactivates the account and retains a hashed fingerprint to prevent re-registration, but does not wipe the soft-deleted data manually.

3. **Data Protection Officer (DPO):**
   - **Scope:** Compliance and Audit.
   - **Capabilities:** Read-only access to system Audit Logs (ClickHouse). Can monitor automated deletion pipelines and oversee user Data Export requests.

4. **Support / Helpdesk:**
   - **Scope:** Basic User Assistance.
   - **Capabilities:** Can view high-level account status (active/suspended) and trigger password reset flows.
   - **Restrictions:** No access to personal data, IPs, or behavioral history.

#### The "Zero Trust" Admin Philosophy
- **No Manual Deletion:** Admins cannot manually perform a "Hard Delete" on a user account. Hard Deletes are exclusively triggered by the user via the "Right to be Forgotten" self-service flow, which initiates a scheduled Cron Job.
- **Audit Logging:** Every state change initiated by an admin (e.g., banning a user, changing a role) is immutably logged in the analytical database (ClickHouse).

### Privacy & GDPR Compliance
- **PII Masking:** Personally Identifiable Information is masked at the application layer before logging or analytics processing.
- **Soft Deletes:** User data deletion requests trigger soft deletes initially, ensuring data recovery windows while complying with "Right to Be Forgotten" mandates through scheduled hard sweeps.
- **Data Minimization:** Only essential data required for service operation is collected.
- **Hard Delete Cron Jobs:** While initial deletions are "soft", a Go worker (Cron Job) is scheduled to permanently purge soft-deleted records from PostgreSQL once the legal retention window (e.g., 30 days) expires, satisfying GDPR requirements.
- **Log Management & Analytics:** System logs and analytics are stored in a high-performance column-oriented database like **ClickHouse**, rather than the transactional database, to prevent write bottlenecks while allowing fast, privacy-respecting aggregate queries.

## 3. Observability & Secret Management
### Observability (Monitoring & Tracing)
A comprehensive observability stack is critical for a distributed, privacy-first system.
- **Metrics:** **Prometheus** scrapes metrics from both Go services and Next.js applications, visualized via **Grafana**.
- **Tracing:** **OpenTelemetry** is used to trace requests as they flow from the Ingress Gateway, through the Go APIs, and down to other dependent microservices. This allows developers to pinpoint latency bottlenecks without logging user PII.

### Secret Management
- **Centralized Vault:** Secrets (e.g., mTLS certificates, OIDC signing keys, PostgreSQL credentials) are never stored in the source code or environment variables directly. They are managed via a secure KMS (Key Management Service) such as **HashiCorp Vault** or **AWS KMS / Azure Key Vault**. Kubernetes injects these secrets into containers at runtime.

## 4. Monorepo Strategy
### Development Workflow
- **Nx:** Orchestrates builds, caching, and task execution across the monorepo, providing seamless integration for both TypeScript (Next.js) and Go projects.
- **Project Structure:** The Nx workspace is structured logically:
  - `apps/web`: The Next.js frontend application.
  - `apps/identity-api`: The Go Identity Provider service.
  - `libs/`: Shared TypeScript components (UI), Go utility packages, and generated protobuf schemas.
- **Shared Packages:** Common configurations (ESLint, Prettier, Tailwind) and UI components (using shadcn/ui or MUI) are extracted into shared packages.

### Type Safety (Next.js & Go)
- To maintain type safety across the stack, API contracts are defined using **Protocol Buffers (protobuf) or OpenAPI specs**.
- TypeScript types and Go structs are auto-generated from these schemas, ensuring the frontend and backend are always in sync.

## 5. API Design & Integration
### Internal vs. External APIs
- **Internal APIs (gRPC):** Used for fast, low-latency communication between the IdP and other Hatef microservices (e.g., token validation).
- **External APIs (REST/GraphQL/OIDC):** The Go backend exposes well-documented REST endpoints and standard OIDC discovery endpoints for the Next.js frontend, mobile applications, and third-party integrations.

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
- **Go:** Follow standard Go formatting (`gofmt`) and linting (`golangci-lint`).
- **Next.js/TypeScript:** Adhere to the ESLint and Prettier configurations provided in the monorepo.
- **Commit Messages:** Follow Conventional Commits format for automated changelog generation.

### Security First
- **Never commit secrets:** Use environment variables and secret management tools.
- **Review for Privacy:** Always consider the privacy implications of new features. Ensure data minimization and proper masking of PII in logs.
